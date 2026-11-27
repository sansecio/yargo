package scanner

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	maxSignatures      = 16
	maxSignatureDepth  = 8
	maxCertificates    = 256
	maxNameOnelineLen  = 255
	maxSerialBytes     = 20
	securityDirectory  = 4
	winCertHeaderBytes = 8

	winCertTypePKCSSignedData = 0x0002
)

var (
	oidPKCS7SignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidSpcIndirectData = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}
	oidSpcNestedSig    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 4, 1}
	oidMSCountersig    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 3, 3, 1}
)

type peSignature struct {
	hasSigner    bool
	certificates int64
	signer       peCertificate
}

type peCertificate struct {
	thumbprint string
	issuer     string
	subject    string
	version    int64
	serial     string
	hasSerial  bool
	notBefore  int64
	notAfter   int64
}

type pkcs7ContentInfo struct {
	Type    asn1.ObjectIdentifier
	Content asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type pkcs7Certificates struct {
	Raw asn1.RawContent
}

type pkcs7Attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue
}

type pkcs7IssuerAndSerial struct {
	Issuer asn1.RawValue
	Serial asn1.RawValue
}

type pkcs7SignerInfo struct {
	Version      int
	IssuerSerial pkcs7IssuerAndSerial
	DigestAlg    pkix.AlgorithmIdentifier
	AuthAttrs    []pkcs7Attribute `asn1:"optional,tag:0"`
	EncryptAlg   pkix.AlgorithmIdentifier
	EncDigest    []byte
	UnauthAttrs  []pkcs7Attribute `asn1:"optional,tag:1"`
}

type pkcs7SignedData struct {
	Version    int
	DigestAlgs []pkix.AlgorithmIdentifier `asn1:"set"`
	Content    pkcs7ContentInfo
	Certs      pkcs7Certificates `asn1:"optional,tag:0"`
	CRLs       pkcs7Certificates `asn1:"optional,tag:1"`
	Signers    []pkcs7SignerInfo `asn1:"set"`
}

type certificateTBS struct {
	Raw      asn1.RawContent
	Version  int `asn1:"optional,explicit,default:0,tag:0"`
	Serial   asn1.RawValue
	SigAlg   asn1.RawValue
	Issuer   asn1.RawValue
	Validity struct{ NotBefore, NotAfter time.Time }
	Subject  asn1.RawValue
}

type certificateDER struct {
	Raw    asn1.RawContent
	TBS    asn1.RawValue
	SigAlg asn1.RawValue
	Sig    asn1.BitString
}

type parsedCertificate struct {
	peCertificate
	issuerRaw  []byte
	serialBody []byte
}

func (p *peInfo) ensureSignatures() {
	if p.signaturesParsed {
		return
	}
	p.signaturesParsed = true
	if len(p.dirs) <= securityDirectory {
		return
	}
	dir := p.dirs[securityDirectory]
	size := uint64(len(p.buf))
	if dir.VirtualAddress == 0 || uint64(dir.VirtualAddress) > size || uint64(dir.Size) > size || uint64(dir.VirtualAddress)+uint64(dir.Size) > size {
		return
	}
	off := int(dir.VirtualAddress)
	if dir.Size < winCertHeaderBytes || !p.fits(off, winCertHeaderBytes) {
		return
	}
	end := off + int(dir.Size)
	for off+winCertHeaderBytes <= end && len(p.signatures) < maxSignatures && !p.stopped() {
		length := int(binary.LittleEndian.Uint32(p.buf[off:]))
		if length < winCertHeaderBytes || length > end-off {
			return
		}
		if binary.LittleEndian.Uint16(p.buf[off+6:]) == winCertTypePKCSSignedData {
			p.signatures = parseAuthenticode(p.buf[off+winCertHeaderBytes:off+length], 0, p.signatures)
		}
		off += (length + 7) &^ 7
	}
}

func parseAuthenticode(der []byte, depth int, out []peSignature) []peSignature {
	if depth >= maxSignatureDepth || len(out) >= maxSignatures {
		return out
	}
	var info pkcs7ContentInfo
	if _, err := asn1.Unmarshal(der, &info); err != nil || !info.Type.Equal(oidPKCS7SignedData) {
		return out
	}
	var sd pkcs7SignedData
	if _, err := asn1.Unmarshal(info.Content.Bytes, &sd); err != nil {
		return out
	}
	certs := parseCertificates(sd.Certs)
	sig := peSignature{certificates: int64(len(certs))}
	if len(sd.Signers) > 0 {
		sig.certificates += countersignatureCertificates(sd.Signers[0].UnauthAttrs)
	}
	if !sd.Content.Type.Equal(oidSpcIndirectData) {
		return append(out, sig)
	}
	if len(sd.Signers) == 0 {
		return out
	}
	signer := sd.Signers[0]
	out = append(out, sig)
	self := len(out) - 1
	for _, nested := range nestedSignatures(signer.UnauthAttrs) {
		out = parseAuthenticode(nested, depth+1, out)
	}
	for _, c := range certs {
		if bytes.Equal(c.issuerRaw, signer.IssuerSerial.Issuer.FullBytes) && bytes.Equal(c.serialBody, signer.IssuerSerial.Serial.Bytes) {
			out[self].signer, out[self].hasSigner = c.peCertificate, true
			return out
		}
	}
	return append(out[:self], out[self+1:]...)
}

func countersignatureCertificates(attrs []pkcs7Attribute) int64 {
	var total int64
	for _, attr := range attrs {
		if !attr.Type.Equal(oidMSCountersig) {
			continue
		}
		values := attr.Values.Bytes
		for n := 0; len(values) > 0 && n < maxSignatures; n++ {
			var v asn1.RawValue
			var err error
			if values, err = asn1.Unmarshal(values, &v); err != nil {
				break
			}
			var info pkcs7ContentInfo
			if _, err := asn1.Unmarshal(v.FullBytes, &info); err != nil || !info.Type.Equal(oidPKCS7SignedData) {
				continue
			}
			var sd pkcs7SignedData
			if _, err := asn1.Unmarshal(info.Content.Bytes, &sd); err != nil {
				continue
			}
			total += int64(len(parseCertificates(sd.Certs)))
		}
	}
	return total
}

func nestedSignatures(attrs []pkcs7Attribute) [][]byte {
	var nested [][]byte
	for _, attr := range attrs {
		if !attr.Type.Equal(oidSpcNestedSig) {
			continue
		}
		values := attr.Values.Bytes
		for len(values) > 0 && len(nested) < maxSignatures {
			var v asn1.RawValue
			var err error
			if values, err = asn1.Unmarshal(values, &v); err != nil {
				break
			}
			nested = append(nested, v.FullBytes)
		}
	}
	return nested
}

func parseCertificates(raw pkcs7Certificates) []parsedCertificate {
	if len(raw.Raw) == 0 {
		return nil
	}
	var set asn1.RawValue
	if _, err := asn1.Unmarshal(raw.Raw, &set); err != nil {
		return nil
	}
	var certs []parsedCertificate
	rest := set.Bytes
	for len(rest) > 0 && len(certs) < maxCertificates {
		var cert certificateDER
		var err error
		if rest, err = asn1.Unmarshal(rest, &cert); err != nil {
			break
		}
		if c, ok := parseCertificate(cert); ok {
			certs = append(certs, c)
		}
	}
	return certs
}

func parseCertificate(cert certificateDER) (parsedCertificate, bool) {
	var tbs certificateTBS
	if _, err := asn1.Unmarshal(cert.TBS.FullBytes, &tbs); err != nil {
		return parsedCertificate{}, false
	}
	sum := sha1.Sum(cert.Raw)
	c := parsedCertificate{issuerRaw: tbs.Issuer.FullBytes, serialBody: tbs.Serial.Bytes}
	c.thumbprint = hex.EncodeToString(sum[:])
	c.issuer = oneline(tbs.Issuer.FullBytes)
	c.subject = oneline(tbs.Subject.FullBytes)
	c.version = int64(tbs.Version) + 1
	c.notBefore, c.notAfter = tbs.Validity.NotBefore.Unix(), tbs.Validity.NotAfter.Unix()
	if n := len(tbs.Serial.Bytes); n >= 1 && n <= maxSerialBytes {
		parts := make([]string, n)
		for i, b := range tbs.Serial.Bytes {
			parts[i] = fmt.Sprintf("%02x", b)
		}
		c.serial, c.hasSerial = strings.Join(parts, ":"), true
	}
	return c, true
}

var nameShortNames = map[string]string{
	"2.5.4.3": "CN", "2.5.4.4": "SN", "2.5.4.5": "serialNumber", "2.5.4.6": "C", "2.5.4.7": "L",
	"2.5.4.8": "ST", "2.5.4.9": "street", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.12": "title",
	"2.5.4.13": "description", "2.5.4.15": "businessCategory", "2.5.4.17": "postalCode",
	"2.5.4.42": "GN", "2.5.4.43": "initials", "2.5.4.46": "dnQualifier",
	"1.2.840.113549.1.9.1":       "emailAddress",
	"0.9.2342.19200300.100.1.25": "DC", "0.9.2342.19200300.100.1.1": "UID",
	"1.3.6.1.4.1.311.60.2.1.1": "jurisdictionL", "1.3.6.1.4.1.311.60.2.1.2": "jurisdictionST",
	"1.3.6.1.4.1.311.60.2.1.3": "jurisdictionC",
}

type nameAttribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue
}

func oneline(der []byte) string {
	var name asn1.RawValue
	if _, err := asn1.Unmarshal(der, &name); err != nil {
		return ""
	}
	var sb strings.Builder
	for rdns := name.Bytes; len(rdns) > 0 && sb.Len() <= maxNameOnelineLen; {
		var rdn asn1.RawValue
		var err error
		if rdns, err = asn1.Unmarshal(rdns, &rdn); err != nil {
			break
		}
		for attrs := rdn.Bytes; len(attrs) > 0; {
			var attr nameAttribute
			if attrs, err = asn1.Unmarshal(attrs, &attr); err != nil {
				break
			}
			label, ok := nameShortNames[attr.Type.String()]
			if !ok {
				label = attr.Type.String()
			}
			sb.WriteString("/" + label + "=" + attributeText(attr.Value))
		}
	}
	return sb.String()[:min(sb.Len(), maxNameOnelineLen)]
}

func attributeText(v asn1.RawValue) string {
	if v.Tag != asn1.TagBMPString {
		return string(v.Bytes)
	}
	units := make([]uint16, len(v.Bytes)/2)
	for i := range units {
		units[i] = binary.BigEndian.Uint16(v.Bytes[2*i:])
	}
	return string(utf16.Decode(units))
}

func (p *peInfo) signatureField(i int64, field string) any {
	p.ensureSignatures()
	if i < 0 || i >= int64(len(p.signatures)) {
		return nil
	}
	s := p.signatures[i]
	if field == "number_of_certificates" {
		return s.certificates
	}
	if !s.hasSigner {
		return nil
	}
	switch field {
	case "thumbprint":
		return s.signer.thumbprint
	case "issuer":
		return s.signer.issuer
	case "subject":
		return s.signer.subject
	case "version":
		return s.signer.version
	case "serial":
		if !s.signer.hasSerial {
			return nil
		}
		return s.signer.serial
	case "not_before":
		return s.signer.notBefore
	case "not_after":
		return s.signer.notAfter
	}
	return nil
}
