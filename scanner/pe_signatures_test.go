package scanner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	mrand "math/rand"
	"testing"
	"time"
)

func derSeq(parts ...[]byte) []byte {
	return derValue(asn1.ClassUniversal, asn1.TagSequence, parts...)
}

func derSet(parts ...[]byte) []byte {
	return derValue(asn1.ClassUniversal, asn1.TagSet, parts...)
}

func derContext(tag int, parts ...[]byte) []byte {
	return derValue(asn1.ClassContextSpecific, tag, parts...)
}

func derValue(class, tag int, parts ...[]byte) []byte {
	var body []byte
	for _, p := range parts {
		body = append(body, p...)
	}
	out, err := asn1.Marshal(asn1.RawValue{Class: class, Tag: tag, IsCompound: true, Bytes: body})
	if err != nil {
		panic(err)
	}
	return out
}

func derMarshal(v any) []byte {
	out, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return out
}

var (
	oidSignedData   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidSpcIndirect  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}
	oidSpcNested    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 4, 1}
	oidSHA256       = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidRSAEncrypted = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
)

type testCert struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCert(t *testing.T, serial *big.Int, subject pkix.Name, parent *testCert) *testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		NotBefore:    time.Unix(1_600_000_000, 0),
		NotAfter:     time.Unix(1_900_000_000, 0),
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCert{cert: cert, key: key}
}

func buildSignedData(signer *testCert, extraCerts []*testCert, spcContent bool, nested ...[]byte) []byte {
	var certs []byte
	certs = append(certs, signer.cert.Raw...)
	for _, c := range extraCerts {
		certs = append(certs, c.cert.Raw...)
	}
	contentType := oidSpcIndirect
	if !spcContent {
		contentType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	}
	content := derSeq(derMarshal(contentType), derContext(0, derSeq(derMarshal(1))))
	signerInfo := [][]byte{
		derMarshal(1),
		derSeq(signer.cert.RawIssuer, derMarshal(signer.cert.SerialNumber)),
		derSeq(derMarshal(oidSHA256)),
		derSeq(derMarshal(oidRSAEncrypted)),
		derMarshal([]byte{1, 2, 3}),
	}
	if len(nested) > 0 {
		var attrs [][]byte
		for _, n := range nested {
			attrs = append(attrs, derSeq(derMarshal(oidSpcNested), derSet(n)))
		}
		signerInfo = append(signerInfo, derContext(1, attrs...))
	}
	signedData := derSeq(derMarshal(1), derSet(), content, derContext(0, certs), derSet(derSeq(signerInfo...)))
	return derSeq(derMarshal(oidSignedData), derContext(0, signedData))
}

func attachSignature(t *testing.T, pkcs7 []byte) []byte {
	t.Helper()
	b := buildPE(t)
	for len(b)%8 != 0 {
		b = append(b, 0)
	}
	offset := len(b)
	b = binary.LittleEndian.AppendUint32(b, uint32(8+len(pkcs7)))
	b = binary.LittleEndian.AppendUint16(b, 0x200)
	b = binary.LittleEndian.AppendUint16(b, 2)
	b = append(b, pkcs7...)
	binary.LittleEndian.PutUint32(b[0x58+112+32:], uint32(offset))
	binary.LittleEndian.PutUint32(b[0x58+112+36:], uint32(len(b)-offset))
	return b
}

func TestPESignatures(t *testing.T) {
	root := newTestCert(t, big.NewInt(1), pkix.Name{Country: []string{"US"}, Organization: []string{"Test CA"}, CommonName: "Test Root"}, nil)
	leaf := newTestCert(t, new(big.Int).SetBytes([]byte{0xff, 0x12, 0x00}), pkix.Name{Country: []string{"US"}, Organization: []string{"Acme, Inc."}, CommonName: "Acme Signing"}, root)
	other := newTestCert(t, big.NewInt(0x0102), pkix.Name{CommonName: "Second Signer", OrganizationalUnit: []string{"Dev"}}, root)
	nested := buildSignedData(other, []*testCert{root}, true)
	data := attachSignature(t, buildSignedData(leaf, []*testCert{root}, true, nested))
	thumb := sha1.Sum(leaf.cert.Raw)
	tests := []struct {
		cond string
		want bool
	}{
		{"pe.number_of_signatures == 2", true},
		{`pe.signatures[0].issuer == "/C=US/O=Test CA/CN=Test Root"`, true},
		{`pe.signatures[0].subject == "/C=US/O=Acme, Inc./CN=Acme Signing"`, true},
		{`pe.signatures[0].serial == "00:ff:12:00"`, true},
		{`pe.signatures[0].thumbprint == "` + hex.EncodeToString(thumb[:]) + `"`, true},
		{"pe.signatures[0].version == 3", true},
		{"pe.signatures[0].not_before == 1600000000", true},
		{"pe.signatures[0].not_after == 1900000000", true},
		{"pe.signatures[0].number_of_certificates == 2", true},
		{`pe.signatures[1].subject == "/CN=Second Signer/OU=Dev"`, false},
		{`pe.signatures[1].subject == "/OU=Dev/CN=Second Signer"`, true},
		{`pe.signatures[1].serial == "01:02"`, true},
		{`not pe.signatures[2].serial == "x"`, false},
		{`for any i in (0..pe.number_of_signatures-1) : (pe.signatures[i].issuer contains "Test Root" and pe.signatures[i].serial == "01:02")`, true},
	}
	for _, tt := range tests {
		t.Run(tt.cond, func(t *testing.T) {
			rules := compileSource(t, "rule r { condition: "+tt.cond+" }")
			if rules.NumRules() != 1 {
				t.Fatalf("rule skipped: %+v", rules.Skipped())
			}
			if got := len(scanNames(t, rules, data)) == 1; got != tt.want {
				t.Errorf("expected %v, got %v", tt.want, got)
			}
		})
	}
}

func TestPESignatureCounts(t *testing.T) {
	root := newTestCert(t, big.NewInt(1), pkix.Name{CommonName: "Root"}, nil)
	leaf := newTestCert(t, big.NewInt(2), pkix.Name{CommonName: "Leaf"}, root)
	tests := []struct {
		name string
		data []byte
		want int
	}{
		{"unsigned", buildPE(t), 0},
		{"not a pkcs7", attachSignature(t, []byte("garbage garbage garbage")), 0},
		{"signed", attachSignature(t, buildSignedData(leaf, nil, true)), 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := compileSource(t, fmt.Sprintf("rule r { condition: pe.number_of_signatures == %d }", tt.want))
			if got := scanNames(t, rules, tt.data); len(got) != 1 {
				t.Errorf("number_of_signatures != %d", tt.want)
			}
		})
	}
}

func TestPESignatureWithoutIndirectContentHasNoSignerFields(t *testing.T) {
	root := newTestCert(t, big.NewInt(1), pkix.Name{CommonName: "Root"}, nil)
	leaf := newTestCert(t, big.NewInt(2), pkix.Name{CommonName: "Leaf"}, root)
	data := attachSignature(t, buildSignedData(leaf, nil, false))
	rules := compileSource(t, `rule counted { condition: pe.number_of_signatures == 1 }
rule has_subject { condition: pe.signatures[0].subject contains "Leaf" }
rule certificates { condition: pe.signatures[0].number_of_certificates == 1 }`)
	got := scanNames(t, rules, data)
	if len(got) != 2 || got[0] != "counted" || got[1] != "certificates" {
		t.Errorf("matches = %v", got)
	}
}

func TestPESignatureParsingIsBounded(t *testing.T) {
	root := newTestCert(t, big.NewInt(1), pkix.Name{CommonName: "Root"}, nil)
	leaf := newTestCert(t, big.NewInt(2), pkix.Name{CommonName: "Leaf"}, root)
	inner := buildSignedData(leaf, nil, true)
	for range 40 {
		inner = buildSignedData(leaf, nil, true, inner)
	}
	data := attachSignature(t, inner)
	rules := compileSource(t, "rule r { condition: pe.number_of_signatures > 0 }")
	start := time.Now()
	scanNames(t, rules, data)
	if d := time.Since(start); d > time.Second {
		t.Errorf("scan took %v", d)
	}
	info := parsePE(data, nil)
	info.ensureSignatures()
	if len(info.signatures) > maxSignatures {
		t.Errorf("collected %d signatures", len(info.signatures))
	}
}

func TestPESignatureDirectoryOutsideTheFileIsIgnored(t *testing.T) {
	b := buildPE(t)
	binary.LittleEndian.PutUint32(b[0x58+112+32:], 0xFFFFFF00)
	binary.LittleEndian.PutUint32(b[0x58+112+36:], 0x1000)
	rules := compileSource(t, "rule r { condition: pe.number_of_signatures == 0 }")
	if got := scanNames(t, rules, b); len(got) != 1 {
		t.Errorf("matches = %v", got)
	}
}

func TestPEExtendedMembersSurviveCorruption(t *testing.T) {
	root := newTestCert(t, big.NewInt(1), pkix.Name{CommonName: "Root"}, nil)
	leaf := newTestCert(t, big.NewInt(2), pkix.Name{CommonName: "Leaf"}, root)
	signed := attachSignature(t, buildSignedData(leaf, []*testCert{root}, true, buildSignedData(leaf, nil, true)))
	withResources := buildPEWithResources(t, [][2]string{{"CompanyName", "ACME"}, {"FileVersion", "1.2.3.4"}})
	rules := compileSource(t, `rule r { condition:
	pe.number_of_signatures > 100 or pe.signatures[0].issuer contains "x" or pe.signatures[1].serial == "x" or
	pe.number_of_resources > 100 or pe.resources[0].type_string == "x" or pe.resources[1].offset == 1 or
	pe.version_info["CompanyName"] == "x" or pe.version_info_list[0].value == "x" or pe.overlay.size > 1000000000 }`)
	rng := mrand.New(mrand.NewSource(7))
	for _, base := range [][]byte{signed, withResources} {
		for i := range 3000 {
			data := append([]byte(nil), base...)
			for range 1 + rng.Intn(8) {
				data[rng.Intn(len(data))] = byte(rng.Intn(256))
			}
			if i%9 == 0 {
				data = data[:rng.Intn(len(data))]
			}
			scanNames(t, rules, data)
		}
	}
}
