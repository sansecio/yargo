package scanner

import (
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"testing"
)

type winCert struct {
	typ  uint16
	body []byte
}

func attachCertificates(t *testing.T, certs ...winCert) []byte {
	t.Helper()
	b := buildPE(t)
	for len(b)%8 != 0 {
		b = append(b, 0)
	}
	offset := len(b)
	for _, c := range certs {
		b = binary.LittleEndian.AppendUint32(b, uint32(8+len(c.body)))
		b = binary.LittleEndian.AppendUint16(b, 0x200)
		b = binary.LittleEndian.AppendUint16(b, c.typ)
		b = append(b, c.body...)
		for len(b)%8 != 0 {
			b = append(b, 0)
		}
	}
	binary.LittleEndian.PutUint32(b[0x58+112+32:], uint32(offset))
	binary.LittleEndian.PutUint32(b[0x58+112+36:], uint32(len(b)-offset))
	return b
}

func TestPESignaturesWalkEveryWinCertificateOfTypePKCSSignedData(t *testing.T) {
	root := newTestCert(t, big.NewInt(1), pkix.Name{CommonName: "Root"}, nil)
	first := newTestCert(t, big.NewInt(2), pkix.Name{CommonName: "First"}, root)
	second := newTestCert(t, big.NewInt(3), pkix.Name{CommonName: "Second"}, root)
	x509Body := buildSignedData(first, []*testCert{root}, true)
	tests := []struct {
		name  string
		certs []winCert
		want  int
	}{
		{"two PKCS entries", []winCert{{2, buildSignedData(first, []*testCert{root}, true)}, {2, buildSignedData(second, []*testCert{root}, true)}}, 2},
		{"X509 entry before a PKCS entry", []winCert{{1, x509Body}, {2, buildSignedData(second, []*testCert{root}, true)}}, 1},
		{"only a non-PKCS entry", []winCert{{1, x509Body}}, 0},
		{"PKCS entry then padding entry of another type", []winCert{{2, buildSignedData(first, []*testCert{root}, true)}, {0x0EF0, x509Body}}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := parsePE(attachCertificates(t, tt.certs...))
			if info == nil {
				t.Fatal("PE did not parse")
			}
			info.ensureSignatures()
			if len(info.signatures) != tt.want {
				t.Errorf("got %d signatures, want %d", len(info.signatures), tt.want)
			}
		})
	}
}

func TestPESignatureEntryPastTheSecurityDirectoryIsIgnored(t *testing.T) {
	root := newTestCert(t, big.NewInt(1), pkix.Name{CommonName: "Root"}, nil)
	signer := newTestCert(t, big.NewInt(2), pkix.Name{CommonName: "Signer"}, root)
	b := attachCertificates(t, winCert{2, buildSignedData(signer, []*testCert{root}, true)})
	binary.LittleEndian.PutUint32(b[0x58+112+36:], 16)
	info := parsePE(b)
	if info == nil {
		t.Fatal("PE did not parse")
	}
	info.ensureSignatures()
	if len(info.signatures) != 0 {
		t.Errorf("got %d signatures from an entry longer than the security directory, want 0", len(info.signatures))
	}
}
