package scanner

import (
	"encoding/binary"
	"testing"
)

func TestPERVAToOffsetFollowsLibyara(t *testing.T) {
	sec := 0x58 + 240 + 40
	tests := []struct {
		name    string
		virtual uint32
		pointer uint32
		rva     uint32
		want    int
		ok      bool
	}{
		{"inside raw data", 0x500, 0x400, 0x2010, 0x410, true},
		{"virtual size larger than raw size", 0x2000, 0x400, 0x2700, 0, false},
		{"last raw byte", 0x2000, 0x400, 0x25ff, 0x9ff, true},
		{"pointer aligned down to 0x200", 0x500, 0x410, 0x2010, 0x410, true},
		{"pointer aligned down to 0x200 at section start", 0x500, 0x5ff, 0x2000, 0x400, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := append(buildPE(t), make([]byte, 0x1000)...)
			binary.LittleEndian.PutUint32(b[sec+8:], tt.virtual)
			binary.LittleEndian.PutUint32(b[sec+20:], tt.pointer)
			info := parsePE(b, nil)
			if info == nil {
				t.Fatal("PE did not parse")
			}
			got, ok := info.rvaToOffset(tt.rva)
			if ok != tt.ok || (ok && got != tt.want) {
				t.Errorf("rvaToOffset(%#x) = %#x, %v; want %#x, %v", tt.rva, got, ok, tt.want, tt.ok)
			}
		})
	}
}
