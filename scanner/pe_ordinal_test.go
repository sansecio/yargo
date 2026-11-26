package scanner

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestPEImportsByOrdinalUseTheLibyaraNameTables(t *testing.T) {
	at := func(rva int) int { return 0x400 + rva - 0x2000 }
	tests := []struct {
		name    string
		dll     string
		ordinal uint64
		want    string
	}{
		{"ws2_32", "WS2_32.dll", 5, "ws2_32.getpeername"},
		{"ws2_32 upper case extension", "WS2_32.DLL", 115, "ws2_32.wsastartup"},
		{"wsock32", "wsock32.dll", 3, "wsock32.closesocket"},
		{"oleaut32", "OLEAUT32.dll", 2, "oleaut32.sysallocstring"},
		{"ordinal without a name", "OLEAUT32.dll", 9999, "oleaut32.ord9999"},
		{"other dll", "MSVCRT.dll", 5, "msvcrt.ord5"},
		{"dll name without extension", "WS2_32", 5, "ws2_32.ord5"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := buildPE(t)
			copy(b[at(0x2210):], make([]byte, 16))
			copy(b[at(0x2210):], tt.dll)
			binary.LittleEndian.PutUint64(b[at(0x2120):], 0x8000000000000000|tt.ordinal)
			sum := md5.Sum([]byte("kernel32.createfilea," + tt.want))
			rules := compileSource(t, `import "pe" rule r { condition: pe.imphash() == "`+hex.EncodeToString(sum[:])+`" }`)
			if got := scanNames(t, rules, b); len(got) != 1 {
				t.Errorf("imphash does not hash %q", tt.want)
			}
		})
	}
}

func TestPEImportsByOrdinalMatchByLookedUpNameAndByOrdinal(t *testing.T) {
	at := func(rva int) int { return 0x400 + rva - 0x2000 }
	b := buildPE(t)
	copy(b[at(0x2210):], make([]byte, 16))
	copy(b[at(0x2210):], "WS2_32.dll")
	binary.LittleEndian.PutUint64(b[at(0x2120):], 0x8000000000000005)
	for _, cond := range []string{`pe.imports("ws2_32.dll", "getpeername")`, `pe.imports("ws2_32.dll", 5)`} {
		rules := compileSource(t, `import "pe" `+"rule r { condition: "+cond+" }")
		if got := scanNames(t, rules, b); len(got) != 1 {
			t.Errorf("%s did not match", cond)
		}
	}
}
