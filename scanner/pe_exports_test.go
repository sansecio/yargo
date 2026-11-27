package scanner

import (
	"encoding/binary"
	"testing"
)

func TestPEExportsOrdinalIsBasePlusTableIndex(t *testing.T) {
	at := func(rva int) int { return 0x400 + rva - 0x2000 }
	tests := []struct {
		name    string
		base    uint32
		funcs   uint32
		names   uint32
		cond    string
		matches bool
	}{
		{"unnamed entry next to named ones", 1, 3, 2, "pe.exports(3)", true},
		{"past the table", 1, 3, 2, "pe.exports(4)", false},
		{"below the base", 5, 3, 2, "pe.exports(4)", false},
		{"no names honours the base", 2, 3, 0, "pe.exports(3)", true},
		{"no names ignores base-less index", 2, 3, 0, "pe.exports(1)", false},
		{"ordinal above the export count", 2, 3, 0, "pe.exports(4)", false},
		{"base above the export count", 5, 2, 0, "pe.exports(5)", false},
		{"ordinal zero", 0, 3, 0, "pe.exports(0)", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := buildPE(t)
			e := at(0x2400)
			binary.LittleEndian.PutUint32(b[e+16:], tt.base)
			binary.LittleEndian.PutUint32(b[e+20:], tt.funcs)
			binary.LittleEndian.PutUint32(b[e+24:], tt.names)
			rules := compileSource(t, `import "pe"
rule r { condition: `+tt.cond+` }`)
			if got := len(scanNames(t, rules, b)) == 1; got != tt.matches {
				t.Errorf("%s: got %v, want %v", tt.cond, got, tt.matches)
			}
		})
	}
}
