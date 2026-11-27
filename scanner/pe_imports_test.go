package scanner

import (
	"encoding/binary"
	"testing"
)

func TestPEImportsWithAFunctionReturnBooleansWhileDLLOnlyCounts(t *testing.T) {
	at := func(rva int) int { return 0x400 + rva - 0x2000 }
	b := buildPE(t)
	le := binary.LittleEndian
	le.PutUint64(b[at(0x2100)+8:], 0x2300)
	le.PutUint64(b[at(0x2100)+16:], 0x8000000000000005)
	le.PutUint64(b[at(0x2100)+24:], 0x8000000000000005)
	tests := []struct {
		cond string
		want bool
	}{
		{`pe.imports("kernel32.dll", "CreateFileA") == 1`, true},
		{`pe.imports("kernel32.dll", "CreateFileA") == 2`, false},
		{`pe.imports("kernel32.dll", "Nope") == 0`, true},
		{`pe.imports("kernel32.dll", 5) == 1`, true},
		{`pe.imports("kernel32.dll", 6) == 0`, true},
		{`pe.imports("kernel32.dll") == 5`, true},
	}
	for _, tt := range tests {
		t.Run(tt.cond, func(t *testing.T) {
			rules := compileSource(t, `import "pe"
rule r { condition: `+tt.cond+` }`)
			if got := len(scanNames(t, rules, b)) == 1; got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
