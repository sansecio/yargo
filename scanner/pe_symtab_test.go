package scanner

import (
	"encoding/binary"
	"testing"
)

func TestPEGarbageSymbolTablePointerDoesNotLoseTheModule(t *testing.T) {
	b := buildPE(t)
	binary.LittleEndian.PutUint32(b[0x4c:], 0xFFFFFF00)
	binary.LittleEndian.PutUint32(b[0x50:], 0x7FFFFFFF)
	rules := compileSource(t, `import "pe"
rule r { condition: pe.number_of_sections == 2 and pe.exports("Alpha") }`)
	if got := scanNames(t, rules, b); len(got) != 1 {
		t.Errorf("pe module lost on a garbage symbol table pointer: %v", got)
	}
}
