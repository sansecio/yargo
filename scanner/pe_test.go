package scanner

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"math/rand"
	"testing"
)

func buildPE(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 0xA00)
	le := binary.LittleEndian
	copy(b, "MZ")
	le.PutUint32(b[0x3c:], 0x40)
	copy(b[0x40:], "PE\x00\x00")
	le.PutUint16(b[0x44:], 0x8664)
	le.PutUint16(b[0x46:], 2)
	le.PutUint32(b[0x48:], 1234)
	le.PutUint16(b[0x54:], 240)
	le.PutUint16(b[0x56:], 0x2022)
	o := 0x58
	le.PutUint16(b[o:], 0x20b)
	le.PutUint32(b[o+16:], 0x1000)
	le.PutUint64(b[o+24:], 0x140000000)
	le.PutUint32(b[o+32:], 0x1000)
	le.PutUint32(b[o+36:], 0x200)
	le.PutUint32(b[o+56:], 0x3000)
	le.PutUint32(b[o+60:], 0x200)
	le.PutUint16(b[o+68:], 3)
	le.PutUint32(b[o+108:], 16)
	le.PutUint32(b[o+112:], 0x2400)
	le.PutUint32(b[o+116:], 0x80)
	le.PutUint32(b[o+120:], 0x2000)
	le.PutUint32(b[o+124:], 60)
	s := 0x58 + 240
	copy(b[s:], ".text")
	le.PutUint32(b[s+8:], 0x200)
	le.PutUint32(b[s+12:], 0x1000)
	le.PutUint32(b[s+16:], 0x200)
	le.PutUint32(b[s+20:], 0x200)
	copy(b[s+40:], ".idata")
	le.PutUint32(b[s+48:], 0x500)
	le.PutUint32(b[s+52:], 0x2000)
	le.PutUint32(b[s+56:], 0x600)
	le.PutUint32(b[s+60:], 0x400)
	at := func(rva int) int { return 0x400 + rva - 0x2000 }
	d := at(0x2000)
	le.PutUint32(b[d:], 0x2100)
	le.PutUint32(b[d+12:], 0x2200)
	le.PutUint32(b[d+16:], 0x2100)
	le.PutUint32(b[d+20:], 0x2120)
	le.PutUint32(b[d+32:], 0x2210)
	le.PutUint32(b[d+36:], 0x2120)
	le.PutUint64(b[at(0x2100):], 0x2300)
	le.PutUint64(b[at(0x2120):], 0x8000000000000005)
	copy(b[at(0x2200):], "KERNEL32.dll")
	copy(b[at(0x2210):], "MSVCRT.dll")
	copy(b[at(0x2302):], "CreateFileA")
	e := at(0x2400)
	le.PutUint32(b[e+16:], 1)
	le.PutUint32(b[e+20:], 2)
	le.PutUint32(b[e+24:], 2)
	le.PutUint32(b[e+28:], 0x2440)
	le.PutUint32(b[e+32:], 0x2450)
	le.PutUint32(b[e+36:], 0x2460)
	le.PutUint32(b[at(0x2440):], 0x1000)
	le.PutUint32(b[at(0x2444):], 0x1010)
	le.PutUint32(b[at(0x2450):], 0x2470)
	le.PutUint32(b[at(0x2454):], 0x2480)
	le.PutUint16(b[at(0x2464):], 1)
	copy(b[at(0x2470):], "Alpha")
	copy(b[at(0x2480):], "Beta")
	return b
}

func TestPEModule(t *testing.T) {
	sum := md5.Sum([]byte("kernel32.createfilea,msvcrt.ord5"))
	imphash := hex.EncodeToString(sum[:])
	tests := []struct {
		cond string
		want bool
	}{
		{"pe.is_dll()", true},
		{"pe.is_64bit()", true},
		{"pe.is_32bit()", false},
		{"not pe.is_32bit()", true},
		{"pe.machine == pe.MACHINE_AMD64", true},
		{"pe.machine == pe.MACHINE_I386", false},
		{"pe.characteristics & pe.DLL", true},
		{"pe.subsystem == 3", true},
		{"pe.timestamp == 1234", true},
		{"pe.entry_point == 0x200", true},
		{"pe.number_of_sections == 2", true},
		{`pe.sections[0].name == ".text"`, true},
		{`pe.sections[1].name == ".idata"`, true},
		{"pe.sections[1].raw_data_size == 0x600", true},
		{"pe.sections[1].virtual_address == 0x2000", true},
		{"pe.sections[2].raw_data_size == 0", false},
		{"not pe.sections[2].raw_data_size == 0", false},
		{`pe.section_index(".idata") == 1`, true},
		{`pe.section_index(".none") == -1`, false},
		{`pe.imphash() == "` + imphash + `"`, true},
		{`pe.imphash() == "00"`, false},
		{`pe.exports("Alpha")`, true},
		{`pe.exports("Zeta")`, false},
		{"pe.exports(1)", true},
		{"pe.exports(3)", false},
		{"pe.number_of_exports == 2", true},
		{`pe.imports("kernel32.dll", "CreateFileA")`, true},
		{`pe.imports("KERNEL32.DLL", "CreateFileW")`, false},
		{`pe.imports("kernel32.dll") == 1`, true},
		{`pe.imports("msvcrt.dll", 5)`, true},
		{`pe.imports("user32.dll") == 0`, true},
	}
	data := buildPE(t)
	for _, tt := range tests {
		t.Run(tt.cond, func(t *testing.T) {
			rules := compileSource(t, "import \"pe\"\nrule r { condition: "+tt.cond+" }")
			if rules.NumRules() != 1 {
				t.Fatalf("rule skipped: %+v", rules.Skipped())
			}
			if got := len(scanNames(t, rules, data)) == 1; got != tt.want {
				t.Errorf("expected %v, got %v", tt.want, got)
			}
		})
	}
}

func TestPEModuleOnNonPEIsUndefined(t *testing.T) {
	for _, cond := range []string{"pe.is_dll()", "not pe.is_dll()", "pe.number_of_sections == 0", "not pe.number_of_sections == 0", "pe.exports(\"a\")"} {
		rules := compileSource(t, `import "pe" `+"rule r { condition: "+cond+" }")
		if got := scanNames(t, rules, []byte("MZ not a pe file at all")); len(got) != 0 {
			t.Errorf("%s matched a non-PE file", cond)
		}
	}
}

func TestPEModuleSkipsUnsupportedMembers(t *testing.T) {
	rules := compileSource(t, `import "pe" rule r { condition: pe.is_signed }`)
	if rules.NumRules() != 0 || len(rules.Skipped()) != 1 {
		t.Errorf("expected skipped rule, got %d rules, %+v", rules.NumRules(), rules.Skipped())
	}
}

func TestPEModuleSurvivesCorruptHeaders(t *testing.T) {
	rules := compileSource(t, `import "pe" rule r { condition: pe.imphash() == "x" or pe.exports("a") or pe.imports("a.dll") or pe.sections[0].name == "a" or pe.number_of_exports > 100 }`)
	rng := rand.New(rand.NewSource(1))
	base := buildPE(t)
	for i := range 3000 {
		data := append([]byte(nil), base...)
		for range 1 + rng.Intn(6) {
			data[rng.Intn(0x900)] = byte(rng.Intn(256))
		}
		if i%7 == 0 {
			data = data[:rng.Intn(len(data))]
		}
		scanNames(t, rules, data)
	}
}
