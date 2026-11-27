package scanner

import "testing"

func TestPESectionIndexByFileOffset(t *testing.T) {
	tests := []struct {
		cond string
		want bool
	}{
		{"pe.section_index(0x200) == 0", true},
		{"pe.section_index(0x3ff) == 0", true},
		{"pe.section_index(0x400) == 1", true},
		{"pe.section_index(0x9ff) == 1", true},
		{"pe.section_index(0xa00) == 1", false},
		{"pe.section_index(0x1ff) == 0", false},
		{"pe.section_index(0x1000) == 0", false},
	}
	data := buildPE(t)
	for _, tt := range tests {
		t.Run(tt.cond, func(t *testing.T) {
			rules := compileSource(t, `import "pe"
rule r { condition: `+tt.cond+` }`)
			if rules.NumRules() != 1 {
				t.Fatalf("rule skipped: %+v", rules.Skipped())
			}
			if got := len(scanNames(t, rules, data)) == 1; got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPESectionIndexOutOfAnySectionIsUndefined(t *testing.T) {
	data := buildPE(t)
	for _, cond := range []string{"pe.section_index(0xa00) == 0", "not pe.section_index(0xa00) == 0", "pe.section_index(0) == 0"} {
		rules := compileSource(t, `import "pe"
rule r { condition: `+cond+` }`)
		if got := scanNames(t, rules, data); len(got) != 0 {
			t.Errorf("%s matched", cond)
		}
	}
}
