package scanner

import (
	"strings"
	"testing"
)

// libyara fails compilation with `undefined identifier "x"` for names that
// are not rules defined earlier, externals, loop variables or imported
// modules, so a typo cannot silently turn a rule off.
// https://yara.readthedocs.io/en/stable/writingrules.html#referencing-other-rules
// https://yara.readthedocs.io/en/stable/modules.html
func TestUndefinedIdentifiersFailCompilation(t *testing.T) {
	for _, src := range []string{
		`rule r { condition: nosuch }`,
		`rule r { condition: foo.bar == 0 }`,
		`rule r { condition: later } rule later { condition: true }`,
		`rule r { condition: pe.number_of_sections == 0 }`,
		`rule r { condition: pe.imphash() == "x" }`,
		`rule r { condition: pe.sections[0].name == "x" }`,
		`rule r { condition: math.entropy(0, filesize) > 7 }`,
		`rule r { condition: hash.md5(0, filesize) == "x" }`,
		`import "math" rule r { condition: pe.is_pe }`,
		`rule r { condition: nosuch(1) == 0 }`,
		`rule r { condition: for any i in (0..1): (j == 1) }`,
		`rule r { condition: (for any i in (1..2) : (i == 2)) and not i == 2 }`,
	} {
		_, err := compileWith(t, src, CompileOptions{})
		if err == nil || !strings.Contains(err.Error(), "undefined identifier") {
			t.Errorf("%s: expected an undefined identifier error, got %v", src, err)
		}
	}
}

func TestKnownButUnsupportedIdentifiersAreSkipped(t *testing.T) {
	for _, src := range []string{
		`rule r { condition: entrypoint == 0 }`,
		`import "elf" rule r { condition: elf.type == 1 }`,
		`import "math" rule r { condition: math.serial_correlation(0, filesize) < 0.1 }`,
		`rule skipped { strings: $a = "a" frobnicate condition: $a } rule r { condition: skipped }`,
	} {
		rules := compileSource(t, src)
		var reasons []string
		for _, s := range rules.Skipped() {
			if s.Rule == "r" {
				reasons = append(reasons, s.Reason)
			}
		}
		if len(reasons) != 1 || reasons[0] == "" {
			t.Errorf("%s: expected rule r skipped with a reason, got %+v", src, rules.Skipped())
		}
	}
}

func TestDefinedIdentifiersCompile(t *testing.T) {
	src := `import "pe" import "math" import "hash"
rule a { condition: true }
rule r { condition: a and pe.is_pe == 0 and math.entropy(0, filesize) >= 0 and hash.md5(0, 0) != "" and for any i in (0..1): (i == 1) and filename != "" }`
	rules := compileSource(t, src)
	if rules.NumRules() != 2 || len(rules.Skipped()) != 0 {
		t.Errorf("expected both rules compiled, got %d, skipped %+v", rules.NumRules(), rules.Skipped())
	}
}
