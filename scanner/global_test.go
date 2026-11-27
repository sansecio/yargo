package scanner

import (
	"slices"
	"testing"
)

func TestGlobalRuleGatesTheOthers(t *testing.T) {
	rules := compileSource(t, `
global rule only_small { condition: filesize < 64 }
rule finds_abc { strings: $a = "abc" condition: $a }
rule finds_xyz { strings: $a = "xyz" condition: $a }
`)
	tests := []struct {
		name string
		data string
		want []string
	}{
		{"small file", "abc", []string{"finds_abc", "only_small"}},
		{"large file", "abc" + string(make([]byte, 100)), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scanNames(t, rules, []byte(tt.data))
			slices.Sort(got)
			if !slices.Equal(got, tt.want) {
				t.Errorf("matches = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGlobalRuleWithStringsFailsWithoutHits(t *testing.T) {
	rules := compileSource(t, `
global rule needs_marker { strings: $m = "MARKER" condition: $m }
rule finds_abc { strings: $a = "abc" condition: $a }
`)
	if got := scanNames(t, rules, []byte("abc")); len(got) != 0 {
		t.Errorf("rules matched without the global marker: %v", got)
	}
	got := scanNames(t, rules, []byte("abc MARKER"))
	slices.Sort(got)
	if !slices.Equal(got, []string{"finds_abc", "needs_marker"}) {
		t.Errorf("matches = %v", got)
	}
}

func TestPrivateGlobalRuleGatesWithoutBeingReported(t *testing.T) {
	rules := compileSource(t, `
private global rule gate { strings: $m = "MARKER" condition: $m }
rule finds_abc { strings: $a = "abc" condition: $a }
`)
	if got := scanNames(t, rules, []byte("abc")); len(got) != 0 {
		t.Errorf("matched without the gate: %v", got)
	}
	if got := scanNames(t, rules, []byte("abc MARKER")); !slices.Equal(got, []string{"finds_abc"}) {
		t.Errorf("matches = %v", got)
	}
}
