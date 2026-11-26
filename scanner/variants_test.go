package scanner

import (
	"strings"
	"testing"
	"time"
)

func TestOversizedXorAndWideStringsAreSkipped(t *testing.T) {
	for _, mods := range []string{"xor wide", "xor", "wide ascii xor(1-255)"} {
		src := `rule r { strings: $a = "` + strings.Repeat("A", 200_000) + `" ` + mods + ` condition: $a }`
		start := time.Now()
		rules := compileSource(t, src)
		if d := time.Since(start); d > time.Second {
			t.Errorf("%s: compile took %v", mods, d)
		}
		if rules.NumRules() != 0 || len(rules.Skipped()) != 1 || !strings.Contains(rules.Skipped()[0].Reason, "too large") {
			t.Errorf("%s: expected the rule skipped as too large, got %d rules, %+v", mods, rules.NumRules(), rules.Skipped())
		}
	}
}

func TestLargeStringsWithinTheVariantCapCompile(t *testing.T) {
	for _, src := range []string{
		`rule r { strings: $a = "` + strings.Repeat("A", 1000) + `" xor wide ascii condition: $a }`,
		`rule r { strings: $a = "` + strings.Repeat("A", 400_000) + `" wide condition: $a }`,
		`rule r { strings: $a = "` + strings.Repeat("A", 2_000_000) + `" condition: $a }`,
	} {
		if rules := compileSource(t, src); rules.NumRules() != 1 {
			t.Errorf("%d bytes: skipped %+v", len(src), rules.Skipped())
		}
	}
}
