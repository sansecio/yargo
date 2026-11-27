package parser

import (
	"strings"
	"testing"
	"time"
)

func nested(n int) map[string]string {
	return map[string]string{
		"parentheses": strings.Repeat("(", n) + "true" + strings.Repeat(")", n),
		"not":         strings.Repeat("not ", n) + "true",
		"minus":       strings.Repeat("-", n) + "1 == 1",
		"tilde":       strings.Repeat("~", n) + "1 == 1",
		"index":       strings.Repeat("pe.sections[", n) + "0" + strings.Repeat("].name", n) + ` == ""`,
		"mixed":       strings.Repeat("not (", n/2) + "true" + strings.Repeat(")", n/2),
	}
}

func TestParseRejectsDeepNestingQuickly(t *testing.T) {
	for name, cond := range nested(1_000_000) {
		start := time.Now()
		_, err := New().Parse("rule t { condition: " + cond + " }")
		if err == nil || !strings.Contains(err.Error(), "nested too deeply") {
			t.Errorf("%s: expected a nesting error, got %v", name, err)
		}
		if d := time.Since(start); d > 100*time.Millisecond {
			t.Errorf("%s: rejecting took %v", name, d)
		}
	}
}

func TestParseAcceptsModerateNesting(t *testing.T) {
	for name, cond := range nested(maxConditionDepth) {
		if name == "index" {
			continue
		}
		if _, err := New().Parse("rule t { condition: " + cond + " }"); err != nil {
			t.Errorf("%s at depth %d: %v", name, maxConditionDepth, err)
		}
	}
	flat := strings.Repeat("true and not true or -1 < ~2 and (true) or ", 100_000) + "true"
	if _, err := New().Parse("rule t { condition: " + flat + " }"); err != nil {
		t.Errorf("long flat condition: %v", err)
	}
}
