package scanner

import (
	"testing"
	"time"

	"github.com/sansecio/yargo/parser"
)

func compileWith(t *testing.T, src string, opts CompileOptions) (*Rules, error) {
	t.Helper()
	rs, err := parser.New().Parse(src)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	return CompileWithOptions(rs, opts)
}

func compileSource(t *testing.T, src string) *Rules {
	t.Helper()
	rules, err := compileWith(t, src, CompileOptions{})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	return rules
}

func scanNames(t *testing.T, rules *Rules, data []byte) []string {
	t.Helper()
	var matches MatchRules
	if err := rules.ScanMem(data, 0, time.Second, &matches); err != nil {
		t.Fatalf("ScanMem() error = %v", err)
	}
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, m.Rule)
	}
	return names
}

func TestPrivateRuleIsNotReported(t *testing.T) {
	rules := compileSource(t, `private rule hidden { strings: $a = "abc" condition: $a }
rule shown { strings: $a = "abc" condition: $a }`)
	names := scanNames(t, rules, []byte("xxabcxx"))
	if len(names) != 1 || names[0] != "shown" {
		t.Errorf("expected only rule shown, got %v", names)
	}
}
