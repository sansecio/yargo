package scanner

import (
	"os"
	"testing"
	"time"

	"github.com/sansecio/yargo/ast"
	"github.com/sansecio/yargo/parser"
)

func TestBasicStringMatch(t *testing.T) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "php_tag",
				Strings: []*ast.StringDef{
					{Name: "$php", Value: ast.TextString{Value: "<?php"}},
				},
				Condition: "any of them",
			},
		},
	}

	rules, err := Compile(rs)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	data := []byte("hello <?php echo 'world'; ?>")

	var matches MatchRules
	err = rules.ScanMem(data, 0, time.Second, &matches)
	if err != nil {
		t.Fatalf("ScanMem() error = %v", err)
	}

	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Rule != "php_tag" {
		t.Errorf("expected rule 'php_tag', got %q", matches[0].Rule)
	}
	if len(matches[0].Strings) != 1 || matches[0].Strings[0].Name != "$php" {
		t.Errorf("expected matched string $php, got %v", matches[0].Strings)
	}
}

func TestNoMatch(t *testing.T) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "php_tag",
				Strings: []*ast.StringDef{
					{Name: "$php", Value: ast.TextString{Value: "<?php"}},
				},
				Condition: "any of them",
			},
		},
	}

	rules, err := Compile(rs)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	data := []byte("hello world, no php here")

	var matches MatchRules
	err = rules.ScanMem(data, 0, time.Second, &matches)
	if err != nil {
		t.Fatalf("ScanMem() error = %v", err)
	}

	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d", len(matches))
	}
}

func TestMultipleStringsInRule(t *testing.T) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "web_shell",
				Strings: []*ast.StringDef{
					{Name: "$a", Value: ast.TextString{Value: "eval"}},
					{Name: "$b", Value: ast.TextString{Value: "base64_decode"}},
				},
				Condition: "any of them",
			},
		},
	}

	rules, err := Compile(rs)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	// Data contains only one string
	data := []byte("<?php eval($_POST['cmd']); ?>")

	var matches MatchRules
	err = rules.ScanMem(data, 0, time.Second, &matches)
	if err != nil {
		t.Fatalf("ScanMem() error = %v", err)
	}

	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Rule != "web_shell" {
		t.Errorf("expected rule 'web_shell', got %q", matches[0].Rule)
	}
}

func TestMultipleRules(t *testing.T) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "php_tag",
				Strings: []*ast.StringDef{
					{Name: "$php", Value: ast.TextString{Value: "<?php"}},
				},
				Condition: "any of them",
			},
			{
				Name: "eval_usage",
				Strings: []*ast.StringDef{
					{Name: "$eval", Value: ast.TextString{Value: "eval("}},
				},
				Condition: "any of them",
			},
		},
	}

	rules, err := Compile(rs)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	data := []byte("<?php eval($_POST['cmd']); ?>")

	var matches MatchRules
	err = rules.ScanMem(data, 0, time.Second, &matches)
	if err != nil {
		t.Fatalf("ScanMem() error = %v", err)
	}

	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(matches))
	}

	ruleNames := make(map[string]bool)
	for _, m := range matches {
		ruleNames[m.Rule] = true
	}
	if !ruleNames["php_tag"] || !ruleNames["eval_usage"] {
		t.Errorf("expected both rules to match, got %v", ruleNames)
	}
}

func TestBase64Modifier(t *testing.T) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "base64_encoded",
				Strings: []*ast.StringDef{
					{
						Name:      "$s",
						Value:     ast.TextString{Value: "secret"},
						Modifiers: ast.StringModifiers{Base64: true},
					},
				},
				Condition: "any of them",
			},
		},
	}

	rules, err := Compile(rs)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	// "secret" base64 encoded is "c2VjcmV0"
	// Test all 3 rotations by placing it at different offsets
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"rotation0", []byte("data: c2VjcmV0"), true},   // "secret" at position 0 mod 3
		{"rotation1", []byte("data: AHNlY3JldA"), true}, // ?secret -> base64 -> skip 2 chars
		{"rotation2", []byte("data: AAc2VjcmV0"), true}, // ??secret -> base64 -> skip 4 chars
		{"no_match", []byte("data: not_encoded"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var matches MatchRules
			err = rules.ScanMem(tt.data, 0, time.Second, &matches)
			if err != nil {
				t.Fatalf("ScanMem() error = %v", err)
			}
			got := len(matches) > 0
			if got != tt.want {
				t.Errorf("match = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMetaExtraction(t *testing.T) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "test_rule",
				Meta: []*ast.MetaEntry{
					{Key: "author", Value: "test"},
					{Key: "severity", Value: int64(5)},
				},
				Strings: []*ast.StringDef{
					{Name: "$s", Value: ast.TextString{Value: "match"}},
				},
				Condition: "any of them",
			},
		},
	}

	rules, err := Compile(rs)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	data := []byte("this will match")

	var matches MatchRules
	err = rules.ScanMem(data, 0, time.Second, &matches)
	if err != nil {
		t.Fatalf("ScanMem() error = %v", err)
	}

	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	if len(matches[0].Metas) != 2 {
		t.Fatalf("expected 2 metas, got %d", len(matches[0].Metas))
	}

	metaMap := make(map[string]interface{})
	for _, m := range matches[0].Metas {
		metaMap[m.Identifier] = m.Value
	}

	if metaMap["author"] != "test" {
		t.Errorf("expected author='test', got %v", metaMap["author"])
	}
	if metaMap["severity"] != int64(5) {
		t.Errorf("expected severity=5, got %v", metaMap["severity"])
	}
}

func TestTimeout(t *testing.T) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "test",
				Strings: []*ast.StringDef{
					{Name: "$s", Value: ast.TextString{Value: "test"}},
				},
				Condition: "any of them",
			},
		},
	}

	rules, err := Compile(rs)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	// A very small timeout should still work for small data
	data := []byte("test data")
	var matches MatchRules
	err = rules.ScanMem(data, 0, time.Millisecond, &matches)
	if err != nil {
		t.Fatalf("ScanMem() error = %v", err)
	}
}

func TestEmptyRuleset(t *testing.T) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{},
	}

	rules, err := Compile(rs)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	data := []byte("any data")
	var matches MatchRules
	err = rules.ScanMem(data, 0, time.Second, &matches)
	if err != nil {
		t.Fatalf("ScanMem() error = %v", err)
	}

	if len(matches) != 0 {
		t.Errorf("expected 0 matches for empty ruleset, got %d", len(matches))
	}
}

func TestRuleWithNoStrings(t *testing.T) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name:      "no_strings",
				Strings:   []*ast.StringDef{},
				Condition: "any of them",
			},
		},
	}

	rules, err := Compile(rs)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	data := []byte("any data")
	var matches MatchRules
	err = rules.ScanMem(data, 0, time.Second, &matches)
	if err != nil {
		t.Fatalf("ScanMem() error = %v", err)
	}

	// Rule with no strings and "any of them" condition should not match
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for rule with no strings, got %d", len(matches))
	}
}

func TestScanCallbackAbort(t *testing.T) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "rule1",
				Strings: []*ast.StringDef{
					{Name: "$s", Value: ast.TextString{Value: "test"}},
				},
				Condition: "any of them",
			},
			{
				Name: "rule2",
				Strings: []*ast.StringDef{
					{Name: "$s", Value: ast.TextString{Value: "test"}},
				},
				Condition: "any of them",
			},
		},
	}

	rules, err := Compile(rs)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	data := []byte("test data")

	// Custom callback that aborts after first match
	callCount := 0
	cb := &abortCallback{
		callback: func(r *MatchRule) (abort bool, err error) {
			callCount++
			return true, nil // abort after first
		},
	}

	err = rules.ScanMem(data, 0, time.Second, cb)
	if err != nil {
		t.Fatalf("ScanMem() error = %v", err)
	}

	if callCount != 1 {
		t.Errorf("expected callback to be called once, got %d", callCount)
	}
}

type abortCallback struct {
	callback func(r *MatchRule) (abort bool, err error)
}

func (a *abortCallback) RuleMatching(r *MatchRule) (abort bool, err error) {
	return a.callback(r)
}

func TestIntegrationWithRealYaraFile(t *testing.T) {
	yaraFile := "/home/daniel/Code/ecomscan-signatures/build/ecomscan.yar"
	if _, err := os.Stat(yaraFile); os.IsNotExist(err) {
		t.Skip("Real YARA file not available, skipping integration test")
	}

	p, err := parser.New()
	if err != nil {
		t.Fatalf("parser.New() error = %v", err)
	}

	rs, err := p.ParseFile(yaraFile)
	if err != nil {
		t.Fatalf("ParseFile() error = %v", err)
	}

	rules, err := Compile(rs)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	// Scan some PHP code that should match common webshell signatures
	testData := []byte(`<?php eval(base64_decode($_POST['cmd'])); ?>`)

	var matches MatchRules
	err = rules.ScanMem(testData, 0, 5*time.Second, &matches)
	if err != nil {
		t.Fatalf("ScanMem() error = %v", err)
	}

	t.Logf("Compiled %d rules, found %d matches", len(rs.Rules), len(matches))
	for _, m := range matches {
		t.Logf("  - %s (strings: %v)", m.Rule, m.Strings)
	}
}
