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

func TestFullwordModifier(t *testing.T) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "fullword_test",
				Strings: []*ast.StringDef{
					{
						Name:      "$s",
						Value:     ast.TextString{Value: "test"},
						Modifiers: ast.StringModifiers{Fullword: true},
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

	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"standalone_word", []byte("this is a test here"), true},
		{"at_start", []byte("test is at start"), true},
		{"at_end", []byte("ends with test"), true},
		{"whole_buffer", []byte("test"), true},
		{"with_punctuation", []byte("run test."), true},
		{"with_comma", []byte("test, more"), true},
		{"prefix_no_match", []byte("testing should not match"), false},
		{"suffix_no_match", []byte("a pretest example"), false},
		{"embedded_no_match", []byte("attestation"), false},
		{"with_underscore_no_match", []byte("unit_test here"), false},
		{"with_digit_no_match", []byte("test123 should not"), false},
		{"digit_prefix_no_match", []byte("123test should not"), false},
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

func TestFullwordWithMultipleMatches(t *testing.T) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "fullword_multi",
				Strings: []*ast.StringDef{
					{
						Name:      "$s",
						Value:     ast.TextString{Value: "test"},
						Modifiers: ast.StringModifiers{Fullword: true},
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

	// First occurrence is embedded (no match), second is standalone (match)
	data := []byte("testing is different from test")

	var matches MatchRules
	err = rules.ScanMem(data, 0, time.Second, &matches)
	if err != nil {
		t.Fatalf("ScanMem() error = %v", err)
	}

	if len(matches) != 1 {
		t.Errorf("expected 1 match (for standalone 'test'), got %d", len(matches))
	}
}

func TestFullwordAtBufferBoundaries(t *testing.T) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "boundary_test",
				Strings: []*ast.StringDef{
					{
						Name:      "$s",
						Value:     ast.TextString{Value: "abc"},
						Modifiers: ast.StringModifiers{Fullword: true},
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

	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"exactly_buffer", []byte("abc"), true},
		{"start_of_buffer_word", []byte("abc def"), true},
		{"end_of_buffer_word", []byte("def abc"), true},
		{"start_of_buffer_no_word", []byte("abcd"), false},
		{"end_of_buffer_no_word", []byte("dabc"), false},
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

func TestFullwordMixedWithRegular(t *testing.T) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "mixed_test",
				Strings: []*ast.StringDef{
					{
						Name:      "$fullword",
						Value:     ast.TextString{Value: "test"},
						Modifiers: ast.StringModifiers{Fullword: true},
					},
					{
						Name:  "$regular",
						Value: ast.TextString{Value: "test"},
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

	// "testing" should match $regular but not $fullword
	data := []byte("testing")

	var matches MatchRules
	err = rules.ScanMem(data, 0, time.Second, &matches)
	if err != nil {
		t.Fatalf("ScanMem() error = %v", err)
	}

	if len(matches) != 1 {
		t.Fatalf("expected 1 rule match, got %d", len(matches))
	}

	// Check that only $regular matched
	stringNames := make(map[string]bool)
	for _, s := range matches[0].Strings {
		stringNames[s.Name] = true
	}

	if !stringNames["$regular"] {
		t.Error("expected $regular to match")
	}
	if stringNames["$fullword"] {
		t.Error("expected $fullword NOT to match")
	}
}

func TestIntegrationWithRealYaraFile(t *testing.T) {
	yaraFile := "../fixture/ecomscan.yar"
	phpFile := "../fixture/Product.php"

	if _, err := os.Stat(yaraFile); os.IsNotExist(err) {
		t.Skip("fixture/ecomscan.yar not available, skipping integration test")
	}
	if _, err := os.Stat(phpFile); os.IsNotExist(err) {
		t.Skip("fixture/Product.php not available, skipping integration test")
	}

	// Parse YARA rules
	p, err := parser.New()
	if err != nil {
		t.Fatalf("parser.New() error = %v", err)
	}

	parseStart := time.Now()
	rs, err := p.ParseFile(yaraFile)
	if err != nil {
		t.Fatalf("ParseFile() error = %v", err)
	}
	parseTime := time.Since(parseStart)
	t.Logf("Parse time: %v (%d rules)", parseTime, len(rs.Rules))

	// Compile rules
	compileStart := time.Now()
	rules, err := Compile(rs)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	compileTime := time.Since(compileStart)
	t.Logf("Compile time: %v", compileTime)

	// Load PHP file to scan
	testData, err := os.ReadFile(phpFile)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	t.Logf("Scanning %d bytes (%s)", len(testData), phpFile)

	// Scan the file
	scanStart := time.Now()
	var matches MatchRules
	err = rules.ScanMem(testData, 0, 30*time.Second, &matches)
	if err != nil {
		t.Fatalf("ScanMem() error = %v", err)
	}
	scanTime := time.Since(scanStart)
	t.Logf("Scan time: %v", scanTime)

	t.Logf("Found %d matches:", len(matches))
	for _, m := range matches {
		t.Logf("  - %s (strings: %v)", m.Rule, m.Strings)
	}
}
