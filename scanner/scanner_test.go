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
				Condition: ast.AnyOf{Pattern: "them"},
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
				Condition: ast.AnyOf{Pattern: "them"},
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
				Condition: ast.AnyOf{Pattern: "them"},
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
				Condition: ast.AnyOf{Pattern: "them"},
			},
			{
				Name: "eval_usage",
				Strings: []*ast.StringDef{
					{Name: "$eval", Value: ast.TextString{Value: "eval("}},
				},
				Condition: ast.AnyOf{Pattern: "them"},
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
				Condition: ast.AnyOf{Pattern: "them"},
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
				Condition: ast.AnyOf{Pattern: "them"},
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
				Condition: ast.AnyOf{Pattern: "them"},
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
				Condition: ast.AnyOf{Pattern: "them"},
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
				Condition: ast.AnyOf{Pattern: "them"},
			},
			{
				Name: "rule2",
				Strings: []*ast.StringDef{
					{Name: "$s", Value: ast.TextString{Value: "test"}},
				},
				Condition: ast.AnyOf{Pattern: "them"},
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
				Condition: ast.AnyOf{Pattern: "them"},
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
				Condition: ast.AnyOf{Pattern: "them"},
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
				Condition: ast.AnyOf{Pattern: "them"},
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

func TestRegexWordBoundary(t *testing.T) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "regex_wordboundary",
				Strings: []*ast.StringDef{
					{
						Name:  "$s",
						Value: ast.RegexString{Pattern: `\bmalware\b`},
					},
				},
				Condition: ast.AnyOf{Pattern: "them"},
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
		{"standalone", []byte("this is malware here"), true},
		{"at_start", []byte("malware detected"), true},
		{"at_end", []byte("found malware"), true},
		{"whole_buffer", []byte("malware"), true},
		{"prefix_no_match", []byte("malwarebytes"), false},
		{"suffix_no_match", []byte("antimalware"), false},
		{"embedded_no_match", []byte("testmalwaretest"), false},
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

func TestRegexWordBoundaryWithDot(t *testing.T) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "domain_match",
				Strings: []*ast.StringDef{
					{
						Name:  "$s",
						Value: ast.RegexString{Pattern: `\bevil\.com\b`},
					},
				},
				Condition: ast.AnyOf{Pattern: "them"},
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
		{"match", []byte("visit evil.com today"), true},
		{"at_start", []byte("evil.com is bad"), true},
		{"at_end", []byte("go to evil.com"), true},
		{"no_match_prefix", []byte("notevil.com"), false},
		{"no_match_suffix", []byte("evil.comstuff"), false},
		{"no_match_unescaped", []byte("evilXcom"), false}, // dot must be literal
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

func TestRegexWordBoundaryWithDash(t *testing.T) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "dash_domain",
				Strings: []*ast.StringDef{
					{
						Name:  "$s",
						Value: ast.RegexString{Pattern: `\bevil-site\.com\b`},
					},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
		},
	}

	rules, err := Compile(rs)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	data := []byte("check evil-site.com now")
	var matches MatchRules
	err = rules.ScanMem(data, 0, time.Second, &matches)
	if err != nil {
		t.Fatalf("ScanMem() error = %v", err)
	}

	if len(matches) != 1 {
		t.Errorf("expected 1 match, got %d", len(matches))
	}
}

func TestRegexBasicMatching(t *testing.T) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "regex_test",
				Strings: []*ast.StringDef{
					{
						Name:  "$s",
						Value: ast.RegexString{Pattern: `foo[0-9]+bar`},
					},
				},
				Condition: ast.AnyOf{Pattern: "them"},
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
		{"match_single_digit", []byte("prefix foo1bar suffix"), true},
		{"match_multi_digit", []byte("foo12345bar"), true},
		{"no_match_no_digit", []byte("foobar"), false},
		{"no_match_wrong_pattern", []byte("foo1baz"), false},
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

func TestRegexCaseInsensitive(t *testing.T) {
	// Case-insensitive regexes require full buffer scan (no atom acceleration)
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "case_insensitive",
				Strings: []*ast.StringDef{
					{
						Name:  "$s",
						Value: ast.RegexString{Pattern: `malware`, Modifiers: ast.RegexModifiers{CaseInsensitive: true}},
					},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
		},
	}

	_, err := Compile(rs)
	if err == nil {
		t.Fatal("expected error for full buffer scan regex, got nil")
	}
}

func TestRegexDotMatchesAll(t *testing.T) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "dot_all",
				Strings: []*ast.StringDef{
					{
						Name:  "$s",
						Value: ast.RegexString{Pattern: `start.+end`, Modifiers: ast.RegexModifiers{DotMatchesAll: true}},
					},
				},
				Condition: ast.AnyOf{Pattern: "them"},
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
		{"single_line", []byte("start middle end"), true},
		{"multi_line", []byte("start\nmiddle\nend"), true},
		{"no_match", []byte("begin finish"), false},
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

func TestRegexDotWithoutSFlag(t *testing.T) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "dot_no_s",
				Strings: []*ast.StringDef{
					{
						Name:  "$s",
						Value: ast.RegexString{Pattern: `start.+end`}, // no s flag
					},
				},
				Condition: ast.AnyOf{Pattern: "them"},
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
		{"single_line", []byte("start middle end"), true},
		{"multi_line", []byte("start\nmiddle\nend"), false}, // . doesn't match \n without s flag
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

func TestRegexMultiline(t *testing.T) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "multiline",
				Strings: []*ast.StringDef{
					{
						Name:  "$s",
						Value: ast.RegexString{Pattern: `^line`, Modifiers: ast.RegexModifiers{Multiline: true}},
					},
				},
				Condition: ast.AnyOf{Pattern: "them"},
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
		{"at_start", []byte("line one"), true},
		{"after_newline", []byte("first\nline two"), true},
		{"no_match_middle", []byte("not a line"), false},
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

func TestRegexComplexPatterns(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		data    []byte
		want    bool
	}{
		{"alternation", `cat|dog`, []byte("I have a dog"), true},
		{"alternation_no_match", `cat|dog`, []byte("I have a bird"), false},
		{"quantifier_plus_no_match", `abc+d`, []byte("abd"), false}, // has atom "abc"
		{"quantifier_plus", `abc+d`, []byte("abccd"), true},         // has atom "abc"
		{"optional", `colou?r`, []byte("color"), true},              // has atom "colo"
		{"optional_match", `colou?r`, []byte("colour"), true},       // has atom "colo"
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := &ast.RuleSet{
				Rules: []*ast.Rule{
					{
						Name: "test",
						Strings: []*ast.StringDef{
							{
								Name:  "$s",
								Value: ast.RegexString{Pattern: tt.pattern},
							},
						},
						Condition: ast.AnyOf{Pattern: "them"},
					},
				},
			}

			rules, err := Compile(rs)
			if err != nil {
				t.Fatalf("Compile() error = %v", err)
			}

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

func TestRegexFullBufferScanError(t *testing.T) {
	fullScanPatterns := []struct {
		name    string
		pattern string
	}{
		{"character_class", `[aeiou]+`},
		{"quantifier_star", `ab*c`},
		{"repetition", `a{3}`},
	}

	for _, tt := range fullScanPatterns {
		t.Run(tt.name, func(t *testing.T) {
			rs := &ast.RuleSet{
				Rules: []*ast.Rule{
					{
						Name: "test",
						Strings: []*ast.StringDef{
							{
								Name:  "$s",
								Value: ast.RegexString{Pattern: tt.pattern},
							},
						},
						Condition: ast.AnyOf{Pattern: "them"},
					},
				},
			}

			_, err := Compile(rs)
			if err == nil {
				t.Error("expected error for full buffer scan regex, got nil")
			}
		})
	}
}

func TestRegexInvalidPattern(t *testing.T) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "invalid",
				Strings: []*ast.StringDef{
					{
						Name:  "$s",
						Value: ast.RegexString{Pattern: `[unclosed`},
					},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
		},
	}

	_, err := Compile(rs)
	if err == nil {
		t.Error("expected error for invalid regex, got nil")
	}
}

func TestRegexWordBoundaryBackwardCompatibility(t *testing.T) {
	// Tests that \bLITERAL\b patterns work correctly
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "word_boundary",
				Strings: []*ast.StringDef{
					{
						Name:  "$s",
						Value: ast.RegexString{Pattern: `\btest\b`},
					},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
		},
	}

	rules, err := Compile(rs)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	// Pattern with word boundaries goes through regex path with atom extraction
	if len(rules.regexPatterns) != 1 {
		t.Errorf("expected 1 regex pattern, got %d", len(rules.regexPatterns))
	}

	// Verify matching still works
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"match", []byte("this is a test here"), true},
		{"no_match_prefix", []byte("testing"), false},
		{"no_match_suffix", []byte("pretest"), false},
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

func TestRegexMixedWithTextStrings(t *testing.T) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "mixed",
				Strings: []*ast.StringDef{
					{
						Name:  "$text",
						Value: ast.TextString{Value: "literal"},
					},
					{
						Name:  "$regex",
						Value: ast.RegexString{Pattern: `pattern[0-9]+`},
					},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
		},
	}

	rules, err := Compile(rs)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	tests := []struct {
		name     string
		data     []byte
		wantRule bool
		wantText bool
		wantRgx  bool
	}{
		{"text_only", []byte("has literal"), true, true, false},
		{"regex_only", []byte("has pattern123"), true, false, true},
		{"both", []byte("has literal and pattern456"), true, true, true},
		{"neither", []byte("nothing here"), false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var matches MatchRules
			err = rules.ScanMem(tt.data, 0, time.Second, &matches)
			if err != nil {
				t.Fatalf("ScanMem() error = %v", err)
			}
			gotRule := len(matches) > 0
			if gotRule != tt.wantRule {
				t.Errorf("rule match = %v, want %v", gotRule, tt.wantRule)
			}
			if gotRule {
				stringNames := make(map[string]bool)
				for _, s := range matches[0].Strings {
					stringNames[s.Name] = true
				}
				if stringNames["$text"] != tt.wantText {
					t.Errorf("$text match = %v, want %v", stringNames["$text"], tt.wantText)
				}
				if stringNames["$regex"] != tt.wantRgx {
					t.Errorf("$regex match = %v, want %v", stringNames["$regex"], tt.wantRgx)
				}
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
				Condition: ast.AnyOf{Pattern: "them"},
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

func TestSkipNilCondition(t *testing.T) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "supported",
				Strings: []*ast.StringDef{
					{Name: "$s", Value: ast.TextString{Value: "match"}},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
			{
				Name: "no_condition",
				Strings: []*ast.StringDef{
					{Name: "$a", Value: ast.TextString{Value: "also_match"}},
				},
				Condition: nil, // nil condition (e.g., failed to parse)
			},
		},
	}

	rules, err := Compile(rs)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	// Scan data that matches both rules' strings
	data := []byte("match also_match")

	var matches MatchRules
	err = rules.ScanMem(data, 0, time.Second, &matches)
	if err != nil {
		t.Fatalf("ScanMem() error = %v", err)
	}

	// Only the supported rule should match (the other was skipped)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match (nil condition rule should be skipped), got %d", len(matches))
	}
	if matches[0].Rule != "supported" {
		t.Errorf("expected rule 'supported', got %q", matches[0].Rule)
	}
}

func TestAllOfThemCondition(t *testing.T) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "all_of_them",
				Strings: []*ast.StringDef{
					{Name: "$a", Value: ast.TextString{Value: "foo"}},
					{Name: "$b", Value: ast.TextString{Value: "bar"}},
				},
				Condition: ast.AllOf{Pattern: "them"},
			},
		},
	}

	rules, err := Compile(rs)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	// Test with both strings matching
	data := []byte("foo bar")
	var matches MatchRules
	err = rules.ScanMem(data, 0, time.Second, &matches)
	if err != nil {
		t.Fatalf("ScanMem() error = %v", err)
	}
	if len(matches) != 1 {
		t.Errorf("expected 1 match when all strings present, got %d", len(matches))
	}

	// Test with only one string matching
	data2 := []byte("foo only")
	var matches2 MatchRules
	err = rules.ScanMem(data2, 0, time.Second, &matches2)
	if err != nil {
		t.Fatalf("ScanMem() error = %v", err)
	}
	if len(matches2) != 0 {
		t.Errorf("expected 0 matches when only one string present, got %d", len(matches2))
	}
}

func TestNoWarningForSupportedCondition(t *testing.T) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "supported",
				Strings: []*ast.StringDef{
					{Name: "$s", Value: ast.TextString{Value: "test"}},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
		},
	}

	_, err := Compile(rs)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
}

func TestRegexWindowCentering(t *testing.T) {
	// Test that regex matching works when there's content BEFORE the atom.
	// The atom is used to find candidate positions, but the full regex
	// may need to match content before and after the atom position.

	tests := []struct {
		name    string
		pattern string
		data    []byte
		want    bool
	}{
		// Content AFTER the atom - should work with forward-only window
		{
			name:    "content_after_atom",
			pattern: `atom.*suffix`,
			data:    []byte("here is atom and then suffix"),
			want:    true,
		},
		// Content BEFORE the atom - requires looking backward
		{
			name:    "content_before_atom",
			pattern: `prefix.*atom`,
			data:    []byte("here is prefix and then atom"),
			want:    true,
		},
		// Content on BOTH sides of the atom
		{
			name:    "content_both_sides",
			pattern: `prefix.*atom.*suffix`,
			data:    []byte("prefix in the middle atom and suffix"),
			want:    true,
		},
		// Large gap before atom (within window)
		{
			name:    "large_gap_before_atom",
			pattern: `START.*atom`,
			data:    append([]byte("START"), append(make([]byte, 200), []byte("atom")...)...),
			want:    true,
		},
		// Large gap after atom (within window)
		{
			name:    "large_gap_after_atom",
			pattern: `atom.*END`,
			data:    append([]byte("atom"), append(make([]byte, 200), []byte("END")...)...),
			want:    true,
		},
		// No match - pattern doesn't exist
		{
			name:    "no_match",
			pattern: `prefix.*atom`,
			data:    []byte("no matching content here"),
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := &ast.RuleSet{
				Rules: []*ast.Rule{
					{
						Name: "test",
						Strings: []*ast.StringDef{
							{
								Name:  "$s",
								Value: ast.RegexString{Pattern: tt.pattern},
							},
						},
						Condition: ast.AnyOf{Pattern: "them"},
					},
				},
			}

			rules, err := Compile(rs)
			if err != nil {
				t.Fatalf("Compile() error = %v", err)
			}

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

func TestRegexWindowCenteringEdgeCases(t *testing.T) {
	// Test edge cases for window positioning

	tests := []struct {
		name    string
		pattern string
		data    []byte
		want    bool
	}{
		// Atom at very beginning of buffer - can't look back
		{
			name:    "atom_at_start",
			pattern: `atom.*suffix`,
			data:    []byte("atom then suffix"),
			want:    true,
		},
		// Atom at very end of buffer - can't look forward much
		{
			name:    "atom_at_end",
			pattern: `prefix.*atom`,
			data:    []byte("prefix then atom"),
			want:    true,
		},
		// Atom near start, pattern needs to look backward
		{
			name:    "atom_near_start_lookback",
			pattern: `pre.*atom`,
			data:    []byte("pre atom"),
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := &ast.RuleSet{
				Rules: []*ast.Rule{
					{
						Name: "test",
						Strings: []*ast.StringDef{
							{
								Name:  "$s",
								Value: ast.RegexString{Pattern: tt.pattern},
							},
						},
						Condition: ast.AnyOf{Pattern: "them"},
					},
				},
			}

			rules, err := Compile(rs)
			if err != nil {
				t.Fatalf("Compile() error = %v", err)
			}

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
	p := parser.New()

	parseStart := time.Now()
	rs, err := p.ParseFile(yaraFile)
	if err != nil {
		t.Fatalf("ParseFile() error = %v", err)
	}
	t.Logf("Parse: %v (%d rules)", time.Since(parseStart), len(rs.Rules))

	compileStart := time.Now()
	rules, err := CompileWithOptions(rs, CompileOptions{SkipInvalidRegex: true})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	t.Logf("Compile: %v (%d AC patterns, %d regex patterns)", time.Since(compileStart), len(rules.patterns), len(rules.regexPatterns))

	// Load PHP file to scan
	testData, err := os.ReadFile(phpFile)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	// Scan the file
	scanStart := time.Now()
	var matches MatchRules
	err = rules.ScanMem(testData, 0, 30*time.Second, &matches)
	if err != nil {
		t.Fatalf("ScanMem() error = %v", err)
	}
	t.Logf("Scan: %v (%d bytes)", time.Since(scanStart), len(testData))

	t.Logf("Found %d matches:", len(matches))
	for _, m := range matches {
		t.Logf("  - %s (strings: %v)", m.Rule, m.Strings)
	}
}

func TestScanFile(t *testing.T) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "php_tag",
				Strings: []*ast.StringDef{
					{Name: "$php", Value: ast.TextString{Value: "<?php"}},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
		},
	}

	rules, err := Compile(rs)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	// Create a temporary file with test data
	tmpFile, err := os.CreateTemp("", "scanfile_test_*.php")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	defer os.Remove(tmpFile.Name())

	testData := []byte("hello <?php echo 'world'; ?>")
	if _, err := tmpFile.Write(testData); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	tmpFile.Close()

	var matches MatchRules
	err = rules.ScanFile(tmpFile.Name(), 0, time.Second, &matches)
	if err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}

	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Rule != "php_tag" {
		t.Errorf("expected rule 'php_tag', got %q", matches[0].Rule)
	}
}

func TestScanFileNoMatch(t *testing.T) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "php_tag",
				Strings: []*ast.StringDef{
					{Name: "$php", Value: ast.TextString{Value: "<?php"}},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
		},
	}

	rules, err := Compile(rs)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	tmpFile, err := os.CreateTemp("", "scanfile_test_*.txt")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	defer os.Remove(tmpFile.Name())

	testData := []byte("hello world, no php here")
	if _, err := tmpFile.Write(testData); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	tmpFile.Close()

	var matches MatchRules
	err = rules.ScanFile(tmpFile.Name(), 0, time.Second, &matches)
	if err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}

	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d", len(matches))
	}
}

func TestScanFileNotFound(t *testing.T) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "test",
				Strings: []*ast.StringDef{
					{Name: "$s", Value: ast.TextString{Value: "test"}},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
		},
	}

	rules, err := Compile(rs)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	var matches MatchRules
	err = rules.ScanFile("/nonexistent/path/to/file.txt", 0, time.Second, &matches)
	if err == nil {
		t.Error("expected error for nonexistent file, got nil")
	}
}

func TestScanFileEmptyFile(t *testing.T) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "test",
				Strings: []*ast.StringDef{
					{Name: "$s", Value: ast.TextString{Value: "test"}},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
		},
	}

	rules, err := Compile(rs)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	tmpFile, err := os.CreateTemp("", "scanfile_empty_*.txt")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	var matches MatchRules
	err = rules.ScanFile(tmpFile.Name(), 0, time.Second, &matches)
	if err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}

	if len(matches) != 0 {
		t.Errorf("expected 0 matches for empty file, got %d", len(matches))
	}
}

func TestScanFileLargeFile(t *testing.T) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "marker",
				Strings: []*ast.StringDef{
					{Name: "$s", Value: ast.TextString{Value: "MARKER_STRING"}},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
		},
	}

	rules, err := Compile(rs)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	tmpFile, err := os.CreateTemp("", "scanfile_large_*.bin")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write 10MB of padding then marker then more padding
	padding := make([]byte, 5*1024*1024) // 5MB
	marker := []byte("MARKER_STRING")

	if _, err := tmpFile.Write(padding); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if _, err := tmpFile.Write(marker); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if _, err := tmpFile.Write(padding); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	tmpFile.Close()

	var matches MatchRules
	err = rules.ScanFile(tmpFile.Name(), 0, 30*time.Second, &matches)
	if err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}

	if len(matches) != 1 {
		t.Fatalf("expected 1 match in large file, got %d", len(matches))
	}
	if matches[0].Rule != "marker" {
		t.Errorf("expected rule 'marker', got %q", matches[0].Rule)
	}
}

func TestMatchOrderDeterministic(t *testing.T) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name:      "rule_ccc",
				Strings:   []*ast.StringDef{{Name: "$s", Value: ast.TextString{Value: "test"}}},
				Condition: ast.AnyOf{Pattern: "them"},
			},
			{
				Name:      "rule_aaa",
				Strings:   []*ast.StringDef{{Name: "$s", Value: ast.TextString{Value: "test"}}},
				Condition: ast.AnyOf{Pattern: "them"},
			},
			{
				Name:      "rule_bbb",
				Strings:   []*ast.StringDef{{Name: "$s", Value: ast.TextString{Value: "test"}}},
				Condition: ast.AnyOf{Pattern: "them"},
			},
		},
	}

	rules, err := Compile(rs)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	data := []byte("this is a test string")

	for i := 0; i < 50; i++ {
		var matches MatchRules
		err := rules.ScanMem(data, 0, time.Second, &matches)
		if err != nil {
			t.Fatalf("ScanMem() error = %v", err)
		}

		if len(matches) != 3 {
			t.Fatalf("iteration %d: expected 3 matches, got %d", i, len(matches))
		}

		if matches[0].Rule != "rule_ccc" {
			t.Errorf("iteration %d: expected first match 'rule_ccc', got %q", i, matches[0].Rule)
		}
		if matches[1].Rule != "rule_aaa" {
			t.Errorf("iteration %d: expected second match 'rule_aaa', got %q", i, matches[1].Rule)
		}
		if matches[2].Rule != "rule_bbb" {
			t.Errorf("iteration %d: expected third match 'rule_bbb', got %q", i, matches[2].Rule)
		}
	}
}

func TestScanFileMatchesScanMem(t *testing.T) {
	// Verify ScanFile produces the same results as ScanMem
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "multi_match",
				Strings: []*ast.StringDef{
					{Name: "$a", Value: ast.TextString{Value: "foo"}},
					{Name: "$b", Value: ast.TextString{Value: "bar"}},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
		},
	}

	rules, err := Compile(rs)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	testData := []byte("foo and bar and more foo")

	// Test with ScanMem
	var memMatches MatchRules
	err = rules.ScanMem(testData, 0, time.Second, &memMatches)
	if err != nil {
		t.Fatalf("ScanMem() error = %v", err)
	}

	// Test with ScanFile
	tmpFile, err := os.CreateTemp("", "scanfile_compare_*.txt")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(testData); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	tmpFile.Close()

	var fileMatches MatchRules
	err = rules.ScanFile(tmpFile.Name(), 0, time.Second, &fileMatches)
	if err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}

	// Compare results
	if len(memMatches) != len(fileMatches) {
		t.Fatalf("ScanMem returned %d matches, ScanFile returned %d", len(memMatches), len(fileMatches))
	}

	for i := range memMatches {
		if memMatches[i].Rule != fileMatches[i].Rule {
			t.Errorf("match[%d] rule mismatch: ScanMem=%q, ScanFile=%q", i, memMatches[i].Rule, fileMatches[i].Rule)
		}
	}
}
