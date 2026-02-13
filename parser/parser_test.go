package parser

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/sansecio/yargo/ast"
)

func mustParse(t *testing.T, input string) *ast.RuleSet {
	t.Helper()
	p := New()
	rs, err := p.Parse(input)
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	return rs
}

func TestParseMinimalRule(t *testing.T) {
	rs := mustParse(t, `rule test { strings: $ = "text" condition: any of them }`)

	if len(rs.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rs.Rules))
	}
	r := rs.Rules[0]
	if r.Name != "test" {
		t.Errorf("expected name 'test', got %q", r.Name)
	}
	if _, ok := r.Condition.(ast.AnyOf); !ok {
		t.Errorf("expected condition AnyOf, got %T", r.Condition)
	}
	if len(r.Strings) != 1 || r.Strings[0].Name != "$" {
		t.Errorf("expected anonymous string, got %v", r.Strings)
	}
}

func TestParseNamedString(t *testing.T) {
	rs := mustParse(t, `rule test { strings: $foo = "bar" condition: any of them }`)
	if rs.Rules[0].Strings[0].Name != "$foo" {
		t.Errorf("expected '$foo', got %q", rs.Rules[0].Strings[0].Name)
	}
}

func TestParseMeta(t *testing.T) {
	rs := mustParse(t, `rule test {
		meta:
			str = "value"
			num = 123
			neg = -42
		strings: $ = "x"
		condition: any of them
	}`)

	meta := rs.Rules[0].Meta
	if len(meta) != 3 {
		t.Fatalf("expected 3 meta entries, got %d", len(meta))
	}

	tests := []struct {
		key   string
		value any
	}{
		{"str", "value"},
		{"num", int64(123)},
		{"neg", int64(-42)},
	}
	for i, tt := range tests {
		if meta[i].Key != tt.key || meta[i].Value != tt.value {
			t.Errorf("meta[%d]: expected %s=%v, got %s=%v", i, tt.key, tt.value, meta[i].Key, meta[i].Value)
		}
	}
}

func TestParseHexStrings(t *testing.T) {
	tests := []struct {
		name   string
		hex    string
		tokens []ast.HexToken
	}{
		{"bytes", "{ FF D8 }", []ast.HexToken{ast.HexByte{Value: 0xFF}, ast.HexByte{Value: 0xD8}}},
		{"wildcard", "{ FF ?? D8 }", []ast.HexToken{ast.HexByte{Value: 0xFF}, ast.HexWildcard{}, ast.HexByte{Value: 0xD8}}},
		{"jump exact", "{ FF [4] D8 }", []ast.HexToken{ast.HexByte{Value: 0xFF}, ast.HexJump{Min: intPtr(4), Max: intPtr(4)}, ast.HexByte{Value: 0xD8}}},
		{"jump range", "{ FF [4-16] D8 }", []ast.HexToken{ast.HexByte{Value: 0xFF}, ast.HexJump{Min: intPtr(4), Max: intPtr(16)}, ast.HexByte{Value: 0xD8}}},
		{"jump unbounded", "{ FF [-] D8 }", []ast.HexToken{ast.HexByte{Value: 0xFF}, ast.HexJump{}, ast.HexByte{Value: 0xD8}}},
		{"jump min only", "{ FF [4-] D8 }", []ast.HexToken{ast.HexByte{Value: 0xFF}, ast.HexJump{Min: intPtr(4)}, ast.HexByte{Value: 0xD8}}},
		{"jump max only", "{ FF [-16] D8 }", []ast.HexToken{ast.HexByte{Value: 0xFF}, ast.HexJump{Max: intPtr(16)}, ast.HexByte{Value: 0xD8}}},
		{"alternation", "{ FF (41|42) D8 }", []ast.HexToken{ast.HexByte{Value: 0xFF}, ast.HexAlt{Alternatives: []ast.HexAltItem{{Byte: bytePtr(0x41)}, {Byte: bytePtr(0x42)}}}, ast.HexByte{Value: 0xD8}}},
		{"alt with wildcard", "{ (41|??) }", []ast.HexToken{ast.HexAlt{Alternatives: []ast.HexAltItem{{Byte: bytePtr(0x41)}, {Wildcard: true}}}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := mustParse(t, `rule test { strings: $ = `+tt.hex+` condition: any of them }`)
			hex := rs.Rules[0].Strings[0].Value.(ast.HexString)
			if !hexTokensEqual(hex.Tokens, tt.tokens) {
				t.Errorf("expected %v, got %v", tt.tokens, hex.Tokens)
			}
		})
	}
}

func TestParseRegex(t *testing.T) {
	tests := []struct {
		input   string
		pattern string
	}{
		{`/pattern/`, "pattern"},
		{`/pattern/s`, "pattern"},
		{`/pattern/sim`, "pattern"},
		{`/foo\/bar/`, `foo\/bar`},
		{`/\bword\b/i`, `\bword\b`},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			rs := mustParse(t, `rule test { strings: $ = `+tt.input+` condition: any of them }`)
			regex := rs.Rules[0].Strings[0].Value.(ast.RegexString)
			if regex.Pattern != tt.pattern {
				t.Errorf("expected pattern %q, got %q", tt.pattern, regex.Pattern)
			}
		})
	}
}

func TestParseModifiers(t *testing.T) {
	tests := []struct {
		input string
		mods  ast.StringModifiers
	}{
		{`"x" base64`, ast.StringModifiers{Base64: true}},
		{`"x" fullword`, ast.StringModifiers{Fullword: true}},
		{`"x" wide ascii`, ast.StringModifiers{}},
		{`"x" nocase fullword`, ast.StringModifiers{Fullword: true}},
		{`{ FF } base64`, ast.StringModifiers{Base64: true}},
		{`/pattern/ nocase`, ast.StringModifiers{}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			rs := mustParse(t, `rule test { strings: $ = `+tt.input+` condition: any of them }`)
			got := rs.Rules[0].Strings[0].Modifiers
			if got != tt.mods {
				t.Errorf("expected %+v, got %+v", tt.mods, got)
			}
		})
	}
}

func TestParseEscapeSequences(t *testing.T) {
	rs := mustParse(t, `rule test { strings: $ = "a\nb\tc\\d\"e\x41" condition: any of them }`)
	text := rs.Rules[0].Strings[0].Value.(ast.TextString)
	expected := "a\nb\tc\\d\"eA"
	if text.Value != expected {
		t.Errorf("expected %q, got %q", expected, text.Value)
	}
}

func TestParseMultipleStrings(t *testing.T) {
	rs := mustParse(t, `rule test {
		strings:
			$a = "one"
			$b = { FF }
			$ = /pattern/
		condition: any of them
	}`)

	names := []string{"$a", "$b", "$"}
	for i, s := range rs.Rules[0].Strings {
		if s.Name != names[i] {
			t.Errorf("string %d: expected %q, got %q", i, names[i], s.Name)
		}
	}
}

func TestParseMultipleRules(t *testing.T) {
	rs := mustParse(t, `
		rule one { strings: $ = "a" condition: any of them }
		rule two { strings: $ = "b" condition: any of them }
	`)

	if len(rs.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rs.Rules))
	}
	if rs.Rules[0].Name != "one" || rs.Rules[1].Name != "two" {
		t.Errorf("unexpected rule names: %q, %q", rs.Rules[0].Name, rs.Rules[1].Name)
	}
}

func TestParseComments(t *testing.T) {
	inputs := []string{
		`// comment
		rule test { strings: $ = "x" condition: any of them }`,
		`/* block */ rule test { strings: $ = "x" condition: any of them }`,
		`rule test { /* mid */ strings: $ = "x" condition: any of them }`,
		`rule test { strings: $ = "x" /* after */ condition: any of them }`,
		`rule test { strings: $ = { FF /* in hex */ D8 } condition: any of them }`,
		`rule test { strings: $ = { FF } /* after hex */ condition: any of them }`,
	}

	for i, input := range inputs {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			rs := mustParse(t, input)
			if len(rs.Rules) != 1 {
				t.Errorf("expected 1 rule, got %d", len(rs.Rules))
			}
		})
	}
}

func TestParseFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yar")
	content := `rule test { strings: $ = "x" condition: any of them }`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	p := New()
	rs, err := p.ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}
	if len(rs.Rules) != 1 || rs.Rules[0].Name != "test" {
		t.Errorf("unexpected result: %+v", rs)
	}
}

func TestParseFileNotFound(t *testing.T) {
	p := New()
	_, err := p.ParseFile("/nonexistent/file.yar")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestParseConditionWithParens(t *testing.T) {
	// Test that complex conditions with parens are parsed correctly
	rs := mustParse(t, `rule test { strings: $a = "x" condition: ($a at 0) and any of them }`)
	bin, ok := rs.Rules[0].Condition.(ast.BinaryExpr)
	if !ok {
		t.Fatalf("expected BinaryExpr, got %T", rs.Rules[0].Condition)
	}
	if bin.Op != "and" {
		t.Errorf("expected 'and', got %q", bin.Op)
	}
}

// Helpers

func intPtr(i int) *int    { return &i }
func bytePtr(b byte) *byte { return &b }

func hexTokensEqual(a, b []ast.HexToken) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !reflect.DeepEqual(a[i], b[i]) {
			return false
		}
	}
	return true
}
