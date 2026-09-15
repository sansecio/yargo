package parser

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
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
		{"jump exact", "{ FF [4] D8 }", []ast.HexToken{ast.HexByte{Value: 0xFF}, ast.HexJump{Min: new(4), Max: new(4)}, ast.HexByte{Value: 0xD8}}},
		{"jump range", "{ FF [4-16] D8 }", []ast.HexToken{ast.HexByte{Value: 0xFF}, ast.HexJump{Min: new(4), Max: new(16)}, ast.HexByte{Value: 0xD8}}},
		{"jump unbounded", "{ FF [-] D8 }", []ast.HexToken{ast.HexByte{Value: 0xFF}, ast.HexJump{}, ast.HexByte{Value: 0xD8}}},
		{"jump min only", "{ FF [4-] D8 }", []ast.HexToken{ast.HexByte{Value: 0xFF}, ast.HexJump{Min: new(4)}, ast.HexByte{Value: 0xD8}}},
		{"jump max only", "{ FF [-16] D8 }", []ast.HexToken{ast.HexByte{Value: 0xFF}, ast.HexJump{Max: new(16)}, ast.HexByte{Value: 0xD8}}},
		{"alternation", "{ FF (41|42) D8 }", []ast.HexToken{ast.HexByte{Value: 0xFF}, ast.HexAlt{Alternatives: []ast.HexAltItem{{Byte: new(byte(0x41))}, {Byte: new(byte(0x42))}}}, ast.HexByte{Value: 0xD8}}},
		{"alt with wildcard", "{ (41|??) }", []ast.HexToken{ast.HexAlt{Alternatives: []ast.HexAltItem{{Byte: new(byte(0x41))}, {Wildcard: true}}}}},
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
		{`/a[/]b/`, `a[/]b`},
		{`/a[^/]+b/i`, `a[^/]+b`},
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
		{`"x" base64 fullword`, ast.StringModifiers{Base64: true, Fullword: true}},
		{`{ FF } base64`, ast.StringModifiers{Base64: true}},
		{`"x" ascii`, ast.StringModifiers{Ascii: true}},
		{`"x" nocase`, ast.StringModifiers{Nocase: true}},
		{`"x" private`, ast.StringModifiers{Private: true}},
		{`"x" wide`, ast.StringModifiers{Unsupported: []string{"wide"}}},
		{`"x" xor`, ast.StringModifiers{Unsupported: []string{"xor"}}},
		{`"x" base64wide`, ast.StringModifiers{Unsupported: []string{"base64wide"}}},
		{`"x" wide xor nocase`, ast.StringModifiers{Nocase: true, Unsupported: []string{"wide", "xor"}}},
		{`"x" xor(0x01-0xff)`, ast.StringModifiers{Unsupported: []string{"xor(0x01-0xff)"}}},
		{`"x" xor ( 0x01 )`, ast.StringModifiers{Unsupported: []string{"xor( 0x01 )"}}},
		{`"x" base64("!@#$%^&*(){}")`, ast.StringModifiers{Unsupported: []string{`base64("!@#$%^&*(){}")`}}},
		{`"x" base64wide("abc") fullword`, ast.StringModifiers{Fullword: true, Unsupported: []string{`base64wide("abc")`}}},
		{`"x" frobnicate`, ast.StringModifiers{Unsupported: []string{"frobnicate"}}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			p := New()
			rs, err := p.Parse(`rule test { strings: $ = ` + tt.input + ` condition: any of them }`)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			got := rs.Rules[0].Strings[0].Modifiers
			if !reflect.DeepEqual(got, tt.mods) {
				t.Errorf("expected %+v, got %+v", tt.mods, got)
			}
			if len(tt.mods.Unsupported) == 0 && len(rs.Warnings) != 0 {
				t.Errorf("expected no warnings, got %v", rs.Warnings)
			}
			if len(tt.mods.Unsupported) != len(rs.Warnings) {
				t.Errorf("expected %d warnings, got %v", len(tt.mods.Unsupported), rs.Warnings)
			}
		})
	}
}

func TestParseModifierWarnings(t *testing.T) {
	rs := mustParse(t, `
rule first {
	strings:
		$a = "one" wide nocase
		$ = "two" xor(0x10-0x20)
	condition:
		any of them
}

rule second {
	strings:
		$b = "three" fullword private
	condition:
		any of them
}`)

	want := []string{
		`rule "first" string $a: unsupported modifier "wide", rule will not match`,
		`rule "first" string $: unsupported modifier "xor(0x10-0x20)", rule will not match`,
	}
	if !reflect.DeepEqual(rs.Warnings, want) {
		t.Errorf("expected warnings %q, got %q", want, rs.Warnings)
	}
}

func TestParsePrivateModifierRules(t *testing.T) {
	rs := mustParse(t, `
rule private_only {
	strings:
		$secret = "needle" private
	condition:
		$secret
}

rule mixed {
	strings:
		$public = "visible"
		$secret = "needle" private
	condition:
		$public and $secret
}`)

	if len(rs.Warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", rs.Warnings)
	}

	privateOnly := rs.Rules[0]
	if len(privateOnly.Strings) != 1 || !privateOnly.Strings[0].Modifiers.Private {
		t.Fatalf("expected private-only rule to preserve private modifier, got %+v", privateOnly.Strings)
	}

	mixed := rs.Rules[1]
	if len(mixed.Strings) != 2 {
		t.Fatalf("expected 2 strings in mixed rule, got %d", len(mixed.Strings))
	}
	if mixed.Strings[0].Modifiers.Private {
		t.Errorf("expected $public to remain public")
	}
	if !mixed.Strings[1].Modifiers.Private {
		t.Errorf("expected $secret to be private")
	}
}

func TestParseUnterminatedModifierArgs(t *testing.T) {
	p := New()
	_, err := p.Parse(`rule test { strings: $ = "x" xor(0x01 condition: any of them }`)
	if err == nil {
		t.Fatal("expected error for unterminated modifier arguments")
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

func TestParseFilesizeCondition(t *testing.T) {
	tests := []struct {
		name string
		cond string
		want ast.Expr
	}{
		{
			name: "truthy",
			cond: `filesize`,
			want: ast.Filesize{},
		},
		{
			name: "comparison",
			cond: `filesize == 3`,
			want: ast.BinaryExpr{
				Op:    "==",
				Left:  ast.Filesize{},
				Right: ast.IntLit{Value: 3},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := mustParse(t, `rule test { condition: `+tt.cond+` }`)
			if got := rs.Rules[0].Condition; !reflect.DeepEqual(got, tt.want) {
				t.Errorf("condition = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestParseNotCondition(t *testing.T) {
	tests := []struct {
		name string
		cond string
		want ast.Expr
	}{
		{
			name: "string reference",
			cond: `not $a`,
			want: ast.NotExpr{Inner: ast.StringRef{Name: "$a"}},
		},
		{
			name: "parenthesized expression",
			cond: `not ($a or $b)`,
			want: ast.NotExpr{Inner: ast.ParenExpr{Inner: ast.BinaryExpr{
				Op:    "or",
				Left:  ast.StringRef{Name: "$a"},
				Right: ast.StringRef{Name: "$b"},
			}}},
		},
		{
			name: "nested not",
			cond: `not not $a`,
			want: ast.NotExpr{Inner: ast.NotExpr{Inner: ast.StringRef{Name: "$a"}}},
		},
		{
			name: "higher precedence than and",
			cond: `not $a and $b`,
			want: ast.BinaryExpr{
				Op:    "and",
				Left:  ast.NotExpr{Inner: ast.StringRef{Name: "$a"}},
				Right: ast.StringRef{Name: "$b"},
			},
		},
		{
			name: "lower precedence than comparison",
			cond: `not uint8(0) == 0`,
			want: ast.NotExpr{Inner: ast.BinaryExpr{
				Op:    "==",
				Left:  ast.FuncCall{Name: "uint8", Args: []ast.Expr{ast.IntLit{Value: 0}}},
				Right: ast.IntLit{Value: 0},
			}},
		},
		{
			name: "lower precedence than at",
			cond: `not $a at 0`,
			want: ast.NotExpr{Inner: ast.AtExpr{
				Ref: ast.StringRef{Name: "$a"},
				Pos: ast.IntLit{Value: 0},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := mustParse(t, `rule test { condition: `+tt.cond+` }`)
			if got := rs.Rules[0].Condition; !reflect.DeepEqual(got, tt.want) {
				t.Errorf("condition = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestParseHexAltWithSpaces(t *testing.T) {
	rs := mustParse(t, `rule test { strings: $ = { (AB | CD) EF } condition: any of them }`)
	hex := rs.Rules[0].Strings[0].Value.(ast.HexString)
	want := []ast.HexToken{
		ast.HexAlt{Alternatives: []ast.HexAltItem{{Byte: new(byte(0xAB))}, {Byte: new(byte(0xCD))}}},
		ast.HexByte{Value: 0xEF},
	}
	if !hexTokensEqual(hex.Tokens, want) {
		t.Errorf("expected %v, got %v", want, hex.Tokens)
	}
}

func TestParseUppercaseHexInt(t *testing.T) {
	rs := mustParse(t, `rule t { condition: 0XFF }`)
	lit, ok := rs.Rules[0].Condition.(ast.IntLit)
	if !ok {
		t.Fatalf("expected IntLit condition, got %T", rs.Rules[0].Condition)
	}
	if lit.Value != 0xFF {
		t.Errorf("expected 255, got %d", lit.Value)
	}
}

func TestParseComparisonConditions(t *testing.T) {
	tests := []struct {
		name string
		cond string
		want ast.Expr
	}{
		{
			name: "eq",
			cond: `uint8(0) == 1`,
			want: ast.BinaryExpr{
				Op:    "==",
				Left:  ast.FuncCall{Name: "uint8", Args: []ast.Expr{ast.IntLit{Value: 0}}},
				Right: ast.IntLit{Value: 1},
			},
		},
		{
			name: "ne",
			cond: `uint8(0) != 1`,
			want: ast.BinaryExpr{
				Op:    "!=",
				Left:  ast.FuncCall{Name: "uint8", Args: []ast.Expr{ast.IntLit{Value: 0}}},
				Right: ast.IntLit{Value: 1},
			},
		},
		{
			name: "lt",
			cond: `uint8(0) < 1`,
			want: ast.BinaryExpr{
				Op:    "<",
				Left:  ast.FuncCall{Name: "uint8", Args: []ast.Expr{ast.IntLit{Value: 0}}},
				Right: ast.IntLit{Value: 1},
			},
		},
		{
			name: "gt",
			cond: `uint8(0) > 1`,
			want: ast.BinaryExpr{
				Op:    ">",
				Left:  ast.FuncCall{Name: "uint8", Args: []ast.Expr{ast.IntLit{Value: 0}}},
				Right: ast.IntLit{Value: 1},
			},
		},
		{
			name: "le",
			cond: `uint8(0) <= 1`,
			want: ast.BinaryExpr{
				Op:    "<=",
				Left:  ast.FuncCall{Name: "uint8", Args: []ast.Expr{ast.IntLit{Value: 0}}},
				Right: ast.IntLit{Value: 1},
			},
		},
		{
			name: "ge",
			cond: `uint8(0) >= 1`,
			want: ast.BinaryExpr{
				Op:    ">=",
				Left:  ast.FuncCall{Name: "uint8", Args: []ast.Expr{ast.IntLit{Value: 0}}},
				Right: ast.IntLit{Value: 1},
			},
		},
		{
			name: "parenthesized integer",
			cond: `(filesize) >= 1`,
			want: ast.BinaryExpr{
				Op:    ">=",
				Left:  ast.ParenExpr{Inner: ast.Filesize{}},
				Right: ast.IntLit{Value: 1},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := mustParse(t, `rule test { condition: `+tt.cond+` }`)
			if got := rs.Rules[0].Condition; !reflect.DeepEqual(got, tt.want) {
				t.Errorf("condition = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestParseComparisonPrecedence(t *testing.T) {
	rs := mustParse(t, `rule test { condition: not uint8(0) < 1 or $a and uint8(1) >= 2 }`)
	want := ast.BinaryExpr{
		Op: "or",
		Left: ast.NotExpr{Inner: ast.BinaryExpr{
			Op:    "<",
			Left:  ast.FuncCall{Name: "uint8", Args: []ast.Expr{ast.IntLit{Value: 0}}},
			Right: ast.IntLit{Value: 1},
		}},
		Right: ast.BinaryExpr{
			Op:    "and",
			Left:  ast.StringRef{Name: "$a"},
			Right: ast.BinaryExpr{Op: ">=", Left: ast.FuncCall{Name: "uint8", Args: []ast.Expr{ast.IntLit{Value: 1}}}, Right: ast.IntLit{Value: 2}},
		},
	}
	if got := rs.Rules[0].Condition; !reflect.DeepEqual(got, want) {
		t.Errorf("condition = %#v, want %#v", got, want)
	}
}

func TestParseInvalidInputs(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		errPart string
	}{
		{"multi-byte hex alternative", `rule t { strings: $ = { (4142|43) } condition: any of them }`, "alternative"},
		{"garbage hex alternative", `rule t { strings: $ = { (GG|41) } condition: any of them }`, "alternative"},
		{"garbage hex jump", `rule t { strings: $ = { FF [1-x] 41 } condition: any of them }`, "jump"},
		{"inverted hex jump", `rule t { strings: $ = { FF [5-2] 41 } condition: any of them }`, "jump"},
		{"unterminated hex jump", `rule t { strings: $ = { FF [1-2 } condition: any of them }`, "unterminated"},
		{"unterminated hex alternation", `rule t { strings: $ = { FF (41|42 } condition: any of them }`, "unterminated"},
		{"unterminated string", `rule t { strings: $ = "abc`, "unterminated"},
		{"unterminated regex", `rule t { strings: $ = /abc`, "unterminated"},
		{"unterminated block comment", `rule t { /* comment`, "unterminated"},
		{"integer overflow", `rule t { condition: 99999999999999999999 }`, "integer"},
		{"hex integer overflow", `rule t { condition: 0xFFFFFFFFFFFFFFFFFF }`, "integer"},
		{"unsupported bare identifier", `rule t { condition: entrypoint }`, "syntax error"},
		{"string comparison left operand", `rule t { strings: $a = "a" condition: $a >= 0 }`, "integer operands"},
		{"string comparison right operand", `rule t { strings: $a = "a" condition: 0 <= $a }`, "integer operands"},
		{"quantifier comparison operand", `rule t { strings: $a = "a" condition: any of them == 1 }`, "integer operands"},
		{"chained relational comparisons", `rule t { condition: 1 < 2 < 3 }`, "syntax error"},
		{"chained equality comparisons", `rule t { condition: 1 == 1 == 1 }`, "syntax error"},
		{"non-ascii whitespace", "rule t \xa0{ condition: 0 }", "unexpected character"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New().Parse(tt.input)
			if err == nil {
				t.Fatal("expected parse error")
			}
			if !strings.Contains(err.Error(), tt.errPart) {
				t.Errorf("expected error containing %q, got %q", tt.errPart, err.Error())
			}
		})
	}
}

func TestParseErrorMessagePreserved(t *testing.T) {
	_, err := New().Parse(`rule t { condition: @ }`)
	if err == nil {
		t.Fatal("expected parse error")
	}
	if !strings.Contains(err.Error(), "unexpected character") {
		t.Errorf("expected descriptive lexer error to survive, got %q", err.Error())
	}
}

// Helpers

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
