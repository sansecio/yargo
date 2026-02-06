package scanner

import (
	"testing"

	"github.com/sansecio/yargo/ast"
)

func Test_isValidQuantifier(t *testing.T) {
	tests := []struct {
		inner string
		want  bool
	}{
		// Valid quantifiers
		{"5", true},
		{"0", true},
		{"123", true},
		{"5,", true},
		{"5,10", true},
		{"0,100", true},
		{",5", true},
		{",100", true},

		// Invalid - not quantifiers
		{"", false},
		{"abc", false},
		{"..", false},
		{"5a", false},
		{"a5", false},
		{",", false},
		{",,", false},
		{"5,,10", false},
		{"..:function\\(x,y\\){return x!==y;", false},
		{"bar", false},
	}

	for _, tt := range tests {
		t.Run(tt.inner, func(t *testing.T) {
			got := isValidQuantifier(tt.inner)
			if got != tt.want {
				t.Errorf("isValidQuantifier(%q) = %v, want %v", tt.inner, got, tt.want)
			}
		})
	}
}

func Test_fixQuantifiers(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		want    string
	}{
		{"no quantifier", "hello", "hello"},
		{"small quantifier", `a{5}`, `a{5}`},
		{"range under limit", `a{1,100}`, `a{1,100}`},
		{"range at limit", `a{1,1000}`, `a{1,1000}`},
		{"range over limit", `a{1,5000}`, `a{1,1000}`},
		{"exact over limit", `a{5000}`, `a{1000}`},
		{"min over limit", `a{2000,}`, `a{1000,}`},
		{"both over limit", `a{2000,5000}`, `a{1000,1000}`},
		{"zero to over limit", `a{0,4000}`, `a{0,1000}`},
		{"lazy quantifier over limit", `a{0,4000}?`, `a{0,1000}?`},
		{"fix {, syntax", `a{,5}`, `a{0,5}`},
		{"fix {, and cap", `a{,5000}`, `a{0,1000}`},
		{"multiple quantifiers", `a{5000}b{1,2000}c{3,}`, `a{1000}b{1,1000}c{3,}`},
		{"nested in groups", `(a{5000}|b{2000,3000})`, `(a{1000}|b{1000,1000})`},
		{"real pattern 1", `[^\]]{1,5000}`, `[^\]]{1,1000}`},
		{"real pattern 2", `[\s\S]{0,4000}?`, `[\s\S]{0,1000}?`},
		{"real pattern 3", `(_0x\w{6},){200,300}`, `(_0x\w{6},){200,300}`},
		// Literal braces that are NOT quantifiers should be preserved
		{"literal brace in pattern", `var ....={..:function\(x,y\){return x!==y;}`, `var ....={..:function\(x,y\){return x!==y;}`},
		{"literal brace standalone", `foo={bar}`, `foo={bar}`},
		{"literal brace with dots", `{..}`, `{..}`},
		{"literal brace with text", `{abc}`, `{abc}`},
		{"empty braces", `{}`, `{}`},
		{"brace with only comma", `{,}`, `{,}`}, // Not a valid quantifier, preserved as literal
		{"mixed literal and quantifier", `{foo}a{5}`, `{foo}a{5}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fixQuantifiers(tt.pattern)
			if got != tt.want {
				t.Errorf("fixQuantifiers(%q) = %q, want %q", tt.pattern, got, tt.want)
			}
		})
	}
}

func TestSkipTypes(t *testing.T) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "malware_rule",
				Meta: []*ast.MetaEntry{
					{Key: "type", Value: "malware"},
				},
				Strings: []*ast.StringDef{
					{Name: "$s", Value: ast.TextString{Value: "evil"}},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
			{
				Name: "pii_rule",
				Meta: []*ast.MetaEntry{
					{Key: "type", Value: "pii"},
				},
				Strings: []*ast.StringDef{
					{Name: "$s", Value: ast.TextString{Value: "ssn"}},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
			{
				Name: "generic_rule",
				Meta: []*ast.MetaEntry{
					{Key: "author", Value: "test"},
				},
				Strings: []*ast.StringDef{
					{Name: "$s", Value: ast.TextString{Value: "hello"}},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
			{
				Name: "no_meta_rule",
				Strings: []*ast.StringDef{
					{Name: "$s", Value: ast.TextString{Value: "world"}},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
			{
				Name: "empty_type_rule",
				Meta: []*ast.MetaEntry{
					{Key: "type", Value: ""},
				},
				Strings: []*ast.StringDef{
					{Name: "$s", Value: ast.TextString{Value: "empty"}},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
		},
	}

	tests := []struct {
		name      string
		skipTypes []string
		wantRules []string
	}{
		{
			name:      "nil skip types includes all",
			skipTypes: nil,
			wantRules: []string{"malware_rule", "pii_rule", "generic_rule", "no_meta_rule", "empty_type_rule"},
		},
		{
			name:      "empty skip types includes all",
			skipTypes: []string{},
			wantRules: []string{"malware_rule", "pii_rule", "generic_rule", "no_meta_rule", "empty_type_rule"},
		},
		{
			name:      "skip malware",
			skipTypes: []string{"malware"},
			wantRules: []string{"pii_rule", "generic_rule", "no_meta_rule", "empty_type_rule"},
		},
		{
			name:      "skip multiple types",
			skipTypes: []string{"malware", "pii"},
			wantRules: []string{"generic_rule", "no_meta_rule", "empty_type_rule"},
		},
		{
			name:      "skip nonexistent type",
			skipTypes: []string{"nonexistent"},
			wantRules: []string{"malware_rule", "pii_rule", "generic_rule", "no_meta_rule", "empty_type_rule"},
		},
		{
			name:      "rules without type meta are never skipped",
			skipTypes: []string{"malware", "pii"},
			wantRules: []string{"generic_rule", "no_meta_rule", "empty_type_rule"},
		},
		{
			name:      "empty type value is never skipped",
			skipTypes: []string{""},
			wantRules: []string{"malware_rule", "pii_rule", "generic_rule", "no_meta_rule", "empty_type_rule"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := CompileWithOptions(rs, CompileOptions{SkipTypes: tt.skipTypes})
			if err != nil {
				t.Fatalf("CompileWithOptions() error = %v", err)
			}

			if len(rules.rules) != len(tt.wantRules) {
				names := make([]string, len(rules.rules))
				for i, r := range rules.rules {
					names[i] = r.name
				}
				t.Fatalf("expected %d rules %v, got %d rules %v", len(tt.wantRules), tt.wantRules, len(rules.rules), names)
			}

			for i, wantName := range tt.wantRules {
				if rules.rules[i].name != wantName {
					t.Errorf("rule[%d] = %q, want %q", i, rules.rules[i].name, wantName)
				}
			}
		})
	}
}

func intPtr(n int) *int    { return &n }
func bytePtr(b byte) *byte { return &b }

func Test_hexStringToRegex(t *testing.T) {
	tests := []struct {
		name   string
		tokens []ast.HexToken
		want   string
	}{
		{
			name:   "simple bytes",
			tokens: []ast.HexToken{ast.HexByte{Value: 0x4D}, ast.HexByte{Value: 0x5A}},
			want:   `\x4d\x5a`,
		},
		{
			name:   "single wildcard",
			tokens: []ast.HexToken{ast.HexByte{Value: 0x4D}, ast.HexWildcard{}, ast.HexByte{Value: 0x5A}},
			want:   `\x4d.\x5a`,
		},
		{
			name:   "multiple wildcards",
			tokens: []ast.HexToken{ast.HexWildcard{}, ast.HexWildcard{}, ast.HexWildcard{}},
			want:   `.{3}`,
		},
		{
			name:   "exact jump",
			tokens: []ast.HexToken{ast.HexByte{Value: 0x00}, ast.HexJump{Min: intPtr(4), Max: intPtr(4)}, ast.HexByte{Value: 0xFF}},
			want:   `\x00.{4}\xff`,
		},
		{
			name:   "range jump",
			tokens: []ast.HexToken{ast.HexByte{Value: 0x00}, ast.HexJump{Min: intPtr(4), Max: intPtr(8)}, ast.HexByte{Value: 0xFF}},
			want:   `\x00.{4,8}\xff`,
		},
		{
			name:   "unbounded jump",
			tokens: []ast.HexToken{ast.HexByte{Value: 0x00}, ast.HexJump{Min: nil, Max: nil}, ast.HexByte{Value: 0xFF}},
			want:   `\x00.*\xff`,
		},
		{
			name:   "min only jump",
			tokens: []ast.HexToken{ast.HexByte{Value: 0x00}, ast.HexJump{Min: intPtr(4), Max: nil}, ast.HexByte{Value: 0xFF}},
			want:   `\x00.{4,}\xff`,
		},
		{
			name:   "max only jump",
			tokens: []ast.HexToken{ast.HexByte{Value: 0x00}, ast.HexJump{Min: nil, Max: intPtr(8)}, ast.HexByte{Value: 0xFF}},
			want:   `\x00.{0,8}\xff`,
		},
		{
			name: "byte alternation",
			tokens: []ast.HexToken{
				ast.HexByte{Value: 0x00},
				ast.HexAlt{Alternatives: []ast.HexAltItem{
					{Byte: bytePtr(0x90)},
					{Byte: bytePtr(0xCC)},
				}},
				ast.HexByte{Value: 0xFF},
			},
			want: `\x00(?:\x90|\xcc)\xff`,
		},
		{
			name: "alternation with wildcard",
			tokens: []ast.HexToken{
				ast.HexAlt{Alternatives: []ast.HexAltItem{
					{Byte: bytePtr(0x41)},
					{Wildcard: true},
				}},
			},
			want: `(?:\x41|.)`,
		},
		{
			name: "complex pattern",
			tokens: []ast.HexToken{
				ast.HexByte{Value: 0x4D},
				ast.HexByte{Value: 0x5A},
				ast.HexWildcard{},
				ast.HexWildcard{},
				ast.HexJump{Min: intPtr(4), Max: intPtr(8)},
				ast.HexAlt{Alternatives: []ast.HexAltItem{
					{Byte: bytePtr(0x90)},
					{Byte: bytePtr(0xCC)},
				}},
			},
			want: `\x4d\x5a.{2}.{4,8}(?:\x90|\xcc)`,
		},
		{
			name:   "wildcards between bytes",
			tokens: []ast.HexToken{ast.HexByte{Value: 0x41}, ast.HexWildcard{}, ast.HexByte{Value: 0x42}, ast.HexWildcard{}, ast.HexByte{Value: 0x43}},
			want:   `\x41.\x42.\x43`,
		},
		{
			name:   "zero min jump",
			tokens: []ast.HexToken{ast.HexByte{Value: 0x00}, ast.HexJump{Min: intPtr(0), Max: intPtr(10)}, ast.HexByte{Value: 0xFF}},
			want:   `\x00.{0,10}\xff`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := ast.HexString{Tokens: tt.tokens}
			got := hexStringToRegex(h)
			if got != tt.want {
				t.Errorf("hexStringToRegex() = %q, want %q", got, tt.want)
			}
		})
	}
}
