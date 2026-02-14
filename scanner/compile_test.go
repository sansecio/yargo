package scanner

import (
	"testing"

	"github.com/sansecio/yargo/ast"
)

func TestSkipSubtypes(t *testing.T) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "malware_rule",
				Meta: []*ast.MetaEntry{
					{Key: "subtype", Value: "malware"},
				},
				Strings: []*ast.StringDef{
					{Name: "$s", Value: ast.TextString{Value: "evil"}},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
			{
				Name: "pii_rule",
				Meta: []*ast.MetaEntry{
					{Key: "subtype", Value: "pii"},
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
				Name: "empty_subtype_rule",
				Meta: []*ast.MetaEntry{
					{Key: "subtype", Value: ""},
				},
				Strings: []*ast.StringDef{
					{Name: "$s", Value: ast.TextString{Value: "empty"}},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
		},
	}

	tests := []struct {
		name         string
		skipSubtypes []string
		wantRules    []string
	}{
		{
			name:         "nil skip subtypes includes all",
			skipSubtypes: nil,
			wantRules:    []string{"malware_rule", "pii_rule", "generic_rule", "no_meta_rule", "empty_subtype_rule"},
		},
		{
			name:         "empty skip subtypes includes all",
			skipSubtypes: []string{},
			wantRules:    []string{"malware_rule", "pii_rule", "generic_rule", "no_meta_rule", "empty_subtype_rule"},
		},
		{
			name:         "skip malware",
			skipSubtypes: []string{"malware"},
			wantRules:    []string{"pii_rule", "generic_rule", "no_meta_rule", "empty_subtype_rule"},
		},
		{
			name:         "skip multiple subtypes",
			skipSubtypes: []string{"malware", "pii"},
			wantRules:    []string{"generic_rule", "no_meta_rule", "empty_subtype_rule"},
		},
		{
			name:         "skip nonexistent subtype",
			skipSubtypes: []string{"nonexistent"},
			wantRules:    []string{"malware_rule", "pii_rule", "generic_rule", "no_meta_rule", "empty_subtype_rule"},
		},
		{
			name:         "rules without subtype meta are never skipped",
			skipSubtypes: []string{"malware", "pii"},
			wantRules:    []string{"generic_rule", "no_meta_rule", "empty_subtype_rule"},
		},
		{
			name:         "empty subtype value is never skipped",
			skipSubtypes: []string{""},
			wantRules:    []string{"malware_rule", "pii_rule", "generic_rule", "no_meta_rule", "empty_subtype_rule"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := CompileWithOptions(rs, CompileOptions{SkipSubtypes: tt.skipSubtypes})
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
