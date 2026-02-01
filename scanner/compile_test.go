package scanner

import "testing"

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
