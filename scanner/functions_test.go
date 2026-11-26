package scanner

import (
	"errors"
	"strings"
	"testing"
)

// libyara checks module function arguments at compile time and fails with
// `wrong arguments for function "x"`.
// https://yara.readthedocs.io/en/stable/modules/math.html
// https://yara.readthedocs.io/en/stable/modules/hash.html
func TestWrongFunctionArityFailsCompilation(t *testing.T) {
	for _, cond := range []string{
		`math.entropy(0) > 0`,
		`math.entropy(0, 1, 2) > 0`,
		`math.mean() > 0`,
		`math.deviation(0) > 0`,
		`math.count(1, 2) > 0`,
		`hash.md5(0, 1, 2) == ""`,
		`uint8(0, 1) == 0`,
		`uint32be() == 0`,
	} {
		_, err := compileWith(t, `import "math" import "hash" rule r { condition: `+cond+` }`, CompileOptions{})
		if err == nil || !strings.Contains(err.Error(), "wrong arguments") {
			t.Errorf("%s: expected a wrong arguments error, got %v", cond, err)
		}
	}
}

func TestStringOverloadsOfMathAndHash(t *testing.T) {
	data := []byte("xxabcdyy")
	for _, cond := range []string{
		`math.entropy("abcd") == math.entropy(2, 4)`,
		`math.entropy("aaaa") == 0`,
		`math.mean("abcd") == math.mean(2, 4)`,
		`math.deviation("abcd", 98.5) == math.deviation(2, 4, 98.5)`,
		`math.count(0x78) == 2`,
		`math.count(0x78, 0, 2) == 2`,
		`hash.md5("abcd") == hash.md5(2, 4)`,
		`hash.sha1("abcd") == "81fe8bfe87576c3ecb22426f8e57847382917acf"`,
		`hash.sha256("abcd") == hash.sha256(2, 4)`,
	} {
		rules := compileSource(t, `import "math" import "hash" rule r { condition: `+cond+` }`)
		if got := scanNames(t, rules, data); len(got) != 1 {
			t.Errorf("%s: matches = %v", cond, got)
		}
	}
}

// libyara's math.mean and math.deviation over an empty range divide by
// zero; an empty window has no mean, so it is undefined rather than NaN.
func TestMeanAndDeviationOfEmptyWindowAreUndefined(t *testing.T) {
	for _, cond := range []string{
		`not (math.mean(0, 0) >= 0)`,
		`not (math.deviation(0, 0, 1.0) >= 0)`,
		`not (math.mean("") >= 0)`,
	} {
		rules := compileSource(t, `import "math" rule r { condition: `+cond+` }`)
		if got := scanNames(t, rules, []byte("x")); len(got) != 0 {
			t.Errorf("%s: matched %v, want undefined", cond, got)
		}
	}
}

// Condition regexes go through the configured compiler at compile time, so
// an invalid one fails Compile instead of silently evaluating to false.
// https://yara.readthedocs.io/en/stable/writingrules.html#conditions
func TestMatchesUsesTheConfiguredCompiler(t *testing.T) {
	_, err := compileWith(t, `rule r { condition: not ("x" matches /a{2000}/) }`, CompileOptions{})
	if err == nil || !strings.Contains(err.Error(), "invalid regex") {
		t.Errorf("expected an invalid regex error, got %v", err)
	}

	var compiled []string
	refuse := errors.New("refused")
	opts := CompileOptions{RegexCompiler: func(p string) (Regexp, error) {
		compiled = append(compiled, p)
		if strings.Contains(p, "refuse") {
			return nil, refuse
		}
		return defaultCompile(p)
	}}
	rules, err := compileWith(t, `rule r { condition: "hello" matches /hel+o/ and not ("abc" matches /x/) }`, opts)
	if err != nil {
		t.Fatal(err)
	}
	if got := scanNames(t, rules, []byte("data")); len(got) != 1 {
		t.Errorf("matches = %v", got)
	}
	if len(compiled) == 0 {
		t.Error("the configured RegexCompiler was never called")
	}
	if _, err := compileWith(t, `rule r { condition: "x" matches /\Crefuse/ }`, opts); !errors.Is(err, refuse) {
		t.Errorf("expected the compiler's error, got %v", err)
	}
}
