package scanner

import (
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
