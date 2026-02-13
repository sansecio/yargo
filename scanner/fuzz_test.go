package scanner

import (
	"testing"

	"github.com/sansecio/yargo/parser"
)

func FuzzCompile(f *testing.F) {
	seeds := []string{
		`rule test { strings: $a = "hello" condition: any of them }`,
		`rule hex_test { strings: $h = { 48 65 6C 6C 6F } condition: any of them }`,
		`rule regex_test { strings: $r = /foo[0-9]+bar/ condition: any of them }`,
		`rule wildcards { strings: $h = { 48 ?? 6C 6C [2-4] 6F } condition: any of them }`,
		`rule multi {
			strings:
				$a = "foo"
				$b = "bar"
			condition:
				$a and $b
		}`,
		`rule hex_alt { strings: $h = { (AB | CD) EF } condition: any of them }`,
		`rule base64_test { strings: $a = "test" base64 condition: any of them }`,
		`rule fullword_test { strings: $a = "test" fullword condition: any of them }`,
	}

	for _, s := range seeds {
		f.Add(s)
	}

	p := parser.New()

	f.Fuzz(func(t *testing.T, input string) {
		rs, err := p.Parse(input)
		if err != nil {
			return
		}
		CompileWithOptions(rs, CompileOptions{SkipInvalidRegex: true}) //nolint:errcheck
	})
}
