package parser

import "testing"

func FuzzParse(f *testing.F) {
	seeds := []string{
		`rule test { strings: $a = "hello" condition: any of them }`,
		`rule hex_test { strings: $h = { 48 65 6C 6C 6F } condition: any of them }`,
		`rule regex_test { strings: $r = /foo[0-9]+bar/ condition: any of them }`,
		`rule wildcards { strings: $h = { 48 ?? 6C 6C [2-4] 6F } condition: any of them }`,
		`rule meta_test {
			meta:
				author = "test"
				score = 75
				enabled = true
			strings:
				$a = "test"
			condition:
				any of them
		}`,
		`rule multi_strings {
			strings:
				$a = "foo"
				$b = "bar"
				$c = /baz[0-9]/
			condition:
				$a and $b
		}`,
		`rule all_of_test { strings: $a = "x" $b = "y" condition: all of them }`,
		`rule hex_alt { strings: $h = { (AB | CD) EF } condition: any of them }`,
		`rule base64_test { strings: $a = "test" base64 condition: any of them }`,
		`rule fullword_test { strings: $a = "test" fullword condition: any of them }`,
	}

	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		p := New()
		p.Parse(input) //nolint:errcheck
	})
}
