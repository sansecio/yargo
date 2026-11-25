package scanner

import (
	"bytes"
	"encoding/base64"
	"slices"
	"testing"
)

const testAlphabet = "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba9876543210+/"

func widen(b []byte) []byte {
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, c, 0)
	}
	return out
}

func encodeAt(enc *base64.Encoding, prefix int, text []byte) []byte {
	data := append(bytes.Repeat([]byte{'Q'}, prefix), text...)
	data = append(data, "tail!"...)
	return []byte(enc.EncodeToString(data))
}

func TestBase64ModifierVariants(t *testing.T) {
	text := []byte("needle in a haystack")
	std := base64.StdEncoding
	custom := base64.NewEncoding(testAlphabet)
	tests := []struct {
		name  string
		rule  string
		build func(prefix int) []byte
		miss  []byte
	}{
		{"base64", `$a = "needle in a haystack" base64`, func(p int) []byte { return encodeAt(std, p, text) }, []byte("needle in a haystack")},
		{"base64wide", `$a = "needle in a haystack" base64wide`, func(p int) []byte { return widen(encodeAt(std, p, text)) }, encodeAt(std, 0, text)},
		{"wide base64", `$a = "needle in a haystack" wide base64`, func(p int) []byte { return encodeAt(std, p, widen(text)) }, encodeAt(std, 0, text)},
		{"wide base64wide", `$a = "needle in a haystack" wide base64wide`, func(p int) []byte { return widen(encodeAt(std, p, widen(text))) }, encodeAt(std, 0, text)},
		{"ascii base64wide", `$a = "needle in a haystack" ascii base64wide`, func(p int) []byte { return widen(encodeAt(std, p, text)) }, encodeAt(std, 0, text)},
		{"custom alphabet", `$a = "needle in a haystack" base64("` + testAlphabet + `")`, func(p int) []byte { return encodeAt(custom, p, text) }, encodeAt(std, 0, text)},
		{"custom alphabet wide", `$a = "needle in a haystack" base64wide("` + testAlphabet + `")`, func(p int) []byte { return widen(encodeAt(custom, p, text)) }, encodeAt(custom, 0, text)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := compileSource(t, "rule r { strings: "+tt.rule+" condition: $a }")
			for prefix := range 3 {
				if got := scanNames(t, rules, bytes.Join([][]byte{[]byte("xx"), tt.build(prefix), []byte("yy")}, nil)); !slices.Equal(got, []string{"r"}) {
					t.Errorf("prefix %d: matches = %v", prefix, got)
				}
			}
			if got := scanNames(t, rules, tt.miss); len(got) != 0 {
				t.Errorf("unrelated encoding matched: %v", got)
			}
		})
	}
}

func TestBase64WithXorIsSkipped(t *testing.T) {
	rules := compileSource(t, `rule r { strings: $a = "needle in a haystack" base64 xor condition: $a }`)
	if rules.NumRules() != 0 || len(rules.Skipped()) != 1 {
		t.Errorf("rules=%d skipped=%+v", rules.NumRules(), rules.Skipped())
	}
}

func TestBase64AlphabetThatCannotEncodeIsSkipped(t *testing.T) {
	for _, alphabet := range []string{
		"A" + testAlphabet[1:63] + "A",
		testAlphabet[:63] + "=",
	} {
		rules := compileSource(t, `rule r { strings: $a = "needle in a haystack" base64("`+alphabet+`") condition: $a }`)
		if rules.NumRules() != 0 || len(rules.Skipped()) != 1 {
			t.Errorf("alphabet %q: rules=%d skipped=%+v", alphabet, rules.NumRules(), rules.Skipped())
		}
	}
}
