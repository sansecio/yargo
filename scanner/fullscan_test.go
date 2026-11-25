package scanner

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sansecio/yargo/parser"
)

func compileFullBuffer(t *testing.T, src string) *Rules {
	t.Helper()
	rs, err := parser.New().Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := CompileWithOptions(rs, CompileOptions{FullBufferRegex: true})
	if err != nil {
		t.Fatalf("CompileWithOptions() error = %v", err)
	}
	if len(rules.Skipped()) != 0 {
		t.Fatalf("skipped %+v", rules.Skipped())
	}
	return rules
}

func TestFullBufferRegexIsOptIn(t *testing.T) {
	rs, err := parser.New().Parse(`rule r { strings: $a = /[0-9][a-f][0-9]/ condition: $a }`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Compile(rs); err == nil {
		t.Error("expected an error without FullBufferRegex")
	}
}

func TestStringWhoseOnlyAtomIsARepeatedByteNeedsFullBufferScan(t *testing.T) {
	src := "rule r { strings: $a = { 60 [0-8] E8 ?? 00 00 00 [0-8] 58 } condition: $a }"
	rs, err := parser.New().Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Compile(rs); err == nil {
		t.Error("expected an error without FullBufferRegex")
	}
	rules := compileFullBuffer(t, src)
	if got := scanNames(t, rules, []byte{9, 0x60, 0xe8, 1, 0, 0, 0, 0x58}); len(got) != 1 {
		t.Errorf("matches = %v", got)
	}
}

func TestFullBufferRegexMatches(t *testing.T) {
	rules := compileFullBuffer(t, `
rule class { strings: $a = /[0-9][a-f][0-9]/ condition: $a }
rule counted { strings: $a = /[0-9][a-f][0-9]/ condition: #a == 2 }
rule nocase { strings: $a = /hello wor.d/i condition: $a }
rule negated { strings: $a = /[0-9][a-f][0-9]/ condition: not $a }
rule fullword { strings: $a = /[0-9][a-f][0-9]/ fullword condition: $a }
rule offset { strings: $a = /[0-9][a-f][0-9]/ condition: @a[2] == 10 }
rule anchored_atom_free_hex { strings: $a = { 8B 4? ?5 C3 } condition: $a }
`)
	tests := []struct {
		name string
		data string
		want []string
	}{
		{"two hits", "xx 1a2 yy 3b4 zz", []string{"class", "counted", "fullword", "offset"}},
		{"embedded hit", "xx1a2xx", []string{"class"}},
		{"nocase", "say HELLO WORLD now", []string{"nocase", "negated"}},
		{"no hit", "nothing here", []string{"negated"}},
		{"hex nibbles", "\x8b\x4f\x35\xc3", []string{"anchored_atom_free_hex", "negated"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scanNames(t, rules, []byte(tt.data))
			slices.Sort(got)
			slices.Sort(tt.want)
			if !slices.Equal(got, tt.want) {
				t.Errorf("matches = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFullBufferRegexHitCountIsCapped(t *testing.T) {
	rules := compileFullBuffer(t, `rule r { strings: $a = /[a-z][a-z] / condition: #a >= 1 }`)
	data := []byte(strings.Repeat("ab ", maxFullBufferMatches*2))
	var matches MatchRules
	if err := rules.ScanMem(data, 0, 10*time.Second, &matches); err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("matches = %d", len(matches))
	}
	if n := len(matches[0].Strings); n != maxFullBufferMatches {
		t.Errorf("recorded %d matches, want the cap %d", n, maxFullBufferMatches)
	}
}

func TestFullBufferRegexHonorsTheDeadline(t *testing.T) {
	var src strings.Builder
	for i := range 50 {
		src.WriteString("rule r")
		src.WriteString(strings.Repeat("x", i+1))
		src.WriteString(" { strings: $a = /[0-9][a-f][0-9][g-z]/ condition: $a }\n")
	}
	rules := compileFullBuffer(t, src.String())
	data := bytes.Repeat([]byte("abcdefgh"), 4<<20)
	var matches MatchRules
	err := rules.ScanMem(data, 0, time.Nanosecond, &matches)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want deadline exceeded", err)
	}
}
