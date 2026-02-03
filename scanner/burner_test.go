package scanner

import (
	"testing"
	"time"

	"github.com/sansecio/yargo/parser"
)

func TestBurnerDomainVariants(t *testing.T) {
	p := parser.New()

	rs, err := p.ParseFile("../fixture/burner_test.yar")
	if err != nil {
		t.Fatal(err)
	}

	rules, err := Compile(rs)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		input   string
		matches bool
	}{
		// Decimal encoding (no spaces)
		{"decimal", `var x = [48,99,104,101,99,107,46,115,104,111,112];`, true},

		// Decimal encoding (with spaces)
		{"decimal_spaces", `var x = [48, 99, 104, 101, 99, 107, 46, 115, 104, 111, 112];`, true},

		// Hex uppercase
		{"hex_upper", `var x = "\x30\x63\x68\x65\x63\x6B\x2E\x73\x68\x6F\x70";`, true},

		// Hex lowercase
		{"hex_lower", `var x = "\x30\x63\x68\x65\x63\x6b\x2e\x73\x68\x6f\x70";`, true},

		// HTML entities
		{"html_entities", `<a href="&#48;&#99;&#104;&#101;&#99;&#107;&#46;&#115;&#104;&#111;&#112;">x</a>`, true},

		// Base64 - all 3 offset permutations (needle with 0, 1, 2 prefix bytes)
		{"base64_offset0", `var x = atob("MGNoZWNrLnNob3A=");`, true},     // 0check.shop
		{"base64_offset1", `var x = atob("YTBjaGVjay5zaG9w");`, true},     // a0check.shop
		{"base64_offset2", `var x = atob("YWEwY2hlY2suc2hvcA==");`, true}, // aa0check.shop

		// Fullword
		{"fullword", `Load from 0check.shop now`, true},

		// Reversed
		{"reversed", `var d = "pohs.kcehc0".split("").reverse().join("");`, true},

		// Should NOT match (no word boundary)
		{"no_match_embedded", `var x = "a0check.shopx";`, false},

		// Should NOT match (plain text without context)
		{"no_match_plain", `0check.shop`, true}, // actually this should match fullword
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var matches MatchRules
			err := rules.ScanMem([]byte(tt.input), 0, time.Second, &matches)
			if err != nil {
				t.Fatal(err)
			}
			matched := len(matches) > 0
			if matched != tt.matches {
				t.Errorf("got match=%v, want %v", matched, tt.matches)
			}
		})
	}
}
