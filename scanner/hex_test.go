package scanner

import (
	"slices"
	"testing"
)

func TestHexNibblesAndMultiByteAlternatives(t *testing.T) {
	rules := compileFullBuffer(t, `
rule nibbles { strings: $a = { 8B 4? ?5 C3 } condition: $a }
rule alternatives { strings: $a = { 90 (41 B8 | 68 ?? | 5?) 00 00 } condition: $a }
rule nested { strings: $a = { 90 (41 (B8|B9) | 68) 00 } condition: $a }
rule jump_in_alternative { strings: $a = { 90 (41 [1-2] B8 | 68) CC } condition: $a }
`)
	tests := []struct {
		name string
		data []byte
		want []string
	}{
		{"high nibble hit", []byte{0x00, 0x8B, 0x4F, 0x35, 0xC3}, []string{"nibbles"}},
		{"high nibble miss", []byte{0x00, 0x8B, 0x5F, 0x35, 0xC3}, nil},
		{"low nibble miss", []byte{0x00, 0x8B, 0x4F, 0x36, 0xC3}, nil},
		{"two byte alternative", []byte{0x90, 0x41, 0xB8, 0x00, 0x00}, []string{"alternatives", "nested"}},
		{"wildcard alternative", []byte{0x90, 0x68, 0xAA, 0x00, 0x00}, []string{"alternatives"}},
		{"nibble alternative", []byte{0x90, 0x57, 0x00, 0x00}, []string{"alternatives"}},
		{"alternative miss", []byte{0x90, 0x41, 0xBA, 0x00, 0x00}, nil},
		{"nested", []byte{0x90, 0x41, 0xB9, 0x00}, []string{"nested"}},
		{"jump inside alternative", []byte{0x90, 0x41, 0xEE, 0xFF, 0xB8, 0xCC}, []string{"jump_in_alternative"}},
		{"jump inside alternative out of range", []byte{0x90, 0x41, 0xEE, 0xEE, 0xEE, 0xB8, 0xCC}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scanNames(t, rules, tt.data)
			slices.Sort(got)
			if !slices.Equal(got, tt.want) {
				t.Errorf("matches = %v, want %v", got, tt.want)
			}
		})
	}
}
