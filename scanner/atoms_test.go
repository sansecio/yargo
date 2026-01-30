package scanner

import (
	"testing"
)

func TestExtractAtoms(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		minLen   int
		wantOk   bool
		wantAtom string // expected atom bytes as string (for simple cases)
	}{
		{
			name:     "simple literal",
			pattern:  "hello",
			minLen:   3,
			wantOk:   true,
			wantAtom: "hello",
		},
		{
			name:     "literal with escaped dot",
			pattern:  `foo\.bar`,
			minLen:   3,
			wantOk:   true,
			wantAtom: "foo.bar",
		},
		{
			name:     "hex escape",
			pattern:  `\x41\x42\x43`,
			minLen:   3,
			wantOk:   true,
			wantAtom: "ABC",
		},
		{
			name:     "mixed hex and literal",
			pattern:  `test\x2Eexe`,
			minLen:   3,
			wantOk:   true,
			wantAtom: "test.exe",
		},
		{
			name:     "literal before character class",
			pattern:  `hello[0-9]+worldly`,
			minLen:   3,
			wantOk:   true,
			wantAtom: "worldly", // "worldly" is longer than "hello"
		},
		{
			name:     "literal after quantifier",
			pattern:  `a+longword`,
			minLen:   3,
			wantOk:   true,
			wantAtom: "longword",
		},
		{
			name:     "alternation picks longest branch",
			pattern:  `(foo|barbaz)`,
			minLen:   3,
			wantOk:   true,
			wantAtom: "barbaz",
		},
		{
			name:     "word boundary pattern",
			pattern:  `\bhello\b`,
			minLen:   3,
			wantOk:   true,
			wantAtom: "hello",
		},
		{
			name:     "digit class breaks run",
			pattern:  `hello\dworldly`,
			minLen:   3,
			wantOk:   true,
			wantAtom: "worldly",
		},
		{
			name:     "word class breaks run",
			pattern:  `abc\wdef`,
			minLen:   3,
			wantOk:   true,
			wantAtom: "abc",
		},
		{
			name:     "no long enough atom",
			pattern:  `[a-z]+`,
			minLen:   3,
			wantOk:   false,
			wantAtom: "",
		},
		{
			name:     "only short literals",
			pattern:  `a[0-9]b[0-9]c`,
			minLen:   3,
			wantOk:   false,
			wantAtom: "",
		},
		{
			name:     "optional breaks run",
			pattern:  `hello?world`,
			minLen:   3,
			wantOk:   true,
			wantAtom: "world",
		},
		{
			name:     "star breaks run",
			pattern:  `hello*world`,
			minLen:   3,
			wantOk:   true,
			wantAtom: "world",
		},
		{
			name:     "plus breaks run",
			pattern:  `hello+world`,
			minLen:   3,
			wantOk:   true,
			wantAtom: "world",
		},
		{
			name:     "curly brace quantifier",
			pattern:  `a{2,5}hello`,
			minLen:   3,
			wantOk:   true,
			wantAtom: "hello",
		},
		{
			name:     "dot breaks run",
			pattern:  `hello.worldly`,
			minLen:   3,
			wantOk:   true,
			wantAtom: "worldly",
		},
		{
			name:     "caret anchor",
			pattern:  `^hello`,
			minLen:   3,
			wantOk:   true,
			wantAtom: "hello",
		},
		{
			name:     "dollar anchor",
			pattern:  `hello$`,
			minLen:   3,
			wantOk:   true,
			wantAtom: "hello",
		},
		{
			name:     "escaped backslash",
			pattern:  `foo\\bar`,
			minLen:   3,
			wantOk:   true,
			wantAtom: "foo\\bar",
		},
		{
			name:     "pipe outside group picks best from each branch",
			pattern:  `foo|barbaz`,
			minLen:   3,
			wantOk:   true,
			wantAtom: "foo", // First branch atom (both branches have qualifying atoms)
		},
		{
			name:     "nested groups",
			pattern:  `((abc))`,
			minLen:   3,
			wantOk:   true,
			wantAtom: "abc",
		},
		{
			name:     "non-capturing group",
			pattern:  `(?:hello)`,
			minLen:   3,
			wantOk:   true,
			wantAtom: "hello",
		},
		{
			name:     "case insensitive flag",
			pattern:  `(?i)hello`,
			minLen:   3,
			wantOk:   true,
			wantAtom: "hello",
		},
		{
			name:     "minLen 2",
			pattern:  `ab[0-9]cd`,
			minLen:   2,
			wantOk:   true,
			wantAtom: "ab",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			atoms, ok := ExtractAtoms(tt.pattern, tt.minLen)
			if ok != tt.wantOk {
				t.Errorf("ExtractAtoms(%q, %d) ok = %v, want %v", tt.pattern, tt.minLen, ok, tt.wantOk)
				return
			}
			if !ok {
				return
			}
			if len(atoms) == 0 {
				t.Errorf("ExtractAtoms(%q, %d) returned ok=true but no atoms", tt.pattern, tt.minLen)
				return
			}
			got := string(atoms[0].Bytes)
			if got != tt.wantAtom {
				t.Errorf("ExtractAtoms(%q, %d) atom = %q, want %q", tt.pattern, tt.minLen, got, tt.wantAtom)
			}
		})
	}
}

func TestAtomQuality(t *testing.T) {
	tests := []struct {
		name   string
		atom   []byte
		wantGT []byte // should have higher quality than this
		wantLT []byte // should have lower quality than this (optional)
	}{
		{
			name:   "longer is better",
			atom:   []byte("hello"),
			wantGT: []byte("hel"),
		},
		{
			name:   "uncommon bytes better than common",
			atom:   []byte("xyz"),
			wantGT: []byte{0x00, 0x00, 0x00},
		},
		{
			name:   "alphabetic better than whitespace",
			atom:   []byte("abc"),
			wantGT: []byte("   "),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := atomQuality(tt.atom)
			qGT := atomQuality(tt.wantGT)
			if q <= qGT {
				t.Errorf("atomQuality(%q) = %d, want > atomQuality(%q) = %d", tt.atom, q, tt.wantGT, qGT)
			}
			if tt.wantLT != nil {
				qLT := atomQuality(tt.wantLT)
				if q >= qLT {
					t.Errorf("atomQuality(%q) = %d, want < atomQuality(%q) = %d", tt.atom, q, tt.wantLT, qLT)
				}
			}
		})
	}
}

func TestExtractAtomsMultiple(t *testing.T) {
	// Test that top-level alternation extracts atoms from all branches
	atoms, ok := ExtractAtoms(`cat|dog|bird`, 3)
	if !ok {
		t.Fatal("expected atoms to be extracted")
	}
	if len(atoms) != 3 {
		t.Fatalf("expected 3 atoms for 3 branches, got %d", len(atoms))
	}

	// Verify we have atoms from each branch
	found := make(map[string]bool)
	for _, a := range atoms {
		found[string(a.Bytes)] = true
	}
	if !found["cat"] {
		t.Error("expected atom 'cat'")
	}
	if !found["dog"] {
		t.Error("expected atom 'dog'")
	}
	if !found["bird"] {
		t.Error("expected atom 'bird'")
	}
}

func TestExtractAtomsGroupedAlternation(t *testing.T) {
	// Alternation inside a group is not top-level, picks best atom
	atoms, ok := ExtractAtoms(`prefix(foo|bar|baz)suffix`, 3)
	if !ok {
		t.Fatal("expected atoms to be extracted")
	}
	// Should pick "prefix" or "suffix" (both 6 chars, same quality)
	if len(atoms) != 1 {
		t.Fatalf("expected 1 atom for grouped alternation, got %d", len(atoms))
	}
}
