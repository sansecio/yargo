package scanner

import (
	"testing"
)

func Test_extractAtoms(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		minLen   int
		wantOk   bool
		wantAtom string
	}{
		{"simple literal", "hello", 3, true, "hello"},
		{"literal with escaped dot", `foo\.bar`, 3, true, "foo.bar"},
		{"hex escape", `\x41\x42\x43`, 3, true, "ABC"},
		{"mixed hex and literal", `test\x2Eexe`, 3, true, "test.exe"},
		{"literal before character class", `hello[0-9]+worldly`, 3, true, "worldly"},
		{"literal after quantifier", `a+longword`, 3, true, "longword"},
		{"alternation picks longest branch", `(foo|barbaz)`, 3, true, "barbaz"},
		{"word boundary pattern", `\bhello\b`, 3, true, "hello"},
		{"digit class breaks run", `hello\dworldly`, 3, true, "worldly"},
		{"word class breaks run", `abc\wdef`, 3, true, "abc"},
		{"no long enough atom", `[a-z]+`, 3, false, ""},
		{"only short literals", `a[0-9]b[0-9]c`, 3, false, ""},
		{"optional breaks run", `hello?world`, 3, true, "world"},
		{"star breaks run", `hello*world`, 3, true, "world"},
		{"plus breaks run", `hello+world`, 3, true, "world"},
		{"curly brace quantifier", `a{2,5}hello`, 3, true, "hello"},
		{"dot breaks run", `hello.worldly`, 3, true, "worldly"},
		{"caret anchor", `^hello`, 3, true, "hello"},
		{"dollar anchor", `hello$`, 3, true, "hello"},
		{"escaped backslash", `foo\\bar`, 3, true, "foo\\bar"},
		{"pipe outside group picks best from each branch", `foo|barbaz`, 3, true, "foo"},
		{"nested groups", `((abc))`, 3, true, "abc"},
		{"non-capturing group", `(?:hello)`, 3, true, "hello"},
		{"case insensitive flag", `(?i)hello`, 3, true, "hello"},
		{"minLen 2", `ab[0-9]cd`, 2, true, "ab"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			atoms, ok := extractAtoms(tt.pattern, tt.minLen)
			if ok != tt.wantOk {
				t.Errorf("extractAtoms(%q, %d) ok = %v, want %v", tt.pattern, tt.minLen, ok, tt.wantOk)
				return
			}
			if !ok {
				return
			}
			if len(atoms) == 0 {
				t.Errorf("extractAtoms(%q, %d) returned ok=true but no atoms", tt.pattern, tt.minLen)
				return
			}
			if got := string(atoms[0]); got != tt.wantAtom {
				t.Errorf("extractAtoms(%q, %d) atom = %q, want %q", tt.pattern, tt.minLen, got, tt.wantAtom)
			}
		})
	}
}

func TestAtomQuality(t *testing.T) {
	tests := []struct {
		name   string
		atom   []byte
		wantGT []byte
	}{
		{"longer is better", []byte("hello"), []byte("hel")},
		{"uncommon bytes better than common", []byte("xyz"), []byte{0x00, 0x00, 0x00}},
		{"alphabetic better than whitespace", []byte("abc"), []byte("   ")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if q, qGT := atomQuality(tt.atom), atomQuality(tt.wantGT); q <= qGT {
				t.Errorf("atomQuality(%q) = %d, want > atomQuality(%q) = %d", tt.atom, q, tt.wantGT, qGT)
			}
		})
	}
}

func Test_extractAtomsMultiple(t *testing.T) {
	atoms, ok := extractAtoms(`cat|dog|bird`, 3)
	if !ok {
		t.Fatal("expected atoms to be extracted")
	}
	if len(atoms) != 3 {
		t.Fatalf("expected 3 atoms for 3 branches, got %d", len(atoms))
	}

	found := make(map[string]bool)
	for _, a := range atoms {
		found[string(a)] = true
	}
	for _, want := range []string{"cat", "dog", "bird"} {
		if !found[want] {
			t.Errorf("expected atom %q", want)
		}
	}
}

func Test_extractAtomsGroupedAlternation(t *testing.T) {
	atoms, ok := extractAtoms(`prefix(foo|bar|baz)suffix`, 3)
	if !ok {
		t.Fatal("expected atoms to be extracted")
	}
	if len(atoms) != 1 {
		t.Fatalf("expected 1 atom for grouped alternation, got %d", len(atoms))
	}
}
