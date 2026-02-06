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
		{"nested alternation", `(foo|barbaz)`, 3, true, "foo"}, // returns all branches; first is "foo"
		{"word boundary pattern", `\bhello\b`, 3, true, "hello"},
		{"digit class breaks run", `hello\dworldly`, 3, true, "worldly"},
		{"word class breaks run", `abc\wdef`, 3, true, "abc"},
		{"no long enough atom", `[a-z]+`, 3, false, ""},
		{"only short literals", `a[0-9]b[0-9]c`, 3, false, ""},
		{"optional breaks run", `hello?world`, 3, true, "world"},
		{"star breaks run", `hello*world`, 3, true, "world"},
		{"plus keeps preceding byte", `hello+[0-9]`, 3, true, "hello"},
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

func Test_extractAtomsRejectsCommonKeywords(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantOk  bool
	}{
		{"rejects return", `return`, false},
		{"rejects function", `function`, false},
		{"rejects var", `var`, false},
		{"rejects return with trailing space", `return `, false},
		{"accepts return as substring", `return_value`, true},
		{"accepts function as substring", `function_name`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := extractAtoms(tt.pattern, minAtomLength)
			if ok != tt.wantOk {
				t.Errorf("extractAtoms(%q, %d) ok = %v, want %v", tt.pattern, minAtomLength, ok, tt.wantOk)
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
	atoms, ok := extractAtoms(`cat|dog|bird`, minAtomLength)
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
	// When outside literals are better than alternation branches, use outside
	atoms, ok := extractAtoms(`prefix(foo|bar|baz)suffix`, minAtomLength)
	if !ok {
		t.Fatal("expected atoms to be extracted")
	}
	// "prefix" and "suffix" (6 chars) are better than "foo"/"bar"/"baz" (3 chars)
	// so we use the required literal instead of alternation atoms
	if len(atoms) != 1 {
		t.Fatalf("expected 1 atom (best outside literal), got %d", len(atoms))
	}
	atom := string(atoms[0])
	if atom != "prefix" && atom != "suffix" {
		t.Errorf("expected 'prefix' or 'suffix', got %q", atom)
	}
}

func Test_extractAtomsNestedAlternationBetter(t *testing.T) {
	// When alternation branches are better than outside literals, use all branches
	// Pattern: short prefix, longer alternation options
	atoms, ok := extractAtoms(`go(unlink|fwrite|password|eval)`, minAtomLength)
	if !ok {
		t.Fatal("expected atoms to be extracted")
	}
	// "unlink", "fwrite", "password" are better than "go" (2 chars, below minLen)
	if len(atoms) != 4 {
		t.Fatalf("expected 4 atoms (all alternation branches), got %d", len(atoms))
	}
	found := make(map[string]bool)
	for _, a := range atoms {
		found[string(a)] = true
	}
	for _, want := range []string{"unlink", "fwrite", "password", "eval"} {
		if !found[want] {
			t.Errorf("expected atom %q", want)
		}
	}
}

func Test_extractAtomsOptionalGroup(t *testing.T) {
	// Atoms from optional groups should NOT be used - they might not appear in matches
	// Pattern: (window\.)?atob\( - "window." is optional, "atob(" is required
	atoms, ok := extractAtoms(`(window\.)?atob\(`, minAtomLength)
	if !ok {
		t.Fatal("expected atoms to be extracted")
	}
	if len(atoms) != 1 {
		t.Fatalf("expected 1 atom, got %d", len(atoms))
	}
	// Should extract "atob(" (required), NOT "window." (optional)
	if got := string(atoms[0]); got != "atob(" {
		t.Errorf("expected atom 'atob(' (required), got %q (likely from optional group)", got)
	}
}

func Test_extractAtomsOptionalGroupStar(t *testing.T) {
	// Groups followed by * are optional (0 or more)
	atoms, ok := extractAtoms(`(prefix)*suffix`, minAtomLength)
	if !ok {
		t.Fatal("expected atoms to be extracted")
	}
	if len(atoms) != 1 {
		t.Fatalf("expected 1 atom, got %d", len(atoms))
	}
	// Should extract "suffix" (required), NOT "prefix" (optional via *)
	if got := string(atoms[0]); got != "suffix" {
		t.Errorf("expected atom 'suffix' (required), got %q", got)
	}
}

func Test_extractAtomsOptionalGroupZeroMin(t *testing.T) {
	// Groups followed by {0,N} are optional
	atoms, ok := extractAtoms(`(optional){0,5}required`, minAtomLength)
	if !ok {
		t.Fatal("expected atoms to be extracted")
	}
	if len(atoms) != 1 {
		t.Fatalf("expected 1 atom, got %d", len(atoms))
	}
	// Should extract "required", NOT "optional"
	if got := string(atoms[0]); got != "required" {
		t.Errorf("expected atom 'required', got %q", got)
	}
}

func Test_extractAtomsRealPattern(t *testing.T) {
	// Real pattern from base64_obfuscated_inclusion rules
	// The file has "atob(" without "window." prefix
	atoms, ok := extractAtoms(`\.src ?= ?(window\.)?atob\(['"][^\)]{4,250}\)`, minAtomLength)
	if !ok {
		t.Fatal("expected atoms to be extracted")
	}
	// Should NOT extract "window." since it's optional
	for _, a := range atoms {
		if string(a) == "window." {
			t.Errorf("should not extract 'window.' from optional group")
		}
	}
	// Should extract something required like "atob(" or ".src"
	found := false
	for _, a := range atoms {
		s := string(a)
		if s == "atob(" || s == ".src" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected to find required atom like 'atob(' or '.src', got %q", atoms)
	}
}

func Test_extractAtomsMultipleAlternationGroups(t *testing.T) {
	// When there are multiple alternation groups, only extract from the best one.
	// Pattern: [a-z]{0,15}(meriks|pixel)[a-z]{0,15}\.(top|xyz)
	// "meriks" and "pixel" are higher quality atoms than "top" and "xyz"
	// so we should only extract from (meriks|pixel), not from (top|xyz)
	atoms, ok := extractAtoms(`[a-z]{0,15}(meriks|pixel)[a-z]{0,15}\.(top|xyz)`, minAtomLength)
	if !ok {
		t.Fatal("expected atoms to be extracted")
	}

	found := make(map[string]bool)
	for _, a := range atoms {
		found[string(a)] = true
	}

	// Should have atoms from the best alternation group only
	if !found["meriks"] || !found["pixel"] {
		t.Errorf("expected atoms 'meriks' and 'pixel' from best alternation group, got %v", found)
	}

	// Should NOT have atoms from the second alternation group
	if found["top"] || found["xyz"] {
		t.Errorf("should not extract 'top' or 'xyz' from second alternation group, got %v", found)
	}
}

func Test_extractAtomsOptionalAlternationGroup(t *testing.T) {
	// Alternation groups that are optional should not have atoms extracted
	tests := []struct {
		name    string
		pattern string
	}{
		{"question mark", `(meriks|pixel)?suffix`},
		{"star", `(meriks|pixel)*suffix`},
		{"zero min curly", `(meriks|pixel){0,10}suffix`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			atoms, ok := extractAtoms(tt.pattern, minAtomLength)
			if !ok {
				t.Fatal("expected atoms to be extracted")
			}

			found := make(map[string]bool)
			for _, a := range atoms {
				found[string(a)] = true
			}

			// Should NOT extract from optional alternation group
			if found["meriks"] || found["pixel"] {
				t.Errorf("should not extract from optional alternation group, got %v", found)
			}

			// Should extract required literal
			if !found["suffix"] {
				t.Errorf("expected 'suffix' atom, got %v", found)
			}
		})
	}
}
