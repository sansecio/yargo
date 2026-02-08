package ahocorasick

import (
	"sync"
	"testing"
)

func TestFindAll_SinglePattern(t *testing.T) {
	builder := NewAhoCorasickBuilder()
	ac := builder.Build([]string{"abc"})
	matches := ac.FindAll("xxabcxxabcxx")

	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(matches))
	}
	if matches[0].Start() != 2 || matches[0].End() != 5 {
		t.Errorf("match 0: expected [2,5), got [%d,%d)", matches[0].Start(), matches[0].End())
	}
	if matches[1].Start() != 7 || matches[1].End() != 10 {
		t.Errorf("match 1: expected [7,10), got [%d,%d)", matches[1].Start(), matches[1].End())
	}
}

func TestFindAll_MultiplePatterns(t *testing.T) {
	builder := NewAhoCorasickBuilder()
	ac := builder.Build([]string{"he", "she", "his", "hers"})
	matches := ac.FindAll("ushers")

	if len(matches) == 0 {
		t.Fatal("expected at least one match")
	}

	// Standard (earliest) match semantics: non-overlapping, reports as seen.
	// "she" starts at 1, then "he" starts at 2 — but since FindAll advances
	// past each match, we get "she" then "he" (which overlaps, so just "she"
	// is found first at pos 1, then scanning from pos 2 finds "he" at pos 2).
	found := make(map[int]bool)
	for _, m := range matches {
		found[m.Pattern()] = true
	}
	if !found[0] {
		t.Error("expected to find pattern 'he'")
	}
	if !found[1] {
		t.Error("expected to find pattern 'she'")
	}
}

func TestFindAll_NoMatch(t *testing.T) {
	builder := NewAhoCorasickBuilder()
	ac := builder.Build([]string{"foo", "bar"})
	matches := ac.FindAll("nothing here")

	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d", len(matches))
	}
}

func TestFindAll_EmptyHaystack(t *testing.T) {
	builder := NewAhoCorasickBuilder()
	ac := builder.Build([]string{"abc"})
	matches := ac.FindAll("")

	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d", len(matches))
	}
}

func TestIterOverlapping(t *testing.T) {
	builder := NewAhoCorasickBuilder()
	ac := builder.Build([]string{"he", "she", "his", "hers"})
	iter := ac.IterOverlappingByte([]byte("ushers"))

	var matches []Match
	for next := iter.Next(); next != nil; next = iter.Next() {
		matches = append(matches, *next)
	}

	// Overlapping: should find "she", "he", "hers"
	if len(matches) < 3 {
		t.Fatalf("expected at least 3 overlapping matches, got %d", len(matches))
	}

	found := make(map[int]bool)
	for _, m := range matches {
		found[m.Pattern()] = true
	}
	if !found[0] {
		t.Error("expected to find pattern 'he'")
	}
	if !found[1] {
		t.Error("expected to find pattern 'she'")
	}
	if !found[3] {
		t.Error("expected to find pattern 'hers'")
	}
}

func TestIterOverlapping_SubstringPatterns(t *testing.T) {
	builder := NewAhoCorasickBuilder()
	ac := builder.Build([]string{"a", "ab", "abc"})
	iter := ac.IterOverlappingByte([]byte("abc"))

	var matches []Match
	for next := iter.Next(); next != nil; next = iter.Next() {
		matches = append(matches, *next)
	}

	if len(matches) != 3 {
		t.Fatalf("expected 3 overlapping matches, got %d", len(matches))
	}
}

func TestFindAll_Parallel(t *testing.T) {
	builder := NewAhoCorasickBuilder()
	ac := builder.Build([]string{"bear", "masha"})
	haystack := "The bear and masha"

	var w sync.WaitGroup
	w.Add(50)
	for i := 0; i < 50; i++ {
		go func() {
			defer w.Done()
			matches := ac.FindAll(haystack)
			if len(matches) != 2 {
				t.Errorf("expected 2 matches, got %d", len(matches))
			}
		}()
	}
	w.Wait()
}
