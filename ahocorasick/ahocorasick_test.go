package ahocorasick

import (
	"sync"
	"testing"
)

func buildAC(patterns ...string) AhoCorasick {
	builder := NewAhoCorasickBuilder()
	bytePatterns := make([][]byte, len(patterns))
	for i, p := range patterns {
		bytePatterns[i] = []byte(p)
	}
	return builder.BuildByte(bytePatterns)
}

func collectMatches(ac AhoCorasick, haystack string) []Match {
	iter := ac.IterOverlappingByte([]byte(haystack))
	var matches []Match
	for next := iter.Next(); next != nil; next = iter.Next() {
		matches = append(matches, *next)
	}
	return matches
}

func TestIterOverlapping_SinglePattern(t *testing.T) {
	ac := buildAC("abc")
	matches := collectMatches(ac, "xxabcxxabcxx")

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

func TestIterOverlapping_MultiplePatterns(t *testing.T) {
	ac := buildAC("he", "she", "his", "hers")
	matches := collectMatches(ac, "ushers")

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

func TestIterOverlapping_NoMatch(t *testing.T) {
	ac := buildAC("foo", "bar")
	matches := collectMatches(ac, "nothing here")

	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d", len(matches))
	}
}

func TestIterOverlapping_EmptyHaystack(t *testing.T) {
	ac := buildAC("abc")
	matches := collectMatches(ac, "")

	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d", len(matches))
	}
}

func TestIterOverlapping_SubstringPatterns(t *testing.T) {
	ac := buildAC("a", "ab", "abc")
	matches := collectMatches(ac, "abc")

	if len(matches) != 3 {
		t.Fatalf("expected 3 overlapping matches, got %d", len(matches))
	}
}

func TestIterOverlapping_Parallel(t *testing.T) {
	ac := buildAC("bear", "masha")
	haystack := []byte("The bear and masha")

	var w sync.WaitGroup
	w.Add(50)
	for range 50 {
		go func() {
			defer w.Done()
			iter := ac.IterOverlappingByte(haystack)
			var count int
			for next := iter.Next(); next != nil; next = iter.Next() {
				count++
			}
			if count != 2 {
				t.Errorf("expected 2 matches, got %d", count)
			}
		}()
	}
	w.Wait()
}
