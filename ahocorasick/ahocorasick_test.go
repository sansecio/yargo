package ahocorasick

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
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

func TestPrefilter_Engages(t *testing.T) {
	ac := buildAC("zzq")
	if ac.i.prefil == nil {
		t.Fatal("expected prefilter to be built for a single pattern")
	}

	haystack := bytes.Repeat([]byte{'a'}, 1<<20)
	iter := ac.IterOverlappingByte(haystack)
	if m := iter.Next(); m != nil {
		t.Fatalf("unexpected match at [%d,%d)", m.Start(), m.End())
	}
	if iter.prestate.skips == 0 {
		t.Error("expected prefilter to engage during the scan (skips > 0)")
	}
}

func TestPrefilter_SkipsToMatch(t *testing.T) {
	haystack := bytes.Repeat([]byte{'q'}, 100000)
	copy(haystack[50000:], "abz")

	ac := buildAC("abz")
	matches := collectMatches(ac, string(haystack))

	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Start() != 50000 || matches[0].End() != 50003 {
		t.Errorf("expected match at [50000,50003), got [%d,%d)", matches[0].Start(), matches[0].End())
	}
}

func TestPrefilter_DifferentialAgainstNoPrefilter(t *testing.T) {
	// Three patterns so the fixed rare-bytes builder (one byte per pattern)
	// stays within the ≤3 byte limit and the prefilter is guaranteed to build.
	patterns := [][]byte{
		[]byte("zqx"),
		[]byte("~jklm"),
		[]byte("jkl"),
	}
	noPreBuilder := &iNFABuilder{denseDepth: 3, prefilter: false}

	rng := rand.New(rand.NewPCG(42, 0))
	for round := range 20 {
		haystack := make([]byte, 1<<16)
		for i := range haystack {
			haystack[i] = byte('a' + rng.IntN(16))
		}
		for range 10 {
			p := patterns[rng.IntN(len(patterns))]
			pos := rng.IntN(len(haystack) - len(p))
			copy(haystack[pos:], p)
		}

		builder := NewAhoCorasickBuilder()
		withPre := builder.BuildByte(patterns)
		if withPre.i.prefil == nil {
			t.Fatal("expected prefilter to be built for these patterns")
		}
		noPre := AhoCorasick{noPreBuilder.build(patterns)}

		got := collectMatches(withPre, string(haystack))
		want := collectMatches(noPre, string(haystack))

		if len(got) != len(want) {
			t.Fatalf("round %d: prefilter scan found %d matches, reference found %d", round, len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("round %d: match %d differs: got %+v, want %+v", round, i, got[i], want[i])
			}
		}
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

// bruteForceFold finds every case-insensitive occurrence of each pattern.
func bruteForceFold(patterns [][]byte, haystack []byte) []string {
	var out []string
	for pi, p := range patterns {
		for i := 0; i+len(p) <= len(haystack); i++ {
			if strings.EqualFold(string(haystack[i:i+len(p)]), string(p)) {
				out = append(out, fmt.Sprintf("%d@%d", pi, i))
			}
		}
	}
	slices.Sort(out)
	return out
}

var benchmarkNextStateID stateID

func BenchmarkNextStateSparse(b *testing.B) {
	transitions := make([]innerSparse, 8)
	for i := range transitions {
		transitions[i] = innerSparse{b: byte(i * 16), s: stateID(i + 1)}
	}
	nfa := iNFA{states: []state{
		{dense: -1},
		{dense: -1, sparse: []innerSparse{{b: 'm', s: 2}}},
		{dense: -1, sparse: transitions},
	}}

	benchmarks := []struct {
		name  string
		state stateID
		input byte
	}{
		{name: "zero", state: 0, input: 'x'},
		{name: "one-hit", state: 1, input: 'm'},
		{name: "one-miss", state: 1, input: 'x'},
		{name: "eight-hit", state: 2, input: 64},
		{name: "eight-miss", state: 2, input: 65},
	}
	for _, bench := range benchmarks {
		b.Run(bench.name, func(b *testing.B) {
			var id stateID
			for b.Loop() {
				id = nfa.nextState(bench.state, bench.input)
			}
			benchmarkNextStateID = id
		})
	}
}

func TestAsciiCaseFoldMatchesBruteForce(t *testing.T) {
	// small sets keep the prefilter active, large sets disable it —
	// both paths must fold the haystack identically
	patternSets := [][][]byte{
		{[]byte("abc")},
		{[]byte("aB"), []byte("Ab")},
		{[]byte("she"), []byte("he"), []byte("hers"), []byte("his")},
		{[]byte("GetProcAddress"), []byte("eval"), []byte("\x01\x02Z"), []byte("Zz")},
	}
	alphabet := []byte("aAbBcCzZeEhHsSrRgG\x00\x01\x02 ")
	rng := rand.New(rand.NewPCG(7, 11))

	var sawPrefilter bool
	for si, patterns := range patternSets {
		builder := NewAhoCorasickBuilder()
		builder.AsciiCaseFold(true)
		ac := builder.BuildByte(patterns)
		sawPrefilter = sawPrefilter || ac.i.prefil != nil

		for range 200 {
			haystack := make([]byte, rng.IntN(64))
			for i := range haystack {
				haystack[i] = alphabet[rng.IntN(len(alphabet))]
			}

			var got []string
			iter := ac.IterOverlappingByte(haystack)
			for m := iter.Next(); m != nil; m = iter.Next() {
				got = append(got, fmt.Sprintf("%d@%d", m.Pattern(), m.Start()))
			}
			slices.Sort(got)

			want := bruteForceFold(patterns, haystack)
			if !slices.Equal(got, want) {
				t.Fatalf("set %d, haystack %q:\n got %v\nwant %v", si, haystack, got, want)
			}
		}
	}

	if !sawPrefilter {
		t.Error("no pattern set built a prefilter, so the folded prefilter path went untested")
	}
}
