package ahocorasick

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"
	"unsafe"
)

func TestStateMemoryBudget(t *testing.T) {
	// Production rulesets have millions of states; accidental padding or a
	// per-state slice can add tens of MiB to compilation's memory peak.
	if size := unsafe.Sizeof(state{}); size > 12 {
		t.Fatalf("state occupies %d bytes, want at most 12", size)
	}
}

func TestSparseTransitionsAllBytes(t *testing.T) {
	// Insert out of order and force a sparse state through every fan-out size.
	rng := rand.New(rand.NewPCG(10, 20))
	patterns := make([][]byte, 256)
	for i, b := range rng.Perm(256) {
		patterns[i] = []byte{'a', 'b', 'c', byte(b), 'z'}
	}
	for _, fold := range []bool{false, true} {
		builder := NewAhoCorasickBuilder()
		builder.AsciiCaseFold(fold)
		ac := builder.BuildByte(patterns)
		checkMatches(t, ac, patterns, bytes.Join(patterns, []byte{0}), fold)
	}
}

func TestSparseTransitionUpdates(t *testing.T) {
	var n iNFA
	id := n.addSparseState()
	var want [256]stateID
	updates := []struct {
		b    byte
		next stateID
	}{
		{'a', 7}, {'A', 7}, {'A', 8}, {'a', 9}, {0, 9}, {255, 7},
	}
	for _, update := range updates {
		n.setNextState(id, update.b, update.next)
		want[update.b] = update.next
		for b, next := range want {
			if got := n.nextState(id, byte(b)); got != next {
				t.Fatalf("after %+v: byte %d = %d, want %d", update, b, got, next)
			}
		}
	}
}

func TestTransitionLayouts(t *testing.T) {
	patterns := [][]byte{[]byte("abcde"), []byte("abcde"), []byte("AbCdE"), []byte("cde"), {0, 255, 'A'}}
	haystack := bytes.Join(patterns, []byte{0})
	for _, depth := range []int{0, 1, 2, 3, 5} {
		for _, fold := range []bool{false, true} {
			builder := &iNFABuilder{denseDepth: depth, fold: fold}
			checkMatches(t, AhoCorasick{builder.build(patterns)}, patterns, haystack, fold)
		}
	}
}

func TestAutomatonRandomMatches(t *testing.T) {
	rng := rand.New(rand.NewPCG(42, 7))
	alphabet := []byte("aAbBcCdD\x00\xff")
	for range 30 {
		patterns := make([][]byte, 80)
		for i := range patterns {
			patterns[i] = make([]byte, 1+rng.IntN(30))
			for j := range patterns[i] {
				patterns[i][j] = alphabet[rng.IntN(len(alphabet))]
			}
		}
		// Duplicate and suffix patterns must preserve all pattern IDs.
		patterns = append(patterns, patterns[0], patterns[0][len(patterns[0])/2:])
		haystack := bytes.Join(patterns, []byte{0})
		for _, fold := range []bool{false, true} {
			builder := NewAhoCorasickBuilder()
			builder.AsciiCaseFold(fold)
			checkMatches(t, builder.BuildByte(patterns), patterns, haystack, fold)
		}
	}
}

func TestLongSparseChain(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 9))
	long := make([]byte, 4096)
	for i := range long {
		long[i] = byte(rng.IntN(256))
	}
	branch := slices.Clone(long)
	branch[len(branch)-1] ^= 0xff
	patterns := [][]byte{long, branch, long[len(long)-20:], long}
	haystack := bytes.Join(patterns, []byte{0})
	for _, fold := range []bool{false, true} {
		builder := NewAhoCorasickBuilder()
		builder.AsciiCaseFold(fold)
		checkMatches(t, builder.BuildByte(patterns), patterns, haystack, fold)
	}
}

func checkMatches(t *testing.T, ac AhoCorasick, patterns [][]byte, haystack []byte, fold bool) {
	t.Helper()
	var got, want []string
	it := ac.IterOverlappingByte(haystack)
	for m := it.Next(); m != nil; m = it.Next() {
		got = append(got, fmt.Sprintf("%d@%d", m.Pattern(), m.Start()))
	}
	if fold {
		patterns = foldPatterns(patterns)
		haystack = foldPatterns([][]byte{haystack})[0]
	}
	for pi, p := range patterns {
		for offset := 0; offset+len(p) <= len(haystack); offset++ {
			if bytes.Equal(haystack[offset:offset+len(p)], p) {
				want = append(want, fmt.Sprintf("%d@%d", pi, offset))
			}
		}
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("fold=%v: got %d matches, want %d; match sets differ", fold, len(got), len(want))
	}
}

func BenchmarkBuildLarge(b *testing.B) {
	rng := rand.New(rand.NewPCG(1, 2))
	patterns := make([][]byte, 10000)
	for i := range patterns {
		patterns[i] = make([]byte, 80)
		for j := range patterns[i] {
			patterns[i][j] = byte('a' + rng.IntN(26))
		}
	}
	b.ReportAllocs()
	for b.Loop() {
		builder := NewAhoCorasickBuilder()
		builder.BuildByte(patterns)
	}
}
