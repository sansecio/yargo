package ahocorasick

import (
	"unicode"
)

type findIter struct {
	fsm                 *iNFA
	prestate            *prefilterState
	haystack            []byte
	pos                 int
	matchOnlyWholeWords bool
}

func newFindIter(ac AhoCorasick, haystack []byte) findIter {
	prestate := prefilterState{
		skips:       0,
		skipped:     0,
		maxMatchLen: ac.i.MaxPatternLen(),
		inert:       false,
		lastScanAt:  0,
	}

	return findIter{
		fsm:                 ac.i,
		prestate:            &prestate,
		haystack:            haystack,
		pos:                 0,
		matchOnlyWholeWords: ac.matchOnlyWholeWords,
	}
}

// Iter is an iterator over matches found on the current haystack.
type Iter interface {
	Next() *Match
}

// Next gives a pointer to the next match yielded by the iterator or nil, if there is none.
func (f *findIter) Next() *Match {
	for {
		if f.pos > len(f.haystack) {
			return nil
		}

		result := findAtNoState(f.fsm, f.prestate, f.haystack, f.pos)

		if result == nil {
			return nil
		}

		f.pos = result.end - result.len + 1

		if f.matchOnlyWholeWords {
			if result.Start()-1 >= 0 && (unicode.IsLetter(rune(f.haystack[result.Start()-1])) || unicode.IsDigit(rune(f.haystack[result.Start()-1]))) {
				continue
			}
			if result.end < len(f.haystack) && (unicode.IsLetter(rune(f.haystack[result.end])) || unicode.IsDigit(rune(f.haystack[result.end]))) {
				continue
			}
		}
		return result
	}
}

type overlappingIter struct {
	fsm                 *iNFA
	prestate            *prefilterState
	haystack            []byte
	pos                 int
	stateID             stateID
	matchIndex          int
	matchOnlyWholeWords bool
}

func (f *overlappingIter) Next() *Match {
	for {
		if f.pos > len(f.haystack) {
			return nil
		}

		result := overlappingFindAt(f.fsm, f.prestate, f.haystack, f.pos, &f.stateID, &f.matchIndex)

		if result == nil {
			return nil
		}

		f.pos = result.End()

		if f.matchOnlyWholeWords {
			if result.Start()-1 >= 0 && (unicode.IsLetter(rune(f.haystack[result.Start()-1])) || unicode.IsDigit(rune(f.haystack[result.Start()-1]))) {
				continue
			}
			if result.end < len(f.haystack) && (unicode.IsLetter(rune(f.haystack[result.end])) || unicode.IsDigit(rune(f.haystack[result.end]))) {
				continue
			}
		}

		return result
	}
}

func newOverlappingIter(ac AhoCorasick, haystack []byte) overlappingIter {
	prestate := prefilterState{
		skips:       0,
		skipped:     0,
		maxMatchLen: ac.i.MaxPatternLen(),
		inert:       false,
		lastScanAt:  0,
	}
	return overlappingIter{
		fsm:                 ac.i,
		prestate:            &prestate,
		haystack:            haystack,
		pos:                 0,
		stateID:             ac.i.startID,
		matchIndex:          0,
		matchOnlyWholeWords: ac.matchOnlyWholeWords,
	}
}

// AhoCorasick is the main data structure that does most of the work.
type AhoCorasick struct {
	i                   *iNFA
	matchKind           matchKind
	matchOnlyWholeWords bool
}

// IterOverlappingByte gives an iterator over the built patterns with overlapping matches.
func (ac AhoCorasick) IterOverlappingByte(haystack []byte) Iter {
	if ac.matchKind != StandardMatch {
		panic("only StandardMatch allowed for overlapping matches")
	}
	i := newOverlappingIter(ac, haystack)
	return &i
}

// FindAll returns the matches found in the haystack.
func (ac AhoCorasick) FindAll(haystack string) []Match {
	iter := newFindIter(ac, unsafeBytes(haystack))

	var matches []Match
	for {
		next := iter.Next()
		if next == nil {
			break
		}

		matches = append(matches, *next)
	}

	return matches
}

// AhoCorasickBuilder defines a set of options applied before the patterns are built.
type AhoCorasickBuilder struct {
	nfaBuilder          *iNFABuilder
	matchOnlyWholeWords bool
}

// Opts defines a set of options applied before the patterns are built.
// MatchOnlyWholeWords does filtering after matching with MatchKind
// this could lead to situations where, in this case, nothing is matched
//
//	    trieBuilder := NewAhoCorasickBuilder(Opts{
//		     MatchOnlyWholeWords: true,
//		     MatchKind:           LeftMostLongestMatch,
//	    })
//
//			trie := trieBuilder.Build([]string{"testing", "testing 123"})
//			result := trie.FindAll("testing 12345")
//		 len(result) == 0
//
// this is due to the fact LeftMostLongestMatch is the matching strategy
// "testing 123" is found but then is filtered out by MatchOnlyWholeWords
// use MatchOnlyWholeWords with caution
type Opts struct {
	AsciiCaseInsensitive bool
	MatchOnlyWholeWords  bool
	MatchKind            matchKind
}

// NewAhoCorasickBuilder creates a new AhoCorasickBuilder based on Opts.
func NewAhoCorasickBuilder(o Opts) AhoCorasickBuilder {
	return AhoCorasickBuilder{
		nfaBuilder:          newNFABuilder(o.MatchKind, o.AsciiCaseInsensitive),
		matchOnlyWholeWords: o.MatchOnlyWholeWords,
	}
}

// Build builds a (non)deterministic finite automata from the user provided patterns.
func (a *AhoCorasickBuilder) Build(patterns []string) AhoCorasick {
	bytePatterns := make([][]byte, len(patterns))
	for pati, pat := range patterns {
		bytePatterns[pati] = unsafeBytes(pat)
	}

	return a.BuildByte(bytePatterns)
}

// BuildByte builds an automaton from the user provided patterns.
func (a *AhoCorasickBuilder) BuildByte(patterns [][]byte) AhoCorasick {
	nfa := a.nfaBuilder.build(patterns)
	return AhoCorasick{nfa, nfa.matchKind, a.matchOnlyWholeWords}
}

type matchKind int

const (
	// Use standard match semantics, which support overlapping matches. When
	// used with non-overlapping matches, matches are reported as they are seen.
	StandardMatch matchKind = iota
	// Use leftmost-first match semantics, which reports leftmost matches.
	// When there are multiple possible leftmost matches, the match
	// corresponding to the pattern that appeared earlier when constructing
	// the automaton is reported.
	// This does **not** support overlapping matches or stream searching
	LeftMostFirstMatch
	// Use leftmost-longest match semantics, which reports leftmost matches.
	// When there are multiple possible leftmost matches, the longest match is chosen.
	LeftMostLongestMatch
)

func (m matchKind) isLeftmost() bool {
	return m == LeftMostFirstMatch || m == LeftMostLongestMatch
}

func (m matchKind) isLeftmostFirst() bool {
	return m == LeftMostFirstMatch
}

// A representation of a match reported by an Aho-Corasick automaton.
//
// A match has two essential pieces of information: the identifier of the
// pattern that matched, along with the start and end offsets of the match
// in the haystack.
type Match struct {
	pattern int
	len     int
	end     int
}

// Pattern returns the index of the pattern in the slice of the patterns provided by the user that
// was matched.
func (m *Match) Pattern() int {
	return m.pattern
}

// End gives the index of the last character of this match inside the haystack.
func (m *Match) End() int {
	return m.end
}

// Start gives the index of the first character of this match inside the haystack.
func (m *Match) Start() int {
	return m.end - m.len
}

type stateID uint32

const (
	failedStateID stateID = 0
	deadStateID   stateID = 1
)
