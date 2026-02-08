package ahocorasick

type findIter struct {
	fsm      *iNFA
	prestate *prefilterState
	haystack []byte
	pos      int
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
		fsm:      ac.i,
		prestate: &prestate,
		haystack: haystack,
		pos:      0,
	}
}

// Iter is an iterator over matches found on the current haystack.
type Iter interface {
	Next() *Match
}

// Next gives a pointer to the next match yielded by the iterator or nil, if there is none.
func (f *findIter) Next() *Match {
	if f.pos > len(f.haystack) {
		return nil
	}

	result := findAtNoState(f.fsm, f.prestate, f.haystack, f.pos)

	if result == nil {
		return nil
	}

	f.pos = result.end - result.len + 1
	return result
}

type overlappingIter struct {
	fsm        *iNFA
	prestate   *prefilterState
	haystack   []byte
	pos        int
	stateID    stateID
	matchIndex int
}

func (f *overlappingIter) Next() *Match {
	if f.pos > len(f.haystack) {
		return nil
	}

	result := overlappingFindAt(f.fsm, f.prestate, f.haystack, f.pos, &f.stateID, &f.matchIndex)

	if result == nil {
		return nil
	}

	f.pos = result.End()
	return result
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
		fsm:        ac.i,
		prestate:   &prestate,
		haystack:   haystack,
		pos:        0,
		stateID:    ac.i.startID,
		matchIndex: 0,
	}
}

// AhoCorasick is the main data structure that does most of the work.
type AhoCorasick struct {
	i *iNFA
}

// IterOverlappingByte gives an iterator over the built patterns with overlapping matches.
func (ac AhoCorasick) IterOverlappingByte(haystack []byte) Iter {
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
	nfaBuilder *iNFABuilder
}

// NewAhoCorasickBuilder creates a new AhoCorasickBuilder.
func NewAhoCorasickBuilder() AhoCorasickBuilder {
	return AhoCorasickBuilder{
		nfaBuilder: newNFABuilder(),
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
	return AhoCorasick{nfa}
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
