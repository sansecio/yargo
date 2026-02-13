package ahocorasick

import "unsafe"

func unsafeBytes(s string) []byte {
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

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

func standardFindAt(a *iNFA, prestate *prefilterState, haystack []byte, at int, sID *stateID) *Match {
	return standardFindAtImp(a, prestate, a.prefil, haystack, at, sID)
}

func standardFindAtImp(a *iNFA, prestate *prefilterState, prefilter prefilter, haystack []byte, at int, sID *stateID) *Match {
	sid := *sID
	for at < len(haystack) {
		if prefilter != nil {
			if prestate.IsEffective(at) && sID == &a.startID {
				c := nextPrefilter(prestate, prefilter, haystack, at)
				if c == noneCandidate {
					*sID = sid
					return nil
				} else {
					at = c
				}
			}
		}
		sid = a.NextStateNoFail(sid, haystack[at])
		at += 1

		if sid == deadStateID || a.hasMatch(sid) {
			*sID = sid
			if sid == deadStateID {
				return nil
			}
			return a.GetMatch(sid, 0, at)
		}
	}
	*sID = sid
	return nil
}

func overlappingFindAt(a *iNFA, prestate *prefilterState, haystack []byte, at int, id *stateID, matchIndex *int) *Match {
	if a.anchored && at > 0 && *id == a.startID {
		return nil
	}

	matchCount := len(a.states[*id].matches)

	if *matchIndex < matchCount {
		result := a.GetMatch(*id, *matchIndex, at)
		*matchIndex += 1
		return result
	}

	*matchIndex = 0
	match := standardFindAt(a, prestate, haystack, at, id)

	if match == nil {
		return nil
	}

	*matchIndex = 1
	return match
}

func earliestFindAt(a *iNFA, prestate *prefilterState, haystack []byte, at int, id *stateID) *Match {
	if *id == a.startID {
		if a.anchored && at > 0 {
			return nil
		}
		match := a.GetMatch(*id, 0, at)
		if match != nil {
			return match
		}
	}
	return standardFindAt(a, prestate, haystack, at, id)
}

func findAtNoState(a *iNFA, prestate *prefilterState, haystack []byte, at int) *Match {
	state := a.startID
	return earliestFindAt(a, prestate, haystack, at, &state)
}
