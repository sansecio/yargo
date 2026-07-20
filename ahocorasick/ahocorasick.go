package ahocorasick

type overlappingIter struct {
	fsm        *iNFA
	prestate   *prefilterState
	haystack   []byte
	pos        int
	stateID    stateID
	matchIndex int
	match      Match
}

// Next gives a pointer to the next match yielded by the iterator or nil, if
// there is none. The Match is owned by the iterator and is overwritten by the
// following call to Next, so copy it if you need to keep it.
func (f *overlappingIter) Next() *Match {
	if f.pos > len(f.haystack) {
		return nil
	}

	if !overlappingFindAt(f.fsm, f.prestate, f.haystack, f.pos, &f.stateID, &f.matchIndex, &f.match) {
		return nil
	}

	f.pos = f.match.End()
	return &f.match
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
func (ac AhoCorasick) IterOverlappingByte(haystack []byte) *overlappingIter {
	i := newOverlappingIter(ac, haystack)
	return &i
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

// AsciiCaseFold makes the automaton match case-insensitively over ASCII A-Z.
// Patterns are folded when the automaton is built and the haystack is folded
// as it is scanned, so no copy of the haystack is needed and match offsets
// still refer to the original bytes.
func (a *AhoCorasickBuilder) AsciiCaseFold(fold bool) {
	a.nfaBuilder.fold = fold
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
	matchStateBit stateID = 1 << 31
)

func standardFindAt(a *iNFA, prestate *prefilterState, haystack []byte, at int, sID *stateID, dst *Match) bool {
	return standardFindAtImp(a, prestate, a.prefil, haystack, at, sID, dst)
}

func standardFindAtImp(a *iNFA, prestate *prefilterState, pf *prefilter, haystack []byte, at int, sID *stateID, dst *Match) bool {
	sid := *sID
	states := a.states
	denseTable := a.denseTable
	for at < len(haystack) {
		if pf != nil {
			if prestate.IsEffective(at) && sid == a.startID {
				c := nextPrefilter(prestate, pf, haystack, at)
				if c == noneCandidate {
					*sID = sid
					return false
				} else {
					at = c
				}
			}
		}
		b := haystack[at]
		// dense rows are premultiplied full DFA rows, so one lookup suffices;
		// in fold mode their A-Z edges mirror a-z, so bytes need no folding
		var next stateID
		if d := states[sid].dense; d >= 0 {
			next = denseTable[int(d)+int(b)]
		} else {
			next = a.nextStateNoFail(sid, b)
		}
		at += 1

		matched := next&matchStateBit != 0
		sid = next &^ matchStateBit
		if sid == deadStateID || matched {
			*sID = sid
			if sid == deadStateID {
				return false
			}
			return a.getMatch(sid, 0, at, dst)
		}
	}
	*sID = sid
	return false
}

func overlappingFindAt(a *iNFA, prestate *prefilterState, haystack []byte, at int, id *stateID, matchIndex *int, dst *Match) bool {
	if a.anchored && at > 0 && *id == a.startID {
		return false
	}

	if *matchIndex < len(a.matches[*id]) {
		ok := a.getMatch(*id, *matchIndex, at, dst)
		*matchIndex += 1
		return ok
	}

	*matchIndex = 0
	if !standardFindAt(a, prestate, haystack, at, id, dst) {
		return false
	}

	*matchIndex = 1
	return true
}
