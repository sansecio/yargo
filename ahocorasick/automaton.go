package ahocorasick

type automaton interface {
	MatchKind() *matchKind
	Anchored() bool
	Prefilter() prefilter
	StartState() stateID
	IsMatchOrDeadState(stateID) bool
	GetMatch(stateID, int, int) *Match
	MatchCount(stateID) int
	NextStateNoFail(stateID, byte) stateID
	StandardFindAt(*prefilterState, []byte, int, *stateID) *Match
	StandardFindAtImp(*prefilterState, prefilter, []byte, int, *stateID) *Match
	LeftmostFindAtNoState(*prefilterState, []byte, int) *Match
	OverlappingFindAt(*prefilterState, []byte, int, *stateID, *int) *Match
	EarliestFindAt(*prefilterState, []byte, int, *stateID) *Match
	FindAtNoState(*prefilterState, []byte, int) *Match
}

func standardFindAt(a automaton, prestate *prefilterState, haystack []byte, at int, sID *stateID) *Match {
	pre := a.Prefilter()
	return a.StandardFindAtImp(prestate, pre, haystack, at, sID)
}

func standardFindAtImp(a automaton, prestate *prefilterState, prefilter prefilter, haystack []byte, at int, sID *stateID) *Match {
	for at < len(haystack) {
		if prefilter != nil {
			startState := a.StartState()
			if prestate.IsEffective(at) && sID == &startState {
				c := nextPrefilter(prestate, prefilter, haystack, at)
				if c == noneCandidate {
					return nil
				} else {
					at = c
				}
			}
		}
		*sID = a.NextStateNoFail(*sID, haystack[at])
		at += 1

		if a.IsMatchOrDeadState(*sID) {
			if *sID == deadStateID {
				return nil
			}
			return a.GetMatch(*sID, 0, at)
		}
	}
	return nil
}

func leftmostFindAtNoState(a automaton, prestate *prefilterState, haystack []byte, at int) *Match {
	return leftmostFindAtNoStateImp(a, prestate, a.Prefilter(), haystack, at)
}

func leftmostFindAtNoStateImp(a automaton, prestate *prefilterState, prefilter prefilter, haystack []byte, at int) *Match {
	if a.Anchored() && at > 0 {
		return nil
	}
	if prefilter != nil && !prefilter.ReportsFalsePositives() {
		c := prefilter.NextCandidate(prestate, haystack, at)
		if c == noneCandidate {
			return nil
		}
	}

	stateID := a.StartState()
	lastMatch := a.GetMatch(stateID, 0, at)

	for at < len(haystack) {
		if prefilter != nil && prestate.IsEffective(at) && stateID == a.StartState() {
			c := prefilter.NextCandidate(prestate, haystack, at)
			if c == noneCandidate {
				return nil
			} else {
				at = c
			}
		}

		stateID = a.NextStateNoFail(stateID, haystack[at])
		at += 1

		if a.IsMatchOrDeadState(stateID) {
			if stateID == deadStateID {
				return lastMatch
			}
			lastMatch = a.GetMatch(stateID, 0, at)
		}
	}

	return lastMatch
}

func overlappingFindAt(a automaton, prestate *prefilterState, haystack []byte, at int, id *stateID, matchIndex *int) *Match {
	if a.Anchored() && at > 0 && *id == a.StartState() {
		return nil
	}

	matchCount := a.MatchCount(*id)

	if *matchIndex < matchCount {
		result := a.GetMatch(*id, *matchIndex, at)
		*matchIndex += 1
		return result
	}

	*matchIndex = 0
	match := a.StandardFindAt(prestate, haystack, at, id)

	if match == nil {
		return nil
	}

	*matchIndex = 1
	return match
}

func earliestFindAt(a automaton, prestate *prefilterState, haystack []byte, at int, id *stateID) *Match {
	if *id == a.StartState() {
		if a.Anchored() && at > 0 {
			return nil
		}
		match := a.GetMatch(*id, 0, at)
		if match != nil {
			return match
		}
	}
	return a.StandardFindAt(prestate, haystack, at, id)
}

func findAtNoState(a automaton, prestate *prefilterState, haystack []byte, at int) *Match {
	kind := a.MatchKind()
	if kind == nil {
		return nil
	}
	switch *kind {
	case StandardMatch:
		state := a.StartState()
		return a.EarliestFindAt(prestate, haystack, at, &state)
	case LeftMostFirstMatch, LeftMostLongestMatch:
		return a.LeftmostFindAtNoState(prestate, haystack, at)
	}
	return nil
}
