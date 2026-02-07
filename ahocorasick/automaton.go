package ahocorasick

func standardFindAt(a *iNFA, prestate *prefilterState, haystack []byte, at int, sID *stateID) *Match {
	return standardFindAtImp(a, prestate, a.prefil, haystack, at, sID)
}

func standardFindAtImp(a *iNFA, prestate *prefilterState, prefilter prefilter, haystack []byte, at int, sID *stateID) *Match {
	for at < len(haystack) {
		if prefilter != nil {
			if prestate.IsEffective(at) && sID == &a.startID {
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

		if *sID == deadStateID || a.state(*sID).isMatch() {
			if *sID == deadStateID {
				return nil
			}
			return a.GetMatch(*sID, 0, at)
		}
	}
	return nil
}

func leftmostFindAtNoState(a *iNFA, prestate *prefilterState, haystack []byte, at int) *Match {
	return leftmostFindAtNoStateImp(a, prestate, a.prefil, haystack, at)
}

func leftmostFindAtNoStateImp(a *iNFA, prestate *prefilterState, prefilter prefilter, haystack []byte, at int) *Match {
	if a.anchored && at > 0 {
		return nil
	}
	if prefilter != nil && !prefilter.ReportsFalsePositives() {
		c := prefilter.NextCandidate(prestate, haystack, at)
		if c == noneCandidate {
			return nil
		}
	}

	sid := a.startID
	lastMatch := a.GetMatch(sid, 0, at)

	for at < len(haystack) {
		if prefilter != nil && prestate.IsEffective(at) && sid == a.startID {
			c := prefilter.NextCandidate(prestate, haystack, at)
			if c == noneCandidate {
				return nil
			} else {
				at = c
			}
		}

		sid = a.NextStateNoFail(sid, haystack[at])
		at += 1

		if sid == deadStateID || a.state(sid).isMatch() {
			if sid == deadStateID {
				return lastMatch
			}
			lastMatch = a.GetMatch(sid, 0, at)
		}
	}

	return lastMatch
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
	switch a.matchKind {
	case StandardMatch:
		state := a.startID
		return earliestFindAt(a, prestate, haystack, at, &state)
	case LeftMostFirstMatch, LeftMostLongestMatch:
		return leftmostFindAtNoState(a, prestate, haystack, at)
	}
	return nil
}
