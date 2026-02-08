package ahocorasick

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
