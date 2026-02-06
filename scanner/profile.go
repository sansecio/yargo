package scanner

import (
	"sort"
	"time"
)

// RegexTiming holds the timing result for a single regex pattern.
type RegexTiming struct {
	Rule           string
	String         string
	Pattern        string
	MatchedAtoms   []string // Atoms that actually matched in the buffer
	ExtractedAtoms []string // All atoms extracted from the regex
	Duration       time.Duration
	Calls          int
}

type atomCandidate struct {
	positions []int
	atoms     map[string]struct{}
}

// RegexProfile scans a buffer and returns per-regex timing information,
// sorted slowest first.
func (r *Rules) RegexProfile(buf []byte) []RegexTiming {
	atomCandidates := make(map[int]*atomCandidate)

	if r.matcher != nil {
		iter := r.matcher.IterOverlappingByte(buf)
		for match := iter.Next(); match != nil; match = iter.Next() {
			ref := r.patternMap[match.Pattern()]
			if ref.isAtom {
				ac := atomCandidates[ref.regexIdx]
				if ac == nil {
					ac = &atomCandidate{atoms: make(map[string]struct{})}
					atomCandidates[ref.regexIdx] = ac
				}
				ac.atoms[string(r.patterns[match.Pattern()])] = struct{}{}
				ac.positions = append(ac.positions, match.Start())
			}
		}
	}

	halfWindow := maxMatchLen / 2
	timings := make([]RegexTiming, 0, len(atomCandidates))

	for regexIdx, ac := range atomCandidates {
		rp := r.regexPatterns[regexIdx]
		positions := dedupe(ac.positions)

		start := time.Now()
		calls := 0
		for _, pos := range positions {
			s := max(0, pos-halfWindow)
			e := min(len(buf), pos+halfWindow)
			rp.re.FindIndex(buf[s:e])
			calls++
		}
		dur := time.Since(start)

		matchedAtoms := make([]string, 0, len(ac.atoms))
		for atom := range ac.atoms {
			matchedAtoms = append(matchedAtoms, atom)
		}
		sort.Strings(matchedAtoms)

		var extractedAtoms []string
		if atoms, ok := extractAtoms(rp.re.String(), minAtomLength); ok {
			extractedAtoms = make([]string, len(atoms))
			for i, a := range atoms {
				extractedAtoms[i] = string(a)
			}
		}

		timings = append(timings, RegexTiming{
			Rule:           r.rules[rp.ruleIndex].name,
			String:         rp.stringName,
			Pattern:        rp.re.String(),
			MatchedAtoms:   matchedAtoms,
			ExtractedAtoms: extractedAtoms,
			Duration:       dur,
			Calls:          calls,
		})
	}

	sort.Slice(timings, func(i, j int) bool {
		return timings[i].Duration > timings[j].Duration
	})
	return timings
}
