package scanner

import (
	"sort"
	"time"
)

// RegexTiming holds the timing result for a single regex pattern.
type RegexTiming struct {
	Rule     string
	String   string
	Pattern  string
	Duration time.Duration
	Calls    int
}

// RegexProfile scans a buffer and returns per-regex timing information,
// sorted slowest first.
func (r *Rules) RegexProfile(buf []byte) []RegexTiming {
	atomCandidates := make(map[int][]int)

	if r.matcher != nil {
		iter := r.matcher.IterOverlappingByte(buf)
		for match := iter.Next(); match != nil; match = iter.Next() {
			ref := r.patternMap[match.Pattern()]
			if ref.isAtom {
				atomCandidates[ref.regexIdx] = append(atomCandidates[ref.regexIdx], match.Start())
			}
		}
	}

	halfWindow := maxMatchLen / 2
	timings := make([]RegexTiming, 0, len(atomCandidates))

	for regexIdx, positions := range atomCandidates {
		rp := r.regexPatterns[regexIdx]
		positions = dedupe(positions)

		start := time.Now()
		calls := 0
		for _, pos := range positions {
			s := max(0, pos-halfWindow)
			e := min(len(buf), pos+halfWindow)
			rp.re.FindIndex(buf[s:e])
			calls++
		}
		dur := time.Since(start)

		timings = append(timings, RegexTiming{
			Rule:     r.rules[rp.ruleIndex].name,
			String:   rp.stringName,
			Pattern:  rp.re.String(),
			Duration: dur,
			Calls:    calls,
		})
	}

	sort.Slice(timings, func(i, j int) bool {
		return timings[i].Duration > timings[j].Duration
	})
	return timings
}
