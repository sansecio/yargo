package scanner

import (
	"context"
	"sort"
	"time"
)

const maxMatchLen = 1024

func isWordChar(b byte) bool {
	return (b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') ||
		b == '_'
}

func checkWordBoundary(buf []byte, start, end int) bool {
	if start > 0 && isWordChar(buf[start-1]) {
		return false
	}
	if end < len(buf) && isWordChar(buf[end]) {
		return false
	}
	return true
}

// ScanMem scans a byte buffer for matching rules.
func (r *Rules) ScanMem(buf []byte, flags ScanFlags, timeout time.Duration, cb ScanCallback) error {
	if r.matcher == nil && len(r.regexPatterns) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Track match positions per rule and string
	ruleMatches := make(map[int]map[string][]int)
	atomCandidates := make(map[int][]int)

	if r.matcher != nil {
		iter := r.matcher.IterOverlappingByte(buf)
		for match := iter.Next(); match != nil; match = iter.Next() {
			ref := r.patternMap[match.Pattern()]

			if ref.isAtom {
				atomCandidates[ref.regexIdx] = append(atomCandidates[ref.regexIdx], match.Start())
				continue
			}

			if ref.fullword && !checkWordBoundary(buf, match.Start(), match.End()) {
				continue
			}

			addMatchPos(ruleMatches, ref.ruleIndex, ref.stringName, match.Start())
		}
	}

	halfWindow := maxMatchLen / 2
	for regexIdx, positions := range atomCandidates {
		rp := r.regexPatterns[regexIdx]
		positions = dedupe(positions)

		for _, pos := range positions {
			start := max(0, pos-halfWindow)
			end := min(len(buf), pos+halfWindow)

			if loc := rp.re.FindIndex(buf[start:end]); loc != nil {
				addMatchPos(ruleMatches, rp.ruleIndex, rp.stringName, start+loc[0])
				break
			}
		}
	}

	for _, rp := range r.regexPatterns {
		if rp.hasAtom {
			continue
		}
		if loc := rp.re.FindIndex(buf); loc != nil {
			addMatchPos(ruleMatches, rp.ruleIndex, rp.stringName, loc[0])
		}
	}

	// Evaluate conditions for each rule with matches
	for ruleIdx, matchedStrings := range ruleMatches {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		cr := r.rules[ruleIdx]

		// Evaluate condition
		evalCtx := &evalContext{
			matches:     matchedStrings,
			buf:         buf,
			stringNames: cr.stringNames,
		}
		if !evalExpr(cr.condition, evalCtx) {
			continue
		}

		strings := make([]MatchString, 0, len(matchedStrings))
		for name := range matchedStrings {
			strings = append(strings, MatchString{Name: name})
		}

		abort, err := cb.RuleMatching(&MatchRule{
			Rule:    cr.name,
			Metas:   cr.metas,
			Strings: strings,
		})
		if err != nil {
			return err
		}
		if abort {
			return nil
		}
	}

	return nil
}

func addMatchPos(m map[int]map[string][]int, ruleIdx int, stringName string, pos int) {
	if m[ruleIdx] == nil {
		m[ruleIdx] = make(map[string][]int)
	}
	m[ruleIdx][stringName] = append(m[ruleIdx][stringName], pos)
}

func dedupe(positions []int) []int {
	if len(positions) <= 1 {
		return positions
	}
	sort.Ints(positions)
	j := 1
	for i := 1; i < len(positions); i++ {
		if positions[i] != positions[j-1] {
			positions[j] = positions[i]
			j++
		}
	}
	return positions[:j]
}
