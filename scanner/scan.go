package scanner

import (
	"context"
	"sort"
	"time"
)

// maxMatchLen is the maximum window size for regex verification.
// Most YARA regex patterns match within a reasonable window.
const maxMatchLen = 512

// isWordChar returns true if b is alphanumeric or underscore (YARA word character).
func isWordChar(b byte) bool {
	return (b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') ||
		b == '_'
}

// checkWordBoundary returns true if the match at [start:end) has word boundaries.
func checkWordBoundary(buf []byte, start, end int) bool {
	if start > 0 && isWordChar(buf[start-1]) {
		return false
	}
	if end < len(buf) && isWordChar(buf[end]) {
		return false
	}
	return true
}

// dedupePositions removes duplicate positions and sorts them.
func dedupePositions(positions []int) []int {
	if len(positions) <= 1 {
		return positions
	}
	sort.Ints(positions)
	result := positions[:1]
	for i := 1; i < len(positions); i++ {
		if positions[i] != result[len(result)-1] {
			result = append(result, positions[i])
		}
	}
	return result
}

// ScanMem scans a byte buffer for matching rules.
func (r *Rules) ScanMem(buf []byte, flags ScanFlags, timeout time.Duration, cb ScanCallback) error {
	if (r.matcher == nil || len(r.patterns) == 0) && len(r.regexPatterns) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Check for timeout before starting
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Track which rules had matches and which strings matched per rule
	ruleMatches := make(map[int]map[string]bool)

	// Collect atom candidate positions for regex verification
	atomCandidates := make(map[int][]int) // regexIdx -> candidate start positions

	// Run Aho-Corasick matching using iterator (handles both literals and atoms)
	if r.matcher != nil {
		iter := r.matcher.IterOverlappingByte(buf)
		for {
			match := iter.Next()
			if match == nil {
				break
			}
			patternIdx := match.Pattern()
			ref := r.patternMap[patternIdx]

			if ref.isAtom {
				// Atom match - store position for regex verification
				atomCandidates[ref.regexIdx] = append(atomCandidates[ref.regexIdx], match.Start())
				continue
			}

			// Literal match - check word boundaries if required
			if ref.fullword && !checkWordBoundary(buf, match.Start(), match.End()) {
				continue
			}

			if ruleMatches[ref.ruleIndex] == nil {
				ruleMatches[ref.ruleIndex] = make(map[string]bool)
			}
			ruleMatches[ref.ruleIndex][ref.stringName] = true
		}
	}

	// Verify regexes at atom candidate positions
	halfWindow := maxMatchLen / 2
	for regexIdx, positions := range atomCandidates {
		rp := r.regexPatterns[regexIdx]
		positions = dedupePositions(positions)

		for _, atomPos := range positions {
			// Center the window around the atom position to capture
			// content both before and after the atom
			start := atomPos - halfWindow
			if start < 0 {
				start = 0
			}
			end := atomPos + halfWindow
			if end > len(buf) {
				end = len(buf)
			}
			window := buf[start:end]

			if rp.re.Match(window) {
				if ruleMatches[rp.ruleIndex] == nil {
					ruleMatches[rp.ruleIndex] = make(map[string]bool)
				}
				ruleMatches[rp.ruleIndex][rp.stringName] = true
				break // found a match, no need to check more positions
			}
		}
	}

	// Call callback for each matching rule
	for ruleIdx, matchedStrings := range ruleMatches {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		cr := r.rules[ruleIdx]

		// Build matched strings list
		strings := make([]MatchString, 0, len(matchedStrings))
		for name := range matchedStrings {
			strings = append(strings, MatchString{Name: name})
		}

		match := &MatchRule{
			Rule:    cr.name,
			Metas:   cr.metas,
			Strings: strings,
		}

		abort, err := cb.RuleMatching(match)
		if err != nil {
			return err
		}
		if abort {
			return nil
		}
	}

	return nil
}
