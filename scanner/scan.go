package scanner

import (
	"context"
	"time"
)

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

	// Run Aho-Corasick matching using iterator
	if r.matcher != nil {
		iter := r.matcher.IterOverlappingByte(buf)
		for {
			match := iter.Next()
			if match == nil {
				break
			}
			patternIdx := match.Pattern()
			ref := r.patternMap[patternIdx]

			// Check word boundaries if required
			if ref.fullword && !checkWordBoundary(buf, match.Start(), match.End()) {
				continue
			}

			if ruleMatches[ref.ruleIndex] == nil {
				ruleMatches[ref.ruleIndex] = make(map[string]bool)
			}
			ruleMatches[ref.ruleIndex][ref.stringName] = true
		}
	}

	// Run regex pattern matching
	for _, rp := range r.regexPatterns {
		if rp.re.Match(buf) {
			if ruleMatches[rp.ruleIndex] == nil {
				ruleMatches[rp.ruleIndex] = make(map[string]bool)
			}
			ruleMatches[rp.ruleIndex][rp.stringName] = true
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
