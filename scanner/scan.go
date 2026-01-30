package scanner

import (
	"context"
	"time"
)

// ScanMem scans a byte buffer for matching rules.
func (r *Rules) ScanMem(buf []byte, flags ScanFlags, timeout time.Duration, cb ScanCallback) error {
	if r.matcher == nil || len(r.patterns) == 0 {
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
	iter := r.matcher.IterOverlappingByte(buf)
	for {
		match := iter.Next()
		if match == nil {
			break
		}
		patternIdx := match.Pattern()
		ref := r.patternMap[patternIdx]
		if ruleMatches[ref.ruleIndex] == nil {
			ruleMatches[ref.ruleIndex] = make(map[string]bool)
		}
		ruleMatches[ref.ruleIndex][ref.stringName] = true
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
