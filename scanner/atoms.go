package scanner

import (
	"strconv"
)

// Atom represents a literal extracted from a regex pattern.
type Atom struct {
	Bytes  []byte
	Offset int // Position in regex where atom starts (approximate)
}

// extractAtoms parses a regex and extracts literal atoms for matching.
// For alternation patterns (a|b|c), returns atoms from all branches.
// For sequential patterns, returns the single best atom.
// Returns the atoms and whether any were found meeting minLen.
func extractAtoms(pattern string, minLen int) ([]Atom, bool) {
	// Check if this is a top-level alternation (e.g., "cat|dog|bird")
	if isTopLevelAlternation(pattern) {
		return extractAlternationAtoms(pattern, minLen)
	}

	runs := extractLiteralRuns(pattern)
	if len(runs) == 0 {
		return nil, false
	}

	// Find the best atom (highest quality)
	var best literalRun
	bestQuality := -1
	for _, run := range runs {
		if len(run.bytes) < minLen {
			continue
		}
		q := atomQuality(run.bytes)
		if q > bestQuality {
			bestQuality = q
			best = run
		}
	}

	if bestQuality < 0 {
		return nil, false
	}

	return []Atom{{Bytes: best.bytes, Offset: best.offset}}, true
}

// isTopLevelAlternation checks if the pattern has alternation at the top level.
func isTopLevelAlternation(pattern string) bool {
	depth := 0
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch c {
		case '\\':
			i++ // skip next char
		case '(':
			depth++
		case ')':
			depth--
		case '|':
			if depth == 0 {
				return true
			}
		}
	}
	return false
}

// extractAlternationAtoms extracts atoms from each branch of a top-level alternation.
func extractAlternationAtoms(pattern string, minLen int) ([]Atom, bool) {
	branches := splitTopLevelAlternation(pattern)
	var atoms []Atom

	for _, branch := range branches {
		runs := extractLiteralRuns(branch)
		// Find the best atom in this branch
		var best literalRun
		bestQuality := -1
		for _, run := range runs {
			if len(run.bytes) < minLen {
				continue
			}
			q := atomQuality(run.bytes)
			if q > bestQuality {
				bestQuality = q
				best = run
			}
		}
		if bestQuality >= 0 {
			atoms = append(atoms, Atom{Bytes: best.bytes, Offset: best.offset})
		}
	}

	if len(atoms) == 0 {
		return nil, false
	}
	return atoms, true
}

// splitTopLevelAlternation splits a pattern by top-level | characters.
func splitTopLevelAlternation(pattern string) []string {
	var branches []string
	depth := 0
	start := 0

	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch c {
		case '\\':
			i++ // skip next char
		case '(':
			depth++
		case ')':
			depth--
		case '|':
			if depth == 0 {
				branches = append(branches, pattern[start:i])
				start = i + 1
			}
		}
	}
	branches = append(branches, pattern[start:])
	return branches
}

// literalRun represents a contiguous run of literal bytes in a regex.
type literalRun struct {
	bytes  []byte
	offset int
}

// extractLiteralRuns walks a regex pattern and extracts all literal runs.
func extractLiteralRuns(pattern string) []literalRun {
	var runs []literalRun
	var current []byte
	currentOffset := 0

	i := 0
	for i < len(pattern) {
		c := pattern[i]

		switch c {
		case '\\':
			// Escape sequence
			if i+1 >= len(pattern) {
				// Trailing backslash, treat as literal
				current = append(current, c)
				i++
				continue
			}

			next := pattern[i+1]
			switch next {
			case 'x':
				// Hex escape: \xNN
				if i+3 < len(pattern) {
					hexStr := pattern[i+2 : i+4]
					if b, err := strconv.ParseUint(hexStr, 16, 8); err == nil {
						current = append(current, byte(b))
						i += 4
						continue
					}
				}
				// Invalid hex, break the run
				runs = appendRun(runs, current, currentOffset)
				current = nil
				i += 2

			case 'd', 'D', 'w', 'W', 's', 'S':
				// Character classes - break the run
				runs = appendRun(runs, current, currentOffset)
				current = nil
				currentOffset = i + 2
				i += 2

			case 'b', 'B':
				// Word boundary - doesn't consume characters, skip it
				i += 2

			case 'n':
				current = append(current, '\n')
				i += 2

			case 'r':
				current = append(current, '\r')
				i += 2

			case 't':
				current = append(current, '\t')
				i += 2

			case '0':
				current = append(current, 0)
				i += 2

			case '.', '*', '+', '?', '[', ']', '(', ')', '{', '}', '|', '^', '$', '\\':
				// Escaped metacharacter - literal
				current = append(current, next)
				i += 2

			default:
				// Unknown escape, treat as literal
				current = append(current, next)
				i += 2
			}

		case '[':
			// Character class - break the run and skip to ]
			runs = appendRun(runs, current, currentOffset)
			current = nil
			i = skipCharClass(pattern, i)
			currentOffset = i

		case '(':
			// Group start - check for special syntax
			runs = appendRun(runs, current, currentOffset)
			current = nil
			if i+1 < len(pattern) && pattern[i+1] == '?' {
				// Non-capturing or flag group
				i = skipGroupPrefix(pattern, i)
			} else {
				i++
			}
			currentOffset = i

		case ')':
			// Group end - break the run
			runs = appendRun(runs, current, currentOffset)
			current = nil
			i++
			currentOffset = i

		case '|':
			// Alternation - break the run
			runs = appendRun(runs, current, currentOffset)
			current = nil
			i++
			currentOffset = i

		case '*', '+', '?':
			// Quantifier - the previous char is optional/repeated
			// Remove the last byte from current run if any
			if len(current) > 0 {
				current = current[:len(current)-1]
			}
			runs = appendRun(runs, current, currentOffset)
			current = nil
			i++
			currentOffset = i

		case '{':
			// Curly brace quantifier {n} or {n,m}
			// Remove the last byte from current run
			if len(current) > 0 {
				current = current[:len(current)-1]
			}
			runs = appendRun(runs, current, currentOffset)
			current = nil
			i = skipQuantifier(pattern, i)
			currentOffset = i

		case '.':
			// Dot matches any character - break the run
			runs = appendRun(runs, current, currentOffset)
			current = nil
			i++
			currentOffset = i

		case '^', '$':
			// Anchors - don't contribute bytes, just skip
			i++

		default:
			// Regular character
			if current == nil {
				currentOffset = i
			}
			current = append(current, c)
			i++
		}
	}

	// Add final run if any
	runs = appendRun(runs, current, currentOffset)

	return runs
}

// appendRun adds a run to the list if it's non-empty.
func appendRun(runs []literalRun, bytes []byte, offset int) []literalRun {
	if len(bytes) > 0 {
		return append(runs, literalRun{bytes: bytes, offset: offset})
	}
	return runs
}

// skipCharClass skips from '[' to the matching ']'.
func skipCharClass(pattern string, i int) int {
	i++ // skip '['
	if i < len(pattern) && pattern[i] == '^' {
		i++ // skip negation
	}
	if i < len(pattern) && pattern[i] == ']' {
		i++ // literal ] at start
	}
	for i < len(pattern) {
		if pattern[i] == '\\' && i+1 < len(pattern) {
			i += 2 // skip escape
		} else if pattern[i] == ']' {
			i++ // skip closing ]
			break
		} else {
			i++
		}
	}
	return i
}

// skipGroupPrefix skips (?...) non-capturing or flag groups.
func skipGroupPrefix(pattern string, i int) int {
	i += 2 // skip '(?'
	for i < len(pattern) {
		c := pattern[i]
		if c == ':' || c == ')' {
			i++
			break
		}
		if c >= 'a' && c <= 'z' {
			i++ // flag character
			continue
		}
		break
	}
	return i
}

// skipQuantifier skips {n} or {n,m} quantifiers.
func skipQuantifier(pattern string, i int) int {
	i++ // skip '{'
	for i < len(pattern) && pattern[i] != '}' {
		i++
	}
	if i < len(pattern) {
		i++ // skip '}'
	}
	return i
}

// atomQuality scores an atom - longer + uncommon bytes = better.
// YARA-style: common bytes like 0x00, 0x20, 0xFF score low.
func atomQuality(atom []byte) int {
	if len(atom) == 0 {
		return 0
	}

	score := 0
	for _, b := range atom {
		score += byteQuality(b)
	}

	// Bonus for length
	score += len(atom) * 10

	return score
}

// byteQuality returns a quality score for a single byte.
// Common bytes score low, uncommon bytes score high.
func byteQuality(b byte) int {
	switch {
	case b == 0x00:
		return 1
	case b == 0xFF:
		return 1
	case b == 0x20: // space
		return 2
	case b == 0x09 || b == 0x0A || b == 0x0D: // tab, newline, carriage return
		return 2
	case b >= 'a' && b <= 'z':
		return 8
	case b >= 'A' && b <= 'Z':
		return 8
	case b >= '0' && b <= '9':
		return 6
	case b == '_' || b == '-':
		return 5
	case b >= 0x21 && b <= 0x7E: // other printable ASCII
		return 7
	default:
		return 4 // other bytes
	}
}
