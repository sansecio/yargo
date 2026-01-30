package scanner

import (
	"strconv"
)

// extractAtoms parses a regex and extracts literal atoms for matching.
// For alternation patterns (a|b|c), returns atoms from all branches.
// For sequential patterns, returns the single best atom.
// Returns the atoms and whether any were found meeting minLen.
func extractAtoms(pattern string, minLen int) ([][]byte, bool) {
	if isTopLevelAlternation(pattern) {
		return extractAlternationAtoms(pattern, minLen)
	}

	runs := extractLiteralRuns(pattern)
	best := findBestRun(runs, minLen)
	if best == nil {
		return nil, false
	}
	return [][]byte{best}, true
}

// findBestRun returns the highest quality run meeting minLen, or nil if none qualify.
func findBestRun(runs [][]byte, minLen int) []byte {
	var best []byte
	bestQuality := -1
	for _, run := range runs {
		if len(run) < minLen {
			continue
		}
		if q := atomQuality(run); q > bestQuality {
			bestQuality = q
			best = run
		}
	}
	return best
}

// isTopLevelAlternation checks if the pattern has alternation at the top level.
func isTopLevelAlternation(pattern string) bool {
	depth := 0
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '\\':
			i++
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
func extractAlternationAtoms(pattern string, minLen int) ([][]byte, bool) {
	var atoms [][]byte
	for _, branch := range splitTopLevelAlternation(pattern) {
		if best := findBestRun(extractLiteralRuns(branch), minLen); best != nil {
			atoms = append(atoms, best)
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
	depth, start := 0, 0

	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '\\':
			i++
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
	return append(branches, pattern[start:])
}

// extractLiteralRuns walks a regex pattern and extracts all literal byte runs.
func extractLiteralRuns(pattern string) [][]byte {
	var runs [][]byte
	var current []byte

	for i := 0; i < len(pattern); {
		c := pattern[i]

		switch c {
		case '\\':
			if i+1 >= len(pattern) {
				current = append(current, c)
				i++
				continue
			}
			next := pattern[i+1]
			switch next {
			case 'x':
				if i+3 < len(pattern) {
					if b, err := strconv.ParseUint(pattern[i+2:i+4], 16, 8); err == nil {
						current = append(current, byte(b))
						i += 4
						continue
					}
				}
				runs, current = appendRun(runs, current)
				i += 2
			case 'd', 'D', 'w', 'W', 's', 'S':
				runs, current = appendRun(runs, current)
				i += 2
			case 'b', 'B':
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
				current = append(current, next)
				i += 2
			default:
				current = append(current, next)
				i += 2
			}

		case '[':
			runs, current = appendRun(runs, current)
			i = skipCharClass(pattern, i)

		case '(':
			runs, current = appendRun(runs, current)
			if i+1 < len(pattern) && pattern[i+1] == '?' {
				i = skipGroupPrefix(pattern, i)
			} else {
				i++
			}

		case ')', '|':
			runs, current = appendRun(runs, current)
			i++

		case '*', '+', '?':
			if len(current) > 0 {
				current = current[:len(current)-1]
			}
			runs, current = appendRun(runs, current)
			i++

		case '{':
			if isQuantifier(pattern, i) {
				if len(current) > 0 {
					current = current[:len(current)-1]
				}
				runs, current = appendRun(runs, current)
				i = skipQuantifier(pattern, i)
			} else {
				current = append(current, c)
				i++
			}

		case '.':
			runs, current = appendRun(runs, current)
			i++

		case '^', '$':
			i++

		default:
			current = append(current, c)
			i++
		}
	}

	runs, _ = appendRun(runs, current)
	return runs
}

func appendRun(runs [][]byte, current []byte) ([][]byte, []byte) {
	if len(current) > 0 {
		return append(runs, current), nil
	}
	return runs, nil
}

func skipCharClass(pattern string, i int) int {
	i++
	if i < len(pattern) && pattern[i] == '^' {
		i++
	}
	if i < len(pattern) && pattern[i] == ']' {
		i++
	}
	for i < len(pattern) {
		if pattern[i] == '\\' && i+1 < len(pattern) {
			i += 2
		} else if pattern[i] == ']' {
			return i + 1
		} else {
			i++
		}
	}
	return i
}

func skipGroupPrefix(pattern string, i int) int {
	i += 2
	for i < len(pattern) {
		c := pattern[i]
		if c == ':' || c == ')' {
			return i + 1
		}
		if c < 'a' || c > 'z' {
			break
		}
		i++
	}
	return i
}

func skipQuantifier(pattern string, i int) int {
	for i++; i < len(pattern) && pattern[i] != '}'; i++ {
	}
	if i < len(pattern) {
		i++
	}
	return i
}

func isQuantifier(pattern string, i int) bool {
	if i >= len(pattern) || pattern[i] != '{' {
		return false
	}
	i++
	if i >= len(pattern) || pattern[i] < '0' || pattern[i] > '9' {
		return false
	}
	for i < len(pattern) && pattern[i] >= '0' && pattern[i] <= '9' {
		i++
	}
	if i >= len(pattern) {
		return false
	}
	if pattern[i] == '}' {
		return true
	}
	if pattern[i] != ',' {
		return false
	}
	for i++; i < len(pattern) && pattern[i] >= '0' && pattern[i] <= '9'; i++ {
	}
	return i < len(pattern) && pattern[i] == '}'
}

// atomQuality scores an atom - longer + uncommon bytes = better.
func atomQuality(atom []byte) int {
	score := len(atom) * 10
	for _, b := range atom {
		score += byteQuality(b)
	}
	return score
}

func byteQuality(b byte) int {
	switch {
	case b == 0x00, b == 0xFF:
		return 1
	case b == 0x20, b == 0x09, b == 0x0A, b == 0x0D:
		return 2
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z':
		return 8
	case b >= '0' && b <= '9':
		return 6
	case b == '_', b == '-':
		return 5
	case b >= 0x21 && b <= 0x7E:
		return 7
	default:
		return 4
	}
}
