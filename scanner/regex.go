package scanner

import (
	"strconv"
	"strings"
)

// fixCommaQuantifiers rewrites {,N} to {0,N} because RE2 treats {,N}
// as literal text rather than a quantifier.
func fixCommaQuantifiers(pattern string) string {
	var b strings.Builder
	b.Grow(len(pattern))
	for i := 0; i < len(pattern); i++ {
		if pattern[i] == '\\' && i+1 < len(pattern) {
			b.WriteByte(pattern[i])
			b.WriteByte(pattern[i+1])
			i++
			continue
		}
		if pattern[i] == '{' && i+1 < len(pattern) && pattern[i+1] == ',' {
			b.WriteString("{0")
			continue
		}
		b.WriteByte(pattern[i])
	}
	return b.String()
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

		case '+':
			runs, current = appendRun(runs, current)
			i++

		case '*', '?':
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
	if i >= len(pattern) {
		return false
	}
	// Accept {,N} syntax (skip straight to comma handling)
	if pattern[i] == ',' {
		for i++; i < len(pattern) && pattern[i] >= '0' && pattern[i] <= '9'; i++ {
		}
		return i < len(pattern) && pattern[i] == '}'
	}
	if pattern[i] < '0' || pattern[i] > '9' {
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

// isOptionalQuantifier checks if position i starts an optional quantifier (?, *, {0,N}).
func isOptionalQuantifier(pattern string, i int) bool {
	if i >= len(pattern) {
		return false
	}
	switch pattern[i] {
	case '?', '*':
		return true
	case '{':
		// Check for {0 or {,N} patterns
		if i+1 < len(pattern) {
			if pattern[i+1] == '0' || pattern[i+1] == ',' {
				return true
			}
		}
	}
	return false
}
