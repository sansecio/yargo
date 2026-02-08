package scanner

import (
	"bytes"
	"strconv"
)

// extractAtoms parses a regex and extracts literal atoms for matching.
// For alternation patterns (a|b|c), returns atoms from all branches.
// For patterns with nested alternations like "prefix(a|b|c)suffix", returns
// atoms from all branches of the alternation when they're the best choice.
// Returns the atoms and whether any were found meeting minLen.
func extractAtoms(pattern string, minLen int) ([][]byte, bool) {
	if isTopLevelAlternation(pattern) {
		return extractAlternationAtoms(pattern, minLen)
	}

	// Find all literal runs and check for nested alternations
	runs := extractLiteralRuns(pattern)
	altAtoms := extractNestedAlternationAtoms(pattern, minLen)

	// Find best atom from OUTSIDE alternation groups (the required literals)
	outsideRuns := extractLiteralRunsOutsideAlternations(pattern)
	bestOutside := findBestRun(outsideRuns, minLen)

	// If alternation atoms exist and are better than outside literals, use them
	// This handles "prefix(a|b|c)" where we need to match any branch
	if len(altAtoms) > 0 {
		bestAlt := findBestRun(altAtoms, minLen)
		if bestAlt != nil && (bestOutside == nil || atomQuality(bestAlt) > atomQuality(bestOutside)) {
			return altAtoms, true
		}
	}

	// Use the best outside literal if available
	if bestOutside != nil {
		return [][]byte{bestOutside}, true
	}

	// Fall back to best overall atom
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
		if isCommonToken(run) {
			continue
		}
		if q := atomQuality(run); q > bestQuality {
			bestQuality = q
			best = run
		}
	}
	return best
}

// commonTokens are tokens too prevalent in code to be useful as atoms.
var commonTokens = [][]byte{
	[]byte("return"),
	[]byte("function"),
	[]byte("var"),
	[]byte("();"),
	[]byte("="),
}

// isCommonToken returns true for atoms that, after trimming spaces, match
// a common token.
func isCommonToken(atom []byte) bool {
	trimmed := bytes.TrimSpace(atom)
	for _, kw := range commonTokens {
		if bytes.Equal(trimmed, kw) {
			return true
		}
	}
	return false
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

// extractNestedAlternationAtoms finds alternation groups within the pattern
// and extracts atoms from the best group only. For example, "prefix(a|b|c)suffix"
// would extract atoms from "a", "b", "c". When multiple alternation groups exist,
// only atoms from the group with the highest quality atoms are returned.
// Optional groups (followed by ?, *, {0,N}) are skipped.
func extractNestedAlternationAtoms(pattern string, minLen int) [][]byte {
	// Find all alternation groups (content between matching parens that contains |)
	groups := findAlternationGroups(pattern)
	if len(groups) == 0 {
		return nil
	}

	// Find optional groups to exclude
	optionalGroups := findOptionalGroups(pattern)
	isOptional := func(g altGroup) bool {
		for _, og := range optionalGroups {
			if g.start == og.start && g.end == og.end {
				return true
			}
		}
		return false
	}

	// For each group, collect atoms and find the best atom's quality
	type groupAtoms struct {
		atoms       [][]byte
		bestQuality int
	}
	var best *groupAtoms

	for _, g := range groups {
		if isOptional(g) {
			continue
		}
		var atoms [][]byte
		bestQuality := -1
		branches := splitAlternation(g.content)
		for _, branch := range branches {
			runs := extractLiteralRuns(branch)
			if atom := findBestRun(runs, minLen); atom != nil {
				atoms = append(atoms, atom)
				if q := atomQuality(atom); q > bestQuality {
					bestQuality = q
				}
			}
		}
		if len(atoms) == 0 {
			continue
		}
		if best == nil || bestQuality > best.bestQuality {
			best = &groupAtoms{atoms: atoms, bestQuality: bestQuality}
		}
	}

	if best == nil {
		return nil
	}
	return best.atoms
}

type altGroup struct {
	start, end int
	content    string
}

// findAlternationGroups finds parenthesized groups that contain alternation.
func findAlternationGroups(pattern string) []altGroup {
	var groups []altGroup
	var stack []int // stack of '(' positions

	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '\\':
			i++ // skip escaped char
		case '(':
			stack = append(stack, i)
		case ')':
			if len(stack) > 0 {
				start := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				content := pattern[start+1 : i]
				// Check if this group contains alternation at its level
				if containsAlternationAtDepth0(content) {
					groups = append(groups, altGroup{start, i, content})
				}
			}
		}
	}
	return groups
}

// containsAlternationAtDepth0 checks if the string has | at depth 0.
func containsAlternationAtDepth0(s string) bool {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
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

// splitAlternation splits a string by | at depth 0.
func splitAlternation(s string) []string {
	var parts []string
	depth, start := 0, 0

	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '(':
			depth++
		case ')':
			depth--
		case '|':
			if depth == 0 {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}
	return append(parts, s[start:])
}

// extractLiteralRunsOutsideAlternations extracts literals from parts of the
// pattern that are not inside alternation groups or optional groups.
// These are "required" literals that must appear in any match.
func extractLiteralRunsOutsideAlternations(pattern string) [][]byte {
	// Find groups to exclude: alternations and optional groups
	altGroups := findAlternationGroups(pattern)
	optGroups := findOptionalGroups(pattern)

	if len(altGroups) == 0 && len(optGroups) == 0 {
		return extractLiteralRuns(pattern)
	}

	// Build pattern with excluded groups replaced by dots to break literal runs
	modified := []byte(pattern)

	// Replace alternation groups
	for i := len(altGroups) - 1; i >= 0; i-- {
		g := altGroups[i]
		for j := g.start; j <= g.end && j < len(modified); j++ {
			modified[j] = '.'
		}
	}

	// Replace optional groups
	for i := len(optGroups) - 1; i >= 0; i-- {
		g := optGroups[i]
		for j := g.start; j <= g.end && j < len(modified); j++ {
			modified[j] = '.'
		}
	}

	return extractLiteralRuns(string(modified))
}

// findOptionalGroups finds parenthesized groups that are optional
// (followed by ?, *, or {0,N}).
func findOptionalGroups(pattern string) []altGroup {
	var groups []altGroup
	var stack []int // stack of '(' positions

	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '\\':
			i++ // skip escaped char
		case '(':
			stack = append(stack, i)
		case ')':
			if len(stack) > 0 {
				start := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				// Check if this group is followed by an optional quantifier
				if isOptionalQuantifier(pattern, i+1) {
					groups = append(groups, altGroup{start, i, pattern[start+1 : i]})
				}
			}
		}
	}
	return groups
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

// atomQuality scores an atom using YARA-inspired heuristics.
// Higher scores indicate more selective atoms (fewer false positives).
func atomQuality(atom []byte) int {
	if len(atom) == 0 {
		return 0
	}

	score := 0
	uniqueBytes := make(map[byte]struct{})
	allSame := true
	firstByte := atom[0]

	for _, b := range atom {
		score += byteQuality(b)
		uniqueBytes[b] = struct{}{}
		if b != firstByte {
			allSame = false
		}
	}

	// Unique byte diversity bonus: +2 per unique byte
	score += len(uniqueBytes) * 2

	// Heavy penalty for repeated common bytes (e.g. spaces, blank lines)
	if allSame && isCommonByte(firstByte) {
		score -= 10 * len(atom)
	}

	if score < 0 {
		return 0
	}
	return score
}

// byteQuality returns per-byte quality score using YARA's heuristic.
func byteQuality(b byte) int {
	// Common bytes (frequently appear, less selective)
	if isCommonByte(b) {
		return 12
	}
	// Alphabetic bytes (slightly penalized - common in text)
	if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') {
		return 18
	}
	// Normal bytes (most selective)
	return 20
}

// isCommonByte returns true for bytes that commonly appear in web files.
func isCommonByte(b byte) bool {
	switch b {
	case 0x20, 0x0A:
		return true
	}
	return false
}
