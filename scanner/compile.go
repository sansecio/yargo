package scanner

import (
	"encoding/base64"
	"fmt"
	"strings"

	ahocorasick "github.com/pgavlin/aho-corasick"
	"github.com/wasilibs/go-re2/experimental"

	"github.com/sansecio/yargo/ast"
)

// CompileOptions configures compilation behavior.
type CompileOptions struct {
	SkipInvalidRegex bool
}

// Compile compiles an AST RuleSet into Rules ready for scanning.
func Compile(rs *ast.RuleSet) (*Rules, error) {
	return CompileWithOptions(rs, CompileOptions{})
}

// CompileWithOptions compiles an AST RuleSet with the given options.
func CompileWithOptions(rs *ast.RuleSet, opts CompileOptions) (*Rules, error) {
	rules := &Rules{
		rules: make([]*compiledRule, 0, len(rs.Rules)),
	}

	var allPatterns [][]byte
	ruleIdx := 0

	for _, r := range rs.Rules {
		if r.Condition != "any of them" {
			rules.warnings = append(rules.warnings,
				fmt.Sprintf("rule %q: skipping, unsupported condition %q (only \"any of them\" is supported)", r.Name, r.Condition))
			continue
		}

		cr := &compiledRule{
			name:  r.Name,
			metas: make([]Meta, len(r.Meta)),
		}
		for i, m := range r.Meta {
			cr.metas[i] = Meta{Identifier: m.Key, Value: m.Value}
		}
		rules.rules = append(rules.rules, cr)

		for _, s := range r.Strings {
			patterns, isRegex := generatePatterns(s)
			if isRegex {
				var err error
				allPatterns, err = compileRegex(rules, s, r.Name, ruleIdx, allPatterns, opts)
				if err != nil {
					return nil, err
				}
				continue
			}
			for _, p := range patterns {
				rules.patternMap = append(rules.patternMap, patternRef{
					ruleIndex:  ruleIdx,
					stringName: s.Name,
					fullword:   s.Modifiers.Fullword,
				})
				allPatterns = append(allPatterns, p)
			}
		}
		ruleIdx++
	}

	rules.patterns = allPatterns
	if len(allPatterns) > 0 {
		builder := ahocorasick.NewAhoCorasickBuilder(ahocorasick.Opts{DFA: false})
		ac := builder.BuildByte(allPatterns)
		rules.matcher = &ac
	}

	return rules, nil
}

func compileRegex(rules *Rules, s *ast.StringDef, ruleName string, ruleIdx int, allPatterns [][]byte, opts CompileOptions) ([][]byte, error) {
	v, ok := s.Value.(ast.RegexString)
	if !ok {
		rules.warnings = append(rules.warnings,
			fmt.Sprintf("rule %q: skipping complex hex string", ruleName))
		return allPatterns, nil
	}

	rePattern := buildRE2Pattern(v.Pattern, v.Modifiers)
	compiled, err := experimental.CompileLatin1(rePattern)
	if err != nil {
		if opts.SkipInvalidRegex {
			return allPatterns, nil
		}
		return nil, fmt.Errorf("rule %q string %s: invalid regex: %w", ruleName, s.Name, err)
	}

	rp := &regexPattern{
		re:         compiled,
		ruleIndex:  ruleIdx,
		stringName: s.Name,
	}
	regexIdx := len(rules.regexPatterns)
	rules.regexPatterns = append(rules.regexPatterns, rp)

	atoms, hasAtoms := extractAtoms(rePattern, 3)
	if hasAtoms && !v.Modifiers.CaseInsensitive {
		rp.hasAtom = true
		for _, atom := range atoms {
			rules.patternMap = append(rules.patternMap, patternRef{
				isAtom:   true,
				regexIdx: regexIdx,
			})
			allPatterns = append(allPatterns, atom)
		}
	} else {
		rules.warnings = append(rules.warnings,
			fmt.Sprintf("rule %q: regex requires full buffer scan", ruleName))
	}
	return allPatterns, nil
}

func generatePatterns(s *ast.StringDef) ([][]byte, bool) {
	switch v := s.Value.(type) {
	case ast.TextString:
		if s.Modifiers.Base64 {
			return generateBase64Patterns([]byte(v.Value)), false
		}
		return [][]byte{[]byte(v.Value)}, false
	case ast.RegexString:
		return nil, true
	case ast.HexString:
		if isSimpleHexString(v) {
			return [][]byte{hexStringToBytes(v)}, false
		}
		return nil, true
	default:
		return nil, false
	}
}

func isSimpleHexString(h ast.HexString) bool {
	for _, t := range h.Tokens {
		if _, ok := t.(ast.HexByte); !ok {
			return false
		}
	}
	return true
}

func hexStringToBytes(h ast.HexString) []byte {
	result := make([]byte, 0, len(h.Tokens))
	for _, t := range h.Tokens {
		if b, ok := t.(ast.HexByte); ok {
			result = append(result, b.Value)
		}
	}
	return result
}

func generateBase64Patterns(data []byte) [][]byte {
	patterns := make([][]byte, 0, 3)

	// Offset 0: full encoding, trim trailing context-dependent char if needed
	enc0 := base64.StdEncoding.EncodeToString(data)
	enc0 = strings.TrimRight(enc0, "=")
	if trim := trailingUnstableChars(len(data)); trim > 0 && len(enc0) > trim {
		enc0 = enc0[:len(enc0)-trim]
	}
	if len(enc0) > 0 {
		patterns = append(patterns, []byte(enc0))
	}

	// Offset 1: skip first 2 chars (depend on prefix), trim trailing unstable
	padded1 := append([]byte{0}, data...)
	if enc := base64.StdEncoding.EncodeToString(padded1); len(enc) > 2 {
		trimmed := strings.TrimRight(enc[2:], "=")
		if trim := trailingUnstableChars(len(data) + 1); trim > 0 && len(trimmed) > trim {
			trimmed = trimmed[:len(trimmed)-trim]
		}
		if len(trimmed) > 0 {
			patterns = append(patterns, []byte(trimmed))
		}
	}

	// Offset 2: skip first 3 chars (depend on prefix), trim trailing unstable
	padded2 := append([]byte{0, 0}, data...)
	if enc := base64.StdEncoding.EncodeToString(padded2); len(enc) > 3 {
		trimmed := strings.TrimRight(enc[3:], "=")
		if trim := trailingUnstableChars(len(data) + 2); trim > 0 && len(trimmed) > trim {
			trimmed = trimmed[:len(trimmed)-trim]
		}
		if len(trimmed) > 0 {
			patterns = append(patterns, []byte(trimmed))
		}
	}

	return patterns
}

// trailingUnstableChars returns how many trailing base64 chars depend on
// what follows the data. When data length isn't a multiple of 3, the final
// base64 chars encode partial bytes that include bits from following data.
func trailingUnstableChars(dataLen int) int {
	switch dataLen % 3 {
	case 1:
		return 1 // last char encodes 2 bits of data + 4 bits of next byte
	case 2:
		return 1 // last char encodes 4 bits of data + 2 bits of next byte
	default:
		return 0 // complete 3-byte groups, fully stable
	}
}

func buildRE2Pattern(pattern string, mods ast.RegexModifiers) string {
	var prefix string
	if mods.CaseInsensitive {
		prefix = "(?i)"
	}
	if mods.DotMatchesAll {
		prefix += "(?s)"
	}
	if mods.Multiline {
		prefix += "(?m)"
	}
	return prefix + fixQuantifiers(pattern)
}

const maxRepetition = 1000

// isValidQuantifier checks if inner looks like a valid regex quantifier:
// digits, digits+comma, digits+comma+digits, or comma+digits.
func isValidQuantifier(inner string) bool {
	if inner == "" {
		return false
	}

	i := 0

	// Case 1: starts with comma (for {,N} syntax)
	if inner[i] == ',' {
		i++
		// Must have at least one digit after comma
		if i >= len(inner) || inner[i] < '0' || inner[i] > '9' {
			return false
		}
		// Consume remaining digits
		for i < len(inner) && inner[i] >= '0' && inner[i] <= '9' {
			i++
		}
		return i >= len(inner) // Must have consumed everything
	}

	// Case 2: starts with digits
	if inner[i] < '0' || inner[i] > '9' {
		return false
	}
	for i < len(inner) && inner[i] >= '0' && inner[i] <= '9' {
		i++
	}

	// If we've consumed everything, it's valid (e.g., "5")
	if i >= len(inner) {
		return true
	}

	// Next must be comma
	if inner[i] != ',' {
		return false
	}
	i++

	// Rest must be digits or empty (e.g., "5," or "5,10")
	for i < len(inner) {
		if inner[i] < '0' || inner[i] > '9' {
			return false
		}
		i++
	}

	return true
}

func fixQuantifiers(pattern string) string {
	var result strings.Builder
	result.Grow(len(pattern))

	i := 0
	for i < len(pattern) {
		if pattern[i] == '\\' && i+1 < len(pattern) {
			result.WriteByte(pattern[i])
			result.WriteByte(pattern[i+1])
			i += 2
			continue
		}

		if pattern[i] == '{' {
			end := strings.IndexByte(pattern[i:], '}')
			if end == -1 {
				result.WriteByte(pattern[i])
				i++
				continue
			}
			end += i

			inner := pattern[i+1 : end]

			// Only process if this looks like a valid quantifier
			if !isValidQuantifier(inner) {
				// Not a quantifier, write literal brace and continue
				result.WriteByte(pattern[i])
				i++
				continue
			}

			fixed := fixRepetition(inner)
			result.WriteByte('{')
			result.WriteString(fixed)
			result.WriteByte('}')

			i = end + 1
			if i < len(pattern) && pattern[i] == '?' {
				result.WriteByte('?')
				i++
			}
			continue
		}

		result.WriteByte(pattern[i])
		i++
	}

	return result.String()
}

func fixRepetition(inner string) string {
	if strings.HasPrefix(inner, ",") {
		inner = "0" + inner
	}

	commaIdx := strings.IndexByte(inner, ',')
	if commaIdx == -1 {
		n := parseIntCapped(inner)
		return fmt.Sprintf("%d", n)
	}

	minStr := inner[:commaIdx]
	maxStr := inner[commaIdx+1:]

	minVal := parseIntCapped(minStr)

	if maxStr == "" {
		return fmt.Sprintf("%d,", minVal)
	}

	maxVal := parseIntCapped(maxStr)
	return fmt.Sprintf("%d,%d", minVal, maxVal)
}

func parseIntCapped(s string) int {
	if s == "" {
		return 0
	}
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
		if n > maxRepetition {
			return maxRepetition
		}
	}
	return n
}
