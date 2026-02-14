package scanner

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/sansecio/yargo/ahocorasick"
	"github.com/wasilibs/go-re2/experimental"

	"github.com/sansecio/yargo/ast"
)

// CompileOptions configures compilation behavior.
type CompileOptions struct {
	// SkipInvalidRegex silently skips regexes that are invalid or require
	// a full buffer scan, instead of returning an error.
	SkipInvalidRegex bool

	// SkipSubtypes filters out rules whose meta "subtype" field matches
	// any of the given values. Rules without a "subtype" meta or with an
	// empty subtype value are never filtered.
	SkipSubtypes []string
}

const (
	// minAtomLength is the minimum length of atoms extracted from regexes
	// for use in the Aho-Corasick matcher. 3 bytes gives 16M possible values
	// (255^3), making false positives rare while still allowing generic regexes.
	minAtomLength = 3
)

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
	var errs []error
	ruleIdx := 0

	skipSubtypes := make(map[string]bool, len(opts.SkipSubtypes))
	for _, t := range opts.SkipSubtypes {
		if t != "" {
			skipSubtypes[t] = true
		}
	}

	for _, r := range rs.Rules {
		if r.Condition == nil {
			continue
		}

		if len(skipSubtypes) > 0 {
			if subtype := metaValue(r, "subtype"); subtype != "" && skipSubtypes[subtype] {
				continue
			}
		}

		cr := &compiledRule{
			name:      r.Name,
			metas:     make([]Meta, len(r.Meta)),
			condition: r.Condition,
		}
		for i, m := range r.Meta {
			cr.metas[i] = Meta{Identifier: m.Key, Value: m.Value}
		}
		for _, s := range r.Strings {
			cr.stringNames = append(cr.stringNames, s.Name)
		}
		rules.rules = append(rules.rules, cr)

		for _, s := range r.Strings {
			patterns, isRegex := generatePatterns(s)
			if isRegex {
				var err error
				allPatterns, err = compileRegex(rules, s, r.Name, ruleIdx, allPatterns, opts)
				if err != nil {
					errs = append(errs, err)
				}
				continue
			}
			for _, p := range patterns {
				rules.patternMap = append(rules.patternMap, patternRef{
					ruleIndex:  ruleIdx,
					stringName: s.Name,
					fullword:   s.Modifiers.Fullword,
					regexIdx:   -1,
				})
				allPatterns = append(allPatterns, p)
			}
		}
		ruleIdx++
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	rules.patterns = allPatterns
	if len(allPatterns) > 0 {
		builder := ahocorasick.NewAhoCorasickBuilder()
		ac := builder.BuildByte(allPatterns)
		rules.matcher = &ac
	}

	return rules, nil
}

func compileRegex(rules *Rules, s *ast.StringDef, ruleName string, ruleIdx int, allPatterns [][]byte, opts CompileOptions) ([][]byte, error) {
	var rePattern string
	var caseInsensitive bool

	switch v := s.Value.(type) {
	case ast.RegexString:
		rePattern = buildRE2Pattern(v.Pattern, v.Modifiers)
		caseInsensitive = v.Modifiers.CaseInsensitive
	case ast.HexString:
		rePattern = "(?s)" + hexStringToRegex(v)
		caseInsensitive = false
	default:
		return allPatterns, nil
	}
	compiled, err := experimental.CompileLatin1(rePattern)
	if err != nil {
		if opts.SkipInvalidRegex {
			return allPatterns, nil
		}
		return nil, fmt.Errorf("rule %q string %s: invalid regex: %w", ruleName, s.Name, err)
	}

	atoms, hasAtoms := extractAtoms(rePattern, minAtomLength)
	requiresFullScan := !hasAtoms || caseInsensitive
	if requiresFullScan {
		if opts.SkipInvalidRegex {
			return allPatterns, nil
		}
		return nil, fmt.Errorf("rule %q string %s: regex requires full buffer scan", ruleName, s.Name)
	}

	rp := &regexPattern{
		re:         compiled,
		ruleIndex:  ruleIdx,
		stringName: s.Name,
	}
	regexIdx := len(rules.regexPatterns)
	rules.regexPatterns = append(rules.regexPatterns, rp)

	for _, atom := range atoms {
		rules.patternMap = append(rules.patternMap, patternRef{
			regexIdx: regexIdx,
		})
		allPatterns = append(allPatterns, atom)
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

func hexStringToRegex(h ast.HexString) string {
	var sb strings.Builder

	// Coalesce consecutive wildcards into a single .{n}
	i := 0
	for i < len(h.Tokens) {
		switch t := h.Tokens[i].(type) {
		case ast.HexByte:
			fmt.Fprintf(&sb, "\\x%02x", t.Value)
		case ast.HexWildcard:
			// Count consecutive wildcards
			count := 1
			for i+count < len(h.Tokens) {
				if _, ok := h.Tokens[i+count].(ast.HexWildcard); ok {
					count++
				} else {
					break
				}
			}
			if count == 1 {
				sb.WriteByte('.')
			} else {
				fmt.Fprintf(&sb, ".{%d}", count)
			}
			i += count - 1 // -1 because the loop will increment
		case ast.HexJump:
			writeJump(&sb, t)
		case ast.HexAlt:
			writeAlt(&sb, t)
		}
		i++
	}

	return sb.String()
}

func writeJump(sb *strings.Builder, j ast.HexJump) {
	switch {
	case j.Min == nil && j.Max == nil:
		sb.WriteString(".*")
	case j.Min != nil && j.Max != nil && *j.Min == *j.Max:
		fmt.Fprintf(sb, ".{%d}", *j.Min)
	case j.Min != nil && j.Max != nil:
		fmt.Fprintf(sb, ".{%d,%d}", *j.Min, *j.Max)
	case j.Min != nil:
		fmt.Fprintf(sb, ".{%d,}", *j.Min)
	case j.Max != nil:
		fmt.Fprintf(sb, ".{0,%d}", *j.Max)
	}
}

func writeAlt(sb *strings.Builder, a ast.HexAlt) {
	sb.WriteString("(?:")
	for i, item := range a.Alternatives {
		if i > 0 {
			sb.WriteByte('|')
		}
		if item.Wildcard {
			sb.WriteByte('.')
		} else if item.Byte != nil {
			fmt.Fprintf(sb, "\\x%02x", *item.Byte)
		}
	}
	sb.WriteByte(')')
}

func generateBase64Patterns(data []byte) [][]byte {
	// Each offset aligns data differently within the base64 3-byte groups.
	// The prefix padding bytes and the number of leading base64 chars to skip
	// (which depend on the unknown preceding context) vary per offset.
	offsets := [3]struct{ pad, skip int }{{0, 0}, {1, 2}, {2, 3}}
	patterns := make([][]byte, 0, 3)

	for _, o := range offsets {
		padded := append(make([]byte, o.pad), data...)
		enc := base64.StdEncoding.EncodeToString(padded)
		if len(enc) <= o.skip {
			continue
		}
		trimmed := strings.TrimRight(enc[o.skip:], "=")
		if trim := trailingUnstableChars(len(data) + o.pad); trim > 0 && len(trimmed) > trim {
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
	return prefix + fixCommaQuantifiers(pattern)
}

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

func metaValue(r *ast.Rule, key string) string {
	for _, m := range r.Meta {
		if m.Key == key {
			if s, ok := m.Value.(string); ok {
				return s
			}
			return ""
		}
	}
	return ""
}
