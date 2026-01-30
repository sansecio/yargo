package scanner

import (
	"encoding/base64"
	"fmt"
	"strings"

	ahocorasick "github.com/pgavlin/aho-corasick"
	re2 "github.com/wasilibs/go-re2"

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
	compiled, err := re2.Compile(rePattern)
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

	patterns = append(patterns, []byte(base64.StdEncoding.EncodeToString(data)))

	padded1 := append([]byte{0}, data...)
	if enc := base64.StdEncoding.EncodeToString(padded1); len(enc) > 2 {
		if trimmed := strings.TrimRight(enc[2:], "="); len(trimmed) > 0 {
			patterns = append(patterns, []byte(trimmed))
		}
	}

	padded2 := append([]byte{0, 0}, data...)
	if enc := base64.StdEncoding.EncodeToString(padded2); len(enc) > 3 {
		if trimmed := strings.TrimRight(enc[3:], "="); len(trimmed) > 0 {
			patterns = append(patterns, []byte(trimmed))
		}
	}

	return patterns
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

func fixQuantifiers(pattern string) string {
	if !strings.Contains(pattern, "{,") {
		return pattern
	}
	return strings.ReplaceAll(pattern, "{,", "{0,")
}
