package scanner

import (
	"encoding/base64"
	"fmt"

	ahocorasick "github.com/pgavlin/aho-corasick"
	re2 "github.com/wasilibs/go-re2"

	"github.com/sansecio/yargo/ast"
)

// CompileOptions configures compilation behavior.
type CompileOptions struct {
	// SkipInvalidRegex skips regexes that fail to compile instead of returning an error.
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

	// Track actual rule index (after skipping unsupported conditions)
	actualRuleIdx := 0

	for _, r := range rs.Rules {
		// Skip rules with unsupported conditions
		if r.Condition != "any of them" {
			rules.warnings = append(rules.warnings,
				fmt.Sprintf("rule %q: skipping, unsupported condition %q (only \"any of them\" is supported)",
					r.Name, r.Condition))
			continue
		}

		cr := &compiledRule{
			name:  r.Name,
			metas: make([]Meta, 0, len(r.Meta)),
		}

		for _, m := range r.Meta {
			cr.metas = append(cr.metas, Meta{
				Identifier: m.Key,
				Value:      m.Value,
			})
		}

		rules.rules = append(rules.rules, cr)
		ruleIdx := actualRuleIdx
		actualRuleIdx++

		for strIdx, s := range r.Strings {
			patterns, isComplexRegex := generatePatterns(s)
			if isComplexRegex {
				// Complex regex - compile with go-re2
				v := s.Value.(ast.RegexString)
				rp, err := compileRegexPattern(v, ruleIdx, strIdx, s.Name)
				if err != nil {
					if opts.SkipInvalidRegex {
						continue
					}
					return nil, fmt.Errorf("rule %q string %s: %w", r.Name, s.Name, err)
				}

				regexIdx := len(rules.regexPatterns)
				rules.regexPatterns = append(rules.regexPatterns, rp)

				// Extract atoms from regex pattern for acceleration
				// Skip atom extraction for case-insensitive patterns since AC is case-sensitive
				atoms, hasAtoms := ExtractAtoms(v.Pattern, 3)
				if hasAtoms && !v.Modifiers.CaseInsensitive {
					rp.hasAtom = true
					for _, atom := range atoms {
						rules.patternMap = append(rules.patternMap, patternRef{
							isAtom:   true,
							regexIdx: regexIdx,
						})
						allPatterns = append(allPatterns, atom.Bytes)
					}
				}
				// Regexes without atoms will be scanned against the full buffer
				continue
			}
			for _, p := range patterns {
				rules.patternMap = append(rules.patternMap, patternRef{
					ruleIndex:   ruleIdx,
					stringIndex: strIdx,
					stringName:  s.Name,
					fullword:    s.Modifiers.Fullword,
				})
				allPatterns = append(allPatterns, p)
			}
		}
	}

	rules.patterns = allPatterns
	if len(allPatterns) > 0 {
		builder := ahocorasick.NewAhoCorasickBuilder(ahocorasick.Opts{DFA: true})
		ac := builder.BuildByte(allPatterns)
		rules.matcher = &ac
	}

	return rules, nil
}

// generatePatterns generates byte patterns for a string definition.
// Returns patterns and whether this is a complex regex.
// For TextString with base64 modifier, it generates 3 rotations.
// For RegexString patterns, returns isComplexRegex=true.
func generatePatterns(s *ast.StringDef) (patterns [][]byte, isComplexRegex bool) {
	switch v := s.Value.(type) {
	case ast.TextString:
		if s.Modifiers.Base64 {
			return generateBase64Patterns([]byte(v.Value)), false
		}
		return [][]byte{[]byte(v.Value)}, false

	case ast.RegexString:
		_ = v // unused, but type switch needs it
		return nil, true

	default:
		return nil, false
	}
}

// generateBase64Patterns generates 3 base64 patterns to handle all alignments.
// YARA's base64 modifier works by generating patterns for each possible
// alignment of the original string within base64 encoding boundaries.
func generateBase64Patterns(data []byte) [][]byte {
	patterns := make([][]byte, 0, 3)

	// Rotation 0: string at position 0 mod 3
	// Simply base64 encode the string
	enc0 := base64.StdEncoding.EncodeToString(data)
	patterns = append(patterns, []byte(enc0))

	// Rotation 1: string at position 1 mod 3
	// Prepend one byte, encode, then skip first 2 characters
	padded1 := append([]byte{0}, data...)
	enc1 := base64.StdEncoding.EncodeToString(padded1)
	if len(enc1) > 2 {
		// Remove padding characters from the end too
		trimmed := trimBase64Padding(enc1[2:])
		if len(trimmed) > 0 {
			patterns = append(patterns, []byte(trimmed))
		}
	}

	// Rotation 2: string at position 2 mod 3
	// Prepend two bytes, encode, then skip first 4 characters
	padded2 := append([]byte{0, 0}, data...)
	enc2 := base64.StdEncoding.EncodeToString(padded2)
	if len(enc2) > 4 {
		trimmed := trimBase64Padding(enc2[4:])
		if len(trimmed) > 0 {
			patterns = append(patterns, []byte(trimmed))
		}
	}

	return patterns
}

// trimBase64Padding removes trailing = padding from a base64 string.
func trimBase64Padding(s string) string {
	for len(s) > 0 && s[len(s)-1] == '=' {
		s = s[:len(s)-1]
	}
	return s
}

// compileRegexPattern compiles a complex regex pattern using go-re2.
func compileRegexPattern(v ast.RegexString, ruleIdx, strIdx int, name string) (*regexPattern, error) {
	pattern := buildRE2Pattern(v.Pattern, v.Modifiers)
	compiled, err := re2.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex: %w", err)
	}
	return &regexPattern{
		re:          compiled,
		ruleIndex:   ruleIdx,
		stringIndex: strIdx,
		stringName:  name,
	}, nil
}

// buildRE2Pattern builds a RE2 pattern string with modifier flags.
func buildRE2Pattern(pattern string, mods ast.RegexModifiers) string {
	var prefix string
	if mods.CaseInsensitive {
		prefix += "(?i)"
	}
	if mods.DotMatchesAll {
		prefix += "(?s)"
	}
	if mods.Multiline {
		prefix += "(?m)"
	}
	return prefix + pattern
}
