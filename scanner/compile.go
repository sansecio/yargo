package scanner

import (
	"encoding/base64"
	"fmt"
	"strings"

	ahocorasick "github.com/pgavlin/aho-corasick"
	re2 "github.com/wasilibs/go-re2"

	"github.com/sansecio/yargo/ast"
)

// Compile compiles an AST RuleSet into Rules ready for scanning.
func Compile(rs *ast.RuleSet) (*Rules, error) {
	rules := &Rules{
		rules: make([]*compiledRule, 0, len(rs.Rules)),
	}

	var allPatterns [][]byte

	for ruleIdx, r := range rs.Rules {
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

		for strIdx, s := range r.Strings {
			patterns, forceFullword, isComplexRegex := generatePatterns(s)
			if isComplexRegex {
				// Complex regex - compile with go-re2
				v := s.Value.(ast.RegexString)
				rp, err := compileRegexPattern(v, ruleIdx, strIdx, s.Name)
				if err != nil {
					return nil, fmt.Errorf("rule %q string %s: %w", r.Name, s.Name, err)
				}
				rules.regexPatterns = append(rules.regexPatterns, rp)
				continue
			}
			for _, p := range patterns {
				rules.patternMap = append(rules.patternMap, patternRef{
					ruleIndex:   ruleIdx,
					stringIndex: strIdx,
					stringName:  s.Name,
					fullword:    s.Modifiers.Fullword || forceFullword,
				})
				allPatterns = append(allPatterns, p)
			}
		}
	}

	rules.patterns = allPatterns
	if len(allPatterns) > 0 {
		builder := ahocorasick.NewAhoCorasickBuilder(ahocorasick.Opts{})
		ac := builder.BuildByte(allPatterns)
		rules.matcher = &ac
	}

	return rules, nil
}

// generatePatterns generates byte patterns for a string definition.
// Returns patterns, whether fullword matching should be forced, and whether this is a complex regex.
// For TextString with base64 modifier, it generates 3 rotations.
// For RegexString with \bLITERAL\b pattern, extracts the literal.
// For complex RegexString patterns, returns isComplexRegex=true.
func generatePatterns(s *ast.StringDef) (patterns [][]byte, forceFullword bool, isComplexRegex bool) {
	switch v := s.Value.(type) {
	case ast.TextString:
		if s.Modifiers.Base64 {
			return generateBase64Patterns([]byte(v.Value)), false, false
		}
		return [][]byte{[]byte(v.Value)}, false, false

	case ast.RegexString:
		if literal, ok := extractWordBoundaryLiteral(v.Pattern); ok {
			return [][]byte{[]byte(literal)}, true, false
		}
		// Complex regex - signal to caller to compile it separately
		return nil, false, true

	default:
		return nil, false, false
	}
}

// extractWordBoundaryLiteral extracts the literal from a \bLITERAL\b regex pattern.
// Returns the unescaped literal and true if successful.
func extractWordBoundaryLiteral(pattern string) (string, bool) {
	if len(pattern) < 5 ||
		pattern[0] != '\\' || pattern[1] != 'b' ||
		pattern[len(pattern)-2] != '\\' || pattern[len(pattern)-1] != 'b' {
		return "", false
	}

	inner := pattern[2 : len(pattern)-2]
	if len(inner) == 0 {
		return "", false
	}

	// Unescape \. to .
	literal := strings.ReplaceAll(inner, `\.`, ".")
	return literal, true
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
