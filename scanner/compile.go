package scanner

import (
	"encoding/base64"

	ahocorasick "github.com/pgavlin/aho-corasick"
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
			patterns := generatePatterns(s)
			for _, p := range patterns {
				rules.patternMap = append(rules.patternMap, patternRef{
					ruleIndex:   ruleIdx,
					stringIndex: strIdx,
					stringName:  s.Name,
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
// For TextString with base64 modifier, it generates 3 rotations.
func generatePatterns(s *ast.StringDef) [][]byte {
	ts, ok := s.Value.(ast.TextString)
	if !ok {
		// Only TextString supported for now
		return nil
	}

	if s.Modifiers.Base64 {
		return generateBase64Patterns([]byte(ts.Value))
	}

	return [][]byte{[]byte(ts.Value)}
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
