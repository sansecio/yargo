// Package scanner provides YARA rule scanning using Aho-Corasick algorithm.
package scanner

import (
	ahocorasick "github.com/pgavlin/aho-corasick"
	re2 "github.com/wasilibs/go-re2"
)

// ScanFlags controls scanning behavior.
type ScanFlags int

// ScanCallback is the interface for receiving match notifications.
type ScanCallback interface {
	RuleMatching(r *MatchRule) (abort bool, err error)
}

// MatchString represents a matched string within a rule.
type MatchString struct {
	Name string
}

// Meta represents a metadata entry from a rule.
type Meta struct {
	Identifier string
	Value      interface{}
}

// MatchRule represents a rule that matched during scanning.
type MatchRule struct {
	Rule    string
	Metas   []Meta
	Strings []MatchString
}

// MatchRules collects matching rules and implements ScanCallback.
type MatchRules []MatchRule

// RuleMatching implements ScanCallback, collecting all matching rules.
func (m *MatchRules) RuleMatching(r *MatchRule) (abort bool, err error) {
	*m = append(*m, *r)
	return false, nil
}

// patternRef maps a pattern index back to its source rule and string.
type patternRef struct {
	ruleIndex   int
	stringIndex int
	stringName  string
	fullword    bool
}

// regexPattern holds a compiled regex for complex regex matching.
type regexPattern struct {
	re          *re2.Regexp
	ruleIndex   int
	stringIndex int
	stringName  string
}

// compiledRule holds the compiled form of a single YARA rule.
type compiledRule struct {
	name  string
	metas []Meta
}

// Rules holds compiled YARA rules ready for scanning.
type Rules struct {
	rules         []*compiledRule
	matcher       *ahocorasick.AhoCorasick
	patterns      [][]byte
	patternMap    []patternRef
	regexPatterns []*regexPattern
	warnings      []string
}

// Warnings returns any warnings generated during compilation.
func (r *Rules) Warnings() []string {
	return r.warnings
}
