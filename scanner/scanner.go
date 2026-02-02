// Package scanner provides YARA rule scanning using Aho-Corasick algorithm.
package scanner

import (
	ahocorasick "github.com/pgavlin/aho-corasick"
	regexp "github.com/wasilibs/go-re2"

	"github.com/sansecio/yargo/ast"
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
	Data []byte
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
	ruleIndex  int
	stringName string
	fullword   bool
	isAtom     bool
	regexIdx   int
}

// regexPattern holds a compiled regex for complex regex matching.
type regexPattern struct {
	re         *regexp.Regexp
	ruleIndex  int
	stringName string
	hasAtom    bool
}

// compiledRule holds the compiled form of a single YARA rule.
type compiledRule struct {
	name        string
	metas       []Meta
	condition   ast.Expr
	stringNames []string
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

// GetRules returns the compiled rules for iteration.
func (r *Rules) GetRules() []*compiledRule {
	return r.rules
}

// Stats returns compilation statistics.
func (r *Rules) Stats() (acPatterns, regexPatterns int) {
	return len(r.patterns), len(r.regexPatterns)
}
