// Package scanner provides YARA rule scanning using Aho-Corasick algorithm.
package scanner

import (
	regexp "github.com/coregx/coregex"
	"github.com/sansecio/yargo/ahocorasick"

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
	Value      any
}

// MatchRule represents a rule that matched during scanning.
type MatchRule struct {
	Rule    string
	Metas   []Meta
	Strings []MatchString
}

// Meta returns the value of the meta field with the given identifier, or nil.
func (m *MatchRule) Meta(identifier string) any {
	for _, meta := range m.Metas {
		if meta.Identifier == identifier {
			return meta.Value
		}
	}
	return nil
}

// MetaString returns the string value of the meta field, or defValue if missing or not a string.
func (m *MatchRule) MetaString(identifier, defValue string) string {
	if val, ok := m.Meta(identifier).(string); ok {
		return val
	}
	return defValue
}

// Trust returns the confidence/trust level from rule metadata, defaulting to 100.
func (m *MatchRule) Trust() int32 {
	switch val := m.Meta("trust").(type) {
	case int:
		return int32(val)
	case int32:
		return val
	case int64:
		return int32(val)
	}
	return 100
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
}

// Stats returns compilation statistics.
func (r *Rules) Stats() (acPatterns, regexPatterns int) {
	return len(r.patterns), len(r.regexPatterns)
}

func (r *Rules) NumRules() int {
	return len(r.rules)
}
