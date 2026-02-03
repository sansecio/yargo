// Package parser provides a YARA rule parser using goyacc.
package parser

import (
	"fmt"
	"os"

	"github.com/sansecio/yargo/ast"
)

//go:generate goyacc -o y.go yara.y

// Parser parses YARA rules.
type Parser struct{}

// New creates a new YARA parser.
func New() *Parser {
	return &Parser{}
}

// Parse parses YARA rules from a string.
func (p *Parser) Parse(input string) (*ast.RuleSet, error) {
	l := newLexer(input)
	yyParse(l)
	if l.err != "" {
		return nil, fmt.Errorf("parse error: %s", l.err)
	}
	if l.ruleSet == nil {
		return &ast.RuleSet{}, nil
	}
	return l.ruleSet, nil
}

// ParseFile parses YARA rules from a file.
func (p *Parser) ParseFile(filename string) (*ast.RuleSet, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}
	return p.Parse(string(content))
}
