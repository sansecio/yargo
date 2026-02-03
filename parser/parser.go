// Package parser provides a YARA rule parser using goyacc.
package parser

import (
	"fmt"
	"os"

	"github.com/sansecio/yargo/ast"
)

//go:generate goyacc -o y.go yara.y

// Parser parses YARA rules.
type Parser struct {
	warnings []string
}

// New creates a new YARA parser.
func New() (*Parser, error) {
	return &Parser{}, nil
}

// Parse parses YARA rules from a string.
func (p *Parser) Parse(input string) (*ast.RuleSet, error) {
	p.warnings = nil
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
	p.warnings = nil
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}
	return p.Parse(string(content))
}

// Warnings returns any warnings generated during the last parse.
func (p *Parser) Warnings() []string {
	return p.warnings
}
