// Package parser provides a YARA rule parser using goyacc.
package parser

import (
	"fmt"
	"os"
	"strconv"
	"strings"

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

func unquoteString(s string) string {
	if len(s) < 2 {
		return s
	}
	s = s[1 : len(s)-1]

	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case '\\':
			b.WriteByte('\\')
		case '"':
			b.WriteByte('"')
		case 'x':
			if i+2 < len(s) {
				if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
					b.WriteByte(byte(v))
					i += 2
					continue
				}
			}
			b.WriteByte('\\')
			b.WriteByte(s[i])
		default:
			b.WriteByte('\\')
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func parseRegex(s string) (string, ast.RegexModifiers) {
	s = s[1:]
	var mods ast.RegexModifiers
	if idx := strings.LastIndex(s, "/"); idx >= 0 {
		for _, c := range s[idx+1:] {
			switch c {
			case 'i':
				mods.CaseInsensitive = true
			case 's':
				mods.DotMatchesAll = true
			case 'm':
				mods.Multiline = true
			}
		}
		s = s[:idx]
	}
	return s, mods
}

func parseHexAlt(s string) ast.HexAlt {
	if len(s) < 2 {
		return ast.HexAlt{}
	}
	s = s[1 : len(s)-1]
	parts := strings.Split(s, "|")
	items := make([]ast.HexAltItem, len(parts))
	for i, part := range parts {
		if part == "??" {
			items[i] = ast.HexAltItem{Wildcard: true}
		} else {
			b, _ := strconv.ParseUint(part, 16, 8)
			v := byte(b)
			items[i] = ast.HexAltItem{Byte: &v}
		}
	}
	return ast.HexAlt{Alternatives: items}
}

func parseHexJump(s string) ast.HexJump {
	s = strings.Trim(s, "[] \t")
	if s == "-" {
		return ast.HexJump{}
	}
	if idx := strings.Index(s, "-"); idx >= 0 {
		var jump ast.HexJump
		if minStr := strings.TrimSpace(s[:idx]); minStr != "" {
			min, _ := strconv.Atoi(minStr)
			jump.Min = &min
		}
		if maxStr := strings.TrimSpace(s[idx+1:]); maxStr != "" {
			max, _ := strconv.Atoi(maxStr)
			jump.Max = &max
		}
		return jump
	}
	n, _ := strconv.Atoi(s)
	return ast.HexJump{Min: &n, Max: &n}
}
