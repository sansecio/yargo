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

type forQuant struct {
	quant string
	n     int64
}

// parseXorModifier parses "xor", "xor(n)" and "xor(min-max)". Keys may be
// decimal or 0x-prefixed hex and must fit a byte.
func parseXorModifier(s string) (*ast.XorRange, bool) {
	if s == "xor" {
		return &ast.XorRange{Min: 0, Max: 255}, true
	}
	args, ok := strings.CutPrefix(s, "xor(")
	if !ok || !strings.HasSuffix(args, ")") {
		return nil, false
	}
	args = strings.TrimSuffix(args, ")")
	lo, hi, isRange := strings.Cut(args, "-")
	min, ok := parseXorKey(lo)
	if !ok {
		return nil, false
	}
	max := min
	if isRange {
		if max, ok = parseXorKey(hi); !ok || max < min {
			return nil, false
		}
	}
	return &ast.XorRange{Min: min, Max: max}, true
}

func parseXorKey(s string) (byte, bool) {
	v, err := strconv.ParseUint(strings.TrimSpace(s), 0, 8)
	return byte(v), err == nil
}

func comparisonExpr(lexer interface{ Error(string) }, op string, left, right ast.Expr) ast.Expr {
	if !isIntegerExpr(left) || !isIntegerExpr(right) {
		lexer.Error("comparison requires integer operands")
	}
	return ast.BinaryExpr{Op: op, Left: left, Right: right}
}

func isIntegerExpr(expr ast.Expr) bool {
	switch e := expr.(type) {
	case ast.IntLit, ast.FloatLit, ast.Filesize, ast.FuncCall, ast.Ident, ast.StrLit,
		ast.CountOf, ast.OffsetOf, ast.LenOf, ast.UnaryExpr:
		return true
	case ast.BinaryExpr:
		return isArithmeticOp(e.Op)
	case ast.ParenExpr:
		return isIntegerExpr(e.Inner)
	default:
		return false
	}
}

func isArithmeticOp(op string) bool {
	switch op {
	case "+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>":
		return true
	default:
		return false
	}
}

// Parse parses YARA rules from a string. Constructs that parse but cannot be
// honored, such as unsupported string modifiers, are reported in the returned
// RuleSet's Warnings instead of failing the parse.
func (p *Parser) Parse(input string) (*ast.RuleSet, error) {
	l := newLexer(input)
	yyParse(l)
	if l.err != "" {
		return nil, fmt.Errorf("parse error: %s", l.err)
	}
	if l.ruleSet == nil {
		return &ast.RuleSet{}, nil
	}
	collectWarnings(l.ruleSet)
	return l.ruleSet, nil
}

// collectWarnings fills rs.Warnings with one entry per unsupported string
// modifier, so callers can log what their ruleset silently loses.
func collectWarnings(rs *ast.RuleSet) {
	for _, r := range rs.Rules {
		for _, s := range r.Strings {
			for _, mod := range s.Modifiers.Unsupported {
				rs.Warnings = append(rs.Warnings, fmt.Sprintf(
					"rule %q string %s: unsupported modifier %q, rule will not match", r.Name, s.Name, mod,
				))
			}
		}
	}
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

func parseHexAlt(s string) (ast.HexAlt, error) {
	if len(s) < 2 || s[0] != '(' || s[len(s)-1] != ')' {
		return ast.HexAlt{}, fmt.Errorf("invalid hex alternation %q", s)
	}
	s = s[1 : len(s)-1]
	parts := strings.Split(s, "|")
	items := make([]ast.HexAltItem, len(parts))
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "??" {
			items[i] = ast.HexAltItem{Wildcard: true}
			continue
		}
		if len(part) != 2 {
			return ast.HexAlt{}, fmt.Errorf("unsupported hex alternative %q (only single bytes and ?? are supported)", part)
		}
		b, err := strconv.ParseUint(part, 16, 8)
		if err != nil {
			return ast.HexAlt{}, fmt.Errorf("invalid hex alternative %q", part)
		}
		v := byte(b)
		items[i] = ast.HexAltItem{Byte: &v}
	}
	return ast.HexAlt{Alternatives: items}, nil
}

func parseHexJump(s string) (ast.HexJump, error) {
	orig := s
	s = strings.Trim(s, "[] \t")
	if s == "-" {
		return ast.HexJump{}, nil
	}
	parseBound := func(s string) (*int, error) {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid hex jump %q", orig)
		}
		return &n, nil
	}
	if before, after, ok := strings.Cut(s, "-"); ok {
		var jump ast.HexJump
		var err error
		if minStr := strings.TrimSpace(before); minStr != "" {
			if jump.Min, err = parseBound(minStr); err != nil {
				return ast.HexJump{}, err
			}
		}
		if maxStr := strings.TrimSpace(after); maxStr != "" {
			if jump.Max, err = parseBound(maxStr); err != nil {
				return ast.HexJump{}, err
			}
		}
		if jump.Min != nil && jump.Max != nil && *jump.Min > *jump.Max {
			return ast.HexJump{}, fmt.Errorf("invalid hex jump %q: lower bound exceeds upper bound", orig)
		}
		return jump, nil
	}
	n, err := parseBound(s)
	if err != nil {
		return ast.HexJump{}, err
	}
	return ast.HexJump{Min: n, Max: n}, nil
}
