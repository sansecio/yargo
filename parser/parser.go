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

func parseBase64Modifier(s string) (wide bool, alphabet string, ok bool) {
	name, args, found := strings.Cut(s, "(")
	if !found || (name != "base64" && name != "base64wide") || !strings.HasSuffix(args, ")") {
		return false, "", false
	}
	args = strings.TrimSpace(strings.TrimSuffix(args, ")"))
	if len(args) < 2 || args[0] != '"' || args[len(args)-1] != '"' {
		return false, "", false
	}
	alphabet = unquoteString(args)
	if len(alphabet) != 64 || strings.ContainsAny(alphabet, "\r\n") {
		return false, "", false
	}
	return name == "base64wide", alphabet, true
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
		ast.CountOf, ast.OffsetOf, ast.LenOf, ast.UnaryExpr, ast.Index, ast.Field:
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

const maxHexAltDepth = 16

type hexAltParser struct {
	s   string
	pos int
}

func parseHexAlt(s string) (ast.HexAlt, error) {
	p := &hexAltParser{s: s}
	alt, err := p.alt(0)
	if err != nil {
		return ast.HexAlt{}, err
	}
	if p.pos != len(s) {
		return ast.HexAlt{}, fmt.Errorf("invalid hex alternation %q", s)
	}
	return alt, nil
}

func (p *hexAltParser) alt(depth int) (ast.HexAlt, error) {
	if depth >= maxHexAltDepth {
		return ast.HexAlt{}, fmt.Errorf("hex alternation nested deeper than %d", maxHexAltDepth)
	}
	p.pos++
	var alt ast.HexAlt
	for {
		branch, err := p.branch(depth)
		if err != nil {
			return ast.HexAlt{}, err
		}
		alt.Alternatives = append(alt.Alternatives, branch)
		if p.pos >= len(p.s) {
			return ast.HexAlt{}, fmt.Errorf("unterminated hex alternation %q", p.s)
		}
		p.pos++
		if p.s[p.pos-1] == ')' {
			return alt, nil
		}
	}
}

func (p *hexAltParser) branch(depth int) ([]ast.HexToken, error) {
	var tokens []ast.HexToken
	for p.pos < len(p.s) {
		c := p.s[p.pos]
		switch {
		case c == '|' || c == ')':
			return checkBranch(tokens)
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			p.pos++
		case c == '(':
			nested, err := p.alt(depth + 1)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, nested)
		case c == '[':
			end := strings.IndexByte(p.s[p.pos:], ']')
			if end < 0 {
				return nil, fmt.Errorf("unterminated hex jump in %q", p.s)
			}
			jump, err := parseHexJump(p.s[p.pos : p.pos+end+1])
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, jump)
			p.pos += end + 1
		default:
			token, err := p.byteToken()
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, token)
		}
	}
	return nil, fmt.Errorf("unterminated hex alternation %q", p.s)
}

func (p *hexAltParser) byteToken() (ast.HexToken, error) {
	if p.pos+1 >= len(p.s) {
		return nil, fmt.Errorf("invalid hex alternative in %q", p.s)
	}
	hi, lo := p.s[p.pos], p.s[p.pos+1]
	p.pos += 2
	switch {
	case hi == '?' && lo == '?':
		return ast.HexWildcard{}, nil
	case hi == '?' && isHexDigit(lo):
		return ast.HexMasked{Value: hexVal(lo), Mask: 0x0F}, nil
	case isHexDigit(hi) && lo == '?':
		return ast.HexMasked{Value: hexVal(hi) << 4, Mask: 0xF0}, nil
	case isHexDigit(hi) && isHexDigit(lo):
		return ast.HexByte{Value: hexVal(hi)<<4 | hexVal(lo)}, nil
	}
	return nil, fmt.Errorf("invalid hex alternative %q", p.s[p.pos-2:p.pos])
}

func checkBranch(tokens []ast.HexToken) ([]ast.HexToken, error) {
	if len(tokens) == 0 {
		return nil, fmt.Errorf("empty hex alternative")
	}
	_, first := tokens[0].(ast.HexJump)
	_, last := tokens[len(tokens)-1].(ast.HexJump)
	if first || last {
		return nil, fmt.Errorf("hex alternative cannot start or end with a jump")
	}
	return tokens, nil
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
