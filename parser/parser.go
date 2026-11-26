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
	first, ok := parseXorKey(lo)
	if !ok {
		return nil, false
	}
	last := first
	if isRange {
		if last, ok = parseXorKey(hi); !ok || last < first {
			return nil, false
		}
	}
	return &ast.XorRange{Min: first, Max: last}, true
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
	if len(alphabet) != 64 || strings.ContainsAny(alphabet, "\r\n=") || hasDuplicateByte(alphabet) {
		return false, "", false
	}
	return name == "base64wide", alphabet, true
}

func hasDuplicateByte(s string) bool {
	var seen [256]bool
	for i := range len(s) {
		if seen[s[i]] {
			return true
		}
		seen[s[i]] = true
	}
	return false
}

// addModifier applies one string modifier. A modifier given twice is
// unsupported, as libyara rejects it with "duplicated modifier".
func addModifier(m ast.StringModifiers, mod string) ast.StringModifiers {
	if mod == "base64" || mod == "base64wide" {
		if m.Base64Alphabet != "" {
			m.Unsupported = append(m.Unsupported, mod)
			return m
		}
	}
	flag := boolModifier(&m, mod)
	if flag == nil {
		// known-but-unimplemented modifiers, argument forms of supported
		// modifiers, or future modifiers; recorded so the rule is skipped
		// at compile time and reported as a warning
		addArgumentModifier(&m, mod)
		return m
	}
	if *flag {
		m.Unsupported = append(m.Unsupported, mod+" "+mod)
	}
	*flag = true
	return m
}

func boolModifier(m *ast.StringModifiers, mod string) *bool {
	switch mod {
	case "ascii":
		return &m.Ascii
	case "wide":
		return &m.Wide
	case "fullword":
		return &m.Fullword
	case "nocase":
		return &m.Nocase
	case "private":
		return &m.Private
	case "base64":
		return &m.Base64
	case "base64wide":
		return &m.Base64Wide
	}
	return nil
}

func addArgumentModifier(m *ast.StringModifiers, mod string) {
	if x, ok := parseXorModifier(mod); ok {
		if m.Xor != nil {
			m.Unsupported = append(m.Unsupported, "xor "+mod)
		}
		m.Xor = x
		return
	}
	wide, alphabet, ok := parseBase64Modifier(mod)
	if !ok {
		m.Unsupported = append(m.Unsupported, mod)
		return
	}
	switch {
	case m.Base64Alphabet == "" && (m.Base64 || m.Base64Wide), m.Base64Alphabet != "" && m.Base64Alphabet != alphabet:
		m.Unsupported = append(m.Unsupported, mod)
	case wide && m.Base64Wide, !wide && m.Base64:
		m.Unsupported = append(m.Unsupported, mod+" "+mod)
	}
	m.Base64Alphabet = alphabet
	m.Base64 = m.Base64 || !wide
	m.Base64Wide = m.Base64Wide || wide
}

// invalidModifierCombination names the modifier pair libyara refuses to
// combine on one string (_yr_parser_check_string_modifiers), or "".
func invalidModifierCombination(m ast.StringModifiers) string {
	base64 := ""
	switch {
	case m.Base64:
		base64 = "base64"
	case m.Base64Wide:
		base64 = "base64wide"
	}
	switch {
	case m.Xor != nil && m.Nocase:
		return "xor nocase"
	case base64 != "" && m.Nocase:
		return base64 + " nocase"
	case base64 != "" && m.Fullword:
		return base64 + " fullword"
	case base64 != "" && m.Xor != nil:
		return base64 + " xor"
	}
	return ""
}

// parseXorKey reads a libyara number: decimal, 0x hex or 0o octal.
func parseXorKey(s string) (byte, bool) {
	s = strings.TrimSpace(s)
	base := 10
	if digits, ok := strings.CutPrefix(s, "0x"); ok {
		s, base = digits, 16
	} else if digits, ok := strings.CutPrefix(s, "0o"); ok {
		s, base = digits, 8
	}
	v, err := strconv.ParseUint(s, base, 8)
	return byte(v), err == nil
}

func comparisonExpr(lexer interface{ Error(string) }, op string, left, right ast.Expr) ast.Expr {
	if !isIntegerExpr(left) || !isIntegerExpr(right) {
		lexer.Error("comparison requires integer operands")
	}
	if l, r := staticType(left), staticType(right); l != typeUnknown && r != typeUnknown && l != r {
		lexer.Error("type mismatch")
	}
	return ast.BinaryExpr{Op: op, Left: left, Right: right}
}

type exprType int

const (
	typeUnknown exprType = iota
	typeNumber
	typeString
)

// staticType is the type an expression has whatever the scanned data,
// or typeUnknown when it depends on identifiers or functions.
func staticType(expr ast.Expr) exprType {
	switch e := expr.(type) {
	case ast.IntLit, ast.FloatLit, ast.Filesize, ast.CountOf, ast.OffsetOf, ast.LenOf, ast.UnaryExpr:
		return typeNumber
	case ast.StrLit:
		return typeString
	case ast.BinaryExpr:
		if isArithmeticOp(e.Op) {
			return typeNumber
		}
	case ast.ParenExpr:
		return staticType(e.Inner)
	}
	return typeUnknown
}

// indexExpr builds base[index]. Besides @a[i] and !a[i], only module
// identifiers like pe.sections can be indexed.
func indexExpr(lexer interface{ Error(string) }, base, index ast.Expr) ast.Expr {
	switch b := base.(type) {
	case ast.OffsetOf:
		return ast.OffsetOf{Name: b.Name, Index: index}
	case ast.LenOf:
		return ast.LenOf{Name: b.Name, Index: index}
	case ast.Ident:
	default:
		lexer.Error("only identifiers can be indexed")
	}
	return ast.Index{Base: base, Index: index}
}

// fieldExpr builds base.name, which only applies to an indexed identifier
// like pe.sections[0]; plain dotted names are lexed as one identifier.
func fieldExpr(lexer interface{ Error(string) }, base ast.Expr, name string) ast.Expr {
	if idx, ok := base.(ast.Index); !ok || !isIdent(idx.Base) {
		lexer.Error("only indexed identifiers have fields")
	}
	return ast.Field{Base: base, Name: name}
}

func isIdent(expr ast.Expr) bool {
	_, ok := expr.(ast.Ident)
	return ok
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

// Error is a parse error. Its text keeps the "parse error: <message>" form;
// Line is the 1-based input line where parsing stopped.
type Error struct {
	Msg  string
	Line int
}

func (e *Error) Error() string {
	return "parse error: " + e.Msg
}

// Parse parses YARA rules from a string. Constructs that parse but cannot be
// honored, such as unsupported string modifiers, are reported in the returned
// RuleSet's Warnings instead of failing the parse.
func (p *Parser) Parse(input string) (*ast.RuleSet, error) {
	l := newLexer(input)
	yyParse(l)
	if l.err != "" {
		return nil, &Error{Msg: l.err, Line: l.errLine}
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
			if combo := invalidModifierCombination(s.Modifiers); combo != "" {
				s.Modifiers.Unsupported = append(s.Modifiers.Unsupported, combo)
			}
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

func parseHexAlt(s string) (ast.HexToken, error) {
	p := &hexAltParser{s: s}
	alt, err := p.alt(0)
	if err != nil {
		return nil, err
	}
	if p.pos != len(s) {
		return nil, fmt.Errorf("invalid hex alternation %q", s)
	}
	return alt, nil
}

func (p *hexAltParser) alt(depth int) (ast.HexToken, error) {
	if depth >= maxHexAltDepth {
		return nil, fmt.Errorf("hex alternation nested deeper than %d", maxHexAltDepth)
	}
	p.pos++
	var branches [][]ast.HexToken
	for {
		branch, err := p.branch(depth)
		if err != nil {
			return nil, err
		}
		branches = append(branches, branch)
		if p.pos >= len(p.s) {
			return nil, fmt.Errorf("unterminated hex alternation %q", p.s)
		}
		p.pos++
		if p.s[p.pos-1] == ')' {
			return hexAltToken(branches), nil
		}
	}
}

// hexAltToken keeps the HexAlt shape for alternations of single bytes and
// ?? wildcards, and uses HexAlternation only when a branch needs more.
func hexAltToken(branches [][]ast.HexToken) ast.HexToken {
	items := make([]ast.HexAltItem, 0, len(branches))
	for _, branch := range branches {
		if len(branch) != 1 {
			return ast.HexAlternation{Alternatives: branches}
		}
		switch t := branch[0].(type) {
		case ast.HexByte:
			items = append(items, ast.HexAltItem{Byte: &t.Value})
		case ast.HexWildcard:
			items = append(items, ast.HexAltItem{Wildcard: true})
		default:
			return ast.HexAlternation{Alternatives: branches}
		}
	}
	return ast.HexAlt{Alternatives: items}
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
