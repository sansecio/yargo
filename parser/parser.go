// Package parser provides a YARA rule parser using participle.
package parser

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/alecthomas/participle/v2"
	"github.com/alecthomas/participle/v2/lexer"
	"github.com/sansecio/yargo/ast"
)

// Parser parses YARA rules.
type Parser struct {
	parser   *participle.Parser[file]
	warnings []string
}

// New creates a new YARA parser.
func New() (*Parser, error) {
	lex := lexer.MustStateful(lexer.Rules{
		"Common": {
			{Name: "LineComment", Pattern: `//[^\n]*`},
			{Name: "BlockComment", Pattern: `/\*(?:[^*]|\*[^/])*\*/`},
			{Name: "Whitespace", Pattern: `[\s]+`},
		},
		"Root": {
			{Name: "Rule", Pattern: `\brule\b`, Action: lexer.Push("RuleBody")},
			lexer.Include("Common"),
		},
		"RuleBody": {
			{Name: "Meta", Pattern: `\bmeta\b`},
			{Name: "Strings", Pattern: `\bstrings\b`},
			{Name: "Condition", Pattern: `\bcondition\b`, Action: lexer.Push("ConditionExpr")},
			{Name: "Ident", Pattern: `[a-zA-Z_][a-zA-Z0-9_]*`},
			{Name: "LBrace", Pattern: `\{`},
			{Name: "String", Pattern: `"(?:[^"\\]|\\.)*"`},
			{Name: "Int", Pattern: `-?[0-9]+`},
			{Name: "StringIdent", Pattern: `\$[a-zA-Z0-9_]*`, Action: lexer.Push("StringValue")},
			{Name: "Colon", Pattern: `:`},
			{Name: "Equals", Pattern: `=`},
			{Name: "RBrace", Pattern: `\}`, Action: lexer.Pop()},
			lexer.Include("Common"),
		},
		"StringValue": {
			{Name: "Equals", Pattern: `=`},
			lexer.Include("Common"),
			{Name: "String", Pattern: `"(?:[^"\\]|\\.)*"`},
			{Name: "Regex", Pattern: `/(?:[^/\\]|\\.)+/[sim]*`},
			{Name: "HexOpen", Pattern: `\{`, Action: lexer.Push("HexString")},
			{Name: "Modifier", Pattern: `\b(base64|base64wide|fullword|wide|ascii|nocase|xor|private)\b`},
			lexer.Return(),
		},
		"HexString": {
			{Name: "HexByte", Pattern: `[0-9A-Fa-f]{2}`},
			{Name: "HexWildcard", Pattern: `\?\?`},
			{Name: "HexJump", Pattern: `\[\s*-?\d*\s*(?:-\s*-?\d*)?\s*\]`},
			{Name: "HexAlt", Pattern: `\([0-9A-Fa-f?]{2}(?:\|[0-9A-Fa-f?]{2})*\)`},
			{Name: "HexClose", Pattern: `\}`, Action: lexer.Pop()},
			lexer.Include("Common"),
		},
		"ConditionExpr": {
			{Name: "Colon", Pattern: `:`},
			{Name: "CondString", Pattern: `"(?:[^"\\]|\\.)*"`},
			{Name: "CondLineComment", Pattern: `//[^\n]*`},
			{Name: "CondBlockComment", Pattern: `/\*(?:[^*]|\*[^/])*\*/`},
			{Name: "CondRegex", Pattern: `/(?:[^/\\]|\\.)+/[sim]*`},
			{Name: "RBrace", Pattern: `\}`, Action: lexer.Pop()},
			{Name: "CondChar", Pattern: `[\s\S]`},
		},
	})

	p, err := participle.Build[file](
		participle.Lexer(lex),
		participle.Elide("Whitespace", "LineComment", "BlockComment", "CondLineComment", "CondBlockComment"),
		participle.UseLookahead(5),
	)
	if err != nil {
		return nil, fmt.Errorf("building parser: %w", err)
	}

	return &Parser{parser: p}, nil
}

// Parse parses YARA rules from a string.
func (p *Parser) Parse(input string) (*ast.RuleSet, error) {
	p.warnings = nil
	f, err := p.parser.ParseString("", input)
	if err != nil {
		return nil, err
	}
	return p.convertToAST(f)
}

// ParseFile parses YARA rules from a file.
func (p *Parser) ParseFile(filename string) (*ast.RuleSet, error) {
	p.warnings = nil
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}
	f, err := p.parser.ParseBytes(filename, content)
	if err != nil {
		return nil, err
	}
	return p.convertToAST(f)
}

// Warnings returns any warnings generated during the last parse.
func (p *Parser) Warnings() []string {
	return p.warnings
}

func (p *Parser) convertToAST(f *file) (*ast.RuleSet, error) {
	rs := &ast.RuleSet{Rules: make([]*ast.Rule, 0, len(f.Rules))}
	for _, r := range f.Rules {
		rule, err := p.convertRule(r)
		if err != nil {
			return nil, err
		}
		rs.Rules = append(rs.Rules, rule)
	}
	return rs, nil
}

func (p *Parser) convertRule(r *ruleGrammar) (*ast.Rule, error) {
	rule := &ast.Rule{Name: r.Name}

	if r.Meta != nil {
		for _, m := range r.Meta.Entries {
			entry := &ast.MetaEntry{Key: m.Key}
			if m.StringValue != nil {
				entry.Value = unquoteString(*m.StringValue)
			} else if m.IntValue != nil {
				entry.Value = *m.IntValue
			}
			rule.Meta = append(rule.Meta, entry)
		}
	}

	if r.Strings != nil {
		for _, s := range r.Strings.Defs {
			def, err := convertStringDef(s)
			if err != nil {
				return nil, err
			}
			rule.Strings = append(rule.Strings, def)
		}
	}

	if r.Condition != nil {
		rule.Condition = strings.TrimSpace(strings.Join(r.Condition.Parts, ""))
		if rule.Condition != "any of them" && rule.Condition != "all of them" {
			p.warnings = append(p.warnings,
				fmt.Sprintf("rule %q: complex condition %q (only 'any of them' is fully supported)",
					rule.Name, rule.Condition))
		}
	}

	return rule, nil
}

func convertStringDef(s *stringDefGrammar) (*ast.StringDef, error) {
	def := &ast.StringDef{Name: s.Name}

	for _, mod := range s.Modifiers {
		switch mod {
		case "base64":
			def.Modifiers.Base64 = true
		case "base64wide":
			def.Modifiers.Base64Wide = true
		case "fullword":
			def.Modifiers.Fullword = true
		case "wide":
			def.Modifiers.Wide = true
		case "ascii":
			def.Modifiers.Ascii = true
		case "nocase":
			def.Modifiers.Nocase = true
		case "xor":
			def.Modifiers.Xor = true
		case "private":
			def.Modifiers.Private = true
		}
	}

	switch {
	case s.Text != nil:
		def.Value = ast.TextString{Value: unquoteString(*s.Text)}
	case s.Hex != nil:
		def.Value = convertHexString(s.Hex)
	case s.Regex != nil:
		pattern, mods := parseRegex(*s.Regex)
		def.Value = ast.RegexString{Pattern: pattern, Modifiers: mods}
	}

	return def, nil
}

func convertHexString(h *hexStringGrammar) ast.HexString {
	tokens := make([]ast.HexToken, 0, len(h.Tokens))
	for _, t := range h.Tokens {
		switch {
		case t.Byte != nil:
			b, _ := strconv.ParseUint(*t.Byte, 16, 8)
			tokens = append(tokens, ast.HexByte{Value: byte(b)})
		case t.Wildcard:
			tokens = append(tokens, ast.HexWildcard{})
		case t.Jump != nil:
			tokens = append(tokens, parseHexJump(*t.Jump))
		case t.Alt != nil:
			tokens = append(tokens, parseHexAlt(*t.Alt))
		}
	}
	return ast.HexString{Tokens: tokens}
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
