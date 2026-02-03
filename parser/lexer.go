package parser

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/sansecio/yargo/ast"
)

// Lexer modes
const (
	modeRoot = iota
	modeRuleBody
	modeStringValue
	modeHexString
	modeCondition
)

type yaraLexer struct {
	input   string
	pos     int
	modes   []int
	ruleSet *ast.RuleSet
	err     string
}

func newLexer(input string) *yaraLexer {
	return &yaraLexer{
		input: input,
		modes: []int{modeRoot},
	}
}

func (l *yaraLexer) mode() int {
	return l.modes[len(l.modes)-1]
}

func (l *yaraLexer) pushMode(m int) {
	l.modes = append(l.modes, m)
}

func (l *yaraLexer) popMode() {
	if len(l.modes) > 1 {
		l.modes = l.modes[:len(l.modes)-1]
	}
}

func (l *yaraLexer) Lex(lval *yySymType) int {
	for l.pos < len(l.input) {
		// Skip whitespace
		if l.skipWhitespace() {
			continue
		}
		// Skip comments
		if l.skipComment() {
			continue
		}

		switch l.mode() {
		case modeRoot:
			return l.lexRoot(lval)
		case modeRuleBody:
			return l.lexRuleBody(lval)
		case modeStringValue:
			return l.lexStringValue(lval)
		case modeHexString:
			return l.lexHexString(lval)
		case modeCondition:
			return l.lexCondition(lval)
		}
	}
	return 0 // EOF
}

func (l *yaraLexer) Error(s string) {
	l.err = s
}

func (l *yaraLexer) skipWhitespace() bool {
	if l.pos >= len(l.input) {
		return false
	}
	if unicode.IsSpace(rune(l.input[l.pos])) {
		l.pos++
		return true
	}
	return false
}

func (l *yaraLexer) skipComment() bool {
	if l.pos+1 >= len(l.input) {
		return false
	}
	if l.input[l.pos] == '/' && l.input[l.pos+1] == '/' {
		// Line comment
		for l.pos < len(l.input) && l.input[l.pos] != '\n' {
			l.pos++
		}
		return true
	}
	if l.input[l.pos] == '/' && l.input[l.pos+1] == '*' {
		// Block comment
		l.pos += 2
		for l.pos+1 < len(l.input) {
			if l.input[l.pos] == '*' && l.input[l.pos+1] == '/' {
				l.pos += 2
				return true
			}
			l.pos++
		}
		l.pos = len(l.input)
		return true
	}
	return false
}

func (l *yaraLexer) peek() byte {
	if l.pos < len(l.input) {
		return l.input[l.pos]
	}
	return 0
}

func (l *yaraLexer) readIdent() string {
	start := l.pos
	for l.pos < len(l.input) && (l.input[l.pos] == '_' || isAlnum(l.input[l.pos])) {
		l.pos++
	}
	return l.input[start:l.pos]
}

func (l *yaraLexer) readQuotedString() string {
	start := l.pos
	l.pos++ // skip opening "
	for l.pos < len(l.input) {
		if l.input[l.pos] == '\\' && l.pos+1 < len(l.input) {
			l.pos += 2
			continue
		}
		if l.input[l.pos] == '"' {
			l.pos++
			return l.input[start:l.pos]
		}
		l.pos++
	}
	return l.input[start:l.pos]
}

func (l *yaraLexer) readRegex() string {
	start := l.pos
	l.pos++ // skip opening /
	for l.pos < len(l.input) {
		if l.input[l.pos] == '\\' && l.pos+1 < len(l.input) {
			l.pos += 2
			continue
		}
		if l.input[l.pos] == '/' {
			l.pos++ // skip closing /
			// Read flags
			for l.pos < len(l.input) && (l.input[l.pos] == 's' || l.input[l.pos] == 'i' || l.input[l.pos] == 'm') {
				l.pos++
			}
			return l.input[start:l.pos]
		}
		l.pos++
	}
	return l.input[start:l.pos]
}

func (l *yaraLexer) lexRoot(lval *yySymType) int {
	ch := l.peek()
	if isAlpha(ch) || ch == '_' {
		word := l.readIdent()
		if word == "rule" {
			l.pushMode(modeRuleBody)
			return RULE
		}
		lval.str = word
		return IDENT
	}
	l.pos++
	l.err = fmt.Sprintf("unexpected character %q at position %d", ch, l.pos-1)
	return 0
}

func (l *yaraLexer) lexRuleBody(lval *yySymType) int {
	ch := l.peek()

	switch ch {
	case '{':
		l.pos++
		return '{'
	case '}':
		l.pos++
		l.popMode()
		return '}'
	case ':':
		l.pos++
		return ':'
	case '=':
		l.pos++
		return '='
	case '"':
		lval.str = l.readQuotedString()
		return STRING_LIT
	case '$':
		return l.lexStringIdent(lval)
	}

	if ch == '-' || isDigit(ch) {
		return l.lexInt(lval)
	}

	if isAlpha(ch) || ch == '_' {
		word := l.readIdent()
		switch word {
		case "meta":
			return META
		case "strings":
			return STRINGS
		case "condition":
			l.pushMode(modeCondition)
			return CONDITION
		default:
			lval.str = word
			return IDENT
		}
	}

	l.pos++
	l.err = fmt.Sprintf("unexpected character %q in rule body", ch)
	return 0
}

func (l *yaraLexer) lexStringIdent(lval *yySymType) int {
	start := l.pos
	l.pos++ // skip $
	for l.pos < len(l.input) && (l.input[l.pos] == '_' || isAlnum(l.input[l.pos])) {
		l.pos++
	}
	lval.str = l.input[start:l.pos]
	l.pushMode(modeStringValue)
	return STRING_IDENT
}

func (l *yaraLexer) lexStringValue(lval *yySymType) int {
	ch := l.peek()

	switch ch {
	case '=':
		l.pos++
		return '='
	case '"':
		lval.str = l.readQuotedString()
		return STRING_LIT
	case '/':
		lval.str = l.readRegex()
		return REGEX_LIT
	case '{':
		l.pos++
		l.pushMode(modeHexString)
		return '{'
	}

	if isAlpha(ch) {
		word := l.readIdent()
		switch word {
		case "base64", "base64wide", "fullword", "wide", "ascii", "nocase", "xor", "private":
			lval.str = word
			return MODIFIER
		default:
			// Not a modifier — this belongs to the next section.
			// Put the word back and pop mode.
			l.pos -= len(word)
			l.popMode()
			return l.Lex(lval)
		}
	}

	// Any other character means the string value + modifiers are done
	l.popMode()
	return l.Lex(lval)
}

func (l *yaraLexer) lexHexString(lval *yySymType) int {
	ch := l.peek()

	switch ch {
	case '}':
		l.pos++
		l.popMode()
		return '}'
	case '?':
		if l.pos+1 < len(l.input) && l.input[l.pos+1] == '?' {
			l.pos += 2
			return HEX_WILDCARD
		}
	case '[':
		return l.lexHexJumpToken(lval)
	case '(':
		return l.lexHexAltToken(lval)
	}

	if isHexDigit(ch) {
		if l.pos+1 < len(l.input) && isHexDigit(l.input[l.pos+1]) {
			hi := l.input[l.pos]
			lo := l.input[l.pos+1]
			val, _ := strconv.ParseUint(string([]byte{hi, lo}), 16, 8)
			lval.byt = byte(val)
			l.pos += 2
			return HEX_BYTE
		}
	}

	l.pos++
	l.err = fmt.Sprintf("unexpected character %q in hex string", ch)
	return 0
}

func (l *yaraLexer) lexHexJumpToken(lval *yySymType) int {
	start := l.pos
	for l.pos < len(l.input) && l.input[l.pos] != ']' {
		l.pos++
	}
	if l.pos < len(l.input) {
		l.pos++ // skip ]
	}
	lval.str = l.input[start:l.pos]
	return HEX_JUMP
}

func (l *yaraLexer) lexHexAltToken(lval *yySymType) int {
	start := l.pos
	for l.pos < len(l.input) && l.input[l.pos] != ')' {
		l.pos++
	}
	if l.pos < len(l.input) {
		l.pos++ // skip )
	}
	lval.str = l.input[start:l.pos]
	return HEX_ALT
}

func (l *yaraLexer) lexCondition(lval *yySymType) int {
	ch := l.peek()

	switch ch {
	case ':':
		l.pos++
		return ':'
	case '}':
		l.pos++
		// Pop both modeCondition and modeRuleBody since } ends both
		l.popMode() // pop modeCondition → modeRuleBody
		l.popMode() // pop modeRuleBody → modeRoot
		return '}'
	case '(':
		l.pos++
		return '('
	case ')':
		l.pos++
		return ')'
	case ',':
		l.pos++
		return ','
	case '=':
		if l.pos+1 < len(l.input) && l.input[l.pos+1] == '=' {
			l.pos += 2
			return EQ
		}
		l.pos++
		return '='
	case '$':
		return l.lexCondStringRef(lval)
	}

	if ch == '0' && l.pos+1 < len(l.input) && (l.input[l.pos+1] == 'x' || l.input[l.pos+1] == 'X') {
		return l.lexHexInt(lval)
	}

	if isDigit(ch) {
		return l.lexCondInt(lval)
	}

	if isAlpha(ch) || ch == '_' {
		word := l.readIdent()
		switch word {
		case "and":
			return AND
		case "or":
			return OR
		case "at":
			return AT
		case "any":
			return ANY
		case "all":
			return ALL
		case "of":
			return OF
		case "them":
			return THEM
		default:
			lval.str = word
			return COND_IDENT
		}
	}

	l.pos++
	l.err = fmt.Sprintf("unexpected character %q in condition", ch)
	return 0
}

func (l *yaraLexer) lexCondStringRef(lval *yySymType) int {
	start := l.pos
	l.pos++ // skip $
	for l.pos < len(l.input) && (l.input[l.pos] == '_' || isAlnum(l.input[l.pos])) {
		l.pos++
	}
	// Check for wildcard pattern like $foo*
	if l.pos < len(l.input) && l.input[l.pos] == '*' {
		l.pos++
		lval.str = l.input[start:l.pos]
		return STRING_PATTERN
	}
	lval.str = l.input[start:l.pos]
	return COND_STRING_ID
}

func (l *yaraLexer) lexHexInt(lval *yySymType) int {
	start := l.pos
	l.pos += 2 // skip 0x
	for l.pos < len(l.input) && isHexDigit(l.input[l.pos]) {
		l.pos++
	}
	s := l.input[start:l.pos]
	v, _ := strconv.ParseInt(strings.TrimPrefix(s, "0x"), 16, 64)
	lval.num = v
	return INT_LIT
}

func (l *yaraLexer) lexCondInt(lval *yySymType) int {
	start := l.pos
	for l.pos < len(l.input) && isDigit(l.input[l.pos]) {
		l.pos++
	}
	v, _ := strconv.ParseInt(l.input[start:l.pos], 10, 64)
	lval.num = v
	return INT_LIT
}

func (l *yaraLexer) lexInt(lval *yySymType) int {
	start := l.pos
	if l.input[l.pos] == '-' {
		l.pos++
	}
	for l.pos < len(l.input) && isDigit(l.input[l.pos]) {
		l.pos++
	}
	v, _ := strconv.ParseInt(l.input[start:l.pos], 10, 64)
	lval.num = v
	return INT_LIT
}

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func isAlnum(c byte) bool {
	return isAlpha(c) || isDigit(c)
}

func isHexDigit(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
