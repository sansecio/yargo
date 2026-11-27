package parser

import (
	"fmt"
	"math"
	"strconv"
	"strings"

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
	imports []string
	err     string
	errLine int
	// depth counts the open brackets and pending prefix operators of the
	// current condition; prefix counts the prefix operators still waiting
	// for their operand, and afterOperand whether the last token ended one.
	depth        int
	prefix       int
	afterOperand bool
}

// maxConditionDepth caps nesting in a condition. Real rules nest a handful
// of levels; without a cap, a million parentheses or not operators keep the
// parser and every recursive pass over the condition busy.
const maxConditionDepth = 1000

// trackNesting updates the nesting depth for tok and fails the parse when
// it exceeds maxConditionDepth. A minus is a prefix operator unless it
// follows an operand.
func (l *yaraLexer) trackNesting(tok int) int {
	switch {
	case tok == '(' || tok == '[':
		l.depth++
	case tok == ')' || tok == ']':
		l.depth--
	case tok == NOT || tok == '~' || (tok == '-' && !l.afterOperand):
		l.depth++
		l.prefix++
	case isOperand(tok):
		l.depth -= l.prefix
		l.prefix = 0
	}
	l.afterOperand = tok == ')' || tok == ']' || isOperand(tok)
	if l.depth > maxConditionDepth {
		l.errorf("condition nested too deeply (more than %d levels)", maxConditionDepth)
		return 0
	}
	return tok
}

func isOperand(tok int) bool {
	switch tok {
	case COND_IDENT, INT_LIT, FLOAT_LIT, STRING_LIT, REGEX_LIT, COND_STRING_ID,
		STR_COUNT, STR_OFFSET, STR_LEN, FILESIZE, TRUE, FALSE, THEM:
		return true
	}
	return false
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
			return l.trackNesting(l.lexCondition(lval))
		}
	}
	return 0 // EOF
}

// Error records a parse error. The first error wins: goyacc reports a generic
// "syntax error" after the lexer has already recorded a descriptive one.
func (l *yaraLexer) Error(s string) {
	if l.err == "" {
		l.err = s
		l.errLine = l.line()
	}
}

func (l *yaraLexer) line() int {
	return 1 + strings.Count(l.input[:min(l.pos, len(l.input))], "\n")
}

func (l *yaraLexer) errorf(format string, args ...any) {
	l.Error(fmt.Sprintf(format, args...))
}

func (l *yaraLexer) skipWhitespace() bool {
	if l.pos >= len(l.input) {
		return false
	}
	switch l.input[l.pos] {
	case ' ', '\t', '\n', '\r', '\v', '\f':
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
		l.errorf("unterminated block comment")
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
	l.errorf("unterminated string literal")
	return l.input[start:l.pos]
}

func (l *yaraLexer) readRegex() string {
	start := l.pos
	l.pos++ // skip opening /
	inClass := false
	for l.pos < len(l.input) {
		switch {
		case l.input[l.pos] == '\\' && l.pos+1 < len(l.input):
			l.pos += 2
		case l.input[l.pos] == '[':
			inClass = true
			l.pos++
		case inClass && l.input[l.pos] == ']':
			inClass = false
			l.pos++
		case !inClass && l.input[l.pos] == '/':
			l.pos++ // skip closing /
			// Read flags
			for l.pos < len(l.input) && (l.input[l.pos] == 's' || l.input[l.pos] == 'i' || l.input[l.pos] == 'm') {
				l.pos++
			}
			return l.input[start:l.pos]
		default:
			l.pos++
		}
	}
	l.errorf("unterminated regular expression")
	return l.input[start:l.pos]
}

func (l *yaraLexer) lexRoot(lval *yySymType) int {
	ch := l.peek()
	if isAlpha(ch) || ch == '_' {
		word := l.readIdent()
		switch word {
		case "rule":
			l.pushMode(modeRuleBody)
			return RULE
		case "import":
			return IMPORT
		case "private":
			return PRIVATE
		case "global":
			return GLOBAL
		}
		lval.str = word
		return IDENT
	}
	if ch == '"' {
		lval.str = l.readQuotedString()
		return STRING_LIT
	}
	l.pos++
	l.errorf("unexpected character %q at position %d", ch, l.pos-1)
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
	l.errorf("unexpected character %q in rule body", ch)
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
		start := l.pos
		word := l.readIdent()
		if l.aheadIsColon() {
			// a section keyword like "condition:", not a modifier —
			// put the word back and pop mode
			l.pos = start
			l.popMode()
			return l.Lex(lval)
		}
		// any other identifier is a modifier, known or not; the grammar
		// warns about the ones the scanner cannot honor
		lval.str = word + l.readModifierArgs()
		return MODIFIER
	}

	// Any other character means the string value + modifiers are done
	l.popMode()
	return l.Lex(lval)
}

// aheadIsColon reports whether the next token is a colon, without consuming
// anything. It distinguishes a section keyword from a string modifier.
func (l *yaraLexer) aheadIsColon() bool {
	save := l.pos
	for l.skipWhitespace() || l.skipComment() {
	}
	isColon := l.peek() == ':'
	l.pos = save
	return isColon
}

// readModifierArgs consumes a modifier's parenthesized arguments, like
// xor(0x01-0xff) or base64("alphabet"), and returns them verbatim. Quoted
// strings are skipped as a whole so alphabets may contain parentheses.
func (l *yaraLexer) readModifierArgs() string {
	save := l.pos
	for l.skipWhitespace() || l.skipComment() {
	}
	if l.peek() != '(' {
		l.pos = save
		return ""
	}
	start := l.pos
	depth := 0
	for l.pos < len(l.input) {
		switch l.input[l.pos] {
		case '"':
			l.readQuotedString()
			continue
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				l.pos++
				return l.input[start:l.pos]
			}
		}
		l.pos++
	}
	l.errorf("unterminated modifier arguments")
	return l.input[start:l.pos]
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
		if l.pos+1 < len(l.input) && isHexDigit(l.input[l.pos+1]) {
			lval.hexToken = ast.HexMasked{Value: hexVal(l.input[l.pos+1]), Mask: 0x0F}
			l.pos += 2
			return HEX_MASKED
		}
	case '[':
		return l.lexHexJumpToken(lval)
	case '(':
		return l.lexHexAltToken(lval)
	}

	if isHexDigit(ch) && l.pos+1 < len(l.input) {
		next := l.input[l.pos+1]
		if isHexDigit(next) {
			lval.byt = hexVal(l.input[l.pos])<<4 | hexVal(next)
			l.pos += 2
			return HEX_BYTE
		}
		if next == '?' {
			lval.hexToken = ast.HexMasked{Value: hexVal(ch) << 4, Mask: 0xF0}
			l.pos += 2
			return HEX_MASKED
		}
	}

	l.pos++
	l.errorf("unexpected character %q in hex string", ch)
	return 0
}

func (l *yaraLexer) lexHexJumpToken(lval *yySymType) int {
	start := l.pos
	for l.pos < len(l.input) && l.input[l.pos] != ']' {
		l.pos++
	}
	if l.pos >= len(l.input) {
		l.errorf("unterminated hex jump")
		return 0
	}
	l.pos++ // skip ]
	lval.str = l.input[start:l.pos]
	return HEX_JUMP
}

func (l *yaraLexer) lexHexAltToken(lval *yySymType) int {
	start := l.pos
	depth := 0
	for l.pos < len(l.input) {
		switch l.input[l.pos] {
		case '(':
			depth++
		case ')':
			depth--
		}
		l.pos++
		if depth == 0 {
			break
		}
	}
	if depth != 0 {
		l.errorf("unterminated hex alternation")
		return 0
	}
	lval.str = l.input[start:l.pos]
	return HEX_ALT
}

// conditionKeywords maps the reserved words of a condition to their tokens.
var conditionKeywords = map[string]int{
	"and":         AND,
	"or":          OR,
	"not":         NOT,
	"at":          AT,
	"any":         ANY,
	"all":         ALL,
	"none":        NONE,
	"for":         FOR,
	"in":          IN,
	"of":          OF,
	"them":        THEM,
	"filesize":    FILESIZE,
	"contains":    CONTAINS,
	"icontains":   ICONTAINS,
	"startswith":  STARTSWITH,
	"istartswith": ISTARTSWITH,
	"endswith":    ENDSWITH,
	"iendswith":   IENDSWITH,
	"iequals":     IEQUALS,
	"matches":     MATCHES,
	"true":        TRUE,
	"false":       FALSE,
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
	case '!':
		if l.pos+1 < len(l.input) && l.input[l.pos+1] != '=' {
			return l.lexCondStringOp(lval, STR_LEN)
		}
		return l.lexConditionOp()
	case '<', '>', '=':
		return l.lexConditionOp()
	case '$':
		return l.lexCondStringRef(lval)
	case '"':
		lval.str = l.readQuotedString()
		return STRING_LIT
	case '/':
		lval.str = l.readRegex()
		return REGEX_LIT
	case '+', '*', '\\', '%', '&', '|', '^', '~', '[', ']', '-':
		l.pos++
		return int(ch)
	case '#':
		return l.lexCondStringOp(lval, STR_COUNT)
	case '@':
		return l.lexCondStringOp(lval, STR_OFFSET)
	case '.':
		return l.lexDot()
	}

	if ch == '0' && l.pos+1 < len(l.input) && (l.input[l.pos+1] == 'x' || l.input[l.pos+1] == 'X') {
		return l.lexHexInt(lval)
	}

	if isDigit(ch) {
		return l.lexCondInt(lval)
	}

	if isAlpha(ch) || ch == '_' {
		word := l.readDottedIdent()
		if tok, ok := conditionKeywords[word]; ok {
			return tok
		}
		lval.str = word
		return COND_IDENT
	}

	l.pos++
	l.errorf("unexpected character %q in condition", ch)
	return 0
}

func (l *yaraLexer) lexConditionOp() int {
	if l.pos+1 < len(l.input) {
		switch l.input[l.pos : l.pos+2] {
		case "<<":
			l.pos += 2
			return SHL
		case ">>":
			l.pos += 2
			return SHR
		case "!=":
			l.pos += 2
			return NE
		case "<=":
			l.pos += 2
			return LE
		case ">=":
			l.pos += 2
			return GE
		case "==":
			l.pos += 2
			return EQ
		}
	}

	switch l.input[l.pos] {
	case '<':
		l.pos++
		return LT
	case '>':
		l.pos++
		return GT
	case '=':
		l.pos++
		return '='
	default:
		l.pos++
		l.errorf("unexpected character %q in condition", l.input[l.pos-1])
		return 0
	}
}

func (l *yaraLexer) readDottedIdent() string {
	start := l.pos
	l.readIdent()
	for l.pos+1 < len(l.input) && l.input[l.pos] == '.' && (isAlpha(l.input[l.pos+1]) || l.input[l.pos+1] == '_') {
		l.pos++
		l.readIdent()
	}
	return l.input[start:l.pos]
}

func (l *yaraLexer) lexDot() int {
	if l.pos+1 < len(l.input) && l.input[l.pos+1] == '.' {
		l.pos += 2
		return RANGE
	}
	l.pos++
	return '.'
}

func (l *yaraLexer) lexCondStringOp(lval *yySymType, tok int) int {
	l.pos++
	start := l.pos
	for l.pos < len(l.input) && (l.input[l.pos] == '_' || isAlnum(l.input[l.pos])) {
		l.pos++
	}
	lval.str = "$" + l.input[start:l.pos]
	return tok
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
	l.pos += 2 // skip 0x or 0X
	for l.pos < len(l.input) && isHexDigit(l.input[l.pos]) {
		l.pos++
	}
	s := l.input[start:l.pos]
	v, err := strconv.ParseInt(s[2:], 16, 64)
	if err != nil {
		l.errorf("invalid integer literal %q", s)
		return 0
	}
	lval.num = v
	return INT_LIT
}

func (l *yaraLexer) lexCondInt(lval *yySymType) int {
	start := l.pos
	for l.pos < len(l.input) && isDigit(l.input[l.pos]) {
		l.pos++
	}
	if l.pos+1 < len(l.input) && l.input[l.pos] == '.' && isDigit(l.input[l.pos+1]) {
		l.pos++
		for l.pos < len(l.input) && isDigit(l.input[l.pos]) {
			l.pos++
		}
		v, err := strconv.ParseFloat(l.input[start:l.pos], 64)
		if err != nil {
			l.errorf("invalid float literal %q", l.input[start:l.pos])
			return 0
		}
		lval.flt = v
		return FLOAT_LIT
	}
	end := l.pos
	scale := int64(1)
	if l.pos+1 < len(l.input) && l.input[l.pos+1] == 'B' {
		switch l.input[l.pos] {
		case 'K':
			scale = 1 << 10
		case 'M':
			scale = 1 << 20
		}
		if scale > 1 {
			l.pos += 2
		}
	}
	tok := l.intToken(lval, l.input[start:end])
	if tok == INT_LIT && lval.num > math.MaxInt64/scale {
		l.errorf("integer overflow %q", l.input[start:l.pos])
		return 0
	}
	lval.num *= scale
	return tok
}

func (l *yaraLexer) lexInt(lval *yySymType) int {
	start := l.pos
	if l.input[l.pos] == '-' {
		l.pos++
	}
	for l.pos < len(l.input) && isDigit(l.input[l.pos]) {
		l.pos++
	}
	return l.intToken(lval, l.input[start:l.pos])
}

func (l *yaraLexer) intToken(lval *yySymType, s string) int {
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		l.errorf("invalid integer literal %q", s)
		return 0
	}
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

// hexVal returns the value of a hex digit; c must satisfy isHexDigit.
func hexVal(c byte) byte {
	switch {
	case c <= '9':
		return c - '0'
	case c >= 'a':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}
