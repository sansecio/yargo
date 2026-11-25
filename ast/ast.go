// Package ast defines the Abstract Syntax Tree types for YARA rules.
package ast

// RuleSet represents a collection of YARA rules.
type RuleSet struct {
	// Imports lists the modules named by import statements, in order.
	Imports []string
	Rules   []*Rule
	// Warnings lists constructs that parsed but cannot be honored, such as
	// unsupported string modifiers. The affected rules never match.
	Warnings []string
}

// Rule represents a single YARA rule.
type Rule struct {
	Name      string
	Tags      []string
	Private   bool // matches are not reported
	Global    bool // condition applies to every rule in the set
	Meta      []*MetaEntry
	Strings   []*StringDef
	Condition Expr // parsed condition expression
}

// MetaEntry represents a key-value pair in the meta section.
type MetaEntry struct {
	Key   string
	Value any // string or int64
}

// StringDef represents a string definition in the strings section.
type StringDef struct {
	Name      string      // $identifier or $ (anonymous)
	Value     StringValue // TextString, HexString, or RegexString
	Modifiers StringModifiers
}

// StringModifiers represents the modifiers applied to a string.
type StringModifiers struct {
	Ascii    bool
	Wide     bool
	Base64   bool
	Fullword bool
	Nocase   bool
	Private  bool
	// Unsupported holds modifiers the scanner cannot honor (e.g. wide, xor,
	// or base64 with a custom alphabet). Compilation skips rules that use
	// them, since matching without the modifier would be wrong.
	Unsupported []string
}

// StringValue is an interface for the different string types.
type StringValue interface {
	stringValue()
}

// TextString represents a quoted text string.
type TextString struct {
	Value string
}

func (TextString) stringValue() {}

// HexString represents a hex byte sequence with optional wildcards and jumps.
type HexString struct {
	Tokens []HexToken
}

func (HexString) stringValue() {}

// RegexModifiers represents the inline modifiers for a regex pattern.
type RegexModifiers struct {
	CaseInsensitive bool // i flag
	DotMatchesAll   bool // s flag
	Multiline       bool // m flag
}

// RegexString represents a regular expression pattern.
type RegexString struct {
	Pattern   string
	Modifiers RegexModifiers
}

func (RegexString) stringValue() {}

// HexToken is an interface for hex string components.
type HexToken interface {
	hexToken()
}

// HexByte represents a literal byte value.
type HexByte struct {
	Value byte
}

func (HexByte) hexToken() {}

// HexWildcard represents a ?? wildcard matching any byte.
type HexWildcard struct{}

func (HexWildcard) hexToken() {}

// HexJump represents a jump like [4], [4-16], or [-].
type HexJump struct {
	Min *int // nil means unbounded
	Max *int // nil means unbounded
}

func (HexJump) hexToken() {}

// HexAlt represents an alternation like (41|42|43) matching any of the byte values.
// Each alternative can be a byte value or ?? wildcard.
type HexAlt struct {
	Alternatives []HexAltItem
}

func (HexAlt) hexToken() {}

// HexAltItem represents a single item in a hex alternation.
type HexAltItem struct {
	Byte     *byte // nil if wildcard
	Wildcard bool
}

// Expr represents a condition expression node.
type Expr interface {
	exprNode()
}

// StringRef represents a string variable reference like $foo.
type StringRef struct {
	Name string
}

func (StringRef) exprNode() {}

// AtExpr represents a positional match like "$foo at 0".
type AtExpr struct {
	Ref StringRef
	Pos Expr
}

func (AtExpr) exprNode() {}

// IntLit represents an integer literal (decimal or hex).
type IntLit struct {
	Value int64
}

func (IntLit) exprNode() {}

// Filesize represents the bare filesize condition expression.
type Filesize struct{}

func (Filesize) exprNode() {}

// FuncCall represents a function call like uint32be(0).
type FuncCall struct {
	Name string
	Args []Expr
}

func (FuncCall) exprNode() {}

// BinaryExpr represents a binary operation like and, or, or an integer comparison.
type BinaryExpr struct {
	Op    string
	Left  Expr
	Right Expr
}

func (BinaryExpr) exprNode() {}

// NotExpr represents a negated condition like "not $foo".
type NotExpr struct {
	Inner Expr
}

func (NotExpr) exprNode() {}

// ParenExpr represents a parenthesized expression.
type ParenExpr struct {
	Inner Expr
}

func (ParenExpr) exprNode() {}

// AnyOf represents "any of (pattern)" with optional wildcard.
type AnyOf struct {
	Pattern string // e.g., "$b64_*" or "them"
}

func (AnyOf) exprNode() {}

// StrLit represents a string literal in a condition.
type StrLit struct {
	Value string
}

func (StrLit) exprNode() {}

// BoolLit represents true or false.
type BoolLit struct {
	Value bool
}

func (BoolLit) exprNode() {}

// Ident represents a bare identifier: an external variable such as filename,
// a reference to another rule, or a loop variable.
type Ident struct {
	Name string
}

func (Ident) exprNode() {}

// RegexLit represents the regular expression operand of matches.
type RegexLit struct {
	Pattern   string
	Modifiers RegexModifiers
}

func (RegexLit) exprNode() {}

// NOf represents a quantifier over a set of strings: "N of", "none of", or
// "any of" and "all of" with more than one pattern. Quant is "count" (at
// least N), "none", "any" or "all". Patterns hold "them" or $names with an
// optional trailing wildcard.
type NOf struct {
	Quant    string
	N        int64
	Patterns []string
}

func (NOf) exprNode() {}

// AllOf represents "all of them" or "all of (pattern)".
type AllOf struct {
	Pattern string // e.g., "them" or "$prefix_*"
}

func (AllOf) exprNode() {}
