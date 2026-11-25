// Package ast defines the Abstract Syntax Tree types for YARA rules.
package ast

// RuleSet represents a collection of YARA rules.
type RuleSet struct {
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
	Private   bool
	Global    bool
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
	Ascii          bool
	Wide           bool
	Xor            *XorRange
	Base64         bool
	Fullword       bool
	Base64Wide     bool
	Base64Alphabet string
	Nocase         bool
	Private        bool
	// Unsupported holds modifiers the scanner cannot honor (e.g. wide, xor,
	// or base64 with a custom alphabet). Compilation skips rules that use
	// them, since matching without the modifier would be wrong.
	Unsupported []string
}

// XorRange is the key range of an xor(min-max) modifier.
type XorRange struct {
	Min, Max byte
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

// HexMasked represents a nibble wildcard like 4? or ?4: a byte matches when
// byte&Mask == Value.
type HexMasked struct {
	Value byte
	Mask  byte
}

func (HexMasked) hexToken() {}

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

// HexAlternation represents an alternation whose branches are token sequences,
// like (41 42|43), (4?|50) or (41 (42|43)|44). Alternations where every branch
// is a single byte or ?? wildcard are parsed as HexAlt instead.
type HexAlternation struct {
	Alternatives [][]HexToken
}

func (HexAlternation) hexToken() {}

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

// FloatLit represents a floating point literal like 7.5.
type FloatLit struct {
	Value float64
}

func (FloatLit) exprNode() {}

// UnaryExpr represents arithmetic negation (Op "-") or bitwise not (Op "~").
type UnaryExpr struct {
	Op    string
	Inner Expr
}

func (UnaryExpr) exprNode() {}

// CountOf represents a string count like #a.
type CountOf struct {
	Name string
}

func (CountOf) exprNode() {}

// OffsetOf represents a match offset like @a[i]. Index is nil for @a,
// which means the first match.
type OffsetOf struct {
	Name  string
	Index Expr
}

func (OffsetOf) exprNode() {}

// LenOf represents a match length like !a[i]. Index is nil for !a,
// which means the first match.
type LenOf struct {
	Name  string
	Index Expr
}

func (LenOf) exprNode() {}

// InExpr represents a string match inside an offset range, like $a in (0..100).
type InExpr struct {
	Ref    StringRef
	Lo, Hi Expr
}

func (InExpr) exprNode() {}

// ForExpr represents a for loop. Quant is "any", "all", "none" or "count"
// (with N). It iterates Var over the range Lo..Hi, or over Patterns when
// Patterns is set, and requires Body to hold for the quantified number of items.
type ForExpr struct {
	Quant    string
	N        int64
	Var      string
	Lo, Hi   Expr
	Patterns []string
	Body     Expr
}

func (ForExpr) exprNode() {}

// Index represents an array or dictionary access like pe.sections[0].
type Index struct {
	Base  Expr
	Index Expr
}

func (Index) exprNode() {}

// Field represents a member access like pe.number_of_sections.
type Field struct {
	Base Expr
	Name string
}

func (Field) exprNode() {}

// StrLit represents a text string literal in a condition.
type StrLit struct {
	Value string
}

func (StrLit) exprNode() {}

// BoolLit represents the true and false literals.
type BoolLit struct {
	Value bool
}

func (BoolLit) exprNode() {}

// Ident represents a bare identifier in a condition: a rule reference,
// an external variable, a loop variable or a module name.
type Ident struct {
	Name string
}

func (Ident) exprNode() {}

// RegexLit represents a regular expression used with the matches operator.
type RegexLit struct {
	Pattern   string
	Modifiers RegexModifiers
}

func (RegexLit) exprNode() {}

// NOf represents "<quantifier> of <string set>". Quant is "any", "all",
// "none" or "count" (with N).
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
