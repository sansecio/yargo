// Package ast defines the Abstract Syntax Tree types for YARA rules.
package ast

// RuleSet represents a collection of YARA rules.
type RuleSet struct {
	Rules []*Rule
}

// Rule represents a single YARA rule.
type Rule struct {
	Name      string
	Meta      []*MetaEntry
	Strings   []*StringDef
	Condition Expr // parsed condition expression
}

// MetaEntry represents a key-value pair in the meta section.
type MetaEntry struct {
	Key   string
	Value interface{} // string or int64
}

// StringDef represents a string definition in the strings section.
type StringDef struct {
	Name      string      // $identifier or $ (anonymous)
	Value     StringValue // TextString, HexString, or RegexString
	Modifiers StringModifiers
}

// StringModifiers represents the modifiers applied to a string.
type StringModifiers struct {
	Base64     bool
	Base64Wide bool
	Fullword   bool
	Wide       bool
	Ascii      bool
	Nocase     bool
	Xor        bool
	Private    bool
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
