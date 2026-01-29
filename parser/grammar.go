package parser

// Grammar structs for participle parser.
// These define the YARA grammar using struct tags.

// File represents a complete YARA file with multiple rules.
type File struct {
	Rules []*RuleGrammar `parser:"@@*"`
}

// RuleGrammar represents a YARA rule in the grammar.
type RuleGrammar struct {
	Name      string           `parser:"'rule' @Ident '{'"`
	Meta      *MetaSection     `parser:"@@?"`
	Strings   *StringsSection  `parser:"@@?"`
	Condition *ConditionClause `parser:"@@ '}'"`
}

// MetaSection represents the meta: section of a rule.
type MetaSection struct {
	Entries []*MetaEntryGrammar `parser:"'meta' ':' @@*"`
}

// MetaEntryGrammar represents a single meta entry.
type MetaEntryGrammar struct {
	Key         string  `parser:"@Ident '='"`
	StringValue *string `parser:"( @String"`
	IntValue    *int64  `parser:"| @Int )"`
}

// StringsSection represents the strings: section of a rule.
type StringsSection struct {
	Defs []*StringDefGrammar `parser:"'strings' ':' @@+"`
}

// StringDefGrammar represents a string definition.
type StringDefGrammar struct {
	Name      string            `parser:"@StringIdent '='"`
	Text      *string           `parser:"( @String"`
	Hex       *HexStringGrammar `parser:"| @@"`
	Regex     *string           `parser:"| @Regex )"`
	Modifiers []string          `parser:"@Modifier*"`
}

// HexStringGrammar represents a hex string { ... }.
type HexStringGrammar struct {
	Tokens []*HexTokenGrammar `parser:"HexOpen @@* HexClose"`
}

// HexTokenGrammar represents a token inside a hex string.
type HexTokenGrammar struct {
	Byte     *string `parser:"( @HexByte"`
	Wildcard bool    `parser:"| @HexWildcard"`
	Jump     *string `parser:"| @HexJump"`
	Alt      *string `parser:"| @HexAlt )"`
}

// ConditionClause represents the condition: section.
type ConditionClause struct {
	Parts []string `parser:"'condition' ':' @(CondString | CondRegex | CondChar)*"`
}
