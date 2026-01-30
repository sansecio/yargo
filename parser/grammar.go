package parser

// Grammar structs for participle parser.
// These define the YARA grammar using struct tags.

type file struct {
	Rules []*ruleGrammar `parser:"@@*"`
}

type ruleGrammar struct {
	Name      string           `parser:"'rule' @Ident '{'"`
	Meta      *metaSection     `parser:"@@?"`
	Strings   *stringsSection  `parser:"@@?"`
	Condition *conditionClause `parser:"@@ '}'"`
}

type metaSection struct {
	Entries []*metaEntryGrammar `parser:"'meta' ':' @@*"`
}

type metaEntryGrammar struct {
	Key         string  `parser:"@Ident '='"`
	StringValue *string `parser:"( @String"`
	IntValue    *int64  `parser:"| @Int )"`
}

type stringsSection struct {
	Defs []*stringDefGrammar `parser:"'strings' ':' @@+"`
}

type stringDefGrammar struct {
	Name      string            `parser:"@StringIdent '='"`
	Text      *string           `parser:"( @String"`
	Hex       *hexStringGrammar `parser:"| @@"`
	Regex     *string           `parser:"| @Regex )"`
	Modifiers []string          `parser:"@Modifier*"`
}

type hexStringGrammar struct {
	Tokens []*hexTokenGrammar `parser:"HexOpen @@* HexClose"`
}

type hexTokenGrammar struct {
	Byte     *string `parser:"( @HexByte"`
	Wildcard bool    `parser:"| @HexWildcard"`
	Jump     *string `parser:"| @HexJump"`
	Alt      *string `parser:"| @HexAlt )"`
}

type conditionClause struct {
	Parts []string `parser:"'condition' ':' @(CondString | CondRegex | CondChar)*"`
}
