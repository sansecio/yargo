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
	Expr *condOrExpr `parser:"'condition' ':' @@"`
}

// Condition expression grammar (operator precedence: or < and < ==)

type condOrExpr struct {
	Left  *condAndExpr   `parser:"@@"`
	Right []*condAndExpr `parser:"('or' @@)*"`
}

type condAndExpr struct {
	Left  *condCmpExpr   `parser:"@@"`
	Right []*condCmpExpr `parser:"('and' @@)*"`
}

type condCmpExpr struct {
	Left  *condPrimary `parser:"@@"`
	Op    *string      `parser:"(@CondEq)?"`
	Right *condPrimary `parser:"@@?"`
}

type condPrimary struct {
	Paren    *condOrExpr   `parser:"( '(' @@ ')'"`
	AnyOf    *condAnyOf    `parser:"| @@"`
	AllOf    *condAllOf    `parser:"| @@"`
	FuncCall *condFuncCall `parser:"| @@"`
	AtExpr   *condAtExpr   `parser:"| @@"`
	StringID *string       `parser:"| @CondStringID"`
	HexInt   *string       `parser:"| @HexInt"`
	Int      *int64        `parser:"| @CondInt )"`
}

type condAnyOf struct {
	Pattern *string `parser:"'any' 'of' ( @'them' | '(' @StringPattern ')' )"`
}

type condAllOf struct {
	Pattern *string `parser:"'all' 'of' ( @'them' | '(' @StringPattern ')' )"`
}

type condFuncCall struct {
	Name string         `parser:"@CondIdent '('"`
	Args []*condPrimary `parser:"(@@ (',' @@)*)? ')'"`
}

type condAtExpr struct {
	Ref *string      `parser:"@CondStringID 'at'"`
	Pos *condPrimary `parser:"@@"`
}
