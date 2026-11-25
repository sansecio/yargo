%{
package parser

import (
	"github.com/sansecio/yargo/ast"
)
%}

%union {
	str       string
	num       int64
	byt       byte
	rule      *ast.Rule
	rules     []*ast.Rule
	meta      []*ast.MetaEntry
	metaEntry *ast.MetaEntry
	stringDef *ast.StringDef
	stringDefs []*ast.StringDef
	strVal    ast.StringValue
	mods      ast.StringModifiers
	hexTokens []ast.HexToken
	hexToken  ast.HexToken
	expr      ast.Expr
	exprs     []ast.Expr
	strs      []string
	flt       float64
	quant     forQuant
}

%token RULE META STRINGS CONDITION IMPORT PRIVATE GLOBAL
%token <str> IDENT STRING_LIT STRING_IDENT REGEX_LIT MODIFIER
%token <str> COND_IDENT COND_STRING_ID STRING_PATTERN
%token <str> HEX_JUMP HEX_ALT
%token <num> INT_LIT
%token <flt> FLOAT_LIT
%token <str> STR_COUNT STR_OFFSET STR_LEN
%token FOR IN RANGE SHL SHR
%token <byt> HEX_BYTE
%token HEX_WILDCARD
%token AND OR NOT AT ANY ALL NONE OF THEM EQ NE LT GT LE GE FILESIZE
%token CONTAINS ICONTAINS STARTSWITH ISTARTSWITH ENDSWITH IENDSWITH IEQUALS MATCHES TRUE FALSE

%left OR
%left AND
%right NOT
%left '|'
%left '^'
%left '&'
%nonassoc EQ NE LT GT LE GE CONTAINS ICONTAINS STARTSWITH ISTARTSWITH ENDSWITH IENDSWITH IEQUALS MATCHES
%nonassoc AT IN
%left SHL SHR
%left '+' '-'
%left '*' '\\' '%'
%right UMINUS '~'

%type <rules> rule_list
%type <rule> rule rule_head
%type <strs> tags tag_list
%type <meta> meta_section meta_entries
%type <metaEntry> meta_entry
%type <stringDefs> strings_section string_defs
%type <stringDef> string_def
%type <strVal> string_value
%type <mods> modifiers
%type <hexTokens> hex_tokens
%type <hexToken> hex_token
%type <expr> expr primary_expr condition_section
%type <exprs> func_args
%type <strs> string_set set_items
%type <quant> for_quant

%%

file:
	rule_list
	{
		l := yylex.(*yaraLexer)
		l.ruleSet = &ast.RuleSet{Imports: l.imports, Rules: $1}
	}
	;

rule_list:
	/* empty */
	{
		$$ = nil
	}
	| rule_list rule
	{
		$$ = append($1, $2)
	}
	| rule_list IMPORT STRING_LIT
	{
		$$ = $1
		l := yylex.(*yaraLexer)
		l.imports = append(l.imports, unquoteString($3))
	}
	;

rule_head:
	RULE IDENT tags
	{
		$$ = &ast.Rule{Name: $2, Tags: $3}
	}
	| PRIVATE RULE IDENT tags
	{
		$$ = &ast.Rule{Name: $3, Tags: $4, Private: true}
	}
	| GLOBAL RULE IDENT tags
	{
		$$ = &ast.Rule{Name: $3, Tags: $4, Global: true}
	}
	| PRIVATE GLOBAL RULE IDENT tags
	{
		$$ = &ast.Rule{Name: $4, Tags: $5, Private: true, Global: true}
	}
	| GLOBAL PRIVATE RULE IDENT tags
	{
		$$ = &ast.Rule{Name: $4, Tags: $5, Private: true, Global: true}
	}
	;

tags:
	/* empty */
	{
		$$ = nil
	}
	| ':' tag_list
	{
		$$ = $2
	}
	;

tag_list:
	IDENT
	{
		$$ = []string{$1}
	}
	| tag_list IDENT
	{
		$$ = append($1, $2)
	}
	;

rule:
	rule_head '{' meta_section strings_section condition_section '}'
	{
		$$ = $1
		$$.Meta, $$.Strings, $$.Condition = $3, $4, $5
	}
	| rule_head '{' strings_section condition_section '}'
	{
		$$ = $1
		$$.Strings, $$.Condition = $3, $4
	}
	| rule_head '{' meta_section condition_section '}'
	{
		$$ = $1
		$$.Meta, $$.Condition = $3, $4
	}
	| rule_head '{' condition_section '}'
	{
		$$ = $1
		$$.Condition = $3
	}
	;

meta_section:
	META ':' meta_entries
	{
		$$ = $3
	}
	;

meta_entries:
	/* empty */
	{
		$$ = nil
	}
	| meta_entries meta_entry
	{
		$$ = append($1, $2)
	}
	;

meta_entry:
	IDENT '=' STRING_LIT
	{
		$$ = &ast.MetaEntry{Key: $1, Value: unquoteString($3)}
	}
	| IDENT '=' INT_LIT
	{
		$$ = &ast.MetaEntry{Key: $1, Value: $3}
	}
	| IDENT '=' IDENT
	{
		switch $3 {
		case "true":
			$$ = &ast.MetaEntry{Key: $1, Value: true}
		case "false":
			$$ = &ast.MetaEntry{Key: $1, Value: false}
		default:
			yylex.Error("invalid meta value " + $3)
			$$ = &ast.MetaEntry{Key: $1}
		}
	}
	;

strings_section:
	STRINGS ':' string_defs
	{
		$$ = $3
	}
	;

string_defs:
	string_def
	{
		$$ = []*ast.StringDef{$1}
	}
	| string_defs string_def
	{
		$$ = append($1, $2)
	}
	;

string_def:
	STRING_IDENT '=' string_value modifiers
	{
		$$ = &ast.StringDef{
			Name:      $1,
			Value:     $3,
			Modifiers: $4,
		}
	}
	;

string_value:
	STRING_LIT
	{
		$$ = ast.TextString{Value: unquoteString($1)}
	}
	| REGEX_LIT
	{
		pattern, mods := parseRegex($1)
		$$ = ast.RegexString{Pattern: pattern, Modifiers: mods}
	}
	| '{' hex_tokens '}'
	{
		$$ = ast.HexString{Tokens: $2}
	}
	;

modifiers:
	/* empty */
	{
		$$ = ast.StringModifiers{}
	}
	| modifiers MODIFIER
	{
		$$ = $1
		switch $2 {
		case "ascii":
			$$.Ascii = true
		case "wide":
			$$.Wide = true
		case "base64":
			$$.Base64 = true
		case "fullword":
			$$.Fullword = true
		case "nocase":
			$$.Nocase = true
		case "private":
			$$.Private = true
		default:
			// known-but-unimplemented (base64wide, ...), argument forms of
			// supported modifiers, or future modifiers; recorded so the
			// rule is skipped at compile time and reported as a warning
			if x, ok := parseXorModifier($2); ok {
				$$.Xor = x
			} else {
				$$.Unsupported = append($$.Unsupported, $2)
			}
		}
	}
	;

hex_tokens:
	/* empty */
	{
		$$ = nil
	}
	| hex_tokens hex_token
	{
		$$ = append($1, $2)
	}
	;

hex_token:
	HEX_BYTE
	{
		$$ = ast.HexByte{Value: $1}
	}
	| HEX_WILDCARD
	{
		$$ = ast.HexWildcard{}
	}
	| HEX_JUMP
	{
		jump, err := parseHexJump($1)
		if err != nil {
			yylex.Error(err.Error())
		}
		$$ = jump
	}
	| HEX_ALT
	{
		alt, err := parseHexAlt($1)
		if err != nil {
			yylex.Error(err.Error())
		}
		$$ = alt
	}
	;

condition_section:
	CONDITION ':' expr
	{
		$$ = $3
	}
	;

expr:
	primary_expr
	{
		$$ = $1
	}
	| expr OR expr
	{
		$$ = ast.BinaryExpr{Op: "or", Left: $1, Right: $3}
	}
	| expr AND expr
	{
		$$ = ast.BinaryExpr{Op: "and", Left: $1, Right: $3}
	}
	| NOT expr
	{
		$$ = ast.NotExpr{Inner: $2}
	}
	| expr EQ expr
	{
		$$ = comparisonExpr(yylex, "==", $1, $3)
	}
	| expr NE expr
	{
		$$ = comparisonExpr(yylex, "!=", $1, $3)
	}
	| expr LT expr
	{
		$$ = comparisonExpr(yylex, "<", $1, $3)
	}
	| expr GT expr
	{
		$$ = comparisonExpr(yylex, ">", $1, $3)
	}
	| expr LE expr
	{
		$$ = comparisonExpr(yylex, "<=", $1, $3)
	}
	| expr GE expr
	{
		$$ = comparisonExpr(yylex, ">=", $1, $3)
	}
	| expr '+' expr
	{
		$$ = ast.BinaryExpr{Op: "+", Left: $1, Right: $3}
	}
	| expr '-' expr
	{
		$$ = ast.BinaryExpr{Op: "-", Left: $1, Right: $3}
	}
	| expr '*' expr
	{
		$$ = ast.BinaryExpr{Op: "*", Left: $1, Right: $3}
	}
	| expr '\\' expr
	{
		$$ = ast.BinaryExpr{Op: "/", Left: $1, Right: $3}
	}
	| expr '%' expr
	{
		$$ = ast.BinaryExpr{Op: "%", Left: $1, Right: $3}
	}
	| expr '&' expr
	{
		$$ = ast.BinaryExpr{Op: "&", Left: $1, Right: $3}
	}
	| expr '|' expr
	{
		$$ = ast.BinaryExpr{Op: "|", Left: $1, Right: $3}
	}
	| expr '^' expr
	{
		$$ = ast.BinaryExpr{Op: "^", Left: $1, Right: $3}
	}
	| expr SHL expr
	{
		$$ = ast.BinaryExpr{Op: "<<", Left: $1, Right: $3}
	}
	| expr SHR expr
	{
		$$ = ast.BinaryExpr{Op: ">>", Left: $1, Right: $3}
	}
	| '-' expr %prec UMINUS
	{
		$$ = ast.UnaryExpr{Op: "-", Inner: $2}
	}
	| '~' expr
	{
		$$ = ast.UnaryExpr{Op: "~", Inner: $2}
	}
	| expr CONTAINS expr
	{
		$$ = ast.BinaryExpr{Op: "contains", Left: $1, Right: $3}
	}
	| expr ICONTAINS expr
	{
		$$ = ast.BinaryExpr{Op: "icontains", Left: $1, Right: $3}
	}
	| expr STARTSWITH expr
	{
		$$ = ast.BinaryExpr{Op: "startswith", Left: $1, Right: $3}
	}
	| expr ISTARTSWITH expr
	{
		$$ = ast.BinaryExpr{Op: "istartswith", Left: $1, Right: $3}
	}
	| expr ENDSWITH expr
	{
		$$ = ast.BinaryExpr{Op: "endswith", Left: $1, Right: $3}
	}
	| expr IENDSWITH expr
	{
		$$ = ast.BinaryExpr{Op: "iendswith", Left: $1, Right: $3}
	}
	| expr IEQUALS expr
	{
		$$ = ast.BinaryExpr{Op: "iequals", Left: $1, Right: $3}
	}
	| expr MATCHES REGEX_LIT
	{
		pattern, mods := parseRegex($3)
		$$ = ast.BinaryExpr{Op: "matches", Left: $1, Right: ast.RegexLit{Pattern: pattern, Modifiers: mods}}
	}
	;

primary_expr:
	'(' expr ')'
	{
		$$ = ast.ParenExpr{Inner: $2}
	}
	| ANY OF string_set
	{
		if len($3) == 1 {
			$$ = ast.AnyOf{Pattern: $3[0]}
		} else {
			$$ = ast.NOf{Quant: "any", Patterns: $3}
		}
	}
	| ALL OF string_set
	{
		if len($3) == 1 {
			$$ = ast.AllOf{Pattern: $3[0]}
		} else {
			$$ = ast.NOf{Quant: "all", Patterns: $3}
		}
	}
	| NONE OF string_set
	{
		$$ = ast.NOf{Quant: "none", Patterns: $3}
	}
	| INT_LIT OF string_set
	{
		$$ = ast.NOf{Quant: "count", N: $1, Patterns: $3}
	}
	| COND_STRING_ID AT expr %prec AT
	{
		$$ = ast.AtExpr{Ref: ast.StringRef{Name: $1}, Pos: $3}
	}
	| COND_STRING_ID IN '(' expr RANGE expr ')'
	{
		$$ = ast.InExpr{Ref: ast.StringRef{Name: $1}, Lo: $4, Hi: $6}
	}
	| STR_COUNT
	{
		$$ = ast.CountOf{Name: $1}
	}
	| STR_OFFSET
	{
		$$ = ast.OffsetOf{Name: $1}
	}
	| STR_OFFSET '[' expr ']'
	{
		$$ = ast.OffsetOf{Name: $1, Index: $3}
	}
	| STR_LEN
	{
		$$ = ast.LenOf{Name: $1}
	}
	| STR_LEN '[' expr ']'
	{
		$$ = ast.LenOf{Name: $1, Index: $3}
	}
	| FLOAT_LIT
	{
		$$ = ast.FloatLit{Value: $1}
	}
	| FOR for_quant COND_IDENT IN '(' expr RANGE expr ')' ':' '(' expr ')'
	{
		$$ = ast.ForExpr{Quant: $2.quant, N: $2.n, Var: $3, Lo: $6, Hi: $8, Body: ast.ParenExpr{Inner: $12}}
	}
	| FOR for_quant OF string_set ':' '(' expr ')'
	{
		$$ = ast.ForExpr{Quant: $2.quant, N: $2.n, Patterns: $4, Body: ast.ParenExpr{Inner: $7}}
	}
	| COND_IDENT '(' func_args ')'
	{
		$$ = ast.FuncCall{Name: $1, Args: $3}
	}
	| COND_IDENT
	{
		$$ = ast.Ident{Name: $1}
	}
	| STRING_LIT
	{
		$$ = ast.StrLit{Value: unquoteString($1)}
	}
	| TRUE
	{
		$$ = ast.BoolLit{Value: true}
	}
	| FALSE
	{
		$$ = ast.BoolLit{Value: false}
	}
	| COND_STRING_ID
	{
		$$ = ast.StringRef{Name: $1}
	}
	| INT_LIT
	{
		$$ = ast.IntLit{Value: $1}
	}
	| FILESIZE
	{
		$$ = ast.Filesize{}
	}
	;

for_quant:
	ANY
	{
		$$ = forQuant{quant: "any"}
	}
	| ALL
	{
		$$ = forQuant{quant: "all"}
	}
	| NONE
	{
		$$ = forQuant{quant: "none"}
	}
	| INT_LIT
	{
		$$ = forQuant{quant: "count", n: $1}
	}
	;

string_set:
	THEM
	{
		$$ = []string{"them"}
	}
	| '(' set_items ')'
	{
		$$ = $2
	}
	;

set_items:
	STRING_PATTERN
	{
		$$ = []string{$1}
	}
	| COND_STRING_ID
	{
		$$ = []string{$1}
	}
	| set_items ',' STRING_PATTERN
	{
		$$ = append($1, $3)
	}
	| set_items ',' COND_STRING_ID
	{
		$$ = append($1, $3)
	}
	;

func_args:
	/* empty */
	{
		$$ = nil
	}
	| primary_expr
	{
		$$ = []ast.Expr{$1}
	}
	| func_args ',' primary_expr
	{
		$$ = append($1, $3)
	}
	;

%%
