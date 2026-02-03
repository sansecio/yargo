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
}

%token RULE META STRINGS CONDITION
%token <str> IDENT STRING_LIT STRING_IDENT REGEX_LIT MODIFIER
%token <str> COND_IDENT COND_STRING_ID STRING_PATTERN
%token <str> HEX_JUMP HEX_ALT
%token <num> INT_LIT
%token <byt> HEX_BYTE
%token HEX_WILDCARD
%token AND OR AT ANY ALL OF THEM EQ

%left OR
%left AND
%left EQ
%nonassoc AT

%type <rules> rule_list
%type <rule> rule
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

%%

file:
	rule_list
	{
		yylex.(*yaraLexer).ruleSet = &ast.RuleSet{Rules: $1}
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
	;

rule:
	RULE IDENT '{' meta_section strings_section condition_section '}'
	{
		$$ = &ast.Rule{
			Name:      $2,
			Meta:      $4,
			Strings:   $5,
			Condition: $6,
		}
	}
	| RULE IDENT '{' strings_section condition_section '}'
	{
		$$ = &ast.Rule{
			Name:      $2,
			Strings:   $4,
			Condition: $5,
		}
	}
	| RULE IDENT '{' meta_section condition_section '}'
	{
		$$ = &ast.Rule{
			Name:      $2,
			Meta:      $4,
			Condition: $5,
		}
	}
	| RULE IDENT '{' condition_section '}'
	{
		$$ = &ast.Rule{
			Name:      $2,
			Condition: $4,
		}
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
		case "base64":
			$$.Base64 = true
		case "base64wide":
			$$.Base64Wide = true
		case "fullword":
			$$.Fullword = true
		case "wide":
			$$.Wide = true
		case "ascii":
			$$.Ascii = true
		case "nocase":
			$$.Nocase = true
		case "xor":
			$$.Xor = true
		case "private":
			$$.Private = true
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
		$$ = parseHexJump($1)
	}
	| HEX_ALT
	{
		$$ = parseHexAlt($1)
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
	| expr EQ expr
	{
		$$ = ast.BinaryExpr{Op: "==", Left: $1, Right: $3}
	}
	;

primary_expr:
	'(' expr ')'
	{
		$$ = ast.ParenExpr{Inner: $2}
	}
	| ANY OF THEM
	{
		$$ = ast.AnyOf{Pattern: "them"}
	}
	| ANY OF '(' STRING_PATTERN ')'
	{
		$$ = ast.AnyOf{Pattern: $4}
	}
	| ALL OF THEM
	{
		$$ = ast.AllOf{Pattern: "them"}
	}
	| ALL OF '(' STRING_PATTERN ')'
	{
		$$ = ast.AllOf{Pattern: $4}
	}
	| COND_STRING_ID AT primary_expr
	{
		$$ = ast.AtExpr{Ref: ast.StringRef{Name: $1}, Pos: $3}
	}
	| COND_IDENT '(' func_args ')'
	{
		$$ = ast.FuncCall{Name: $1, Args: $3}
	}
	| COND_STRING_ID
	{
		$$ = ast.StringRef{Name: $1}
	}
	| INT_LIT
	{
		$$ = ast.IntLit{Value: $1}
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
