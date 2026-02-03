package parser

import "testing"

type tokenExpect struct {
	tok int
	str string
	num int64
	byt byte
}

func collectTokens(input string) []tokenExpect {
	l := newLexer(input)
	var tokens []tokenExpect
	for {
		var lval yySymType
		tok := l.Lex(&lval)
		if tok == 0 {
			break
		}
		tokens = append(tokens, tokenExpect{
			tok: tok,
			str: lval.str,
			num: lval.num,
			byt: lval.byt,
		})
	}
	return tokens
}

func TestLexMinimalRule(t *testing.T) {
	tokens := collectTokens(`rule test { strings: $ = "text" condition: any of them }`)
	expected := []int{RULE, IDENT, '{', STRINGS, ':', STRING_IDENT, '=', STRING_LIT, CONDITION, ':', ANY, OF, THEM, '}'}
	if len(tokens) != len(expected) {
		t.Fatalf("expected %d tokens, got %d", len(expected), len(tokens))
	}
	for i, tok := range tokens {
		if tok.tok != expected[i] {
			t.Errorf("token %d: expected %d, got %d", i, expected[i], tok.tok)
		}
	}
}

func TestLexHexString(t *testing.T) {
	tokens := collectTokens(`rule t { strings: $ = { FF ?? [4-16] (41|42) } condition: any of them }`)
	// Find hex tokens
	var hexToks []int
	inHex := false
	for _, tok := range tokens {
		if tok.tok == '{' && inHex {
			// This is the hex open
		}
		if tok.tok == STRING_LIT || tok.tok == STRING_IDENT {
			continue
		}
		if tok.tok == HEX_BYTE || tok.tok == HEX_WILDCARD || tok.tok == HEX_JUMP || tok.tok == HEX_ALT {
			hexToks = append(hexToks, tok.tok)
			inHex = true
		}
	}
	expectedHex := []int{HEX_BYTE, HEX_WILDCARD, HEX_JUMP, HEX_ALT}
	if len(hexToks) != len(expectedHex) {
		t.Fatalf("expected %d hex tokens, got %d", len(expectedHex), len(hexToks))
	}
	for i, tok := range hexToks {
		if tok != expectedHex[i] {
			t.Errorf("hex token %d: expected %d, got %d", i, expectedHex[i], tok)
		}
	}
}

func TestLexConditionKeywords(t *testing.T) {
	tokens := collectTokens(`rule t { strings: $ = "x" condition: $a and $b or any of them }`)
	// Find the condition tokens after CONDITION ':'
	var condToks []int
	foundCond := false
	for _, tok := range tokens {
		if tok.tok == ':' && foundCond {
			continue
		}
		if tok.tok == CONDITION {
			foundCond = true
			continue
		}
		if foundCond && tok.tok != ':' {
			condToks = append(condToks, tok.tok)
		}
	}
	expected := []int{COND_STRING_ID, AND, COND_STRING_ID, OR, ANY, OF, THEM, '}'}
	if len(condToks) != len(expected) {
		t.Fatalf("expected %d condition tokens, got %d: %v", len(expected), len(condToks), condToks)
	}
	for i, tok := range condToks {
		if tok != expected[i] {
			t.Errorf("cond token %d: expected %d, got %d", i, expected[i], tok)
		}
	}
}

func TestLexComments(t *testing.T) {
	// Comments should be skipped entirely
	tokens := collectTokens(`// line comment
	rule /* block */ test { strings: $ = "x" condition: any of them }`)
	// Should produce same tokens as without comments
	if len(tokens) == 0 {
		t.Fatal("expected tokens, got none")
	}
	if tokens[0].tok != RULE {
		t.Errorf("expected first token RULE, got %d", tokens[0].tok)
	}
}

func TestLexModifiers(t *testing.T) {
	tokens := collectTokens(`rule t { strings: $ = "x" wide ascii nocase condition: any of them }`)
	var modCount int
	for _, tok := range tokens {
		if tok.tok == MODIFIER {
			modCount++
		}
	}
	if modCount != 3 {
		t.Errorf("expected 3 modifiers, got %d", modCount)
	}
}

func TestLexRegex(t *testing.T) {
	tokens := collectTokens(`rule t { strings: $ = /pattern/sim condition: any of them }`)
	var found bool
	for _, tok := range tokens {
		if tok.tok == REGEX_LIT {
			if tok.str != "/pattern/sim" {
				t.Errorf("expected regex '/pattern/sim', got %q", tok.str)
			}
			found = true
		}
	}
	if !found {
		t.Error("regex token not found")
	}
}

func TestLexStringPattern(t *testing.T) {
	tokens := collectTokens(`rule t { strings: $a = "x" condition: any of ($a*) }`)
	var found bool
	for _, tok := range tokens {
		if tok.tok == STRING_PATTERN {
			if tok.str != "$a*" {
				t.Errorf("expected pattern '$a*', got %q", tok.str)
			}
			found = true
		}
	}
	if !found {
		t.Error("string pattern token not found")
	}
}

func TestLexHexInt(t *testing.T) {
	tokens := collectTokens(`rule t { strings: $ = "x" condition: $a at 0xFF }`)
	var found bool
	for _, tok := range tokens {
		if tok.tok == INT_LIT && tok.num == 0xFF {
			found = true
		}
	}
	if !found {
		t.Error("hex int token not found")
	}
}

func TestLexMeta(t *testing.T) {
	tokens := collectTokens(`rule t { meta: key = "val" num = 42 strings: $ = "x" condition: any of them }`)
	if tokens[3].tok != META {
		t.Errorf("expected META token, got %d", tokens[3].tok)
	}
}

func TestLexError(t *testing.T) {
	l := newLexer(`rule t { condition: @ }`)
	for {
		var lval yySymType
		tok := l.Lex(&lval)
		if tok == 0 {
			break
		}
	}
	if l.err == "" {
		t.Error("expected lexer error for invalid character")
	}
}

func TestLexMultipleRules(t *testing.T) {
	tokens := collectTokens(`
		rule one { strings: $ = "a" condition: any of them }
		rule two { strings: $ = "b" condition: any of them }
	`)
	ruleCount := 0
	for _, tok := range tokens {
		if tok.tok == RULE {
			ruleCount++
		}
	}
	if ruleCount != 2 {
		t.Errorf("expected 2 RULE tokens, got %d", ruleCount)
	}
}

func TestLexEqOperator(t *testing.T) {
	tokens := collectTokens(`rule t { strings: $ = "x" condition: uint32be(0) == 0x46 }`)
	var found bool
	for _, tok := range tokens {
		if tok.tok == EQ {
			found = true
		}
	}
	if !found {
		t.Error("EQ token not found")
	}
}

func TestLexFuncCall(t *testing.T) {
	tokens := collectTokens(`rule t { strings: $ = "x" condition: uint32be(0) == 0x46 }`)
	var found bool
	for _, tok := range tokens {
		if tok.tok == COND_IDENT && tok.str == "uint32be" {
			found = true
		}
	}
	if !found {
		t.Error("function name COND_IDENT not found")
	}
}
