package scanner

import (
	"fmt"
	"testing"

	"github.com/sansecio/yargo/ast"
	"github.com/sansecio/yargo/parser"
)

// parseTestCondition parses a condition string using the main parser.
func parseTestCondition(t *testing.T, cond string) ast.Expr {
	t.Helper()
	p, err := parser.New()
	if err != nil {
		t.Fatalf("failed to create parser: %v", err)
	}
	// Wrap condition in a minimal rule
	rule := fmt.Sprintf(`rule test { strings: $x = "x" condition: %s }`, cond)
	rs, err := p.Parse(rule)
	if err != nil {
		t.Fatalf("failed to parse condition %q: %v", cond, err)
	}
	return rs.Rules[0].Condition
}

func TestEvalStringRef(t *testing.T) {
	tests := []struct {
		name    string
		matches map[string][]int
		want    bool
	}{
		{"matched", map[string][]int{"$foo": {0}}, true},
		{"not_matched", map[string][]int{}, false},
		{"other_matched", map[string][]int{"$bar": {0}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr := ast.StringRef{Name: "$foo"}
			ctx := &evalContext{matches: tt.matches, buf: nil}
			got := evalExpr(expr, ctx)
			if got != tt.want {
				t.Errorf("evalExpr() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEvalAtExpr(t *testing.T) {
	tests := []struct {
		name    string
		matches map[string][]int
		pos     int64
		want    bool
	}{
		{"at_correct_pos", map[string][]int{"$foo": {0}}, 0, true},
		{"at_wrong_pos", map[string][]int{"$foo": {5}}, 0, false},
		{"at_multiple_one_correct", map[string][]int{"$foo": {1, 0, 3}}, 0, true},
		{"not_matched", map[string][]int{}, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr := ast.AtExpr{
				Ref: ast.StringRef{Name: "$foo"},
				Pos: ast.IntLit{Value: tt.pos},
			}
			ctx := &evalContext{matches: tt.matches, buf: nil}
			got := evalExpr(expr, ctx)
			if got != tt.want {
				t.Errorf("evalExpr() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEvalUint32be(t *testing.T) {
	// GIF89a magic: 0x47494638 0x3961
	buf := []byte("GIF89a")
	tests := []struct {
		name string
		pos  int64
		want int64
	}{
		{"pos_0", 0, 0x47494638}, // "GIF8"
		{"pos_1", 1, 0x49463839}, // "IF89"
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr := ast.FuncCall{Name: "uint32be", Args: []ast.Expr{ast.IntLit{Value: tt.pos}}}
			ctx := &evalContext{matches: nil, buf: buf}
			got := evalFuncCall(expr, ctx)
			if got != tt.want {
				t.Errorf("evalFuncCall() = %d (0x%x), want %d (0x%x)", got, got, tt.want, tt.want)
			}
		})
	}
}

func TestEvalUint16be(t *testing.T) {
	buf := []byte("GIF89a")
	tests := []struct {
		name string
		pos  int64
		want int64
	}{
		{"pos_4", 4, 0x3961}, // "9a"
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr := ast.FuncCall{Name: "uint16be", Args: []ast.Expr{ast.IntLit{Value: tt.pos}}}
			ctx := &evalContext{matches: nil, buf: buf}
			got := evalFuncCall(expr, ctx)
			if got != tt.want {
				t.Errorf("evalFuncCall() = %d (0x%x), want %d (0x%x)", got, got, tt.want, tt.want)
			}
		})
	}
}

func TestEvalComparison(t *testing.T) {
	buf := []byte("GIF89a")
	tests := []struct {
		name string
		expr ast.Expr
		want bool
	}{
		{
			"gif89a_magic",
			ast.BinaryExpr{
				Op:    "==",
				Left:  ast.FuncCall{Name: "uint32be", Args: []ast.Expr{ast.IntLit{Value: 0}}},
				Right: ast.IntLit{Value: 0x47494638},
			},
			true,
		},
		{
			"gif89a_version",
			ast.BinaryExpr{
				Op:    "==",
				Left:  ast.FuncCall{Name: "uint16be", Args: []ast.Expr{ast.IntLit{Value: 4}}},
				Right: ast.IntLit{Value: 0x3961},
			},
			true,
		},
		{
			"wrong_magic",
			ast.BinaryExpr{
				Op:    "==",
				Left:  ast.FuncCall{Name: "uint32be", Args: []ast.Expr{ast.IntLit{Value: 0}}},
				Right: ast.IntLit{Value: 0xDEADBEEF},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &evalContext{matches: nil, buf: buf}
			got := evalExpr(tt.expr, ctx)
			if got != tt.want {
				t.Errorf("evalExpr() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEvalAnd(t *testing.T) {
	tests := []struct {
		name    string
		matches map[string][]int
		want    bool
	}{
		{"both_matched", map[string][]int{"$a": {0}, "$b": {1}}, true},
		{"only_a", map[string][]int{"$a": {0}}, false},
		{"only_b", map[string][]int{"$b": {0}}, false},
		{"neither", map[string][]int{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr := ast.BinaryExpr{
				Op:    "and",
				Left:  ast.StringRef{Name: "$a"},
				Right: ast.StringRef{Name: "$b"},
			}
			ctx := &evalContext{matches: tt.matches, buf: nil}
			got := evalExpr(expr, ctx)
			if got != tt.want {
				t.Errorf("evalExpr() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEvalOr(t *testing.T) {
	tests := []struct {
		name    string
		matches map[string][]int
		want    bool
	}{
		{"both_matched", map[string][]int{"$a": {0}, "$b": {1}}, true},
		{"only_a", map[string][]int{"$a": {0}}, true},
		{"only_b", map[string][]int{"$b": {0}}, true},
		{"neither", map[string][]int{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr := ast.BinaryExpr{
				Op:    "or",
				Left:  ast.StringRef{Name: "$a"},
				Right: ast.StringRef{Name: "$b"},
			}
			ctx := &evalContext{matches: tt.matches, buf: nil}
			got := evalExpr(expr, ctx)
			if got != tt.want {
				t.Errorf("evalExpr() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEvalAnyOf(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		matches map[string][]int
		strings []string
		want    bool
	}{
		{"them_one_matched", "them", map[string][]int{"$a": {0}}, []string{"$a", "$b"}, true},
		{"them_none_matched", "them", map[string][]int{}, []string{"$a", "$b"}, false},
		{"wildcard_matched", "$b64_*", map[string][]int{"$b64_foo": {0}}, []string{"$a", "$b64_foo", "$b64_bar"}, true},
		{"wildcard_not_matched", "$b64_*", map[string][]int{"$a": {0}}, []string{"$a", "$b64_foo"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr := ast.AnyOf{Pattern: tt.pattern}
			ctx := &evalContext{matches: tt.matches, buf: nil, stringNames: tt.strings}
			got := evalExpr(expr, ctx)
			if got != tt.want {
				t.Errorf("evalExpr() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEvalAllOf(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		matches map[string][]int
		strings []string
		want    bool
	}{
		{"them_all_matched", "them", map[string][]int{"$a": {0}, "$b": {1}}, []string{"$a", "$b"}, true},
		{"them_some_matched", "them", map[string][]int{"$a": {0}}, []string{"$a", "$b"}, false},
		{"them_none_matched", "them", map[string][]int{}, []string{"$a", "$b"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr := ast.AllOf{Pattern: tt.pattern}
			ctx := &evalContext{matches: tt.matches, buf: nil, stringNames: tt.strings}
			got := evalExpr(expr, ctx)
			if got != tt.want {
				t.Errorf("evalExpr() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEvalParen(t *testing.T) {
	matches := map[string][]int{"$a": {0}, "$c": {2}}
	expr := ast.BinaryExpr{
		Op: "or",
		Left: ast.ParenExpr{
			Inner: ast.BinaryExpr{
				Op:    "and",
				Left:  ast.StringRef{Name: "$a"},
				Right: ast.StringRef{Name: "$b"},
			},
		},
		Right: ast.StringRef{Name: "$c"},
	}
	ctx := &evalContext{matches: matches, buf: nil}
	got := evalExpr(expr, ctx)
	if !got {
		t.Errorf("evalExpr() = %v, want true", got)
	}
}

func TestEvalComplexCondition1(t *testing.T) {
	// From php_code_in_gif: $php and ( (uint32be(0) == 0x47494638 and uint16be(4) == 0x3961) or (...3761) )
	// GIF89a has magic 0x47494638 and version 0x3961
	buf := append([]byte("GIF89a"), []byte("<?php echo 1;")...)
	matches := map[string][]int{"$php": {6}}
	stringNames := []string{"$php"}

	expr := parseTestCondition(t, `$php and ( (uint32be(0) == 0x47494638 and uint16be(4) == 0x3961) or (uint32be(0) == 0x47494638 and uint16be(4) == 0x3761) )`)

	ctx := &evalContext{matches: matches, buf: buf, stringNames: stringNames}
	got := evalExpr(expr, ctx)
	if !got {
		t.Errorf("evalExpr() = %v, want true", got)
	}

	// Test GIF87a (0x3761) version
	buf87 := append([]byte("GIF87a"), []byte("<?php echo 1;")...)
	ctx87 := &evalContext{matches: matches, buf: buf87, stringNames: stringNames}
	got87 := evalExpr(expr, ctx87)
	if !got87 {
		t.Errorf("evalExpr() for GIF87a = %v, want true", got87)
	}

	// Test non-GIF should fail
	bufPNG := append([]byte("\x89PNG\r\n"), []byte("<?php echo 1;")...)
	ctxPNG := &evalContext{matches: matches, buf: bufPNG, stringNames: stringNames}
	gotPNG := evalExpr(expr, ctxPNG)
	if gotPNG {
		t.Errorf("evalExpr() for PNG = %v, want false", gotPNG)
	}
}

func TestEvalComplexCondition2(t *testing.T) {
	// From php_code_in_jpeg: ($jpg at 0) and $php
	// JPEG magic is 0xFFD8FF
	buf := append([]byte{0xFF, 0xD8, 0xFF, 0xE0}, []byte("<?php echo 1;")...)
	matches := map[string][]int{"$jpg": {0}, "$php": {4}}
	stringNames := []string{"$jpg", "$php"}

	expr := parseTestCondition(t, `($jpg at 0) and $php`)

	ctx := &evalContext{matches: matches, buf: buf, stringNames: stringNames}
	got := evalExpr(expr, ctx)
	if !got {
		t.Errorf("evalExpr() = %v, want true", got)
	}

	// Test jpg not at 0
	matchesWrongPos := map[string][]int{"$jpg": {5}, "$php": {10}}
	ctxWrongPos := &evalContext{matches: matchesWrongPos, buf: buf, stringNames: stringNames}
	gotWrongPos := evalExpr(expr, ctxWrongPos)
	if gotWrongPos {
		t.Errorf("evalExpr() with wrong pos = %v, want false", gotWrongPos)
	}
}

func TestEvalComplexCondition3(t *testing.T) {
	// From b64_js_in_png: $png at 0 and any of ($b64_*)
	buf := []byte("\x89PNG\r\n\x1a\nsome base64 content")
	matches := map[string][]int{"$png": {0}, "$b64_foo": {10}}
	stringNames := []string{"$png", "$b64_foo", "$b64_bar"}

	expr := parseTestCondition(t, `$png at 0 and any of ($b64_*)`)

	ctx := &evalContext{matches: matches, buf: buf, stringNames: stringNames}
	got := evalExpr(expr, ctx)
	if !got {
		t.Errorf("evalExpr() = %v, want true", got)
	}

	// Test no b64_* matched
	matchesNoB64 := map[string][]int{"$png": {0}}
	ctxNoB64 := &evalContext{matches: matchesNoB64, buf: buf, stringNames: stringNames}
	gotNoB64 := evalExpr(expr, ctxNoB64)
	if gotNoB64 {
		t.Errorf("evalExpr() with no b64 = %v, want false", gotNoB64)
	}
}
