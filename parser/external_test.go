package parser

import (
	"reflect"
	"testing"

	"github.com/sansecio/yargo/ast"
)

func TestParseExternalVariableConditions(t *testing.T) {
	tests := []struct {
		cond string
		want ast.Expr
	}{
		{`filename == "a.exe"`, ast.BinaryExpr{Op: "==", Left: ast.Ident{Name: "filename"}, Right: ast.StrLit{Value: "a.exe"}}},
		{`filepath != "/tmp"`, ast.BinaryExpr{Op: "!=", Left: ast.Ident{Name: "filepath"}, Right: ast.StrLit{Value: "/tmp"}}},
		{`filepath contains "\\Temp\\"`, ast.BinaryExpr{Op: "contains", Left: ast.Ident{Name: "filepath"}, Right: ast.StrLit{Value: "\\Temp\\"}}},
		{`extension icontains ".d"`, ast.BinaryExpr{Op: "icontains", Left: ast.Ident{Name: "extension"}, Right: ast.StrLit{Value: ".d"}}},
		{`filename startswith "a"`, ast.BinaryExpr{Op: "startswith", Left: ast.Ident{Name: "filename"}, Right: ast.StrLit{Value: "a"}}},
		{`filename istartswith "a"`, ast.BinaryExpr{Op: "istartswith", Left: ast.Ident{Name: "filename"}, Right: ast.StrLit{Value: "a"}}},
		{`filename endswith "a"`, ast.BinaryExpr{Op: "endswith", Left: ast.Ident{Name: "filename"}, Right: ast.StrLit{Value: "a"}}},
		{`filename iendswith "a"`, ast.BinaryExpr{Op: "iendswith", Left: ast.Ident{Name: "filename"}, Right: ast.StrLit{Value: "a"}}},
		{`filename iequals "a"`, ast.BinaryExpr{Op: "iequals", Left: ast.Ident{Name: "filename"}, Right: ast.StrLit{Value: "a"}}},
		{`filename matches /\.txt$/is`, ast.BinaryExpr{Op: "matches", Left: ast.Ident{Name: "filename"}, Right: ast.RegexLit{Pattern: `\.txt$`, Modifiers: ast.RegexModifiers{CaseInsensitive: true, DotMatchesAll: true}}}},
		{`not filename matches /x/`, ast.NotExpr{Inner: ast.BinaryExpr{Op: "matches", Left: ast.Ident{Name: "filename"}, Right: ast.RegexLit{Pattern: "x"}}}},
		{`other_rule`, ast.Ident{Name: "other_rule"}},
		{`true`, ast.BoolLit{Value: true}},
		{`false or true`, ast.BinaryExpr{Op: "or", Left: ast.BoolLit{Value: false}, Right: ast.BoolLit{Value: true}}},
	}
	for _, tt := range tests {
		t.Run(tt.cond, func(t *testing.T) {
			rs := mustParse(t, `rule t { condition: `+tt.cond+` }`)
			if got := rs.Rules[0].Condition; !reflect.DeepEqual(got, tt.want) {
				t.Errorf("expected %#v, got %#v", tt.want, got)
			}
		})
	}
}

func TestParseMetaBool(t *testing.T) {
	rs := mustParse(t, `rule t { meta: confidential = false public = true condition: 1 == 1 }`)
	want := []*ast.MetaEntry{{Key: "confidential", Value: false}, {Key: "public", Value: true}}
	if !reflect.DeepEqual(rs.Rules[0].Meta, want) {
		t.Errorf("expected %v, got %v", want, rs.Rules[0].Meta)
	}
}
