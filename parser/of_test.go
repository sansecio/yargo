package parser

import (
	"reflect"
	"testing"

	"github.com/sansecio/yargo/ast"
)

func TestParseStringSetQuantifiers(t *testing.T) {
	tests := []struct {
		cond string
		want ast.Expr
	}{
		{`2 of them`, ast.NOf{Quant: "count", N: 2, Patterns: []string{"them"}}},
		{`1 of ($a*)`, ast.NOf{Quant: "count", N: 1, Patterns: []string{"$a*"}}},
		{`3 of ($a, $b, $c*)`, ast.NOf{Quant: "count", N: 3, Patterns: []string{"$a", "$b", "$c*"}}},
		{`none of them`, ast.NOf{Quant: "none", Patterns: []string{"them"}}},
		{`none of ($a*, $b)`, ast.NOf{Quant: "none", Patterns: []string{"$a*", "$b"}}},
		{`any of ($a, $b)`, ast.NOf{Quant: "any", Patterns: []string{"$a", "$b"}}},
		{`all of ($a*, $b*)`, ast.NOf{Quant: "all", Patterns: []string{"$a*", "$b*"}}},
		{`any of ($a*)`, ast.AnyOf{Pattern: "$a*"}},
		{`all of them`, ast.AllOf{Pattern: "them"}},
	}
	for _, tt := range tests {
		t.Run(tt.cond, func(t *testing.T) {
			rs := mustParse(t, `rule t { strings: $a = "x" condition: `+tt.cond+` }`)
			if got := rs.Rules[0].Condition; !reflect.DeepEqual(got, tt.want) {
				t.Errorf("expected %#v, got %#v", tt.want, got)
			}
		})
	}
}

func TestParseSizeSuffixes(t *testing.T) {
	tests := []struct {
		cond string
		want int64
	}{
		{"filesize < 10KB", 10 * 1024},
		{"filesize < 2MB", 2 * 1024 * 1024},
		{"filesize < 5", 5},
	}
	for _, tt := range tests {
		t.Run(tt.cond, func(t *testing.T) {
			rs := mustParse(t, `rule t { condition: `+tt.cond+` }`)
			be, ok := rs.Rules[0].Condition.(ast.BinaryExpr)
			if !ok {
				t.Fatalf("expected BinaryExpr, got %T", rs.Rules[0].Condition)
			}
			if got := be.Right; !reflect.DeepEqual(got, ast.IntLit{Value: tt.want}) {
				t.Errorf("expected %d, got %#v", tt.want, got)
			}
		})
	}
}
