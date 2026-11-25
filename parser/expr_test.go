package parser

import (
	"reflect"
	"testing"

	"github.com/sansecio/yargo/ast"
)

func TestParseExpressions(t *testing.T) {
	i := func(v int64) ast.Expr { return ast.IntLit{Value: v} }
	tests := []struct {
		cond string
		want ast.Expr
	}{
		{`#a == 2`, ast.BinaryExpr{Op: "==", Left: ast.CountOf{Name: "$a"}, Right: i(2)}},
		{`@a[2] < 10`, ast.BinaryExpr{Op: "<", Left: ast.OffsetOf{Name: "$a", Index: i(2)}, Right: i(10)}},
		{`@a < 10`, ast.BinaryExpr{Op: "<", Left: ast.OffsetOf{Name: "$a"}, Right: i(10)}},
		{`!a[1] == 3`, ast.BinaryExpr{Op: "==", Left: ast.LenOf{Name: "$a", Index: i(1)}, Right: i(3)}},
		{`!a != 3`, ast.BinaryExpr{Op: "!=", Left: ast.LenOf{Name: "$a"}, Right: i(3)}},
		{`$a in (0..100)`, ast.InExpr{Ref: ast.StringRef{Name: "$a"}, Lo: i(0), Hi: i(100)}},
		{`$a in (filesize-10..filesize)`, ast.InExpr{Ref: ast.StringRef{Name: "$a"}, Lo: ast.BinaryExpr{Op: "-", Left: ast.Filesize{}, Right: i(10)}, Hi: ast.Filesize{}}},
		{`$a at filesize-4`, ast.AtExpr{Ref: ast.StringRef{Name: "$a"}, Pos: ast.BinaryExpr{Op: "-", Left: ast.Filesize{}, Right: i(4)}}},
		{`1 + 2 * 3 == 7`, ast.BinaryExpr{Op: "==", Left: ast.BinaryExpr{Op: "+", Left: i(1), Right: ast.BinaryExpr{Op: "*", Left: i(2), Right: i(3)}}, Right: i(7)}},
		{`8 \ 2 % 3 == 1`, ast.BinaryExpr{Op: "==", Left: ast.BinaryExpr{Op: "%", Left: ast.BinaryExpr{Op: "/", Left: i(8), Right: i(2)}, Right: i(3)}, Right: i(1)}},
		{`(1 | 2 & 3) == 3`, ast.BinaryExpr{Op: "==", Left: ast.ParenExpr{Inner: ast.BinaryExpr{Op: "|", Left: i(1), Right: ast.BinaryExpr{Op: "&", Left: i(2), Right: i(3)}}}, Right: i(3)}},
		{`1 << 2 + 1 == 8`, ast.BinaryExpr{Op: "==", Left: ast.BinaryExpr{Op: "<<", Left: i(1), Right: ast.BinaryExpr{Op: "+", Left: i(2), Right: i(1)}}, Right: i(8)}},
		{`-1 < ~2`, ast.BinaryExpr{Op: "<", Left: ast.UnaryExpr{Op: "-", Inner: i(1)}, Right: ast.UnaryExpr{Op: "~", Inner: i(2)}}},
		{`math.entropy(0, filesize) > 7.5`, ast.BinaryExpr{Op: ">", Left: ast.FuncCall{Name: "math.entropy", Args: []ast.Expr{i(0), ast.Filesize{}}}, Right: ast.FloatLit{Value: 7.5}}},
		{`uint8(filesize-1) == 0`, ast.BinaryExpr{Op: "==", Left: ast.FuncCall{Name: "uint8", Args: []ast.Expr{ast.BinaryExpr{Op: "-", Left: ast.Filesize{}, Right: i(1)}}}, Right: i(0)}},
		{`uint16(uint32(0x3c) + 11) == 0x59`, ast.BinaryExpr{Op: "==", Left: ast.FuncCall{Name: "uint16", Args: []ast.Expr{ast.BinaryExpr{Op: "+", Left: ast.FuncCall{Name: "uint32", Args: []ast.Expr{i(0x3c)}}, Right: i(11)}}}, Right: i(0x59)}},
		{`pe.sections[0].name == "x"`, ast.BinaryExpr{Op: "==", Left: ast.Field{Base: ast.Index{Base: ast.Ident{Name: "pe.sections"}, Index: i(0)}, Name: "name"}, Right: ast.StrLit{Value: "x"}}},
		{`pe.version_info["Key"] contains "x"`, ast.BinaryExpr{Op: "contains", Left: ast.Index{Base: ast.Ident{Name: "pe.version_info"}, Index: ast.StrLit{Value: "Key"}}, Right: ast.StrLit{Value: "x"}}},
		{`pe.imports("a.dll", "f") and pe.is_dll()`, ast.BinaryExpr{Op: "and", Left: ast.FuncCall{Name: "pe.imports", Args: []ast.Expr{ast.StrLit{Value: "a.dll"}, ast.StrLit{Value: "f"}}}, Right: ast.FuncCall{Name: "pe.is_dll"}}},
		{`for any i in (1..3) : (@a[i] > 0)`, ast.ForExpr{Quant: "any", Var: "i", Lo: i(1), Hi: i(3), Body: ast.ParenExpr{Inner: ast.BinaryExpr{Op: ">", Left: ast.OffsetOf{Name: "$a", Index: ast.Ident{Name: "i"}}, Right: i(0)}}}},
		{`for 2 i in (0..9) : (i > 0)`, ast.ForExpr{Quant: "count", N: 2, Var: "i", Lo: i(0), Hi: i(9), Body: ast.ParenExpr{Inner: ast.BinaryExpr{Op: ">", Left: ast.Ident{Name: "i"}, Right: i(0)}}}},
		{`for all of ($a*) : ($ at 0)`, ast.ForExpr{Quant: "all", Patterns: []string{"$a*"}, Body: ast.ParenExpr{Inner: ast.AtExpr{Ref: ast.StringRef{Name: "$"}, Pos: i(0)}}}},
		{`for any of them : ($)`, ast.ForExpr{Quant: "any", Patterns: []string{"them"}, Body: ast.ParenExpr{Inner: ast.StringRef{Name: "$"}}}},
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

func TestParseXorModifier(t *testing.T) {
	tests := []struct {
		mod  string
		want *ast.XorRange
	}{
		{"xor", &ast.XorRange{Min: 0, Max: 255}},
		{"xor(1)", &ast.XorRange{Min: 1, Max: 1}},
		{"xor(0x01-0xff)", &ast.XorRange{Min: 1, Max: 255}},
		{"xor(16-32)", &ast.XorRange{Min: 16, Max: 32}},
	}
	for _, tt := range tests {
		t.Run(tt.mod, func(t *testing.T) {
			rs := mustParse(t, `rule t { strings: $a = "x" `+tt.mod+` condition: $a }`)
			m := rs.Rules[0].Strings[0].Modifiers
			if !reflect.DeepEqual(m.Xor, tt.want) || len(m.Unsupported) != 0 {
				t.Errorf("expected xor %+v, got %+v", tt.want, m)
			}
		})
	}
}

func TestParseXorModifierInvalidRange(t *testing.T) {
	rs := mustParse(t, `rule t { strings: $a = "x" xor(0x300) condition: $a }`)
	m := rs.Rules[0].Strings[0].Modifiers
	if m.Xor != nil || len(m.Unsupported) != 1 {
		t.Errorf("expected invalid xor range to stay unsupported, got %+v", m)
	}
}
