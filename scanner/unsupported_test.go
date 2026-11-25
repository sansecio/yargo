package scanner

import (
	"testing"

	"github.com/sansecio/yargo/ast"
)

func TestUnsupportedModuleFieldsRejectedAtCompile(t *testing.T) {
	for _, cond := range []string{
		`pe.version_info["x"] == "y"`,
		`not pe.version_info["x"] == "y"`,
		`not pe.sections[0].bogus == "x"`,
		`not pe.signatures[0].serial == "x"`,
		`not pe.resources[0].offset == 1`,
		`not pe.overlay.size == 1`,
	} {
		rules := compileSource(t, "rule r { condition: "+cond+" }")
		if rules.NumRules() != 0 || len(rules.Skipped()) != 1 {
			t.Errorf("%s: expected rejection, got %d rules, skipped %+v", cond, rules.NumRules(), rules.Skipped())
		}
	}
}

func TestUnevaluatedNodesAreUndefinedNotFalse(t *testing.T) {
	ctx := &evalContext{}
	for _, e := range []ast.Expr{
		ast.Index{Base: ast.Ident{Name: "pe.version_info"}, Index: ast.StrLit{Value: "k"}},
		ast.Field{Base: ast.Ident{Name: "pe.overlay"}, Name: "size"},
	} {
		if v := evalAny(e, ctx); v != nil {
			t.Errorf("%T evaluated to %v, want undefined", e, v)
		}
		if v := evalAny(ast.NotExpr{Inner: e}, ctx); v != nil {
			t.Errorf("not %T evaluated to %v, want undefined", e, v)
		}
	}
}
