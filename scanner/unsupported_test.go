package scanner

import (
	"testing"

	"github.com/sansecio/yargo/ast"
	"github.com/sansecio/yargo/parser"
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

func TestSkippedRegexStringSkipsTheWholeRule(t *testing.T) {
	rs, err := parser.New().Parse(`rule negated { strings: $a = "abc" $re = /xyz/ nocase condition: $a and not $re }`)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := CompileWithOptions(rs, CompileOptions{SkipInvalidRegex: true})
	if err != nil {
		t.Fatal(err)
	}
	if rules.NumRules() != 0 || len(rules.Skipped()) != 1 {
		t.Errorf("expected the rule to be skipped, got %d rules, %+v", rules.NumRules(), rules.Skipped())
	}
	if _, err := Compile(rs); err == nil {
		t.Error("expected a compile error without SkipInvalidRegex")
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
