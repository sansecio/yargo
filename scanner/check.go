package scanner

import (
	"fmt"
	"slices"
	"strings"

	"github.com/sansecio/yargo/ast"
)

// condChecker walks rule conditions at compile time. It reports why a rule
// uses something the scanner cannot evaluate, so the rule is skipped, and
// fails what libyara itself rejects, like undefined identifiers.
type condChecker struct {
	rules   *Rules
	imports map[string]bool
	skipped map[string]bool // rules of the set that were not compiled
	vars    []string        // loop variables in scope
	err     error
}

func newCondChecker(rules *Rules, imports []string) *condChecker {
	c := &condChecker{rules: rules, imports: map[string]bool{}, skipped: map[string]bool{}}
	for _, m := range imports {
		c.imports[m] = true
	}
	return c
}

// rule returns the reason to skip r, or an error when libyara would refuse
// to compile it.
func (c *condChecker) rule(r *ast.Rule) (string, error) {
	c.err = nil
	reason := c.reason(r.Condition)
	if c.err != nil {
		return "", c.err
	}
	if hasUnsupportedModifier(r) {
		return "unsupported string modifier", nil
	}
	return reason, nil
}

func (c *condChecker) fail(format string, args ...any) string {
	if c.err == nil {
		c.err = fmt.Errorf(format, args...)
	}
	return c.err.Error()
}

func (c *condChecker) reason(expr ast.Expr) string {
	switch e := expr.(type) {
	case ast.Ident:
		return c.ident(e)
	case ast.BinaryExpr:
		return c.first(e.Left, e.Right)
	case ast.NotExpr:
		return c.reason(e.Inner)
	case ast.ParenExpr:
		return c.reason(e.Inner)
	case ast.AtExpr:
		return c.reason(e.Pos)
	case ast.UnaryExpr:
		return c.reason(e.Inner)
	case ast.OffsetOf:
		return c.first(e.Index)
	case ast.LenOf:
		return c.first(e.Index)
	case ast.InExpr:
		return c.first(e.Lo, e.Hi)
	case ast.ForExpr:
		return c.forLoop(e)
	case ast.Field:
		return c.field(e)
	case ast.Index:
		return c.index(e)
	case ast.FuncCall:
		if reason := c.callee(e.Name, len(e.Args)); reason != "" {
			return reason
		}
		return c.first(e.Args...)
	}
	return ""
}

func (c *condChecker) first(exprs ...ast.Expr) string {
	for _, e := range exprs {
		if e == nil {
			continue
		}
		if reason := c.reason(e); reason != "" {
			return reason
		}
	}
	return ""
}

func (c *condChecker) forLoop(e ast.ForExpr) string {
	if e.Var == "" {
		return c.reason(e.Body)
	}
	if reason := c.first(e.Lo, e.Hi); reason != "" {
		return reason
	}
	c.vars = append(c.vars, e.Var)
	defer func() { c.vars = c.vars[:len(c.vars)-1] }()
	return c.reason(e.Body)
}

func (c *condChecker) ident(e ast.Ident) string {
	if slices.Contains(c.vars, e.Name) || c.rules.externals[e.Name] {
		return ""
	}
	if _, ok := c.rules.ruleIndex[e.Name]; ok {
		return ""
	}
	if c.skipped[e.Name] {
		return "references skipped rule " + e.Name
	}
	if e.Name == "entrypoint" {
		return "deprecated entrypoint keyword, use pe.entry_point"
	}
	module, _, dotted := strings.Cut(e.Name, ".")
	if !dotted {
		return c.fail("undefined identifier %q", e.Name)
	}
	if reason := c.module(module); reason != "" {
		return reason
	}
	if module != "pe" || !supportedPEMember(e) {
		return "unsupported module member " + e.Name
	}
	return ""
}

// module returns why identifiers of module cannot be evaluated: libyara
// rejects a module that was not imported, and only pe, math and hash are
// implemented here.
func (c *condChecker) module(module string) string {
	if !c.imports[module] {
		return c.fail("undefined identifier %q", module)
	}
	switch module {
	case "pe", "math", "hash":
		return ""
	}
	return "unsupported module " + module
}

func (c *condChecker) field(e ast.Field) string {
	idx, ok := e.Base.(ast.Index)
	if !ok {
		return "unsupported module member " + e.Name
	}
	if reason := c.indexBase(idx); reason != "" {
		return reason
	}
	if !supportedPEMember(e) {
		return "unsupported module member " + e.Name
	}
	return c.reason(idx.Index)
}

func (c *condChecker) index(e ast.Index) string {
	if reason := c.indexBase(e); reason != "" {
		return reason
	}
	if base, ok := e.Base.(ast.Ident); ok && base.Name == "pe.version_info" {
		return c.reason(e.Index)
	}
	return "unsupported module field index"
}

func (c *condChecker) indexBase(e ast.Index) string {
	base, ok := e.Base.(ast.Ident)
	if !ok {
		return "unsupported module field index"
	}
	module, _, _ := strings.Cut(base.Name, ".")
	return c.module(module)
}

func (c *condChecker) callee(name string, args int) string {
	module, _, dotted := strings.Cut(name, ".")
	if !dotted {
		if _, ok := integerReaders[name]; ok {
			return ""
		}
		return c.fail("undefined identifier %q", name)
	}
	if reason := c.module(module); reason != "" {
		return reason
	}
	if module == "pe" {
		if !supportedPEFunction(name, args) {
			return "unsupported pe function " + name
		}
		return ""
	}
	if _, ok := supportedFunctions[name]; !ok {
		return "unsupported function " + name
	}
	return ""
}
