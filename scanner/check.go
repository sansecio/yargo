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
	compile CompileFunc
	imports map[string]bool
	skipped map[string]bool // rules of the set that were not compiled
	vars    []string        // loop variables in scope
	strs    []string        // string names of the rule being checked
	err     error
}

func newCondChecker(rules *Rules, imports []string, compile CompileFunc) *condChecker {
	c := &condChecker{rules: rules, compile: compile, imports: map[string]bool{}, skipped: map[string]bool{}}
	for _, m := range imports {
		c.imports[m] = true
	}
	return c
}

// rule returns the reason to skip r, or an error when libyara would refuse
// to compile it.
func (c *condChecker) rule(r *ast.Rule) (string, error) {
	c.err = nil
	c.strs = c.strs[:0]
	for _, s := range r.Strings {
		c.strs = append(c.strs, s.Name)
	}
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
		if lit, ok := e.Right.(ast.RegexLit); ok && e.Op == "matches" {
			if reason := c.regex(lit); reason != "" {
				return reason
			}
			return c.reason(e.Left)
		}
		return c.first(e.Left, e.Right)
	case ast.NotExpr:
		return c.reason(e.Inner)
	case ast.ParenExpr:
		return c.reason(e.Inner)
	case ast.StringRef:
		return c.str(e.Name)
	case ast.CountOf:
		return c.str(e.Name)
	case ast.AtExpr:
		if reason := c.str(e.Ref.Name); reason != "" {
			return reason
		}
		return c.reason(e.Pos)
	case ast.UnaryExpr:
		return c.reason(e.Inner)
	case ast.OffsetOf:
		if reason := c.str(e.Name); reason != "" {
			return reason
		}
		return c.first(e.Index)
	case ast.LenOf:
		if reason := c.str(e.Name); reason != "" {
			return reason
		}
		return c.first(e.Index)
	case ast.InExpr:
		if reason := c.str(e.Ref.Name); reason != "" {
			return reason
		}
		return c.first(e.Lo, e.Hi)
	case ast.AnyOf:
		return c.set(e.Pattern)
	case ast.AllOf:
		return c.set(e.Pattern)
	case ast.NOf:
		return c.set(e.Patterns...)
	case ast.ForExpr:
		return c.forLoop(e)
	case ast.Field:
		return c.field(e)
	case ast.Index:
		return c.index(e)
	case ast.FuncCall:
		if reason := c.callee(e.Name, e.Args); reason != "" {
			return reason
		}
		return c.first(e.Args...)
	}
	return ""
}

// regex checks a matches operand with the configured compiler, like string
// regexes, and keeps it for the scan, which compiles it on first use.
func (c *condChecker) regex(lit ast.RegexLit) string {
	if _, ok := c.rules.condRegexes[lit]; ok {
		return ""
	}
	pattern := buildRE2Pattern(lit.Pattern, lit.Modifiers)
	if err := checkRegex(pattern, c.compile); err != nil {
		return c.fail("invalid regex /%s/: %w", lit.Pattern, err)
	}
	c.rules.condRegexes[lit] = &regexPattern{pattern: pattern, compile: c.compile}
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

// str fails a reference to a string the rule does not define, like
// libyara's "undefined string identifier". The anonymous $ refers to the
// string of an enclosing for..of loop.
func (c *condChecker) str(name string) string {
	if name == "$" || slices.Contains(c.strs, name) {
		return ""
	}
	return c.fail("undefined string identifier %q", name)
}

// set fails a string set that matches none of the rule's strings.
func (c *condChecker) set(patterns ...string) string {
	for _, p := range patterns {
		if p != "them" && len(matchingStringIndices(p, c.strs)) == 0 {
			return c.fail("undefined string identifier %q", p)
		}
	}
	return ""
}

func (c *condChecker) forLoop(e ast.ForExpr) string {
	if e.Var == "" {
		if reason := c.set(e.Patterns...); reason != "" {
			return reason
		}
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
	return "unsupported module member " + e.Name
}

// module returns why identifiers of module cannot be evaluated: libyara
// rejects a module that was not imported, and only math and hash are
// implemented here.
func (c *condChecker) module(module string) string {
	if !c.imports[module] {
		return c.fail("undefined identifier %q", module)
	}
	switch module {
	case "math", "hash":
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
	return "unsupported module member " + e.Name
}

func (c *condChecker) index(e ast.Index) string {
	if reason := c.indexBase(e); reason != "" {
		return reason
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

func (c *condChecker) callee(name string, args []ast.Expr) string {
	module, _, dotted := strings.Cut(name, ".")
	if !dotted {
		if _, ok := integerReaders[name]; !ok {
			return c.fail("undefined identifier %q", name)
		}
		if !matchesSignature("i", args) {
			return c.fail("wrong arguments for function %q", name)
		}
		return ""
	}
	if reason := c.module(module); reason != "" {
		return reason
	}
	signatures, ok := supportedFunctions[name]
	if !ok {
		return "unsupported function " + name
	}
	for _, sig := range signatures {
		if matchesSignature(sig, args) {
			return ""
		}
	}
	return c.fail("wrong arguments for function %q", name)
}

// matchesSignature reports whether args fit sig (see supportedFunctions).
// Arguments whose type depends on the scan, like identifiers, fit any letter.
func matchesSignature(sig string, args []ast.Expr) bool {
	if len(sig) != len(args) {
		return false
	}
	for i, a := range args {
		switch literalKind(a) {
		case 's':
			if sig[i] != 's' {
				return false
			}
		case 'f':
			if sig[i] != 'f' {
				return false
			}
		case 'i':
			if sig[i] == 's' {
				return false
			}
		}
	}
	return true
}

// literalKind is i, f or s when expr is an integer, float or string
// whatever the scanned data, and 0 when it depends on identifiers or
// function results.
func literalKind(expr ast.Expr) byte {
	switch e := expr.(type) {
	case ast.IntLit, ast.Filesize, ast.CountOf, ast.OffsetOf, ast.LenOf:
		return 'i'
	case ast.FloatLit:
		return 'f'
	case ast.StrLit:
		return 's'
	case ast.ParenExpr:
		return literalKind(e.Inner)
	case ast.UnaryExpr:
		return literalKind(e.Inner)
	}
	return 0
}
