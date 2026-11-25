package scanner

import (
	"cmp"
	"encoding/binary"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/sansecio/yargo/ast"
)

// evalContext holds the context for evaluating a condition.
type evalContext struct {
	hits        []hit            // this rule's hits, sorted by slot then position
	slotBase    int32            // slot of the rule's first string
	buf         []byte           // the buffer being scanned
	stringNames []string         // all string names defined in the rule
	vars        map[string]int64 // loop variables in scope
	externals   Externals
	ruleIndex   map[string]int32 // rules defined before this one
	results     []bool           // outcome of every rule evaluated so far
}

// hitsFor returns the hits for the given string index. They are contiguous
// because the rule's hits are sorted by slot.
func (ctx *evalContext) hitsFor(idx int) []hit {
	slot := ctx.slotBase + int32(idx)
	lo, ok := slices.BinarySearchFunc(ctx.hits, slot, func(h hit, s int32) int {
		return cmp.Compare(h.slot, s)
	})
	if !ok {
		return nil
	}
	hi := lo
	for hi < len(ctx.hits) && ctx.hits[hi].slot == slot {
		hi++
	}
	return ctx.hits[lo:hi]
}

// matched reports whether the string at idx hit anywhere.
func (ctx *evalContext) matched(idx int) bool {
	return len(ctx.hitsFor(idx)) > 0
}

// mayMatchWithoutHits reports whether expr can be true when none of the rule's
// strings matched. It is conservative: unknown constructs return true so a
// future condition type cannot be incorrectly skipped.
func mayMatchWithoutHits(expr ast.Expr) bool {
	switch e := expr.(type) {
	case ast.StringRef, ast.AtExpr, ast.AnyOf, ast.AllOf:
		return false

	case ast.NOf:
		return e.Quant == "none" || (e.Quant == "count" && e.N <= 0)

	case ast.IntLit:
		return e.Value != 0

	case ast.Filesize:
		return true

	case ast.FuncCall:
		return true

	case ast.NotExpr:
		// Determining whether an arbitrary inner expression is false would
		// require evaluating it against the buffer. Keep the rule eligible.
		return true

	case ast.BinaryExpr:
		switch e.Op {
		case "and":
			return mayMatchWithoutHits(e.Left) && mayMatchWithoutHits(e.Right)
		case "or":
			return mayMatchWithoutHits(e.Left) || mayMatchWithoutHits(e.Right)
		default:
			return true
		}

	case ast.ParenExpr:
		return mayMatchWithoutHits(e.Inner)

	default:
		return true
	}
}

// evalExpr evaluates a condition expression and returns true if it matches.
// An undefined result (a missing external, an unparsable module) is false.
func evalExpr(expr ast.Expr, ctx *evalContext) bool {
	return truthy(evalAny(expr, ctx))
}

// evalExprInt evaluates an expression that should return an integer.
func evalExprInt(expr ast.Expr, ctx *evalContext) int64 {
	n, _ := evalAny(expr, ctx).(int64)
	return n
}

// truthy converts an evaluation result to a condition outcome. A nil result
// means undefined and is false.
func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case int64:
		return x != 0
	case string:
		return x != ""
	default:
		return false
	}
}

// evalAny evaluates an expression to a bool, int64, string, or nil for
// undefined. Undefined propagates through comparisons, not, and, or, the way
// YARA propagates it.
func evalAny(expr ast.Expr, ctx *evalContext) any {
	switch e := expr.(type) {
	case ast.StringRef:
		idx := ctx.refIndex(e.Name)
		if idx < 0 {
			return false
		}
		return ctx.matched(idx)

	case ast.AtExpr:
		idx := ctx.refIndex(e.Ref.Name)
		if idx < 0 {
			return false
		}
		pos := evalExprInt(e.Pos, ctx)
		for _, h := range ctx.hitsFor(idx) {
			if int64(h.pos) == pos {
				return true
			}
		}
		return false

	case ast.IntLit:
		return e.Value

	case ast.StrLit:
		return e.Value

	case ast.BoolLit:
		return e.Value

	case ast.Filesize:
		return int64(len(ctx.buf))

	case ast.Ident:
		return ctx.lookup(e.Name)

	case ast.FuncCall:
		return evalFuncCall(e, ctx)

	case ast.BinaryExpr:
		return evalBinaryExpr(e, ctx)

	case ast.NotExpr:
		v := evalAny(e.Inner, ctx)
		if v == nil {
			return nil
		}
		return !truthy(v)

	case ast.ParenExpr:
		return evalAny(e.Inner, ctx)

	case ast.AnyOf:
		return evalAnyOf(e, ctx)

	case ast.AllOf:
		return evalAllOf(e, ctx)

	case ast.NOf:
		return evalNOf(e, ctx)

	default:
		return false
	}
}

// evalFuncCall evaluates a function call and returns its integer result.
func evalFuncCall(fn ast.FuncCall, ctx *evalContext) any {
	if len(fn.Args) == 0 {
		return int64(0)
	}
	pos := evalExprInt(fn.Args[0], ctx)
	if pos < 0 || int(pos) >= len(ctx.buf) {
		return int64(0)
	}

	switch fn.Name {
	case "uint32be":
		if int(pos)+4 > len(ctx.buf) {
			return int64(0)
		}
		return int64(binary.BigEndian.Uint32(ctx.buf[pos:]))

	case "uint16be":
		if int(pos)+2 > len(ctx.buf) {
			return int64(0)
		}
		return int64(binary.BigEndian.Uint16(ctx.buf[pos:]))

	case "uint32":
		if int(pos)+4 > len(ctx.buf) {
			return int64(0)
		}
		return int64(binary.LittleEndian.Uint32(ctx.buf[pos:]))

	case "uint16":
		if int(pos)+2 > len(ctx.buf) {
			return int64(0)
		}
		return int64(binary.LittleEndian.Uint16(ctx.buf[pos:]))

	case "uint8":
		return int64(ctx.buf[pos])

	default:
		return int64(0)
	}
}

// evalBinaryExpr evaluates a binary expression.
func evalBinaryExpr(e ast.BinaryExpr, ctx *evalContext) any {
	switch e.Op {
	case "and":
		l, r := evalAny(e.Left, ctx), evalAny(e.Right, ctx)
		if (l != nil && !truthy(l)) || (r != nil && !truthy(r)) {
			return false
		}
		if l == nil || r == nil {
			return nil
		}
		return true
	case "or":
		l, r := evalAny(e.Left, ctx), evalAny(e.Right, ctx)
		if truthy(l) || truthy(r) {
			return true
		}
		if l == nil || r == nil {
			return nil
		}
		return false
	case "matches":
		return evalMatches(e, ctx)
	}
	l, r := evalAny(e.Left, ctx), evalAny(e.Right, ctx)
	if l == nil || r == nil {
		return nil
	}
	if ls, ok := l.(string); ok {
		rs, ok := r.(string)
		if !ok {
			return nil
		}
		return compareStrings(e.Op, ls, rs)
	}
	ln, lok := toInt(l)
	rn, rok := toInt(r)
	if !lok || !rok {
		return nil
	}
	return compareInts(e.Op, ln, rn)
}

func toInt(v any) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	default:
		return 0, false
	}
}

func compareInts(op string, l, r int64) any {
	switch op {
	case "==":
		return l == r
	case "!=":
		return l != r
	case "<":
		return l < r
	case ">":
		return l > r
	case "<=":
		return l <= r
	case ">=":
		return l >= r
	default:
		return false
	}
}

func compareStrings(op, l, r string) any {
	switch op {
	case "==":
		return l == r
	case "!=":
		return l != r
	case "<":
		return l < r
	case ">":
		return l > r
	case "<=":
		return l <= r
	case ">=":
		return l >= r
	case "contains":
		return strings.Contains(l, r)
	case "icontains":
		return strings.Contains(strings.ToLower(l), strings.ToLower(r))
	case "startswith":
		return strings.HasPrefix(l, r)
	case "istartswith":
		return strings.HasPrefix(strings.ToLower(l), strings.ToLower(r))
	case "endswith":
		return strings.HasSuffix(l, r)
	case "iendswith":
		return strings.HasSuffix(strings.ToLower(l), strings.ToLower(r))
	case "iequals":
		return strings.EqualFold(l, r)
	default:
		return false
	}
}

var condRegexes sync.Map

func evalMatches(e ast.BinaryExpr, ctx *evalContext) any {
	l := evalAny(e.Left, ctx)
	s, ok := l.(string)
	if !ok {
		return nil
	}
	lit, ok := e.Right.(ast.RegexLit)
	if !ok {
		return nil
	}
	pattern := buildRE2Pattern(lit.Pattern, lit.Modifiers)
	cached, ok := condRegexes.Load(pattern)
	if !ok {
		re, err := regexp.Compile(pattern)
		if err != nil {
			re = nil
		}
		cached, _ = condRegexes.LoadOrStore(pattern, re)
	}
	re, _ := cached.(*regexp.Regexp)
	if re == nil {
		return false
	}
	return re.MatchString(s)
}

// lookup resolves a bare identifier: a loop variable, an external variable, or
// a rule defined earlier in the set. Anything else is undefined.
func (ctx *evalContext) lookup(name string) any {
	if v, ok := ctx.vars[name]; ok {
		return v
	}
	if v, ok := ctx.externals[name]; ok {
		return normalizeExternal(v)
	}
	if idx, ok := ctx.ruleIndex[name]; ok && int(idx) < len(ctx.results) {
		return ctx.results[idx]
	}
	return nil
}

func normalizeExternal(v any) any {
	switch x := v.(type) {
	case int:
		return int64(x)
	case int32:
		return int64(x)
	case uint32:
		return int64(x)
	case int64, string, bool:
		return x
	default:
		return nil
	}
}

// refIndex resolves a string reference to its index in the rule.
func (ctx *evalContext) refIndex(name string) int {
	return ctx.stringIndex(name)
}

// stringIndex returns the index of the named string, or -1 if not found.
func (ctx *evalContext) stringIndex(name string) int {
	for i, n := range ctx.stringNames {
		if n == name {
			return i
		}
	}
	return -1
}

// evalAnyOf evaluates "any of" expressions.
func evalAnyOf(e ast.AnyOf, ctx *evalContext) bool {
	return slices.ContainsFunc(matchingStringIndices(e.Pattern, ctx.stringNames), ctx.matched)
}

// evalAllOf evaluates "all of" expressions.
func evalAllOf(e ast.AllOf, ctx *evalContext) bool {
	indices := matchingStringIndices(e.Pattern, ctx.stringNames)
	if len(indices) == 0 {
		return false
	}
	for _, idx := range indices {
		if !ctx.matched(idx) {
			return false
		}
	}
	return true
}

// evalNOf evaluates quantifiers over a set of string patterns. A string named
// by several patterns counts once.
func evalNOf(e ast.NOf, ctx *evalContext) bool {
	var seen []int
	matched := 0
	for _, p := range e.Patterns {
		for _, idx := range matchingStringIndices(p, ctx.stringNames) {
			if slices.Contains(seen, idx) {
				continue
			}
			seen = append(seen, idx)
			if ctx.matched(idx) {
				matched++
			}
		}
	}
	switch e.Quant {
	case "none":
		return matched == 0
	case "any":
		return matched >= 1
	case "all":
		return len(seen) > 0 && matched == len(seen)
	default:
		return matched >= int(e.N)
	}
}

// matchingStringIndices returns the indices of strings that match the pattern.
// Pattern can be "them" (all strings) or a wildcard like "$b64_*".
func matchingStringIndices(pattern string, stringNames []string) []int {
	if pattern == "them" {
		indices := make([]int, len(stringNames))
		for i := range indices {
			indices[i] = i
		}
		return indices
	}

	if !strings.HasSuffix(pattern, "*") {
		// Exact match — return all indices with this name (handles anonymous "$").
		var result []int
		for i, name := range stringNames {
			if name == pattern {
				result = append(result, i)
			}
		}
		return result
	}

	// Wildcard match
	prefix := strings.TrimSuffix(pattern, "*")
	var result []int
	for i, name := range stringNames {
		if strings.HasPrefix(name, prefix) {
			result = append(result, i)
		}
	}
	return result
}
