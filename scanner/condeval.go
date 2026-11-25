package scanner

import (
	"cmp"
	"context"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/sansecio/yargo/ast"
)

// evalContext holds the context for evaluating a condition.
type evalContext struct {
	hits        []hit    // this rule's hits, sorted by slot then position
	slotBase    int32    // slot of the rule's first string
	buf         []byte   // the buffer being scanned
	stringNames []string // all string names defined in the rule
	scan        *scanState
	deadline    context.Context
	vars        map[string]int64
	cur         int
	inSet       bool
	externals   Externals
	ruleIndex   map[string]int32
	results     []bool
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
func evalExpr(expr ast.Expr, ctx *evalContext) bool {
	return truthy(evalAny(expr, ctx))
}

// evalExprInt evaluates an expression that should return an integer.
func evalExprInt(expr ast.Expr, ctx *evalContext) int64 {
	n, _ := evalAny(expr, ctx).(int64)
	return n
}

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

	case ast.FloatLit:
		return e.Value

	case ast.InExpr:
		return evalIn(e, ctx)

	case ast.CountOf:
		idx := ctx.refIndex(e.Name)
		if idx < 0 {
			return nil
		}
		return int64(len(ctx.hitsFor(idx)))

	case ast.OffsetOf:
		h, ok := ctx.nthHit(e.Name, e.Index)
		if !ok {
			return nil
		}
		return int64(h.pos)

	case ast.LenOf:
		h, ok := ctx.nthHit(e.Name, e.Index)
		if !ok {
			return nil
		}
		return int64(h.n)

	case ast.UnaryExpr:
		return evalUnary(e, ctx)

	case ast.ForExpr:
		return evalFor(e, ctx)

	case ast.BoolLit:
		return e.Value

	case ast.Filesize:
		return int64(len(ctx.buf))

	case ast.Ident:
		return ctx.lookup(e.Name)

	case ast.Field:
		return evalPEField(e, ctx)

	case ast.Index:
		return evalPEIndex(e, ctx)

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
		return nil
	}
}

// evalFuncCall evaluates a function call and returns its result.
func evalFuncCall(fn ast.FuncCall, ctx *evalContext) any {
	if len(fn.Args) == 0 && !strings.HasPrefix(fn.Name, "pe.") {
		return nil
	}
	args := make([]any, len(fn.Args))
	for i, a := range fn.Args {
		args[i] = evalAny(a, ctx)
		if args[i] == nil {
			return nil
		}
	}
	if strings.HasPrefix(fn.Name, "pe.") {
		if ctx.scan == nil {
			return nil
		}
		info := ctx.scan.peInfo()
		if info == nil {
			return nil
		}
		return info.call(fn.Name, args)
	}
	if v, ok := readInteger(fn.Name, args[0], ctx.buf); ok {
		return v
	}
	return evalModuleFunc(fn.Name, args, ctx.buf)
}

var integerReaders = map[string]struct {
	size   int
	signed bool
	big    bool
}{
	"uint8": {1, false, false}, "uint16": {2, false, false}, "uint32": {4, false, false},
	"int8": {1, true, false}, "int16": {2, true, false}, "int32": {4, true, false},
	"uint8be": {1, false, true}, "uint16be": {2, false, true}, "uint32be": {4, false, true},
	"int8be": {1, true, true}, "int16be": {2, true, true}, "int32be": {4, true, true},
}

func readInteger(name string, posArg any, buf []byte) (any, bool) {
	r, ok := integerReaders[name]
	if !ok {
		return nil, false
	}
	pos, ok := posArg.(int64)
	if !ok || pos < 0 || len(buf) < r.size || pos > int64(len(buf))-int64(r.size) {
		return int64(0), true
	}
	b := buf[pos : pos+int64(r.size)]
	var u uint64
	for i := range b {
		if r.big {
			u = u<<8 | uint64(b[i])
		} else {
			u |= uint64(b[i]) << (8 * i)
		}
	}
	if !r.signed {
		return int64(u), true
	}
	shift := 64 - 8*r.size
	return int64(u<<shift) >> shift, true
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
	if isArithmeticOp(e.Op) {
		return arithmetic(e.Op, l, r)
	}
	if ls, ok := l.(string); ok {
		rs, ok := r.(string)
		if !ok {
			return nil
		}
		return compareStrings(e.Op, ls, rs)
	}
	ln, lok := toNumber(l)
	rn, rok := toNumber(r)
	if !lok || !rok {
		return nil
	}
	if ln.float || rn.float {
		return compareFloats(e.Op, ln.asFloat(), rn.asFloat())
	}
	return compareInts(e.Op, ln.i, rn.i)
}

func isArithmeticOp(op string) bool {
	switch op {
	case "+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>":
		return true
	default:
		return false
	}
}

type number struct {
	i     int64
	f     float64
	float bool
}

func (n number) asFloat() float64 {
	if n.float {
		return n.f
	}
	return float64(n.i)
}

func toNumber(v any) (number, bool) {
	switch x := v.(type) {
	case int64:
		return number{i: x}, true
	case float64:
		return number{f: x, float: true}, true
	case bool:
		if x {
			return number{i: 1}, true
		}
		return number{}, true
	default:
		return number{}, false
	}
}

func arithmetic(op string, l, r any) any {
	ln, lok := toNumber(l)
	rn, rok := toNumber(r)
	if !lok || !rok {
		return nil
	}
	if ln.float || rn.float {
		return floatArithmetic(op, ln.asFloat(), rn.asFloat())
	}
	a, b := ln.i, rn.i
	switch op {
	case "+":
		return a + b
	case "-":
		return a - b
	case "*":
		return a * b
	case "/":
		if b == 0 {
			return nil
		}
		return a / b
	case "%":
		if b == 0 {
			return nil
		}
		return a % b
	case "&":
		return a & b
	case "|":
		return a | b
	case "^":
		return a ^ b
	case "<<":
		if b < 0 || b > 63 {
			return int64(0)
		}
		return a << uint(b)
	case ">>":
		if b < 0 || b > 63 {
			return int64(0)
		}
		return a >> uint(b)
	default:
		return nil
	}
}

func floatArithmetic(op string, a, b float64) any {
	switch op {
	case "+":
		return a + b
	case "-":
		return a - b
	case "*":
		return a * b
	case "/":
		if b == 0 {
			return nil
		}
		return a / b
	default:
		return nil
	}
}

func compareFloats(op string, l, r float64) any {
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

func evalUnary(e ast.UnaryExpr, ctx *evalContext) any {
	n, ok := toNumber(evalAny(e.Inner, ctx))
	if !ok {
		return nil
	}
	switch {
	case e.Op == "-" && n.float:
		return -n.f
	case e.Op == "-":
		return -n.i
	case e.Op == "~" && !n.float:
		return ^n.i
	default:
		return nil
	}
}

func (ctx *evalContext) nthHit(name string, index ast.Expr) (hit, bool) {
	idx := ctx.refIndex(name)
	if idx < 0 {
		return hit{}, false
	}
	n := int64(1)
	if index != nil {
		var ok bool
		if n, ok = evalAny(index, ctx).(int64); !ok {
			return hit{}, false
		}
	}
	hits := ctx.hitsFor(idx)
	if n < 1 || n > int64(len(hits)) {
		return hit{}, false
	}
	return hits[n-1], true
}

func evalIn(e ast.InExpr, ctx *evalContext) any {
	idx := ctx.refIndex(e.Ref.Name)
	if idx < 0 {
		return false
	}
	lo, lok := evalAny(e.Lo, ctx).(int64)
	hi, hok := evalAny(e.Hi, ctx).(int64)
	if !lok || !hok {
		return nil
	}
	for _, h := range ctx.hitsFor(idx) {
		if int64(h.pos) >= lo && int64(h.pos) <= hi {
			return true
		}
	}
	return false
}

const (
	maxLoopIterations = 1 << 22
	loopCheckInterval = 1 << 10
)

func (ctx *evalContext) expired() bool {
	return ctx.deadline != nil && ctx.deadline.Err() != nil
}

func evalFor(e ast.ForExpr, ctx *evalContext) any {
	satisfied := 0
	total := 0
	tally := func() bool {
		total++
		if evalExpr(e.Body, ctx) {
			satisfied++
		}
		switch e.Quant {
		case "any":
			return satisfied == 0
		case "count":
			return satisfied < int(e.N)
		case "all":
			return satisfied == total
		default:
			return satisfied == 0
		}
	}
	if e.Var != "" {
		lo, lok := evalAny(e.Lo, ctx).(int64)
		hi, hok := evalAny(e.Hi, ctx).(int64)
		if !lok || !hok {
			return nil
		}
		prev, had := ctx.vars[e.Var]
		if ctx.vars == nil {
			ctx.vars = make(map[string]int64, 1)
		}
		aborted := false
		for i, n := lo, 0; lo <= hi; i, n = i+1, n+1 {
			if n >= maxLoopIterations || (n%loopCheckInterval == 0 && ctx.expired()) {
				aborted = true
				break
			}
			ctx.vars[e.Var] = i
			if !tally() || i == hi {
				break
			}
		}
		if had {
			ctx.vars[e.Var] = prev
		} else {
			delete(ctx.vars, e.Var)
		}
		if aborted {
			return nil
		}
	} else {
		prevCur, prevIn := ctx.cur, ctx.inSet
		ctx.inSet = true
		for _, idx := range ctx.setIndices(e.Patterns) {
			ctx.cur = idx
			if !tally() {
				break
			}
		}
		ctx.cur, ctx.inSet = prevCur, prevIn
	}
	switch e.Quant {
	case "any":
		return satisfied > 0
	case "all":
		return satisfied == total
	case "none":
		return satisfied == 0
	default:
		return satisfied >= int(e.N)
	}
}

func (ctx *evalContext) setIndices(patterns []string) []int {
	var seen []int
	for _, p := range patterns {
		for _, idx := range matchingStringIndices(p, ctx.stringNames) {
			if !slices.Contains(seen, idx) {
				seen = append(seen, idx)
			}
		}
	}
	slices.Sort(seen)
	return seen
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

func (ctx *evalContext) lookupPE(name string) any {
	if v, ok := peConstants[name]; ok {
		return v
	}
	if ctx.scan == nil {
		return nil
	}
	info := ctx.scan.peInfo()
	if info == nil {
		if name == "pe.is_pe" {
			return int64(0)
		}
		return nil
	}
	return info.scalar(name)
}

func evalPEField(e ast.Field, ctx *evalContext) any {
	idx, ok := e.Base.(ast.Index)
	if !ok || ctx.scan == nil {
		return nil
	}
	array, ok := idx.Base.(ast.Ident)
	if !ok {
		return nil
	}
	i, ok := evalAny(idx.Index, ctx).(int64)
	info := ctx.scan.peInfo()
	if !ok || info == nil {
		return nil
	}
	switch array.Name {
	case "pe.sections":
		return info.sectionField(i, e.Name)
	case "pe.resources":
		return info.resourceField(i, e.Name)
	case "pe.version_info_list":
		return info.versionInfoListField(i, e.Name)
	case "pe.signatures":
		return info.signatureField(i, e.Name)
	}
	return nil
}

func evalPEIndex(e ast.Index, ctx *evalContext) any {
	base, ok := e.Base.(ast.Ident)
	if !ok || base.Name != "pe.version_info" || ctx.scan == nil {
		return nil
	}
	key, ok := evalAny(e.Index, ctx).(string)
	info := ctx.scan.peInfo()
	if !ok || info == nil {
		return nil
	}
	return info.versionInfoField(key)
}

func (ctx *evalContext) lookup(name string) any {
	if v, ok := ctx.vars[name]; ok {
		return v
	}
	if strings.HasPrefix(name, "pe.") {
		return ctx.lookupPE(name)
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

func (ctx *evalContext) refIndex(name string) int {
	if ctx.inSet && name == "$" {
		return ctx.cur
	}
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

func evalNOf(e ast.NOf, ctx *evalContext) bool {
	seen := ctx.setIndices(e.Patterns)
	matched := 0
	for _, idx := range seen {
		if ctx.matched(idx) {
			matched++
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
