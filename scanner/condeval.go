package scanner

import (
	"cmp"
	"encoding/binary"
	"slices"
	"strings"

	"github.com/sansecio/yargo/ast"
)

// evalContext holds the context for evaluating a condition.
type evalContext struct {
	hits        []hit    // this rule's hits, sorted by slot then position
	slotBase    int32    // slot of the rule's first string
	buf         []byte   // the buffer being scanned
	stringNames []string // all string names defined in the rule
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
	switch e := expr.(type) {
	case ast.StringRef:
		idx := ctx.stringIndex(e.Name)
		if idx < 0 {
			return false
		}
		return ctx.matched(idx)

	case ast.AtExpr:
		idx := ctx.stringIndex(e.Ref.Name)
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
		return e.Value != 0

	case ast.Filesize:
		return len(ctx.buf) != 0

	case ast.FuncCall:
		return evalFuncCall(e, ctx) != 0

	case ast.BinaryExpr:
		return evalBinaryExpr(e, ctx)

	case ast.NotExpr:
		return !evalExpr(e.Inner, ctx)

	case ast.ParenExpr:
		return evalExpr(e.Inner, ctx)

	case ast.AnyOf:
		return evalAnyOf(e, ctx)

	case ast.AllOf:
		return evalAllOf(e, ctx)

	default:
		return false
	}
}

// evalExprInt evaluates an expression that should return an integer.
func evalExprInt(expr ast.Expr, ctx *evalContext) int64 {
	switch e := expr.(type) {
	case ast.IntLit:
		return e.Value
	case ast.Filesize:
		return int64(len(ctx.buf))
	case ast.ParenExpr:
		return evalExprInt(e.Inner, ctx)
	case ast.FuncCall:
		return evalFuncCall(e, ctx)
	default:
		return 0
	}
}

// evalFuncCall evaluates a function call and returns its integer result.
func evalFuncCall(fn ast.FuncCall, ctx *evalContext) int64 {
	if len(fn.Args) == 0 {
		return 0
	}
	pos := evalExprInt(fn.Args[0], ctx)
	if pos < 0 || int(pos) >= len(ctx.buf) {
		return 0
	}

	switch fn.Name {
	case "uint32be":
		if int(pos)+4 > len(ctx.buf) {
			return 0
		}
		return int64(binary.BigEndian.Uint32(ctx.buf[pos:]))

	case "uint16be":
		if int(pos)+2 > len(ctx.buf) {
			return 0
		}
		return int64(binary.BigEndian.Uint16(ctx.buf[pos:]))

	case "uint32":
		if int(pos)+4 > len(ctx.buf) {
			return 0
		}
		return int64(binary.LittleEndian.Uint32(ctx.buf[pos:]))

	case "uint16":
		if int(pos)+2 > len(ctx.buf) {
			return 0
		}
		return int64(binary.LittleEndian.Uint16(ctx.buf[pos:]))

	case "uint8":
		return int64(ctx.buf[pos])

	default:
		return 0
	}
}

// evalBinaryExpr evaluates a binary expression.
func evalBinaryExpr(e ast.BinaryExpr, ctx *evalContext) bool {
	switch e.Op {
	case "and":
		return evalExpr(e.Left, ctx) && evalExpr(e.Right, ctx)
	case "or":
		return evalExpr(e.Left, ctx) || evalExpr(e.Right, ctx)
	case "==":
		return evalExprInt(e.Left, ctx) == evalExprInt(e.Right, ctx)
	case "!=":
		return evalExprInt(e.Left, ctx) != evalExprInt(e.Right, ctx)
	case "<":
		return evalExprInt(e.Left, ctx) < evalExprInt(e.Right, ctx)
	case ">":
		return evalExprInt(e.Left, ctx) > evalExprInt(e.Right, ctx)
	case "<=":
		return evalExprInt(e.Left, ctx) <= evalExprInt(e.Right, ctx)
	case ">=":
		return evalExprInt(e.Left, ctx) >= evalExprInt(e.Right, ctx)
	default:
		return false
	}
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
