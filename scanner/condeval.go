package scanner

import (
	"encoding/binary"
	"strings"

	"github.com/sansecio/yargo/ast"
)

// evalContext holds the context for evaluating a condition.
type evalContext struct {
	matches     map[int][]int // string index -> list of match positions
	buf         []byte        // the buffer being scanned
	stringNames []string      // all string names defined in the rule
}

// evalExpr evaluates a condition expression and returns true if it matches.
func evalExpr(expr ast.Expr, ctx *evalContext) bool {
	switch e := expr.(type) {
	case ast.StringRef:
		idx := ctx.stringIndex(e.Name)
		if idx < 0 {
			return false
		}
		_, ok := ctx.matches[idx]
		return ok

	case ast.AtExpr:
		idx := ctx.stringIndex(e.Ref.Name)
		if idx < 0 {
			return false
		}
		positions, ok := ctx.matches[idx]
		if !ok {
			return false
		}
		pos := evalExprInt(e.Pos, ctx)
		for _, p := range positions {
			if int64(p) == pos {
				return true
			}
		}
		return false

	case ast.IntLit:
		return e.Value != 0

	case ast.FuncCall:
		return evalFuncCall(e, ctx) != 0

	case ast.BinaryExpr:
		return evalBinaryExpr(e, ctx)

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
	for _, idx := range matchingStringIndices(e.Pattern, ctx.stringNames) {
		if _, ok := ctx.matches[idx]; ok {
			return true
		}
	}
	return false
}

// evalAllOf evaluates "all of" expressions.
func evalAllOf(e ast.AllOf, ctx *evalContext) bool {
	indices := matchingStringIndices(e.Pattern, ctx.stringNames)
	if len(indices) == 0 {
		return false
	}
	for _, idx := range indices {
		if _, ok := ctx.matches[idx]; !ok {
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
