package ast

// Expr represents a condition expression node.
type Expr interface {
	exprNode()
}

// StringRef represents a string variable reference like $foo.
type StringRef struct {
	Name string
}

func (StringRef) exprNode() {}

// AtExpr represents a positional match like "$foo at 0".
type AtExpr struct {
	Ref StringRef
	Pos Expr
}

func (AtExpr) exprNode() {}

// IntLit represents an integer literal (decimal or hex).
type IntLit struct {
	Value int64
}

func (IntLit) exprNode() {}

// FuncCall represents a function call like uint32be(0).
type FuncCall struct {
	Name string
	Args []Expr
}

func (FuncCall) exprNode() {}

// BinaryExpr represents a binary operation (and, or, ==).
type BinaryExpr struct {
	Op    string
	Left  Expr
	Right Expr
}

func (BinaryExpr) exprNode() {}

// ParenExpr represents a parenthesized expression.
type ParenExpr struct {
	Inner Expr
}

func (ParenExpr) exprNode() {}

// AnyOf represents "any of (pattern)" with optional wildcard.
type AnyOf struct {
	Pattern string // e.g., "$b64_*" or "them"
}

func (AnyOf) exprNode() {}

// AllOf represents "all of them" or "all of (pattern)".
type AllOf struct {
	Pattern string // e.g., "them" or "$prefix_*"
}

func (AllOf) exprNode() {}
