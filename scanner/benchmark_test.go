package scanner

import (
	"testing"
	"time"

	"github.com/sansecio/yargo/ast"
)

func BenchmarkCompileStringLiterals(b *testing.B) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "rule1",
				Strings: []*ast.StringDef{
					{Name: "$a", Value: ast.TextString{Value: "malware"}},
					{Name: "$b", Value: ast.TextString{Value: "virus"}},
					{Name: "$c", Value: ast.TextString{Value: "trojan"}},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
			{
				Name: "rule2",
				Strings: []*ast.StringDef{
					{Name: "$a", Value: ast.TextString{Value: "eval("}},
					{Name: "$b", Value: ast.TextString{Value: "base64_decode"}},
					{Name: "$c", Value: ast.TextString{Value: "exec("}},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
		},
	}

	for b.Loop() {
		_, err := Compile(rs)
		if err != nil {
			b.Fatalf("Compile() error = %v", err)
		}
	}
}

func BenchmarkCompileRegexPatterns(b *testing.B) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "rule1",
				Strings: []*ast.StringDef{
					{Name: "$a", Value: ast.RegexString{Pattern: `https?://[^\s]+`}},
					{Name: "$b", Value: ast.RegexString{Pattern: `password\s*=\s*"[^"]+"`}},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
			{
				Name: "rule2",
				Strings: []*ast.StringDef{
					{Name: "$a", Value: ast.RegexString{Pattern: `eval\s*\(`}},
					{Name: "$b", Value: ast.RegexString{Pattern: `base64.+decode`}},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
		},
	}

	for b.Loop() {
		_, err := Compile(rs)
		if err != nil {
			b.Fatalf("Compile() error = %v", err)
		}
	}
}

func BenchmarkScanStringLiterals(b *testing.B) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "rule1",
				Strings: []*ast.StringDef{
					{Name: "$a", Value: ast.TextString{Value: "malware"}},
					{Name: "$b", Value: ast.TextString{Value: "virus"}},
					{Name: "$c", Value: ast.TextString{Value: "trojan"}},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
			{
				Name: "rule2",
				Strings: []*ast.StringDef{
					{Name: "$a", Value: ast.TextString{Value: "eval("}},
					{Name: "$b", Value: ast.TextString{Value: "base64_decode"}},
					{Name: "$c", Value: ast.TextString{Value: "exec("}},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
		},
	}

	rules, err := Compile(rs)
	if err != nil {
		b.Fatalf("Compile() error = %v", err)
	}

	// Generate test data - 1MB of sample data with some matches
	data := make([]byte, 1024*1024)
	copy(data[1000:], []byte("This file contains malware"))
	copy(data[5000:], []byte("eval($_POST['cmd'])"))
	copy(data[100000:], []byte("Some virus detected"))

	b.SetBytes(int64(len(data)))

	for b.Loop() {
		var matches MatchRules
		err := rules.ScanMem(data, 0, 30*time.Second, &matches)
		if err != nil {
			b.Fatalf("ScanMem() error = %v", err)
		}
	}
}

func BenchmarkScanRegexPatterns(b *testing.B) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "rule1",
				Strings: []*ast.StringDef{
					{Name: "$a", Value: ast.RegexString{Pattern: `https?://[^\s]+`}},
					{Name: "$b", Value: ast.RegexString{Pattern: `password\s*=\s*"[^"]+"`}},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
			{
				Name: "rule2",
				Strings: []*ast.StringDef{
					{Name: "$a", Value: ast.RegexString{Pattern: `eval\s*\(`}},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
		},
	}

	rules, err := Compile(rs)
	if err != nil {
		b.Fatalf("Compile() error = %v", err)
	}

	// Generate test data - 1MB of sample data with some matches
	data := make([]byte, 1024*1024)
	copy(data[1000:], []byte("visit https://example.com/path"))
	copy(data[5000:], []byte(`password = "secret123"`))
	copy(data[100000:], []byte("eval (something)"))

	b.SetBytes(int64(len(data)))

	for b.Loop() {
		var matches MatchRules
		err := rules.ScanMem(data, 0, 30*time.Second, &matches)
		if err != nil {
			b.Fatalf("ScanMem() error = %v", err)
		}
	}
}

func BenchmarkScanMixed(b *testing.B) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "mixed_rule",
				Strings: []*ast.StringDef{
					{Name: "$literal", Value: ast.TextString{Value: "malware"}},
					{Name: "$regex", Value: ast.RegexString{Pattern: `eval\s*\(`}},
					{Name: "$url", Value: ast.RegexString{Pattern: `https?://[^\s]+`}},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
		},
	}

	rules, err := Compile(rs)
	if err != nil {
		b.Fatalf("Compile() error = %v", err)
	}

	// Generate test data
	data := make([]byte, 1024*1024)
	copy(data[1000:], []byte("This file contains malware"))
	copy(data[5000:], []byte("eval (something)"))
	copy(data[100000:], []byte("visit https://example.com"))

	b.SetBytes(int64(len(data)))

	for b.Loop() {
		var matches MatchRules
		err := rules.ScanMem(data, 0, 30*time.Second, &matches)
		if err != nil {
			b.Fatalf("ScanMem() error = %v", err)
		}
	}
}
