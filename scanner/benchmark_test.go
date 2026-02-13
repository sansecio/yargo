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

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
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
					{Name: "$a", Value: ast.RegexString{Pattern: `[a-z]+[0-9]+`}},
					{Name: "$b", Value: ast.RegexString{Pattern: `\d{3}-\d{3}-\d{4}`}},
					{Name: "$c", Value: ast.RegexString{Pattern: `https?://[^\s]+`}},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
			{
				Name: "rule2",
				Strings: []*ast.StringDef{
					{Name: "$a", Value: ast.RegexString{Pattern: `eval\s*\(`, Modifiers: ast.RegexModifiers{CaseInsensitive: true}}},
					{Name: "$b", Value: ast.RegexString{Pattern: `base64.+decode`, Modifiers: ast.RegexModifiers{DotMatchesAll: true}}},
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
					{Name: "$a", Value: ast.RegexString{Pattern: `[a-z]+[0-9]+`}},
					{Name: "$b", Value: ast.RegexString{Pattern: `\d{3}-\d{3}-\d{4}`}},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
			{
				Name: "rule2",
				Strings: []*ast.StringDef{
					{Name: "$a", Value: ast.RegexString{Pattern: `eval\s*\(`, Modifiers: ast.RegexModifiers{CaseInsensitive: true}}},
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
	copy(data[1000:], []byte("username123"))
	copy(data[5000:], []byte("call 555-123-4567"))
	copy(data[100000:], []byte("EVAL ( something )"))

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
					{Name: "$regex", Value: ast.RegexString{Pattern: `[a-z]+[0-9]+`}},
					{Name: "$wordboundary", Value: ast.RegexString{Pattern: `\bvirus\b`}},
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
	copy(data[5000:], []byte("username123"))
	copy(data[100000:], []byte("This is a virus here"))

	b.SetBytes(int64(len(data)))

	for b.Loop() {
		var matches MatchRules
		err := rules.ScanMem(data, 0, 30*time.Second, &matches)
		if err != nil {
			b.Fatalf("ScanMem() error = %v", err)
		}
	}
}
