package parser_test

import (
	"fmt"

	"github.com/sansecio/yargo/parser"
)

func ExampleParser_Parse() {
	p := parser.New()
	ruleSet, err := p.Parse(`
rule example {
    strings:
        $text = "hello world"
    condition:
        any of them
}
`)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Printf("Parsed %d rule(s)\n", len(ruleSet.Rules))
	fmt.Printf("Rule name: %s\n", ruleSet.Rules[0].Name)
	// Output:
	// Parsed 1 rule(s)
	// Rule name: example
}
