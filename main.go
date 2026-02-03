package main

import (
	"fmt"
	"os"

	"github.com/sansecio/yargo/parser"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <yara-file>\n", os.Args[0])
		os.Exit(1)
	}

	filename := os.Args[1]

	p := parser.New()

	ruleSet, err := p.ParseFile(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing %s: %v\n", filename, err)
		os.Exit(1)
	}

	// Print summary
	fmt.Printf("Parsed %d rules from %s\n", len(ruleSet.Rules), filename)

	// Print rule names
	for _, r := range ruleSet.Rules {
		stringCount := len(r.Strings)
		metaCount := len(r.Meta)
		fmt.Printf("  - %s (strings: %d, meta: %d, condition: %q)\n",
			r.Name, stringCount, metaCount, r.Condition)
	}
}
