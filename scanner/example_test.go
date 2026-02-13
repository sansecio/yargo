package scanner_test

import (
	"fmt"
	"time"

	"github.com/sansecio/yargo/parser"
	"github.com/sansecio/yargo/scanner"
)

func ExampleRules_ScanMem() {
	p := parser.New()
	ruleSet, err := p.Parse(`
rule php_tag {
    strings:
        $php = "<?php"
    condition:
        any of them
}
`)
	if err != nil {
		fmt.Println("parse error:", err)
		return
	}

	rules, err := scanner.Compile(ruleSet)
	if err != nil {
		fmt.Println("compile error:", err)
		return
	}

	data := []byte("hello <?php echo 'world'; ?>")

	var matches scanner.MatchRules
	if err := rules.ScanMem(data, 0, 30*time.Second, &matches); err != nil {
		fmt.Println("scan error:", err)
		return
	}

	for _, m := range matches {
		fmt.Printf("Matched rule: %s\n", m.Rule)
	}
	// Output:
	// Matched rule: php_tag
}
