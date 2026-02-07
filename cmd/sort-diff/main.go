//go:build yara

package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	yara "github.com/hillu/go-yara/v4"
	"github.com/sansecio/yargo/cmd/internal"
	"github.com/sansecio/yargo/scanner"
)

const yaraRulesAlpha = `
rule rule_aaa { strings: $a = "test" condition: $a }
rule rule_bbb { strings: $b = "test" condition: $b }
rule rule_ccc { strings: $c = "test" condition: $c }
rule rule_ddd { strings: $d = "test" condition: $d }
rule rule_eee { strings: $e = "test" condition: $e }
`

const yaraRulesReverse = `
rule rule_eee { strings: $e = "test" condition: $e }
rule rule_ddd { strings: $d = "test" condition: $d }
rule rule_ccc { strings: $c = "test" condition: $c }
rule rule_bbb { strings: $b = "test" condition: $b }
rule rule_aaa { strings: $a = "test" condition: $a }
`

const yaraRulesRandom = `
rule rule_ccc { strings: $c = "test" condition: $c }
rule rule_aaa { strings: $a = "test" condition: $a }
rule rule_eee { strings: $e = "test" condition: $e }
rule rule_bbb { strings: $b = "test" condition: $b }
rule rule_ddd { strings: $d = "test" condition: $d }
`

var ruleSets = []struct {
	name  string
	rules string
}{
	{"alphabetical", yaraRulesAlpha},
	{"reverse", yaraRulesReverse},
	{"random", yaraRulesRandom},
}

func main() {
	iterations := 20
	data := []byte("this is a test string")
	allPassed := true

	for _, rs := range ruleSets {
		fmt.Printf("Rule set: %s\n", rs.name)

		// Write rules to temp file
		tmpFile, err := os.CreateTemp("", "sort-diff-*.yar")
		if err != nil {
			fmt.Fprintf(os.Stderr, "temp file error: %v\n", err)
			os.Exit(1)
		}
		tmpFile.WriteString(rs.rules)
		tmpFile.Close()

		// Compile with both libraries using internal helpers
		goYaraRules, err := internal.GoYaraRules(tmpFile.Name())
		if err != nil {
			fmt.Fprintf(os.Stderr, "go-yara compile error: %v\n", err)
			os.Exit(1)
		}

		yargoRules, err := internal.YargoRules(tmpFile.Name())
		if err != nil {
			fmt.Fprintf(os.Stderr, "yargo compile error: %v\n", err)
			os.Exit(1)
		}

		os.Remove(tmpFile.Name())

		// Get go-yara reference order (single run, it's deterministic)
		goYaraOrder := scanGoYara(goYaraRules, data)
		fmt.Printf("  go-yara order: %s\n", goYaraOrder)

		// Test yargo determinism over multiple runs
		yargoResults := make([]string, iterations)
		for i := 0; i < iterations; i++ {
			yargoResults[i] = scanYargo(yargoRules, data)
		}

		// Check yargo determinism
		yargoFirst := yargoResults[0]
		yargoDeterministic := true
		for _, r := range yargoResults {
			if r != yargoFirst {
				yargoDeterministic = false
				break
			}
		}

		// Compare
		matchesGoYara := yargoFirst == goYaraOrder

		if yargoDeterministic && matchesGoYara {
			fmt.Printf("  yargo order:   %s\n", yargoFirst)
			fmt.Printf("  PASS: yargo is deterministic and matches go-yara\n")
		} else if yargoDeterministic {
			fmt.Printf("  yargo order:   %s\n", yargoFirst)
			fmt.Printf("  FAIL: yargo is deterministic but differs from go-yara\n")
			allPassed = false
		} else {
			fmt.Printf("  yargo order:   NON-DETERMINISTIC\n")
			seen := make(map[string]int)
			for _, r := range yargoResults {
				seen[r]++
			}
			for order, count := range seen {
				fmt.Printf("    %dx: %s\n", count, order)
			}
			fmt.Printf("  FAIL: yargo is non-deterministic\n")
			allPassed = false
		}
		fmt.Println()
	}

	if allPassed {
		fmt.Println("PASS: yargo match order is deterministic and matches go-yara")
		os.Exit(0)
	} else {
		fmt.Println("FAIL: yargo match order differs from go-yara")
		os.Exit(1)
	}
}

func scanGoYara(rules *yara.Rules, data []byte) string {
	var matches yara.MatchRules
	rules.ScanMem(data, 0, 10*time.Second, &matches)
	var names []string
	for _, m := range matches {
		names = append(names, m.Rule)
	}
	return strings.Join(names, ",")
}

func scanYargo(rules *scanner.Rules, data []byte) string {
	var matches scanner.MatchRules
	rules.ScanMem(data, 0, 10*time.Second, &matches)
	var names []string
	for _, m := range matches {
		names = append(names, m.Rule)
	}
	return strings.Join(names, ",")
}
