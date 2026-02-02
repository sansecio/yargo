package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	yara "github.com/hillu/go-yara/v4"

	"github.com/sansecio/yargo/parser"
	"github.com/sansecio/yargo/scanner"
)

func main() {
	yaraFile := filepath.Join(os.Getenv("HOME"), "Code/ecomscan-signatures/build/ecomscan.yar")

	goYaraRules, err := compileGoYaraRules(yaraFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error compiling go-yara rules: %v\n", err)
		os.Exit(1)
	}

	yargoRules, err := compileYargoRules(yaraFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error compiling yargo rules: %v\n", err)
		os.Exit(1)
	}

	db, err := sql.Open("mysql", "root:root@tcp(127.0.0.1:3306)/sansec")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting to MySQL: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	rows, err := db.Query(`SELECT sig_name, snippet FROM detection_log WHERE sig_name != 'uploaded_session_file' AND snippet != '' GROUP BY sig_name, snippet`)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error querying database: %v\n", err)
		os.Exit(1)
	}
	defer rows.Close()

	// Track rule differences: rule -> count
	yargoOnly := make(map[string]int)
	goYaraOnly := make(map[string]int)
	exampleSnippets := make(map[string]string) // rule -> example snippet where it differs
	exampleSigNames := make(map[string]string) // rule -> sig_name where it differs
	exampleMatched := make(map[string]string)  // rule -> matched string data

	// Track matched data mismatches between scanners
	dataMismatch := make(map[string]int)
	mismatchExamples := make(map[string][2]string) // rule -> [yargo data, go-yara data]

	var matchedBoth, skipped int
	skippedSigNames := make(map[string]int) // track which sig_names are being skipped

	for rows.Next() {
		var sigName, snippet string
		if err := rows.Scan(&sigName, &snippet); err != nil {
			continue
		}

		// If snippet contains ... split and take first value
		if idx := strings.Index(snippet, "..."); idx >= 0 {
			snippet = snippet[:idx]
		}

		data := []byte(snippet)

		// Get go-yara matches
		var goYaraMatches yara.MatchRules
		goYaraRules.ScanMem(data, yara.ScanFlagsFastMode, 30*time.Second, &goYaraMatches)
		goYaraSet := make(map[string]bool)
		for _, m := range goYaraMatches {
			goYaraSet[m.Rule] = true
		}

		// Get yargo matches
		var yargoMatches scanner.MatchRules
		yargoRules.ScanMem(data, 0, 30*time.Second, &yargoMatches)
		yargoSet := make(map[string]bool)
		for _, m := range yargoMatches {
			yargoSet[m.Rule] = true
		}

		// Skip if neither matched
		if len(goYaraSet) == 0 && len(yargoSet) == 0 {
			skipped++
			skippedSigNames[sigName]++
			continue
		}

		// Check if at least one rule matched in both
		for rule := range goYaraSet {
			if yargoSet[rule] {
				matchedBoth++
				break
			}
		}

		// Build maps of rule -> matched data for comparison
		yargoData := make(map[string]string)
		for _, m := range yargoMatches {
			if len(m.Strings) > 0 {
				yargoData[m.Rule] = string(m.Strings[0].Data)
			}
		}
		goYaraData := make(map[string]string)
		for _, m := range goYaraMatches {
			if len(m.Strings) > 0 {
				goYaraData[m.Rule] = string(m.Strings[0].Data)
			}
		}

		// Compare matched data for rules that matched in both
		for rule := range yargoSet {
			if goYaraSet[rule] {
				if yargoData[rule] != goYaraData[rule] {
					dataMismatch[rule]++
					if _, ok := mismatchExamples[rule]; !ok {
						mismatchExamples[rule] = [2]string{yargoData[rule], goYaraData[rule]}
					}
				}
			}
		}

		// Find differences
		for rule := range yargoSet {
			if !goYaraSet[rule] {
				yargoOnly[rule]++
				if _, ok := exampleSnippets["yargo:"+rule]; !ok {
					exampleSnippets["yargo:"+rule] = snippet
					exampleSigNames["yargo:"+rule] = sigName
					// Store matched string data from yargo
					for _, m := range yargoMatches {
						if m.Rule == rule && len(m.Strings) > 0 {
							exampleMatched["yargo:"+rule] = string(m.Strings[0].Data)
							break
						}
					}
				}
			}
		}
		for rule := range goYaraSet {
			if !yargoSet[rule] {
				goYaraOnly[rule]++
				if _, ok := exampleSnippets["goyara:"+rule]; !ok {
					exampleSnippets["goyara:"+rule] = snippet
					exampleSigNames["goyara:"+rule] = sigName
					// Store matched string data from go-yara
					for _, m := range goYaraMatches {
						if m.Rule == rule && len(m.Strings) > 0 {
							exampleMatched["goyara:"+rule] = string(m.Strings[0].Data)
							break
						}
					}
				}
			}
		}
	}

	if err := rows.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading rows: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Snippets matched by both: %d\n", matchedBoth)
	fmt.Printf("Snippets skipped (no matches): %d\n", skipped)
	fmt.Printf("Skipped by sig_name:\n")
	for _, sig := range sortByCount(skippedSigNames) {
		fmt.Printf("  %s: %d\n", sig, skippedSigNames[sig])
	}
	fmt.Println()

	// Get warnings to identify skipped rules
	skippedRules := make(map[string]string) // rule -> reason
	for _, w := range yargoRules.Warnings() {
		if idx := strings.Index(w, `rule "`); idx >= 0 {
			rest := w[idx+6:]
			if end := strings.Index(rest, `"`); end >= 0 {
				ruleName := rest[:end]
				reason := rest[end+3:] // skip `": `
				skippedRules[ruleName] = reason
			}
		}
	}

	// Sort and print yargo-only matches
	fmt.Printf("Rules matching in YARGO but NOT in go-yara (%d total extra matches):\n", sumValues(yargoOnly))
	for _, rule := range sortByCount(yargoOnly) {
		fmt.Printf("  %s: %d occurrences (sig: %s)\n", rule, yargoOnly[rule], exampleSigNames["yargo:"+rule])
		fmt.Printf("    snippet: %q\n", exampleSnippets["yargo:"+rule])
		fmt.Printf("    matched: %q\n", exampleMatched["yargo:"+rule])
	}

	fmt.Printf("\nRules matching in go-yara but NOT in yargo (%d total missing matches):\n", sumValues(goYaraOnly))

	var unexplained []string
	for _, rule := range sortByCount(goYaraOnly) {
		if reason, ok := skippedRules[rule]; ok {
			fmt.Printf("  %s: %d occurrences [SKIPPED: %s]\n", rule, goYaraOnly[rule], reason)
		} else {
			fmt.Printf("  %s: %d occurrences (sig: %s) [UNEXPECTED]\n", rule, goYaraOnly[rule], exampleSigNames["goyara:"+rule])
			fmt.Printf("    snippet: %q\n", exampleSnippets["goyara:"+rule])
			fmt.Printf("    matched: %q\n", exampleMatched["goyara:"+rule])
			unexplained = append(unexplained, rule)
		}
	}

	if len(unexplained) > 0 {
		fmt.Printf("\n*** %d rules with UNEXPLAINED missing matches: %v\n", len(unexplained), unexplained)
	}

	// Report matched data mismatches between scanners
	if len(dataMismatch) > 0 {
		fmt.Printf("\nMatched data differs between yargo and go-yara (%d rules):\n", len(dataMismatch))
		for _, rule := range sortByCount(dataMismatch) {
			example := mismatchExamples[rule]
			fmt.Printf("  %s: %d occurrences\n", rule, dataMismatch[rule])
			fmt.Printf("    yargo:   %q\n", example[0])
			fmt.Printf("    go-yara: %q\n", example[1])
		}
	}
}

func sumValues(m map[string]int) int {
	sum := 0
	for _, v := range m {
		sum += v
	}
	return sum
}

func sortByCount(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return m[keys[i]] > m[keys[j]]
	})
	return keys
}

func compileGoYaraRules(yaraFile string) (*yara.Rules, error) {
	compiler, err := yara.NewCompiler()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(yaraFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := compiler.AddFile(f, ""); err != nil {
		return nil, err
	}
	return compiler.GetRules()
}

func compileYargoRules(yaraFile string) (*scanner.Rules, error) {
	p, err := parser.New()
	if err != nil {
		return nil, err
	}
	ruleSet, err := p.ParseFile(yaraFile)
	if err != nil {
		return nil, err
	}

	return scanner.CompileWithOptions(ruleSet, scanner.CompileOptions{
		SkipInvalidRegex: true,
	})
}
