package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	_ "github.com/go-sql-driver/mysql"
	yara "github.com/hillu/go-yara/v4"

	"github.com/sansecio/yargo/parser"
	"github.com/sansecio/yargo/scanner"
)

type Detection struct {
	Name    string `json:"name"`
	Snippet string `json:"snippet"`
}

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

	db, err := sql.Open("mysql", "root:root@tcp(127.0.0.1:3306)/storeminer")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting to MySQL: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	rows, err := db.Query(`SELECT detections FROM detections WHERE detections IS NOT NULL AND LENGTH(detections) > 2`)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error querying database: %v\n", err)
		os.Exit(1)
	}
	defer rows.Close()

	// First pass: collect unique snippets by detection name
	uniqueSnippets := make(map[string]string) // detection name -> snippet
	var rowCount int
	for rows.Next() {
		rowCount++
		if rowCount%100000 == 0 {
			fmt.Fprintf(os.Stderr, "Reading rows: %d, unique names: %d...\n", rowCount, len(uniqueSnippets))
		}
		var detectionsJSON string
		if err := rows.Scan(&detectionsJSON); err != nil {
			continue
		}

		var detections []Detection
		if err := json.Unmarshal([]byte(detectionsJSON), &detections); err != nil {
			continue
		}

		for _, detection := range detections {
			if detection.Snippet == "" {
				continue
			}
			if _, exists := uniqueSnippets[detection.Name]; !exists {
				uniqueSnippets[detection.Name] = detection.Snippet
			}
		}
	}

	if err := rows.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading rows: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Found %d unique detection names from %d rows\n", len(uniqueSnippets), rowCount)

	// Second pass: scan each unique snippet
	yargoOnly := make(map[string]int)
	goYaraOnly := make(map[string]int)
	exampleSnippets := make(map[string]string)
	exampleNames := make(map[string]string)

	var matchedBoth, skipped int
	skippedNames := make(map[string]int)
	scanned := 0

	for name, snippet := range uniqueSnippets {
		scanned++
		if scanned%100 == 0 {
			fmt.Fprintf(os.Stderr, "Scanning: %d/%d...\n", scanned, len(uniqueSnippets))
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
			skippedNames[name]++
			continue
		}

		// Check if at least one rule matched in both
		for rule := range goYaraSet {
			if yargoSet[rule] {
				matchedBoth++
				break
			}
		}

		// Find differences
		for rule := range yargoSet {
			if !goYaraSet[rule] {
				yargoOnly[rule]++
				if _, ok := exampleSnippets["yargo:"+rule]; !ok {
					exampleSnippets["yargo:"+rule] = snippet
					exampleNames["yargo:"+rule] = name
				}
			}
		}
		for rule := range goYaraSet {
			if !yargoSet[rule] {
				goYaraOnly[rule]++
				if _, ok := exampleSnippets["goyara:"+rule]; !ok {
					exampleSnippets["goyara:"+rule] = snippet
					exampleNames["goyara:"+rule] = name
				}
			}
		}
	}

	fmt.Printf("Unique detection names scanned: %d\n", len(uniqueSnippets))
	fmt.Printf("Snippets matched by both: %d\n", matchedBoth)
	fmt.Printf("Snippets skipped (no matches): %d\n", skipped)
	fmt.Printf("Skipped by detection name:\n")
	for _, name := range sortByCount(skippedNames) {
		fmt.Printf("  %s: %d\n", name, skippedNames[name])
	}
	fmt.Println()

	// Get warnings to identify skipped rules
	skippedRules := make(map[string]string) // rule -> reason
	for _, w := range yargoRules.Warnings() {
		if idx := indexString(w, `rule "`); idx >= 0 {
			rest := w[idx+6:]
			if end := indexString(rest, `"`); end >= 0 {
				ruleName := rest[:end]
				reason := rest[end+3:] // skip `": `
				skippedRules[ruleName] = reason
			}
		}
	}

	// Sort and print yargo-only matches
	fmt.Printf("Rules matching in YARGO but NOT in go-yara (%d total extra matches):\n", sumValues(yargoOnly))
	for _, rule := range sortByCount(yargoOnly) {
		fmt.Printf("  %s: %d occurrences (detection: %s)\n", rule, yargoOnly[rule], exampleNames["yargo:"+rule])
	}

	fmt.Printf("\nRules matching in go-yara but NOT in yargo (%d total missing matches):\n", sumValues(goYaraOnly))

	var unexplained []string
	for _, rule := range sortByCount(goYaraOnly) {
		if reason, ok := skippedRules[rule]; ok {
			fmt.Printf("  %s: %d occurrences [SKIPPED: %s]\n", rule, goYaraOnly[rule], reason)
		} else {
			fmt.Printf("  %s: %d occurrences (detection: %s) [UNEXPECTED]\n", rule, goYaraOnly[rule], exampleNames["goyara:"+rule])
			unexplained = append(unexplained, rule)
		}
	}

	if len(unexplained) > 0 {
		fmt.Printf("\n*** %d rules with UNEXPLAINED missing matches: %v\n", len(unexplained), unexplained)
	}
}

func indexString(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
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
	devNull, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	defer devNull.Close()
	savedStderr, _ := syscall.Dup(syscall.Stderr)
	defer syscall.Close(savedStderr)
	syscall.Dup2(int(devNull.Fd()), syscall.Stderr)
	defer syscall.Dup2(savedStderr, syscall.Stderr)

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

	devNull, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	defer devNull.Close()
	savedStderr, _ := syscall.Dup(syscall.Stderr)
	defer syscall.Close(savedStderr)
	syscall.Dup2(int(devNull.Fd()), syscall.Stderr)
	defer syscall.Dup2(savedStderr, syscall.Stderr)

	return scanner.CompileWithOptions(ruleSet, scanner.CompileOptions{
		SkipInvalidRegex: true,
	})
}
