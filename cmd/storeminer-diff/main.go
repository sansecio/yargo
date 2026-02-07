//go:build yara

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/go-sql-driver/mysql"
	yara "github.com/hillu/go-yara/v4"

	"github.com/sansecio/yargo/cmd/internal"
	"github.com/sansecio/yargo/scanner"
)

type Detection struct {
	Name    string `json:"name"`
	Snippet string `json:"snippet"`
}

func main() {
	yaraFile := filepath.Join(os.Getenv("HOME"), "Code/ecomscan-signatures/build/ecomscan.yar")

	goYaraRules, err := internal.GoYaraRules(yaraFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error compiling go-yara rules: %v\n", err)
		os.Exit(1)
	}

	yargoRules, err := internal.YargoRules(yaraFile)
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

	diff := internal.NewDiffTracker()
	scanned := 0

	for name, snippet := range uniqueSnippets {
		scanned++
		if scanned%100 == 0 {
			fmt.Fprintf(os.Stderr, "Scanning: %d/%d...\n", scanned, len(uniqueSnippets))
		}

		data := []byte(snippet)

		var goYaraMatches yara.MatchRules
		goYaraRules.ScanMem(data, yara.ScanFlagsFastMode, 30*time.Second, &goYaraMatches)

		var yargoMatches scanner.MatchRules
		yargoRules.ScanMem(data, 0, 30*time.Second, &yargoMatches)

		diff.Add(matchResult(goYaraMatches), scanResult(yargoMatches), name, snippet)
	}

	fmt.Printf("Unique detection names scanned: %d\n", len(uniqueSnippets))
	diff.PrintReport("detection name")
}

func matchResult(matches yara.MatchRules) internal.ScanResult {
	rules := make(map[string]bool, len(matches))
	data := make(map[string]string, len(matches))
	for _, m := range matches {
		rules[m.Rule] = true
		if len(m.Strings) > 0 {
			data[m.Rule] = string(m.Strings[0].Data)
		}
	}
	return internal.ScanResult{Rules: rules, Data: data}
}

func scanResult(matches scanner.MatchRules) internal.ScanResult {
	rules := make(map[string]bool, len(matches))
	data := make(map[string]string, len(matches))
	for _, m := range matches {
		rules[m.Rule] = true
		if len(m.Strings) > 0 {
			data[m.Rule] = string(m.Strings[0].Data)
		}
	}
	return internal.ScanResult{Rules: rules, Data: data}
}
