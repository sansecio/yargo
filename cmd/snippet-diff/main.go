package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	yara "github.com/hillu/go-yara/v4"

	"github.com/sansecio/yargo/cmd/internal"
	"github.com/sansecio/yargo/scanner"
)

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

	diff := internal.NewDiffTracker()

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

		var goYaraMatches yara.MatchRules
		goYaraRules.ScanMem(data, yara.ScanFlagsFastMode, 30*time.Second, &goYaraMatches)

		var yargoMatches scanner.MatchRules
		yargoRules.ScanMem(data, 0, 30*time.Second, &yargoMatches)

		diff.Add(matchResult(goYaraMatches), scanResult(yargoMatches), sigName, snippet)
	}

	if err := rows.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading rows: %v\n", err)
		os.Exit(1)
	}

	diff.PrintReport("sig_name")
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
