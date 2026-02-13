//go:build yara

package main

import (
	"cmp"
	"flag"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"time"

	yara "github.com/hillu/go-yara/v4"

	"github.com/sansecio/yargo/cmd/internal"
	"github.com/sansecio/yargo/scanner"
)

func main() {
	var yaraFile, corpusDir string
	flag.StringVar(&yaraFile, "yara", "", "path to YARA rules file")
	flag.StringVar(&corpusDir, "corpus", "", "path to corpus directory")
	flag.Parse()

	if yaraFile == "" || corpusDir == "" {
		fmt.Fprintf(os.Stderr, "Usage: corpus-diff -yara <rules.yar> -corpus <dir>\n")
		os.Exit(1)
	}

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

	// Track rule differences: rule -> count
	yargoOnly := make(map[string]int)
	goYaraOnly := make(map[string]int)
	exampleFiles := make(map[string]string) // rule -> example file where it differs

	filepath.WalkDir(corpusDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

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

		// Find differences
		for rule := range yargoSet {
			if !goYaraSet[rule] {
				yargoOnly[rule]++
				if _, ok := exampleFiles["yargo:"+rule]; !ok {
					exampleFiles["yargo:"+rule] = path
				}
			}
		}
		for rule := range goYaraSet {
			if !yargoSet[rule] {
				goYaraOnly[rule]++
				if _, ok := exampleFiles["goyara:"+rule]; !ok {
					exampleFiles["goyara:"+rule] = path
				}
			}
		}

		return nil
	})

	sortByCount := func(m map[string]int) []string {
		return slices.SortedFunc(maps.Keys(m), func(a, b string) int {
			return cmp.Compare(m[b], m[a])
		})
	}
	sumValues := func(m map[string]int) int {
		sum := 0
		for _, v := range m {
			sum += v
		}
		return sum
	}

	// Sort and print yargo-only matches
	fmt.Printf("Rules matching in YARGO but NOT in go-yara (%d total extra matches):\n", sumValues(yargoOnly))
	for _, rule := range sortByCount(yargoOnly) {
		fmt.Printf("  %s: %d occurrences (e.g. %s)\n", rule, yargoOnly[rule], filepath.Base(exampleFiles["yargo:"+rule]))
	}

	fmt.Printf("\nRules matching in go-yara but NOT in yargo (%d total missing matches):\n", sumValues(goYaraOnly))

	var unexplained []string
	for _, rule := range sortByCount(goYaraOnly) {
		fmt.Printf("  %s: %d occurrences (e.g. %s) [UNEXPECTED]\n", rule, goYaraOnly[rule], filepath.Base(exampleFiles["goyara:"+rule]))
		unexplained = append(unexplained, rule)
	}

	if len(unexplained) > 0 {
		fmt.Printf("\n*** %d rules with UNEXPLAINED missing matches: %v\n", len(unexplained), unexplained)
	}
}
