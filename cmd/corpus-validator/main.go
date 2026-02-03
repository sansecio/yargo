package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/sansecio/yargo/parser"
	"github.com/sansecio/yargo/scanner"
)

func main() {
	yaraFile := filepath.Join(os.Getenv("HOME"), "Code/ecomscan-signatures/build/ecomscan.yar")
	corpusBase := filepath.Join(os.Getenv("HOME"), "Code/ecomscan-signatures/corpus")
	corpusDirs := []string{
		filepath.Join(corpusBase, "backend"),
		filepath.Join(corpusBase, "frontend"),
	}

	p := parser.New()

	ruleSet, err := p.ParseFile(yaraFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing %s: %v\n", yaraFile, err)
		os.Exit(1)
	}

	rules, err := scanner.Compile(ruleSet)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error compiling rules: %v\n", err)
		os.Exit(1)
	}

	debug := os.Getenv("DEBUG_FILE")

	fmt.Printf("Compiled %d rules\n", len(ruleSet.Rules))
	acPatterns, regexPatterns := rules.Stats()
	fmt.Printf("AC patterns: %d, Regex patterns: %d\n", acPatterns, regexPatterns)
	var missing []string

	for _, dir := range corpusDirs {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}

			data, err := os.ReadFile(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", path, err)
				return nil
			}

			var matches scanner.MatchRules
			if err := rules.ScanMem(data, 0, 30*time.Second, &matches); err != nil {
				fmt.Fprintf(os.Stderr, "Error scanning %s: %v\n", path, err)
				return nil
			}

			if debug != "" && filepath.Base(path) == debug {
				fmt.Printf("DEBUG %s: %d matches\n", path, len(matches))
				for _, m := range matches {
					trust := int64(100)
					for _, meta := range m.Metas {
						if meta.Identifier == "trust" {
							if v, ok := meta.Value.(int64); ok {
								trust = v
							}
						}
					}
					fmt.Printf("  Rule: %s (trust=%d)\n", m.Rule, trust)
				}
			}

			if !hasTrustedMatch(matches) {
				missing = append(missing, path)
			}

			return nil
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error walking %s: %v\n", dir, err)
		}
	}

	if len(missing) > 0 {
		fmt.Printf("\nFiles without trust>=50 match:\n")
		for _, path := range missing {
			fmt.Printf("  %s\n", path)
		}
	} else {
		fmt.Printf("\nAll files have trust>=50 matches\n")
	}
}

func hasTrustedMatch(matches scanner.MatchRules) bool {
	for _, m := range matches {
		trust := int64(100) // default if not specified
		for _, meta := range m.Metas {
			if meta.Identifier == "trust" {
				if v, ok := meta.Value.(int64); ok {
					trust = v
				}
			}
		}
		if trust >= 50 {
			return true
		}
	}
	return false
}
