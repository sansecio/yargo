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
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "usage: yargo <rules.yar> <path>\n")
		os.Exit(1)
	}

	rulesFile := os.Args[1]
	scanPath := os.Args[2]

	p := parser.New()
	ruleSet, err := p.ParseFile(rulesFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing rules: %v\n", err)
		os.Exit(1)
	}

	rules, err := scanner.Compile(ruleSet)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error compiling rules: %v\n", err)
		os.Exit(1)
	}

	acPatterns, regexPatterns := rules.Stats()
	fmt.Fprintf(os.Stderr, "compiled %d rules (%d AC patterns, %d regex patterns)\n", rules.NumRules(), acPatterns, regexPatterns)

	var scanned, matched int

	err = filepath.WalkDir(scanPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return nil
		}
		if d.IsDir() {
			return nil
		}

		scanned++

		var matches scanner.MatchRules
		if err := rules.ScanFile(path, 0, 30*time.Second, &matches); err != nil {
			fmt.Fprintf(os.Stderr, "error scanning %s: %v\n", path, err)
			return nil
		}

		if len(matches) > 0 {
			matched++
			fmt.Println(path)
		}

		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error walking path: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "scanned %d files, %d matched\n", scanned, matched)
}
