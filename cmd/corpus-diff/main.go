package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	yara "github.com/hillu/go-yara/v4"

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

	// Track rule differences: rule -> count
	yargoOnly := make(map[string]int)
	goYaraOnly := make(map[string]int)
	exampleFiles := make(map[string]string) // rule -> example file where it differs

	for _, dir := range corpusDirs {
		filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
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
	}

	// Sort and print yargo-only matches
	fmt.Printf("Rules matching in YARGO but NOT in go-yara (%d total extra matches):\n", sumValues(yargoOnly))
	for _, rule := range sortByCount(yargoOnly) {
		fmt.Printf("  %s: %d occurrences (e.g. %s)\n", rule, yargoOnly[rule], filepath.Base(exampleFiles["yargo:"+rule]))
	}

	fmt.Printf("\nRules matching in go-yara but NOT in yargo (%d total missing matches):\n", sumValues(goYaraOnly))
	for _, rule := range sortByCount(goYaraOnly) {
		fmt.Printf("  %s: %d occurrences (e.g. %s)\n", rule, goYaraOnly[rule], filepath.Base(exampleFiles["goyara:"+rule]))
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
