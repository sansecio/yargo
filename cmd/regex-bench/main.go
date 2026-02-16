package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/coregx/coregex"
	"github.com/wasilibs/go-re2/experimental"

	"github.com/sansecio/yargo/parser"
	"github.com/sansecio/yargo/scanner"
)

var (
	yaraFlag   = flag.String("yara", "", "path to YARA rules file (required)")
	corpusFlag = flag.String("corpus", "", "path to corpus directory (required)")
	filter     = flag.String("filter", "", "only scan corpus files whose path contains this substring")
)

type engine struct {
	name    string
	compile scanner.CompileFunc
}

var engines = []engine{
	{"go-re2", func(pattern string) (scanner.Regexp, error) {
		return experimental.CompileLatin1(pattern)
	}},
	{"stdlib", func(pattern string) (scanner.Regexp, error) {
		return regexp.Compile(pattern)
	}},
	{"coregex", func(pattern string) (scanner.Regexp, error) {
		return coregex.Compile(pattern)
	}},
}

type result struct {
	name     string
	duration time.Duration
	matches  int
	rules    int
}

func main() {
	flag.Parse()

	if *yaraFlag == "" || *corpusFlag == "" {
		fmt.Fprintf(os.Stderr, "Usage: regex-bench -yara <rules.yar> -corpus <dir> [flags]\n")
		os.Exit(1)
	}

	// Load corpus files into memory
	var files []corpusFile
	err := filepath.WalkDir(*corpusFlag, func(path string, d fs.DirEntry, err error) error {
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
		files = append(files, corpusFile{path: path, data: data})
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error walking %s: %v\n", *corpusFlag, err)
		os.Exit(1)
	}

	if *filter != "" {
		var filtered []corpusFile
		for _, f := range files {
			if strings.Contains(f.path, *filter) {
				filtered = append(filtered, f)
			}
		}
		files = filtered
	}

	fmt.Printf("Loaded %d corpus files\n\n", len(files))

	// Parse rules once
	p := parser.New()
	ruleSet, err := p.ParseFile(*yaraFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing rules: %v\n", err)
		os.Exit(1)
	}

	var results []result
	for _, eng := range engines {
		rules, err := scanner.CompileWithOptions(ruleSet, scanner.CompileOptions{
			SkipInvalidRegex: true,
			RegexCompiler:    eng.compile,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error compiling with %s: %v\n", eng.name, err)
			continue
		}

		acPatterns, regexPatterns := rules.Stats()
		fmt.Printf("%-10s compiled %d rules (%d AC patterns, %d regex patterns)\n",
			eng.name+":", rules.NumRules(), acPatterns, regexPatterns)

		start := time.Now()
		var totalMatches int
		for i, file := range files {
			fmt.Fprintf(os.Stderr, "\r%-10s %d/%d %s\033[K", eng.name+":", i+1, len(files), truncName(file.path, 80))
			var matches scanner.MatchRules
			if err := rules.ScanMem(file.data, 0, 30*time.Second, &matches); err != nil {
				fmt.Fprintf(os.Stderr, "\n%s error scanning %s: %v\n", eng.name, file.path, err)
			}
			totalMatches += len(matches)
		}
		fmt.Fprint(os.Stderr, "\r\033[K")

		results = append(results, result{
			name:     eng.name,
			duration: time.Since(start),
			matches:  totalMatches,
			rules:    rules.NumRules(),
		})
	}

	fmt.Println()
	fmt.Printf("%-10s  %10s  %8s  %8s\n", "Engine", "Time", "Matches", "Ratio")
	fmt.Printf("%-10s  %10s  %8s  %8s\n", "------", "----", "-------", "-----")

	var baseline time.Duration
	if len(results) > 0 {
		baseline = results[0].duration
	}
	for _, r := range results {
		ratio := float64(r.duration) / float64(baseline)
		fmt.Printf("%-10s  %10v  %8d  %7.2fx\n", r.name, r.duration, r.matches, ratio)
	}
}

type corpusFile struct {
	path string
	data []byte
}

func truncName(path string, maxLen int) string {
	name := filepath.Base(path)
	if len(name) <= maxLen {
		return name
	}
	return "…" + name[len(name)-maxLen+len("…"):]
}
