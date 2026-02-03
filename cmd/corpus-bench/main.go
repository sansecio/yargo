package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/pprof"
	"time"

	yara "github.com/hillu/go-yara/v4"
	"github.com/sansecio/yargo/parser"
	"github.com/sansecio/yargo/scanner"
)

type corpusFile struct {
	path string
	data []byte
}

var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file (profiles yargo scan only)")

func main() {
	flag.Parse()

	yaraFile := filepath.Join(os.Getenv("HOME"), "Code/ecomscan-signatures/build/ecomscan.yar")
	corpusBase := filepath.Join(os.Getenv("HOME"), "Code/ecomscan-signatures/corpus")
	corpusDirs := []string{
		filepath.Join(corpusBase, "backend"),
		filepath.Join(corpusBase, "frontend"),
	}

	// Load corpus files into memory
	var files []corpusFile
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
			files = append(files, corpusFile{path: path, data: data})
			return nil
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error walking %s: %v\n", dir, err)
			os.Exit(1)
		}
	}
	fmt.Printf("Loaded %d corpus files\n", len(files))

	// Compile go-yara rules (suppress absl/RE2 stderr noise)
	goYaraRules, err := compileGoYaraRules(yaraFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error compiling go-yara rules: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Compiled go-yara rules\n")

	// Compile yargo rules (suppress absl/RE2 stderr noise)
	yargoRules, err := compileYargoRules(yaraFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error compiling yargo rules: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Compiled yargo rules\n\n")

	// Benchmark go-yara (fast mode)
	start := time.Now()
	var goYaraMatches int
	for _, file := range files {
		var matches yara.MatchRules
		if err := goYaraRules.ScanMem(file.data, yara.ScanFlagsFastMode, 30*time.Second, &matches); err != nil {
			fmt.Fprintf(os.Stderr, "go-yara error scanning %s: %v\n", file.path, err)
		}
		goYaraMatches += len(matches)
	}
	goYaraDuration := time.Since(start)

	// Benchmark yargo
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating profile: %v\n", err)
			os.Exit(1)
		}
		pprof.StartCPUProfile(f)
	}

	start = time.Now()
	var yargoMatches int
	for _, file := range files {
		var matches scanner.MatchRules
		if err := yargoRules.ScanMem(file.data, 0, 30*time.Second, &matches); err != nil {
			fmt.Fprintf(os.Stderr, "yargo error scanning %s: %v\n", file.path, err)
		}
		yargoMatches += len(matches)
	}
	yargoDuration := time.Since(start)

	if *cpuprofile != "" {
		pprof.StopCPUProfile()
	}

	fmt.Printf("go-yara (fast mode): %v (%d matches)\n", goYaraDuration, goYaraMatches)
	fmt.Printf("yargo:               %v (%d matches)\n", yargoDuration, yargoMatches)
	fmt.Printf("\nyargo/go-yara ratio: %.2fx\n", float64(yargoDuration)/float64(goYaraDuration))
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

	return scanner.Compile(ruleSet)
}
