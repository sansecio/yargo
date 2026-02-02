package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime/pprof"
	"time"

	yara "github.com/hillu/go-yara/v4"
	"github.com/sansecio/yargo/parser"
	"github.com/sansecio/yargo/scanner"
)

var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file (profiles scanning only)")

func main() {
	flag.Parse()

	yaraFile := filepath.Join(os.Getenv("HOME"), "Code/ecomscan-signatures/build/ecomscan.yar")
	targetFile := filepath.Join(os.Getenv("HOME"), "Code/yargo/testdata_large_binary")

	// Read the entire file into memory
	fmt.Printf("Reading %s...\n", targetFile)
	data, err := os.ReadFile(targetFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading target file: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Loaded %d bytes (%.2f MB)\n", len(data), float64(len(data))/(1024*1024))

	// Compile go-yara rules
	goYaraRules, err := compileGoYaraRules(yaraFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error compiling go-yara rules: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Compiled go-yara rules\n")

	// Compile yargo rules
	yargoRules, err := compileYargoRules(yaraFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error compiling yargo rules: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Compiled yargo rules\n")
	for _, w := range yargoRules.Warnings() {
		fmt.Printf("  warning: %s\n", w)
	}
	fmt.Println()

	// Benchmark go-yara (fast mode)
	start := time.Now()
	var goYaraMatches yara.MatchRules
	if err := goYaraRules.ScanMem(data, yara.ScanFlagsFastMode, 30*time.Second, &goYaraMatches); err != nil {
		fmt.Fprintf(os.Stderr, "go-yara error: %v\n", err)
	}
	goYaraDuration := time.Since(start)

	// Benchmark yargo (with optional CPU profiling)
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating profile: %v\n", err)
			os.Exit(1)
		}
		pprof.StartCPUProfile(f)
	}

	start = time.Now()
	var yargoMatches scanner.MatchRules
	if err := yargoRules.ScanMem(data, 0, 30*time.Second, &yargoMatches); err != nil {
		fmt.Fprintf(os.Stderr, "yargo error: %v\n", err)
	}
	yargoDuration := time.Since(start)

	if *cpuprofile != "" {
		pprof.StopCPUProfile()
	}

	fmt.Printf("go-yara (fast mode): %v (%d matches)\n", goYaraDuration, len(goYaraMatches))
	fmt.Printf("yargo:               %v (%d matches)\n", yargoDuration, len(yargoMatches))
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

	return scanner.CompileWithOptions(ruleSet, scanner.CompileOptions{
		SkipInvalidRegex:        true,
		SkipFullBufferScanRegex: true,
	})
}
