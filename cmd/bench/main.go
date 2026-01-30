package main

import (
	"flag"
	"fmt"
	"os"
	"runtime/pprof"
	"time"

	"github.com/hillu/go-yara/v4"

	"github.com/sansecio/yargo/parser"
	"github.com/sansecio/yargo/scanner"
)

func main() {
	rulesPath := flag.String("rules", "fixture/ecomscan.yar", "path to YARA rules file")
	scanPath := flag.String("scan", "fixture/Product.php", "path to file to scan")
	iterations := flag.Int("n", 1, "number of iterations")
	cpuprofile := flag.String("cpuprofile", "", "write cpu profile to file (scan only)")
	flag.Parse()

	// Load file to scan
	data, err := os.ReadFile(*scanPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read scan file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Scanning %d bytes, %d iterations\n\n", len(data), *iterations)

	// Benchmark go-yara
	goYaraTime, goYaraMatches := benchGoYara(*rulesPath, data, *iterations)

	// Benchmark yargo
	yargoTime, yargoMatches, warnings := benchYargo(*rulesPath, data, *iterations, *cpuprofile)

	// Print warnings
	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}
	if len(warnings) > 0 {
		fmt.Fprintln(os.Stderr)
	}

	// Output results
	fmt.Printf("go-yara:  %v  (%.2f MB/s)  %d matches\n",
		goYaraTime, float64(len(data))/goYaraTime.Seconds()/1024/1024, goYaraMatches)
	fmt.Printf("yargo:    %v  (%.2f MB/s)  %d matches\n",
		yargoTime, float64(len(data))/yargoTime.Seconds()/1024/1024, yargoMatches)
	fmt.Printf("ratio:    %.2fx\n", float64(yargoTime)/float64(goYaraTime))
}

func benchGoYara(rulesPath string, data []byte, iterations int) (time.Duration, int) {
	compiler, err := yara.NewCompiler()
	if err != nil {
		fmt.Fprintf(os.Stderr, "go-yara: failed to create compiler: %v\n", err)
		os.Exit(1)
	}

	rulesFile, err := os.Open(rulesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "go-yara: failed to open rules: %v\n", err)
		os.Exit(1)
	}
	compiler.AddFile(rulesFile, "")
	rulesFile.Close()

	rules, err := compiler.GetRules()
	if err != nil {
		fmt.Fprintf(os.Stderr, "go-yara: failed to get rules: %v\n", err)
		os.Exit(1)
	}

	// Warm up
	for i := 0; i < 3; i++ {
		var matches yara.MatchRules
		rules.ScanMem(data, 0, time.Minute, &matches)
	}

	// Benchmark
	var lastMatches yara.MatchRules
	start := time.Now()
	for i := 0; i < iterations; i++ {
		var matches yara.MatchRules
		rules.ScanMem(data, 0, time.Minute, &matches)
		lastMatches = matches
	}
	elapsed := time.Since(start)

	return elapsed / time.Duration(iterations), len(lastMatches)
}

func benchYargo(rulesPath string, data []byte, iterations int, cpuprofile string) (time.Duration, int, []string) {
	p, err := parser.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "yargo: failed to create parser: %v\n", err)
		os.Exit(1)
	}

	rs, err := p.ParseFile(rulesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "yargo: failed to parse rules: %v\n", err)
		os.Exit(1)
	}

	rules, err := scanner.CompileWithOptions(rs, scanner.CompileOptions{SkipInvalidRegex: true})
	if err != nil {
		fmt.Fprintf(os.Stderr, "yargo: failed to compile rules: %v\n", err)
		os.Exit(1)
	}

	// Warm up
	for i := 0; i < 3; i++ {
		var matches scanner.MatchRules
		rules.ScanMem(data, 0, time.Minute, &matches)
	}

	// Start CPU profiling if requested (scan only)
	if cpuprofile != "" {
		f, err := os.Create(cpuprofile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create CPU profile: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		if err := pprof.StartCPUProfile(f); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to start CPU profile: %v\n", err)
			os.Exit(1)
		}
		defer pprof.StopCPUProfile()
	}

	// Benchmark
	var lastMatches scanner.MatchRules
	start := time.Now()
	for i := 0; i < iterations; i++ {
		var matches scanner.MatchRules
		rules.ScanMem(data, 0, time.Minute, &matches)
		lastMatches = matches
	}
	elapsed := time.Since(start)

	return elapsed / time.Duration(iterations), len(lastMatches), rules.Warnings()
}
