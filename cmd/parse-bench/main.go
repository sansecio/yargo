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

var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file (profiles yargo parsing/compilation only)")

func main() {
	flag.Parse()

	yaraFile := filepath.Join(os.Getenv("HOME"), "Code/ecomscan-signatures/build/ecomscan.yar")

	fmt.Printf("Benchmarking parsing/compilation of %s\n\n", yaraFile)

	// Benchmark go-yara compilation
	start := time.Now()
	goYaraRules, err := compileGoYara(yaraFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error compiling go-yara rules: %v\n", err)
		os.Exit(1)
	}
	goYaraDuration := time.Since(start)
	_ = goYaraRules

	// Benchmark yargo parsing + compilation (with optional CPU profiling)
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating profile: %v\n", err)
			os.Exit(1)
		}
		pprof.StartCPUProfile(f)
	}

	start = time.Now()
	_, err = compileYargo(yaraFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error compiling yargo rules: %v\n", err)
		os.Exit(1)
	}
	yargoDuration := time.Since(start)

	if *cpuprofile != "" {
		pprof.StopCPUProfile()
	}

	fmt.Println()

	fmt.Printf("go-yara: %v\n", goYaraDuration)
	fmt.Printf("yargo:   %v\n", yargoDuration)
	fmt.Printf("\nyargo/go-yara ratio: %.2fx\n", float64(yargoDuration)/float64(goYaraDuration))
}

func compileGoYara(yaraFile string) (*yara.Rules, error) {
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

func compileYargo(yaraFile string) (*scanner.Rules, error) {
	p := parser.New()
	ruleSet, err := p.ParseFile(yaraFile)
	if err != nil {
		return nil, err
	}

	return scanner.Compile(ruleSet)
}
