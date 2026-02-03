package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime/pprof"
	"time"

	"github.com/sansecio/yargo/cmd/internal"
)

var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file (profiles yargo parsing/compilation only)")

func main() {
	flag.Parse()

	yaraFile := filepath.Join(os.Getenv("HOME"), "Code/ecomscan-signatures/build/ecomscan.yar")

	fmt.Printf("Benchmarking parsing/compilation of %s\n\n", yaraFile)

	// Benchmark go-yara compilation
	start := time.Now()
	_, err := internal.GoYaraRules(yaraFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error compiling go-yara rules: %v\n", err)
		os.Exit(1)
	}
	goYaraDuration := time.Since(start)

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
	_, err = internal.YargoRules(yaraFile)
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
