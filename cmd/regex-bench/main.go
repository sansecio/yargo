package main

import (
	"flag"
	"fmt"
	"os"
	"runtime/pprof"
	"time"

	stdregexp "regexp"

	"github.com/coregx/coregex"
	gore2 "github.com/wasilibs/go-re2/experimental"
)

type matcher interface {
	Match(b []byte) bool
}

type compileFunc func(pattern string) (matcher, error)

var engines = map[string]compileFunc{
	"regexp": func(s string) (matcher, error) {
		return stdregexp.Compile(s)
	},
	"go-re2": func(s string) (matcher, error) {
		return gore2.CompileLatin1(s)
	},
	"coregex": func(s string) (matcher, error) {
		return coregex.Compile(s)
	},
}

var cpuProfile = flag.Bool("cpu-profile", false, "write cpu profiles for each engine")

func main() {
	flag.Parse()

	if flag.NArg() < 2 {
		fmt.Fprintf(os.Stderr, "Usage: regex-bench [-cpu-profile] <file> <regex>\n")
		os.Exit(1)
	}

	filePath := flag.Arg(0)
	pattern := flag.Arg(1)

	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("File: %s (%d bytes)\n", filePath, len(data))
	fmt.Printf("Regex: %s\n\n", pattern)

	results := make(map[string]time.Duration)
	order := []string{"regexp", "go-re2", "coregex"}

	for _, name := range order {
		compile := engines[name]

		var profileFile *os.File
		if *cpuProfile {
			profileFile, err = os.Create(name + ".pprof")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error creating profile for %s: %v\n", name, err)
				os.Exit(1)
			}
		}

		re, err := compile(pattern)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error compiling regex with %s: %v\n", name, err)
			os.Exit(1)
		}

		if profileFile != nil {
			if err := pprof.StartCPUProfile(profileFile); err != nil {
				fmt.Fprintf(os.Stderr, "Error starting CPU profile: %v\n", err)
				os.Exit(1)
			}
		}

		start := time.Now()
		_ = re.Match(data)
		duration := time.Since(start)

		if profileFile != nil {
			pprof.StopCPUProfile()
			_ = profileFile.Close()
		}

		results[name] = duration
	}

	// Print table
	fmt.Println("Engine      Duration (µs)")
	fmt.Println("--------    -------------")
	for _, name := range order {
		fmt.Printf("%-10s  %13.2f\n", name, float64(results[name].Microseconds()))
	}
}
