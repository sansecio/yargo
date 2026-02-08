//go:build yara

package main

import (
	"cmp"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/pprof"
	"slices"
	"strings"
	"time"

	yara "github.com/hillu/go-yara/v4"
	"github.com/sansecio/yargo/cmd/internal"
	"github.com/sansecio/yargo/scanner"
)

type corpusFile struct {
	path string
	data []byte
}

var (
	cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file (profiles yargo scan only)")
	filter     = flag.String("filter", "", "only scan corpus files whose path contains this substring")
	repeat     = flag.Int("repeat", 1, "number of times to repeat the scan (useful with -filter for profiling)")
)

func truncName(path string, maxLen int) string {
	name := filepath.Base(path)
	if len(name) <= maxLen {
		return name
	}
	return "…" + name[len(name)-maxLen+len("…"):]
}

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

	if *filter != "" {
		var filtered []corpusFile
		for _, f := range files {
			if strings.Contains(f.path, *filter) {
				filtered = append(filtered, f)
			}
		}
		files = filtered
	}

	fmt.Printf("Loaded %d corpus files\n", len(files))

	// Compile go-yara rules (suppress absl/RE2 stderr noise)
	goYaraRules, err := internal.GoYaraRules(yaraFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error compiling go-yara rules: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Compiled %d go-yara rules\n", len(goYaraRules.GetRules()))

	// Compile yargo rules (suppress absl/RE2 stderr noise)
	yargoRules, err := internal.YargoRules(yaraFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error compiling yargo rules: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Compiled %d yargo rules\n\n", yargoRules.NumRules())

	// Benchmark go-yara (fast mode)
	start := time.Now()
	var goYaraMatches int
	for r := range *repeat {
		for i, file := range files {
			fmt.Fprintf(os.Stderr, "\rgo-yara [%d/%d]: %d/%d %s\033[K", r+1, *repeat, i+1, len(files), truncName(file.path, 100))
			var matches yara.MatchRules
			if err := goYaraRules.ScanMem(file.data, yara.ScanFlagsFastMode, 30*time.Second, &matches); err != nil {
				fmt.Fprintf(os.Stderr, "\ngo-yara error scanning %s: %v\n", file.path, err)
			}
			goYaraMatches += len(matches)
		}
	}
	fmt.Fprint(os.Stderr, "\r\033[K")
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
	type fileTiming struct {
		path     string
		duration time.Duration
	}
	timings := make([]fileTiming, 0, len(files))

	for r := range *repeat {
		for i, file := range files {
			fmt.Fprintf(os.Stderr, "\ryargo [%d/%d]: %d/%d %s\033[K", r+1, *repeat, i+1, len(files), truncName(file.path, 100))
			fileStart := time.Now()
			var matches scanner.MatchRules
			if err := yargoRules.ScanMem(file.data, 0, 30*time.Second, &matches); err != nil {
				fmt.Fprintf(os.Stderr, "\nyargo error scanning %s: %v\n", file.path, err)
			}
			timings = append(timings, fileTiming{path: file.path, duration: time.Since(fileStart)})
			yargoMatches += len(matches)
		}
	}
	fmt.Fprint(os.Stderr, "\r\033[K")
	yargoDuration := time.Since(start)

	if *cpuprofile != "" {
		pprof.StopCPUProfile()
	}

	fmt.Printf("go-yara (fast mode): %v (%d matches)\n", goYaraDuration, goYaraMatches)
	fmt.Printf("yargo:               %v (%d matches)\n", yargoDuration, yargoMatches)
	fmt.Printf("\nyargo/go-yara ratio: %.2fx\n", float64(yargoDuration)/float64(goYaraDuration))

	slices.SortFunc(timings, func(a, b fileTiming) int {
		return cmp.Compare(b.duration, a.duration)
	})
	fmt.Printf("\nTop 5 slowest files (yargo):\n")
	for i, t := range timings[:min(5, len(timings))] {
		fmt.Printf("  %2d. %v %s\n", i+1, t.duration, truncName(t.path, 100))
	}

	// Profile regexes on the 5 slowest files
	for _, t := range timings[:min(5, len(timings))] {
		data, err := os.ReadFile(t.path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", t.path, err)
			continue
		}
		rt := yargoRules.RegexProfile(data)
		fmt.Printf("\nRegex profile for %s (%d regexes matched):\n", t.path, len(rt))
		for i, p := range rt[:min(5, len(rt))] {
			fmt.Printf("  %2d. %v (%d calls) rule=%s str=%s matched=%q extracted=%q re=%s\n", i+1, p.Duration, p.Calls, p.Rule, p.String, p.MatchedAtoms, p.ExtractedAtoms, p.Pattern)
		}
	}
}
