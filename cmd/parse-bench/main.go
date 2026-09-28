package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"time"

	"github.com/sansecio/yargo/parser"
	"github.com/sansecio/yargo/scanner"
)

// Populated by compare_yara.go when built with -tags yara.
var compareGoYara func(string) (time.Duration, error)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() (err error) {
	yaraFile := flag.String("yara", "", "path to YARA rules file (required)")
	compile := flag.Bool("compile", false, "include scanner compilation after parsing")
	compare := flag.Bool("compare", false, "compare compilation time with go-yara (requires -tags yara; implies -compile)")
	cpuProfile := flag.String("cpuprofile", "", "write CPU profile of Yargo parsing/compilation")
	memProfile := flag.String("memprofile", "", "write heap profile with the result retained after GC")
	flag.Parse()
	if *yaraFile == "" {
		return fmt.Errorf("usage: parse-bench -yara <rules.yar> [flags]")
	}
	if *compare && compareGoYara == nil {
		return fmt.Errorf("-compare requires running with -tags yara")
	}
	if *compare {
		*compile = true
	}
	if *cpuProfile != "" {
		f, err := os.Create(*cpuProfile)
		if err != nil {
			return err
		}
		defer func() {
			err = errors.Join(err, f.Close())
		}()
		if err := pprof.StartCPUProfile(f); err != nil {
			return err
		}
	}

	result, err := benchmark(*yaraFile, *compile, *memProfile)
	if *cpuProfile != "" {
		pprof.StopCPUProfile()
	}
	if err != nil {
		return err
	}
	mode := "parse"
	if *compile {
		mode = "parse + compile"
	}
	fmt.Printf("Yargo %s: %s\nRules: %d\nElapsed: %v\n", mode, *yaraFile, result.rules, result.duration)
	if result.rssErr != nil {
		fmt.Printf("Peak process RSS: unavailable (%v)\n", result.rssErr)
	} else {
		fmt.Printf("Peak process RSS: %.2f MiB (%d bytes)\n", mib(result.peakRSS), result.peakRSS)
	}
	fmt.Printf("Go heap before: %.2f MiB\nGo heap after GC (result retained): %.2f MiB\nTotal Go allocations: %.2f MiB\n", mib(result.heapBefore), mib(result.heapAfter), mib(result.allocated))
	if !*compare {
		return nil
	}
	// Run go-yara afterwards so its allocations cannot inflate Yargo's RSS peak.
	goYaraDuration, err := compareGoYara(*yaraFile)
	if err != nil {
		return err
	}
	fmt.Printf("go-yara: %v\nyargo/go-yara ratio: %.2fx\n", goYaraDuration, float64(result.duration)/float64(goYaraDuration))
	return nil
}

type benchmarkResult struct {
	rules      int
	duration   time.Duration
	peakRSS    uint64
	rssErr     error
	heapBefore uint64
	heapAfter  uint64
	allocated  uint64
}

func benchmark(path string, compile bool, memProfile string) (benchmarkResult, error) {
	var result benchmarkResult
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	rs, err := parser.New().ParseFile(path)
	if err != nil {
		return result, err
	}
	result.rules = len(rs.Rules)
	var retained any = rs
	if compile {
		retained, err = scanner.Compile(rs)
		if err != nil {
			return result, err
		}
	}
	result.duration = time.Since(start)
	runtime.ReadMemStats(&after)
	result.allocated = after.TotalAlloc - before.TotalAlloc
	result.heapBefore = before.HeapAlloc
	// Read the kernel high-water mark before profiling or post-parse GC.
	result.peakRSS, result.rssErr = peakRSS()
	runtime.GC()
	runtime.ReadMemStats(&after)
	result.heapAfter = after.HeapAlloc
	if memProfile != "" {
		f, err := os.Create(memProfile)
		if err != nil {
			return result, err
		}
		err = pprof.WriteHeapProfile(f)
		closeErr := f.Close()
		if err != nil {
			return result, err
		}
		if closeErr != nil {
			return result, closeErr
		}
	}
	runtime.KeepAlive(retained)
	return result, nil
}

func peakRSS() (uint64, error) {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return 0, err
	}
	rss, err := parsePeakRSS(f)
	return rss, errors.Join(err, f.Close())
}

func parsePeakRSS(r io.Reader) (uint64, error) {
	s := bufio.NewScanner(r)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) == 0 || fields[0] != "VmHWM:" {
			continue
		}
		if len(fields) != 3 || fields[2] != "kB" {
			return 0, fmt.Errorf("invalid VmHWM: %q", s.Text())
		}
		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, err
		}
		return kb * 1024, nil
	}
	if err := s.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("VmHWM missing (peak RSS requires Linux /proc)")
}

func mib(bytes uint64) float64 {
	return float64(bytes) / (1024 * 1024)
}
