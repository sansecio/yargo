//go:build yara

package main

import (
	"fmt"
	"os"
	"time"

	yara "github.com/hillu/go-yara/v4"
	"github.com/sansecio/yargo/cmd/internal"
)

func benchGoYara(yaraFile string, files []corpusFile) (time.Duration, int, bool) {
	goYaraRules, err := internal.GoYaraRules(yaraFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error compiling go-yara rules: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Compiled %d go-yara rules\n", len(goYaraRules.GetRules()))

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
	return time.Since(start), goYaraMatches, true
}
