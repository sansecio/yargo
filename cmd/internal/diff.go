package internal

import (
	"cmp"
	"fmt"
	"slices"
)

func SumValues(m map[string]int) int {
	sum := 0
	for _, v := range m {
		sum += v
	}
	return sum
}

func SortByCount(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b string) int {
		return cmp.Compare(m[b], m[a])
	})
	return keys
}

// ScanResult holds the rule names and matched data from a single scan.
type ScanResult struct {
	Rules map[string]bool
	Data  map[string]string // rule -> first matched string data
}

// DiffTracker accumulates differences between go-yara and yargo scan results.
type DiffTracker struct {
	YargoOnly        map[string]int
	GoYaraOnly       map[string]int
	ExampleSnippets  map[string]string
	ExampleLabels    map[string]string
	ExampleMatched   map[string]string
	DataMismatch     map[string]int
	MismatchExamples map[string][2]string
	MatchedBoth      int
	Skipped          int
	SkippedLabels    map[string]int
}

func NewDiffTracker() *DiffTracker {
	return &DiffTracker{
		YargoOnly:        make(map[string]int),
		GoYaraOnly:       make(map[string]int),
		ExampleSnippets:  make(map[string]string),
		ExampleLabels:    make(map[string]string),
		ExampleMatched:   make(map[string]string),
		DataMismatch:     make(map[string]int),
		MismatchExamples: make(map[string][2]string),
		SkippedLabels:    make(map[string]int),
	}
}

// Add records the diff between a go-yara and yargo scan of the same data.
func (d *DiffTracker) Add(goYara, yargo ScanResult, label, snippet string) {
	if len(goYara.Rules) == 0 && len(yargo.Rules) == 0 {
		d.Skipped++
		d.SkippedLabels[label]++
		return
	}

	for rule := range goYara.Rules {
		if yargo.Rules[rule] {
			d.MatchedBoth++
			break
		}
	}

	// Compare matched data for rules in both
	for rule := range yargo.Rules {
		if goYara.Rules[rule] && yargo.Data[rule] != goYara.Data[rule] {
			d.DataMismatch[rule]++
			if _, ok := d.MismatchExamples[rule]; !ok {
				d.MismatchExamples[rule] = [2]string{yargo.Data[rule], goYara.Data[rule]}
			}
		}
	}

	// Find differences
	for rule := range yargo.Rules {
		if !goYara.Rules[rule] {
			d.YargoOnly[rule]++
			if _, ok := d.ExampleSnippets["yargo:"+rule]; !ok {
				d.ExampleSnippets["yargo:"+rule] = snippet
				d.ExampleLabels["yargo:"+rule] = label
				d.ExampleMatched["yargo:"+rule] = yargo.Data[rule]
			}
		}
	}
	for rule := range goYara.Rules {
		if !yargo.Rules[rule] {
			d.GoYaraOnly[rule]++
			if _, ok := d.ExampleSnippets["goyara:"+rule]; !ok {
				d.ExampleSnippets["goyara:"+rule] = snippet
				d.ExampleLabels["goyara:"+rule] = label
				d.ExampleMatched["goyara:"+rule] = goYara.Data[rule]
			}
		}
	}
}

// PrintReport prints the full diff report.
func (d *DiffTracker) PrintReport(labelName string) {
	fmt.Printf("Snippets matched by both: %d\n", d.MatchedBoth)
	fmt.Printf("Snippets skipped (no matches): %d\n", d.Skipped)
	fmt.Printf("Skipped by %s:\n", labelName)
	for _, label := range SortByCount(d.SkippedLabels) {
		fmt.Printf("  %s: %d\n", label, d.SkippedLabels[label])
	}
	fmt.Println()

	fmt.Printf("Rules matching in YARGO but NOT in go-yara (%d total extra matches):\n", SumValues(d.YargoOnly))
	for _, rule := range SortByCount(d.YargoOnly) {
		fmt.Printf("  %s: %d occurrences (%s: %s)\n", rule, d.YargoOnly[rule], labelName, d.ExampleLabels["yargo:"+rule])
		fmt.Printf("    snippet: %q\n", d.ExampleSnippets["yargo:"+rule])
		fmt.Printf("    matched: %q\n", d.ExampleMatched["yargo:"+rule])
	}

	fmt.Printf("\nRules matching in go-yara but NOT in yargo (%d total missing matches):\n", SumValues(d.GoYaraOnly))
	var unexplained []string
	for _, rule := range SortByCount(d.GoYaraOnly) {
		fmt.Printf("  %s: %d occurrences (%s: %s) [UNEXPECTED]\n", rule, d.GoYaraOnly[rule], labelName, d.ExampleLabels["goyara:"+rule])
		fmt.Printf("    snippet: %q\n", d.ExampleSnippets["goyara:"+rule])
		fmt.Printf("    matched: %q\n", d.ExampleMatched["goyara:"+rule])
		unexplained = append(unexplained, rule)
	}

	if len(unexplained) > 0 {
		fmt.Printf("\n*** %d rules with UNEXPLAINED missing matches: %v\n", len(unexplained), unexplained)
	}

	if len(d.DataMismatch) > 0 {
		fmt.Printf("\nMatched data differs between yargo and go-yara (%d rules):\n", len(d.DataMismatch))
		for _, rule := range SortByCount(d.DataMismatch) {
			example := d.MismatchExamples[rule]
			fmt.Printf("  %s: %d occurrences\n", rule, d.DataMismatch[rule])
			fmt.Printf("    yargo:   %q\n", example[0])
			fmt.Printf("    go-yara: %q\n", example[1])
		}
	}
}
