package scanner

import (
	"math/rand/v2"
	"os"
	"testing"

	"github.com/sansecio/yargo/parser"
)

// Set YARGO_BENCH_RULES to compare scanning with a production-sized ruleset.
func BenchmarkScanRuleFile(b *testing.B) {
	path := os.Getenv("YARGO_BENCH_RULES")
	if path == "" {
		b.Skip("set YARGO_BENCH_RULES to a YARA rules file")
	}
	rs, err := parser.New().ParseFile(path)
	if err != nil {
		b.Fatal(err)
	}
	rules, err := Compile(rs)
	if err != nil {
		b.Fatal(err)
	}
	for _, insertPatterns := range []bool{false, true} {
		name := "RandomText"
		if insertPatterns {
			name = "PatternHits"
		}
		b.Run(name, func(b *testing.B) {
			rng := rand.New(rand.NewPCG(42, 7))
			data := make([]byte, 1<<20)
			for i := range data {
				data[i] = byte(' ' + rng.IntN(95))
			}
			if insertPatterns && len(rules.patterns) > 0 {
				for offset := 0; offset < len(data); offset += 1024 {
					p := rules.patterns[rng.IntN(len(rules.patterns))]
					copy(data[offset:offset+1024], p)
				}
			}
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			var count int
			for b.Loop() {
				var matches MatchRules
				if err := rules.ScanMem(data, 0, 0, &matches); err != nil {
					b.Fatal(err)
				}
				count = len(matches)
			}
			b.ReportMetric(float64(count), "matches/op")
		})
	}
}
