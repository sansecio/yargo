package scanner

import (
	"regexp"
	"testing"

	re2 "github.com/wasilibs/go-re2"
)

var testPatterns = []string{
	`[a-z]+[0-9]+`,
	`\d{3}-\d{3}-\d{4}`,
	`https?://[^\s]+`,
	`eval\s*\(`,
	`(?i)malware`,
	`(?s)start.+end`,
}

var testData = make([]byte, 1024*1024) // 1MB

func init() {
	// Populate test data with some matches
	copy(testData[1000:], []byte("username123"))
	copy(testData[5000:], []byte("call 555-123-4567"))
	copy(testData[10000:], []byte("visit https://example.com/path"))
	copy(testData[50000:], []byte("eval ( code )"))
	copy(testData[100000:], []byte("MALWARE detected"))
	copy(testData[500000:], []byte("start middle end"))
}

func BenchmarkRegexCompile_GoRe2(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for _, p := range testPatterns {
			_, err := re2.Compile(p)
			if err != nil {
				b.Fatalf("compile error: %v", err)
			}
		}
	}
}

func BenchmarkRegexCompile_Stdlib(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for _, p := range testPatterns {
			_, err := regexp.Compile(p)
			if err != nil {
				b.Fatalf("compile error: %v", err)
			}
		}
	}
}

func BenchmarkRegexMatch_GoRe2(b *testing.B) {
	compiled := make([]*re2.Regexp, len(testPatterns))
	for i, p := range testPatterns {
		compiled[i] = re2.MustCompile(p)
	}

	b.ResetTimer()
	b.SetBytes(int64(len(testData)))

	for i := 0; i < b.N; i++ {
		for _, re := range compiled {
			re.Match(testData)
		}
	}
}

func BenchmarkRegexMatch_Stdlib(b *testing.B) {
	compiled := make([]*regexp.Regexp, len(testPatterns))
	for i, p := range testPatterns {
		compiled[i] = regexp.MustCompile(p)
	}

	b.ResetTimer()
	b.SetBytes(int64(len(testData)))

	for i := 0; i < b.N; i++ {
		for _, re := range compiled {
			re.Match(testData)
		}
	}
}
