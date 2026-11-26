package scanner

import (
	"testing"
	"time"
)

func TestRepeatedHashAndMathCallsAreComputedOnce(t *testing.T) {
	rules := compileSource(t, `import "hash" import "math"
rule r { condition: for all i in (0..2000) : (hash.sha256(0, filesize) != "" and math.entropy(0, filesize) >= 0) }`)
	data := make([]byte, 1<<20)
	start := time.Now()
	if got := scanNames(t, rules, data); len(got) != 1 {
		t.Errorf("matches = %v", got)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Errorf("2000 identical calls over 1 MiB took %v", d)
	}
}

func TestFunctionMemoIsBounded(t *testing.T) {
	s := &scanState{}
	buf := make([]byte, 1<<16)
	for i := range int64(len(buf)) {
		s.moduleFunc("hash.md5", []any{i, int64(1)}, buf)
	}
	if len(s.funcs) > maxMemoizedCalls {
		t.Errorf("memo holds %d calls, cap is %d", len(s.funcs), maxMemoizedCalls)
	}
}
