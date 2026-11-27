package scanner

import (
	"math"
	"testing"
	"time"
)

func TestWindowRejectsOverflowingOffsets(t *testing.T) {
	buf := make([]byte, 16)
	for _, c := range []struct{ off, size int64 }{
		{math.MaxInt64, 1}, {1, math.MaxInt64}, {math.MaxInt64, math.MaxInt64}, {8, math.MaxInt64 - 4}, {-1, 1}, {17, 0},
	} {
		if _, ok := window(buf, c.off, c.size); ok {
			t.Errorf("window(%d, %d) accepted", c.off, c.size)
		}
	}
	if _, ok := window(buf, int64(8), int64(8)); !ok {
		t.Error("valid window rejected")
	}
}

func TestIntegerReadersRejectOverflowingOffsets(t *testing.T) {
	buf := []byte{1, 2, 3, 4}
	for _, name := range []string{"uint8", "uint16", "uint32", "int32be"} {
		for _, pos := range []int64{math.MaxInt64, math.MaxInt64 - 1, math.MinInt64, 4} {
			v, ok := readInteger(name, pos, buf)
			if !ok || v != int64(0) {
				t.Errorf("%s(%d) = %v, %v; want 0", name, pos, v, ok)
			}
		}
	}
	if v, _ := readInteger("uint32", int64(1), []byte{1, 2}); v != int64(0) {
		t.Errorf("short buffer read = %v", v)
	}
}

func TestHostileConditionsDoNotPanicOrHang(t *testing.T) {
	conds := []string{
		"uint32(0x7fffffffffffffff) == 0",
		"uint8(0x7fffffffffffffff - 1) == 0",
		"hash.md5(0x7fffffffffffffff, 2) == \"x\"",
		"math.entropy(1, 0x7fffffffffffffff) > 1",
		"for all i in (0..0x7fffffffffffffff) : (true)",
		"for all i in (0x7ffffffffffffff0..0x7fffffffffffffff) : (true)",
		"for any i in (0..0x7fffffffffffffff) : (false)",
		"for all i in (0..0x7fffffffffffffff) : (for all j in (0..0x7fffffffffffffff) : (true))",
	}
	for _, cond := range conds {
		t.Run(cond, func(t *testing.T) {
			rules := compileSource(t, `import "math" import "hash" `+"rule r { condition: "+cond+" }")
			start := time.Now()
			var matches MatchRules
			_ = rules.ScanMem([]byte("abcdefgh"), 0, 500*time.Millisecond, &matches)
			if d := time.Since(start); d > 5*time.Second {
				t.Errorf("scan took %v", d)
			}
		})
	}
}

func TestForLoopStopsAtMaxInt(t *testing.T) {
	rules := compileSource(t, "rule r { condition: for all i in (0x7ffffffffffffff0..0x7fffffffffffffff) : (i > 0) }")
	if got := scanNames(t, rules, []byte("x")); len(got) != 1 {
		t.Errorf("expected match, got %v", got)
	}
}
