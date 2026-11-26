package scanner

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestLongLoopWithinTheBudgetIsNotCutShort(t *testing.T) {
	rules := compileSource(t, `rule r { condition: for any i in (0..10000000) : (i == 9000000) }`)
	var matches MatchRules
	if err := rules.ScanMem([]byte("x"), 0, 0, &matches); err != nil || len(matches) != 1 {
		t.Errorf("matches = %v, err = %v", matches, err)
	}
}

func TestLoopBudgetExhaustionFailsTheScan(t *testing.T) {
	for _, src := range []string{
		`rule r { condition: for all i in (0..0x7fffffffffffffff) : (true) }`,
		`rule r { condition: for all i in (0..0x7fffffffffffffff) : (for all j in (0..0x7fffffffffffffff) : (true)) }`,
		`rule a { condition: for all i in (0..20000000) : (true) }
rule b { condition: for all i in (0..20000000) : (true) }`,
	} {
		rules := compileSource(t, src)
		start := time.Now()
		var matches MatchRules
		err := rules.ScanMem([]byte("x"), 0, 0, &matches)
		if !errors.Is(err, ErrLoopBudgetExceeded) {
			t.Errorf("%s: err = %v, want ErrLoopBudgetExceeded", src, err)
		}
		if d := time.Since(start); d > 10*time.Second {
			t.Errorf("%s: took %v", src, d)
		}
	}
}

func TestDeadlineInsideALoopFailsTheScan(t *testing.T) {
	rules := compileSource(t, `import "hash" rule r { condition: for all i in (0..10000000) : (hash.md5(i % 4096, 4096) != "") }`)
	var matches MatchRules
	err := rules.ScanMem(make([]byte, 8192), 0, 20*time.Millisecond, &matches)
	if err == nil || errors.Is(err, ErrLoopBudgetExceeded) {
		t.Errorf("err = %v, want the deadline error", err)
	}
}

func TestAndOrShortCircuit(t *testing.T) {
	loop := `for all i in (0..0x7fffffffffffffff) : (true)`
	for _, tc := range []struct {
		cond string
		want []string
	}{
		{"false and " + loop, nil},
		{"(1 == 2) and " + loop, nil},
		{"true or " + loop, []string{"r"}},
		{"filesize > 0 or " + loop, []string{"r"}},
	} {
		rules := compileSource(t, "rule r { condition: "+tc.cond+" }")
		start := time.Now()
		var matches MatchRules
		if err := rules.ScanMem([]byte("x"), 0, 0, &matches); err != nil {
			t.Errorf("%s: right operand was evaluated: %v", tc.cond, err)
		}
		var got []string
		for _, m := range matches {
			got = append(got, m.Rule)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: matches = %v, want %v", tc.cond, got, tc.want)
		}
		if d := time.Since(start); d > 100*time.Millisecond {
			t.Errorf("%s: took %v", tc.cond, d)
		}
	}
}
