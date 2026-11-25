package scanner

import (
	"reflect"
	"testing"
)

func TestExpressions(t *testing.T) {
	const strs = `strings: $a = "ab" `
	tests := []struct {
		name string
		cond string
		data string
		want bool
	}{
		{"count equal", "#a == 2", "ab..ab", true},
		{"count not equal", "#a == 2", "ab", false},
		{"count at least", "#a >= 2 and #a < 4", "ab ab ab", true},
		{"offset first", "@a[1] == 3", "xyzab", true},
		{"offset second", "@a[2] == 6", "xyzab ab", true},
		{"offset default is first", "@a == 3", "xyzab", true},
		{"offset out of range is undefined", "@a[2] == 3", "xyzab", false},
		{"offset out of range under not", "not @a[2] == 3", "xyzab", false},
		{"offset comparison", "@a[2] > @a[1]", "ab ab", true},
		{"offset arithmetic", "@a[2] - @a[1] == 3", "ab ab", true},
		{"length", "!a == 2", "xab", true},
		{"in range inside", "$a in (2..4)", "xxab", true},
		{"in range outside", "$a in (0..1)", "xxab", false},
		{"in range inclusive bounds", "$a in (2..2)", "xxab", true},
		{"in range with filesize", "$a in (filesize-4..filesize)", "xxxxxxab", true},
		{"in range filesize miss", "$a in (filesize-1..filesize)", "xxxxxxab", false},
		{"at expression", "$a at filesize-2", "xxxab", true},
		{"add", "filesize + 1 == 5", "abcd", true},
		{"subtract", "filesize - 1 == 3", "abcd", true},
		{"multiply", "filesize * 2 == 8", "abcd", true},
		{"divide", "filesize \\ 2 == 2", "abcd", true},
		{"modulo", "filesize % 3 == 1", "abcd", true},
		{"division by zero is undefined", "filesize \\ 0 == 0", "abcd", false},
		{"bitwise and", "(filesize & 6) == 4", "abcd", true},
		{"bitwise or", "(filesize | 3) == 7", "abcd", true},
		{"bitwise xor", "(filesize ^ 1) == 5", "abcd", true},
		{"shift left", "(filesize << 2) == 16", "abcd", true},
		{"shift right", "(filesize >> 1) == 2", "abcd", true},
		{"bitwise xor binds tighter than equality", "filesize ^ 1 == 5", "abcd", true},
		{"bitwise or binds tighter than equality", "filesize | 3 == 7", "abcd", true},
		{"bitwise not", "~0 == -1", "abcd", true},
		{"unary minus", "-filesize < 0", "abcd", true},
		{"precedence multiply over add", "1 + 2 * 3 == 7", "abcd", true},
		{"precedence add over shift", "1 << 2 + 1 == 8", "abcd", true},
		{"float comparison", "1.5 < 2", "abcd", true},
		{"float arithmetic", "filesize \\ 8.0 == 0.5", "abcd", true},
		{"integer and float equal", "2 == 2.0", "abcd", true},
		{"for any in range", "for any i in (1..3) : (@a[i] == 5)", "xxxxxab ab", true},
		{"for any in range miss", "for any i in (1..2) : (@a[i] == 99)", "ab ab", false},
		{"for all in range", "for all i in (1..2) : (@a[i] > 0)", "xab ab", true},
		{"for all in range miss", "for all i in (1..2) : (@a[i] == 1)", "xab ab", false},
		{"for none in range", "for none i in (1..2) : (@a[i] == 99)", "ab ab", true},
		{"for count in range", "for 2 i in (1..3) : (i > 1)", "ab", true},
		{"for count in range too few", "for 3 i in (1..3) : (i > 1)", "ab", false},
		{"for loop variable arithmetic", "for any i in (0..3) : (i * i == 9)", "ab", true},
		{"for of all strings at", "for all of them : ($ at 0)", "ab", true},
		{"for of any string in", "for any of ($a) : ($ in (1..3))", "xab", true},
		{"for empty range", "for any i in (3..1) : (true)", "ab", false},
		{"for loop variable restored", "(for any i in (1..2) : (i == 2)) and not i == 2", "ab", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := compileSource(t, "rule r { "+strs+"condition: "+tt.cond+" }")
			got := len(scanNames(t, rules, []byte(tt.data))) == 1
			if got != tt.want {
				t.Errorf("expected match=%v, got %v", tt.want, got)
			}
		})
	}
}

func TestXorString(t *testing.T) {
	xored := func(s string, key byte) string {
		b := []byte(s)
		for i := range b {
			b[i] ^= key
		}
		return string(b)
	}
	tests := []struct {
		name string
		src  string
		data string
		want bool
	}{
		{"any key", `rule r { strings: $a = "secret" xor condition: $a }`, "..." + xored("secret", 0x41), true},
		{"key zero is included", `rule r { strings: $a = "secret" xor condition: $a }`, "...secret", true},
		{"single key", `rule r { strings: $a = "secret" xor(7) condition: $a }`, xored("secret", 7), true},
		{"single key miss", `rule r { strings: $a = "secret" xor(7) condition: $a }`, xored("secret", 8), false},
		{"key range inside", `rule r { strings: $a = "secret" xor(0x10-0x20) condition: $a }`, xored("secret", 0x18), true},
		{"key range outside", `rule r { strings: $a = "secret" xor(0x10-0x20) condition: $a }`, xored("secret", 0x21), false},
		{"xor wide", `rule r { strings: $a = "ab" xor(5) wide condition: $a }`, xored("a\x00b\x00", 5), true},
		{"xor ascii wide matches ascii", `rule r { strings: $a = "ab" xor(5) ascii wide condition: $a }`, xored("ab", 5), true},
		{"xor wide rejects ascii", `rule r { strings: $a = "ab" xor(5) wide condition: $a }`, xored("ab", 5), false},
		{"xor count", `rule r { strings: $a = "ab" xor(1-2) condition: #a == 2 }`, xored("ab", 1) + xored("ab", 2), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := len(scanNames(t, compileSource(t, tt.src), []byte(tt.data))) == 1
			if got != tt.want {
				t.Errorf("expected match=%v, got %v", tt.want, got)
			}
		})
	}
}

func TestMathAndHashFunctions(t *testing.T) {
	tests := []struct {
		name string
		cond string
		data string
		want bool
	}{
		{"entropy of constant data", "math.entropy(0, filesize) == 0.0", "aaaaaaaa", true},
		{"entropy of two symbols", "math.entropy(0, filesize) == 1.0", "abababab", true},
		{"entropy window", "math.entropy(0, 4) == 1.0", "abababab", true},
		{"entropy high", "math.entropy(0, filesize) > 7.9", string(allBytes()), true},
		{"mean", "math.mean(0, filesize) == 97.5", "abababab", true},
		{"deviation", "math.deviation(0, filesize, 97.5) == 0.5", "abababab", true},
		{"out of range window is undefined", "math.entropy(0, 100) == 0.0", "abab", false},
		{"md5", `hash.md5(0, filesize) == "187ef4436122d1cc2f40dc2b92f0eba0"`, "ab", true},
		{"sha1", `hash.sha1(0, filesize) == "da23614e02469a0d7c7bd1bdab5c9c474b1904dc"`, "ab", true},
		{"sha256", `hash.sha256(0, filesize) == "fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603"`, "ab", true},
		{"md5 window", `hash.md5(1, 1) == "92eb5ffee6ae2fec3ad71c777531578f"`, "ab", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := compileSource(t, "rule r { condition: "+tt.cond+" }")
			if got := reflect.DeepEqual(scanNames(t, rules, []byte(tt.data)), []string{"r"}); got != tt.want {
				t.Errorf("expected match=%v, got %v", tt.want, got)
			}
		})
	}
}

func allBytes() []byte {
	b := make([]byte, 0, 256*4)
	for range 4 {
		for i := range 256 {
			b = append(b, byte(i))
		}
	}
	return b
}
