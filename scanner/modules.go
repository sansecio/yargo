package scanner

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"strings"
)

func window(buf []byte, offset, size any) ([]byte, bool) {
	o, ok1 := offset.(int64)
	s, ok2 := size.(int64)
	if !ok1 || !ok2 || o < 0 || s < 0 || o > int64(len(buf)) || s > int64(len(buf))-o {
		return nil, false
	}
	return buf[o : o+s], true
}

// supportedFunctions maps each implemented math and hash function to the
// signatures of its overloads, one letter per argument: i for an integer,
// f for a number, s for a string. The range overloads read (offset, size)
// of the scanned data, the string ones their string argument.
// https://yara.readthedocs.io/en/stable/modules/math.html
// https://yara.readthedocs.io/en/stable/modules/hash.html
var supportedFunctions = map[string][]string{
	"math.entropy": {"ii", "s"}, "math.mean": {"ii", "s"}, "math.deviation": {"iif", "sf"}, "math.count": {"iii", "i"},
	"hash.md5": {"ii", "s"}, "hash.sha1": {"ii", "s"}, "hash.sha256": {"ii", "s"},
}

func evalModuleFunc(name string, args []any, buf []byte) any {
	if name == "math.count" {
		return countByte(args, buf)
	}
	data, rest, ok := functionData(args, buf)
	if !ok {
		return nil
	}
	switch {
	case name == "math.entropy" && len(rest) == 0:
		return entropy(data)
	case (name == "math.mean" || name == "math.deviation") && len(data) == 0:
		// an empty range has no mean; libyara divides by zero here
		return nil
	case name == "math.mean" && len(rest) == 0:
		return mean(data)
	case name == "math.deviation" && len(rest) == 1:
		m, ok := toNumber(rest[0])
		if !ok {
			return nil
		}
		return deviation(data, m.asFloat())
	case strings.HasPrefix(name, "hash.") && len(rest) == 0:
		return digest(name, data)
	}
	return nil
}

// functionData returns the bytes a math or hash function reads: its string
// argument, or the (offset, size) window of buf, followed by the remaining
// arguments.
func functionData(args []any, buf []byte) ([]byte, []any, bool) {
	if s, ok := args[0].(string); ok {
		return []byte(s), args[1:], true
	}
	if len(args) < 2 {
		return nil, nil, false
	}
	data, ok := window(buf, args[0], args[1])
	return data, args[2:], ok
}

// countByte implements math.count(byte, offset, size) and math.count(byte),
// which counts over the whole scanned data.
func countByte(args []any, buf []byte) any {
	b, ok := args[0].(int64)
	if !ok {
		return nil
	}
	data := buf
	if len(args) == 3 {
		if data, ok = window(buf, args[1], args[2]); !ok {
			return nil
		}
	}
	var n int64
	for _, c := range data {
		if int64(c) == b {
			n++
		}
	}
	return n
}

func entropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	var h float64
	n := float64(len(data))
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func mean(data []byte) float64 {
	var sum float64
	for _, b := range data {
		sum += float64(b)
	}
	return sum / float64(len(data))
}

func deviation(data []byte, m float64) float64 {
	var sum float64
	for _, b := range data {
		sum += math.Abs(float64(b) - m)
	}
	return sum / float64(len(data))
}

func digest(name string, data []byte) string {
	switch name {
	case "hash.md5":
		s := md5.Sum(data)
		return hex.EncodeToString(s[:])
	case "hash.sha1":
		s := sha1.Sum(data)
		return hex.EncodeToString(s[:])
	default:
		s := sha256.Sum256(data)
		return hex.EncodeToString(s[:])
	}
}
