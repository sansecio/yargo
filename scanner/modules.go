package scanner

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"math"
)

// window returns buf[offset:offset+size] when both arguments are integers and
// the range lies inside buf.
func window(buf []byte, offset, size any) ([]byte, bool) {
	o, ok1 := offset.(int64)
	s, ok2 := size.(int64)
	if !ok1 || !ok2 || o < 0 || s < 0 || o > int64(len(buf)) || s > int64(len(buf))-o {
		return nil, false
	}
	return buf[o : o+s], true
}

// supportedFunctions lists the module functions evalModuleFunc implements.
var supportedFunctions = map[string]int{
	"math.entropy": 2, "math.mean": 2, "math.deviation": 3, "math.count": 3,
	"hash.md5": 2, "hash.sha1": 2, "hash.sha256": 2,
}

func evalModuleFunc(name string, args []any, buf []byte) any {
	if want, ok := supportedFunctions[name]; !ok || len(args) != want {
		return nil
	}
	switch name {
	case "math.entropy":
		data, ok := window(buf, args[0], args[1])
		if !ok {
			return nil
		}
		return entropy(data)
	case "math.mean":
		data, ok := window(buf, args[0], args[1])
		if !ok {
			return nil
		}
		return mean(data)
	case "math.deviation":
		data, ok := window(buf, args[0], args[1])
		if !ok {
			return nil
		}
		m, ok := toNumber(args[2])
		if !ok {
			return nil
		}
		return deviation(data, m.asFloat())
	case "math.count":
		data, ok := window(buf, args[1], args[2])
		b, bok := args[0].(int64)
		if !ok || !bok {
			return nil
		}
		var n int64
		for _, c := range data {
			if int64(c) == b {
				n++
			}
		}
		return n
	default:
		data, ok := window(buf, args[0], args[1])
		if !ok {
			return nil
		}
		return digest(name, data)
	}
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
	if len(data) == 0 {
		return math.NaN()
	}
	var sum float64
	for _, b := range data {
		sum += float64(b)
	}
	return sum / float64(len(data))
}

func deviation(data []byte, m float64) float64 {
	if len(data) == 0 {
		return math.NaN()
	}
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
