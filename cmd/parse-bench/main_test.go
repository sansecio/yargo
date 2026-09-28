package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPeakRSS(t *testing.T) {
	for _, tt := range []struct {
		name    string
		status  string
		want    uint64
		wantErr bool
	}{
		{"high water mark", "Name:\tparse-bench\nVmHWM:\t12345 kB\nVmRSS:\t10000 kB\n", 12345 * 1024, false},
		{"missing", "VmRSS:\t10000 kB\n", 0, true},
		{"invalid", "VmHWM:\tinvalid kB\n", 0, true},
		{"wrong unit", "VmHWM:\t12345 MB\n", 0, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePeakRSS(strings.NewReader(tt.status))
			if (err != nil) != tt.wantErr || got != tt.want {
				t.Fatalf("parsePeakRSS() = %d, %v; want %d, error=%v", got, err, tt.want, tt.wantErr)
			}
		})
	}
}

func TestBenchmark(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yar")
	if err := os.WriteFile(path, []byte(`rule first { strings: $a = "first" condition: $a } rule second { strings: $b = "second" condition: $b }`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, compile := range []bool{false, true} {
		result, err := benchmark(path, compile, "")
		if err != nil {
			t.Fatal(err)
		}
		if result.rules != 2 || result.allocated == 0 || result.duration <= 0 {
			t.Fatalf("unexpected benchmark result: %+v", result)
		}
	}
}

func TestBenchmarkErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.yar")
	if _, err := benchmark(path, false, ""); err == nil {
		t.Fatal("expected missing file error")
	}
	if err := os.WriteFile(path, []byte("rule broken {"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := benchmark(path, false, ""); err == nil {
		t.Fatal("expected parse error")
	}
}
