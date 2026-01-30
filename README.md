# Yargo

Pure Go implementation of YARA, eliminating the need for go-yara/cgo dependencies. Currently provides a parser and scanner; the scanner uses the Aho-Corasick algorithm for efficient multi-pattern string matching and go-re2 for full regex support.

## Features

- Pure Go - no cgo dependencies
- YARA rule parser with full syntax support
- Fast multi-pattern scanner using Aho-Corasick
- Full regex support via go-re2 with `/i`, `/s`, `/m` modifiers
- Support for `base64` and `fullword` string modifiers
- Regex patterns like `/\bdomain\.com\b/` optimized via literal extraction
- go-yara compatible API

## Installation

```bash
go get github.com/sansecio/yargo
```

## Usage

### Parsing YARA Rules

```go
import "github.com/sansecio/yargo/parser"

p, err := parser.New()
if err != nil {
    log.Fatal(err)
}

ruleSet, err := p.ParseFile("rules.yar")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Parsed %d rules\n", len(ruleSet.Rules))
```

### Scanning with Compiled Rules

```go
import (
    "github.com/sansecio/yargo/parser"
    "github.com/sansecio/yargo/scanner"
)

// Parse rules
p, _ := parser.New()
ruleSet, _ := p.ParseFile("rules.yar")

// Compile rules
rules, err := scanner.Compile(ruleSet)
if err != nil {
    log.Fatal(err)
}

// Scan data
data, _ := os.ReadFile("suspect.php")
var matches scanner.MatchRules
err = rules.ScanMem(data, 0, 30*time.Second, &matches)
if err != nil {
    log.Fatal(err)
}

for _, m := range matches {
    fmt.Printf("Rule: %s\n", m.Rule)
}
```

## Performance Considerations

### Aho-Corasick Library Comparison

Benchmarked with 106,962 YARA rules scanning a 79KB PHP file:

| Library | Options | Compile Time | Scan Time | Notes |
|---------|---------|--------------|-----------|-------|
| cloudflare/ahocorasick | - | 18.5s | 21ms | |
| pgavlin/aho-corasick | DFA: false | 2.3s | 2.2ms | **Current choice** |
| pgavlin/aho-corasick | DFA: true | 33s | 0.6ms | Faster scans, slower builds |

The `pgavlin/aho-corasick` library with `DFA: false` provides the best balance of compile time and scan performance. Use `DFA: true` if you're compiling rules once and scanning many files.

### Regex Engine Comparison

Benchmarked go-re2 vs Go's standard library regexp (6 patterns, 1MB data):

| Engine | Compile (6 patterns) | Match (1MB) | Throughput |
|--------|---------------------|-------------|------------|
| go-re2 | 126μs | 513μs | 2043 MB/s |
| stdlib regexp | 9μs | 1997μs | 525 MB/s |

go-re2 is ~4x faster for matching, making it ideal for YARA scanning where rules are compiled once and used to scan many files.

### Real-World Performance

Full pipeline with 106,962 YARA rules scanning a 79KB PHP file:

| Phase | go-re2 | stdlib regexp |
|-------|--------|---------------|
| Parse | 4.7s | 4.7s |
| Compile | 2.4s | 2.2s |
| Scan | **140ms** | 277ms |

Both engines compile 134,385 AC patterns + 1,043 regex patterns. The scan phase breaks down as:
- Aho-Corasick matching (134k patterns): ~2ms
- Regex matching (1,043 patterns): ~138ms (go-re2) vs ~275ms (stdlib)

go-re2 provides ~2x faster scanning, which matters when scanning many files.

### Comparison with YARA

Scan-only performance (pre-compiled rules, 106,962 rules, 79KB file):

| Tool | Scan Time |
|------|-----------|
| YARA 4.5.0 | **83ms** |
| Yargo (go-re2) | 140ms |
| Yargo (stdlib) | 277ms |

YARA is ~1.7x faster than Yargo for scanning. Yargo's pure Go implementation trades some performance for easier deployment (no cgo/libyara dependency).

### Recommendations

- **One-time scan**: Use default settings (DFA: false) for fast compilation
- **Repeated scans**: Consider DFA: true if scanning many files with the same ruleset
- **Memory constrained**: DFA: false uses less memory

## Current Limitations

- `TextString` patterns fully supported
- `RegexString` patterns fully supported via go-re2 (RE2 syntax, not PCRE)
  - `/\bLITERAL\b/` patterns optimized via Aho-Corasick
  - Modifiers `/i` (case-insensitive), `/s` (dot-all), `/m` (multiline) supported
- `HexString` patterns not yet supported
- Only `any of them` condition is fully supported
- Modifiers supported: `base64`, `fullword`
- Modifiers not yet implemented: `wide`, `nocase`, `xor`, `base64wide`

## License

MIT
