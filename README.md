# Yargo

Pure Go implementation of YARA, eliminating the need for go-yara/cgo dependencies. Currently provides a parser and scanner; the scanner uses the Aho-Corasick algorithm for efficient multi-pattern string matching.

## Features

- Pure Go - no cgo dependencies
- YARA rule parser with full syntax support
- Fast multi-pattern scanner using Aho-Corasick
- Support for `base64` string modifier
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
| pgavlin/aho-corasick | DFA: false | 2.0s | 1.7ms | **Current choice** |
| pgavlin/aho-corasick | DFA: true | 33s | 0.6ms | Faster scans, slower builds |

The `pgavlin/aho-corasick` library with `DFA: false` provides the best balance of compile time and scan performance. Use `DFA: true` if you're compiling rules once and scanning many files.

### Recommendations

- **One-time scan**: Use default settings (DFA: false) for fast compilation
- **Repeated scans**: Consider DFA: true if scanning many files with the same ruleset
- **Memory constrained**: DFA: false uses less memory

## Current Limitations

- Only `TextString` patterns are supported (no hex strings or regex yet)
- Only `any of them` condition is fully supported
- Modifiers supported: `base64`
- Modifiers not yet implemented: `wide`, `nocase`, `fullword`, `xor`, `base64wide`

## License

MIT
