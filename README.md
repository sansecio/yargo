# Yargo

Pure Go implementation of YARA, eliminating the need for go-yara/cgo dependencies. Provides a parser (via goyacc) and a scanner using Aho-Corasick for multi-pattern string matching and RE2 for regex support.

## Features

- Pure Go - no cgo dependencies
- YARA rule parser (goyacc-based) with full syntax support
- Multi-pattern scanner using a vendored [Aho-Corasick](ahocorasick/) automaton (NFA by default, optional DFA)
- Regex support via [go-re2](https://github.com/wasilibs/go-re2) (RE2 engine compiled to Wasm)
- Condition evaluation: `and`, `or`, `at`, `any of`, `all of`, `uint*` functions, wildcards
- Support for `base64` and `fullword` string modifiers
- Hex strings with wildcards (`??`), jumps (`[4-8]`), and alternations (`(AB|CD)`) compiled to regex
- go-yara compatible scan API

## Installation

```bash
go get github.com/sansecio/yargo
```

## Usage

### Parsing YARA Rules

```go
import "github.com/sansecio/yargo/parser"

p := parser.New()

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
p := parser.New()
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

## Architecture

### Scanner Pipeline

1. **Parse** - goyacc parser produces an AST (`ast.RuleSet`)
2. **Compile** - strings are compiled into two structures:
   - **Aho-Corasick automaton** for literal patterns and regex atoms
   - **RE2 regexes** for complex patterns (hex wildcards, regex strings)
3. **Scan** - Aho-Corasick runs first to find candidate matches, then regex patterns are verified against a window around each candidate, and finally conditions are evaluated per rule

### Atoms and Aho-Corasick

All string types feed into a single Aho-Corasick automaton. Text strings and simple hex strings go in as full literals. Regex and complex hex strings can't be matched by Aho-Corasick directly, so the compiler extracts **atoms** -- short literal substrings that must appear in any match -- and adds those instead. For example, `/foo[0-9]+bar/` produces atoms `foo` and `bar`. Atoms are scored by byte rarity and diversity to pick the most selective candidates (minimum length 2).

At scan time, Aho-Corasick runs a single pass over the buffer. Literal hits are recorded directly. Atom hits mark candidate positions, and the full regex is verified against a ~1KB window around each candidate. This avoids running every regex against the entire buffer.

Regexes without extractable atoms are rejected at compile time. Use `CompileOptions{SkipInvalidRegex: true}` to skip them silently.

### Key Libraries

| Component | Library | Notes |
|-----------|---------|-------|
| Parser | `goyacc` (stdlib) | LALR(1) grammar in `parser/yara.y` |
| String matching | `ahocorasick/` (vendored) | Based on [pgavlin/aho-corasick](https://github.com/pgavlin/aho-corasick) with performance fixes (reduced GC pressure, etc.). NFA by default; optional DFA for faster scans at higher memory cost |
| Regex | [wasilibs/go-re2](https://github.com/wasilibs/go-re2) | RE2 compiled to Wasm via wazero; Latin-1 mode for binary scanning |

## Current Limitations

### Conditions

Supported:
- String references: `$a`, `$b`
- Positional matching: `$a at 0`
- Boolean operators: `and`, `or`, parentheses
- Comparison: `==`
- Byte functions: `uint32be(n)`, `uint16be(n)`, `uint32(n)`, `uint16(n)`, `uint8(n)`
- Quantifiers: `any of them`, `all of them`, `any of ($prefix_*)`, `all of ($prefix_*)`

Not yet supported:
- `filesize`, `entrypoint`
- String count/offset/length operators: `#a`, `@a`, `!a`
- Numeric quantifiers: `2 of them`, `50% of them`
- Loops: `for`, `of`
- Arithmetic operators: `+`, `-`, `*`, `/`, `%`
- Bitwise operators: `&`, `|`, `^`, `~`, `<<`, `>>`
- Other comparisons: `!=`, `<`, `>`, `<=`, `>=`

### String Types

**TextString** - Fully supported, including `base64` and `fullword` modifiers.

**RegexString** - Supported via RE2. RE2 does not support backreferences, lookahead/lookbehind, or possessive quantifiers.

**HexString** - Fully supported. Simple hex strings are matched as literals via Aho-Corasick. Complex hex strings (wildcards, jumps, alternations) are compiled to regex.

### Modifiers

- **Supported**: `base64`, `fullword`
- **Not yet implemented**: `wide`, `nocase`, `xor`, `base64wide`

## License

MIT
