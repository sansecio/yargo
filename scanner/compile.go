package scanner

import (
	"encoding/base64"
	"errors"
	"fmt"
	"regexp/syntax"
	"strings"

	"github.com/sansecio/yargo/ahocorasick"
	"github.com/wasilibs/go-re2/experimental"

	"github.com/sansecio/yargo/ast"
)

// CompileOptions configures compilation behavior.
type CompileOptions struct {
	// SkipInvalidRegex silently skips regexes that are invalid or require
	// a full buffer scan, instead of returning an error.
	SkipInvalidRegex bool

	// SkipSubtypes filters out rules whose meta "subtype" field matches
	// any of the given values. Rules without a "subtype" meta or with an
	// empty subtype value are never filtered.
	SkipSubtypes []string

	// RegexCompiler overrides the function used to compile regex patterns.
	// When nil, defaults to go-re2's experimental.CompileLatin1.
	RegexCompiler CompileFunc
}

const (
	// minAtomLength is the minimum length of atoms extracted from regexes
	// for use in the Aho-Corasick matcher. 3 bytes gives 16M possible values
	// (255^3), making false positives rare while still allowing generic regexes.
	minAtomLength = 3
)

// Compile compiles an AST RuleSet into Rules ready for scanning.
func Compile(rs *ast.RuleSet) (*Rules, error) {
	return CompileWithOptions(rs, CompileOptions{})
}

// CompileWithOptions compiles an AST RuleSet with the given options.
func CompileWithOptions(rs *ast.RuleSet, opts CompileOptions) (*Rules, error) {
	if opts.RegexCompiler == nil {
		opts.RegexCompiler = func(pattern string) (Regexp, error) {
			return experimental.CompileLatin1(pattern)
		}
	}
	opts.RegexCompiler = recoverCompile(opts.RegexCompiler)

	rules := &Rules{
		rules: make([]*compiledRule, 0, len(rs.Rules)),
	}

	var allPatterns [][]byte
	var errs []error
	var hasNocase bool
	ruleIdx := 0

	skipSubtypes := make(map[string]bool, len(opts.SkipSubtypes))
	for _, t := range opts.SkipSubtypes {
		if t != "" {
			skipSubtypes[t] = true
		}
	}

	for _, r := range rs.Rules {
		if r.Condition == nil || hasUnsupportedModifier(r) {
			continue
		}

		if len(skipSubtypes) > 0 {
			if subtype := metaValue(r, "subtype"); subtype != "" && skipSubtypes[subtype] {
				continue
			}
		}

		cr := &compiledRule{
			name:      r.Name,
			metas:     make([]Meta, len(r.Meta)),
			condition: r.Condition,
			slotBase:  int32(len(rules.slotRule)),
		}
		for i, m := range r.Meta {
			cr.metas[i] = Meta{Identifier: m.Key, Value: m.Value}
		}
		for _, s := range r.Strings {
			cr.stringNames = append(cr.stringNames, s.Name)
			cr.stringPrivates = append(cr.stringPrivates, s.Modifiers.Private)
			rules.slotRule = append(rules.slotRule, int32(ruleIdx))
		}
		rules.rules = append(rules.rules, cr)
		if mayMatchWithoutHits(cr.condition) {
			rules.zeroHitRules = append(rules.zeroHitRules, int32(ruleIdx))
		}

		for si, s := range r.Strings {
			slot := cr.slotBase + int32(si)

			patterns, isRegex := generatePatterns(s)
			if isRegex {
				var err error
				allPatterns, err = compileRegex(rules, s, slot, r.Name, allPatterns, opts)
				if err != nil {
					errs = append(errs, err)
				}
				continue
			}
			for _, p := range patterns {
				rules.patternMap = append(rules.patternMap, patternRef{
					slot:     slot,
					fullword: s.Modifiers.Fullword,
					verify:   !s.Modifiers.Nocase && hasASCIILetter(p),
					regexIdx: -1,
				})
				allPatterns = append(allPatterns, p)
				if s.Modifiers.Nocase {
					hasNocase = true
				}
			}
		}
		ruleIdx++
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	if !hasNocase {
		// without nocase patterns the automaton matches exactly, so no
		// hit ever needs verifying against the original buffer
		for i := range rules.patternMap {
			rules.patternMap[i].verify = false
		}
	}

	rules.patterns = allPatterns
	if len(allPatterns) > 0 {
		builder := ahocorasick.NewAhoCorasickBuilder()
		// one case-folding pass over the buffer finds both nocase and
		// case-sensitive hits; the latter are verified during the scan
		builder.AsciiCaseFold(hasNocase)
		ac := builder.BuildByte(allPatterns)
		rules.matcher = &ac
	}

	return rules, nil
}

// hasUnsupportedModifier reports whether any of the rule's strings carries a
// modifier the scanner cannot honor. Such rules are skipped entirely: matching
// only the honorable strings could flip negated conditions and cause false
// positives, and matching without a modifier like xor would be plain wrong.
func hasUnsupportedModifier(r *ast.Rule) bool {
	for _, s := range r.Strings {
		if len(s.Modifiers.Unsupported) > 0 {
			return true
		}
	}
	return false
}

// hasASCIILetter reports whether folding can make p match bytes it otherwise
// would not. Only A-Z/a-z fold, so a pattern without them never needs
// verification against the original buffer.
func hasASCIILetter(p []byte) bool {
	for _, b := range p {
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') {
			return true
		}
	}
	return false
}

func compileRegex(rules *Rules, s *ast.StringDef, slot int32, ruleName string, allPatterns [][]byte, opts CompileOptions) ([][]byte, error) {
	var rePattern string
	var caseInsensitive bool

	switch v := s.Value.(type) {
	case ast.RegexString:
		// on a regex, nocase means the same as the i flag
		if s.Modifiers.Nocase {
			v.Modifiers.CaseInsensitive = true
		}
		rePattern = buildRE2Pattern(v.Pattern, v.Modifiers)
		caseInsensitive = v.Modifiers.CaseInsensitive
	case ast.HexString:
		rePattern = "(?s)" + hexStringToRegex(v)
		caseInsensitive = false
	default:
		return allPatterns, nil
	}
	// The regex itself is compiled lazily on first use, which discards
	// errors, so reject invalid patterns here.
	if err := checkRegex(rePattern, opts.RegexCompiler); err != nil {
		if opts.SkipInvalidRegex {
			return allPatterns, nil
		}
		return nil, fmt.Errorf("rule %q string %s: invalid regex: %w", ruleName, s.Name, err)
	}
	atoms, hasAtoms := extractAtoms(rePattern, minAtomLength)
	requiresFullScan := !hasAtoms || caseInsensitive
	if requiresFullScan {
		if opts.SkipInvalidRegex {
			return allPatterns, nil
		}
		return nil, fmt.Errorf("rule %q string %s: regex requires full buffer scan", ruleName, s.Name)
	}

	rp := &regexPattern{
		pattern:  rePattern,
		compile:  opts.RegexCompiler,
		slot:     slot,
		fullword: s.Modifiers.Fullword,
	}
	regexIdx := len(rules.regexPatterns)
	rules.regexPatterns = append(rules.regexPatterns, rp)

	// a case-insensitive regex always requires a full scan (see above), so
	// every atom that reaches here belongs to a case-sensitive regex
	for _, atom := range atoms {
		rules.patternMap = append(rules.patternMap, patternRef{
			regexIdx: regexIdx,
			verify:   hasASCIILetter(atom),
		})
		allPatterns = append(allPatterns, atom)
	}
	return allPatterns, nil
}

func generatePatterns(s *ast.StringDef) ([][]byte, bool) {
	switch v := s.Value.(type) {
	case ast.TextString:
		if s.Modifiers.Base64 {
			return generateBase64Patterns([]byte(v.Value)), false
		}
		return [][]byte{[]byte(v.Value)}, false
	case ast.RegexString:
		return nil, true
	case ast.HexString:
		if isSimpleHexString(v) {
			return [][]byte{hexStringToBytes(v)}, false
		}
		return nil, true
	default:
		return nil, false
	}
}

func isSimpleHexString(h ast.HexString) bool {
	for _, t := range h.Tokens {
		if _, ok := t.(ast.HexByte); !ok {
			return false
		}
	}
	return true
}

func hexStringToBytes(h ast.HexString) []byte {
	result := make([]byte, 0, len(h.Tokens))
	for _, t := range h.Tokens {
		if b, ok := t.(ast.HexByte); ok {
			result = append(result, b.Value)
		}
	}
	return result
}

// checkRegex reports whether compile would accept pattern. regexp/syntax
// follows RE2 syntax (including the repetition limit of 1000) and parses in
// microseconds, where a go-re2 compile takes a WASM round trip. It is
// stricter than RE2 in places (raw Latin-1 bytes, \C), and compile may be a
// custom engine, so compile has the final say on anything it rejects.
func checkRegex(pattern string, compile CompileFunc) error {
	if _, err := syntax.Parse(pattern, syntax.Perl); err == nil {
		return nil
	}
	_, err := compile(pattern)
	return err
}

func hexStringToRegex(h ast.HexString) string {
	var sb strings.Builder

	// Coalesce consecutive wildcards into a single .{n}
	i := 0
	for i < len(h.Tokens) {
		switch t := h.Tokens[i].(type) {
		case ast.HexByte:
			fmt.Fprintf(&sb, "\\x%02x", t.Value)
		case ast.HexWildcard:
			// Count consecutive wildcards
			count := 1
			for i+count < len(h.Tokens) {
				if _, ok := h.Tokens[i+count].(ast.HexWildcard); ok {
					count++
				} else {
					break
				}
			}
			if count == 1 {
				sb.WriteByte('.')
			} else {
				fmt.Fprintf(&sb, ".{%d}", count)
			}
			i += count - 1 // -1 because the loop will increment
		case ast.HexJump:
			writeJump(&sb, t)
		case ast.HexAlt:
			writeAlt(&sb, t)
		}
		i++
	}

	return sb.String()
}

func writeJump(sb *strings.Builder, j ast.HexJump) {
	switch {
	case j.Min == nil && j.Max == nil:
		sb.WriteString(".*")
	case j.Min != nil && j.Max != nil && *j.Min == *j.Max:
		fmt.Fprintf(sb, ".{%d}", *j.Min)
	case j.Min != nil && j.Max != nil:
		fmt.Fprintf(sb, ".{%d,%d}", *j.Min, *j.Max)
	case j.Min != nil:
		fmt.Fprintf(sb, ".{%d,}", *j.Min)
	case j.Max != nil:
		fmt.Fprintf(sb, ".{0,%d}", *j.Max)
	}
}

func writeAlt(sb *strings.Builder, a ast.HexAlt) {
	sb.WriteString("(?:")
	for i, item := range a.Alternatives {
		if i > 0 {
			sb.WriteByte('|')
		}
		if item.Wildcard {
			sb.WriteByte('.')
		} else if item.Byte != nil {
			fmt.Fprintf(sb, "\\x%02x", *item.Byte)
		}
	}
	sb.WriteByte(')')
}

func generateBase64Patterns(data []byte) [][]byte {
	// Each offset aligns data differently within the base64 3-byte groups.
	// The prefix padding bytes and the number of leading base64 chars to skip
	// (which depend on the unknown preceding context) vary per offset.
	offsets := [3]struct{ pad, skip int }{{0, 0}, {1, 2}, {2, 3}}
	patterns := make([][]byte, 0, 3)

	for _, o := range offsets {
		padded := append(make([]byte, o.pad), data...)
		enc := base64.StdEncoding.EncodeToString(padded)
		if len(enc) <= o.skip {
			continue
		}
		trimmed := strings.TrimRight(enc[o.skip:], "=")
		if trim := trailingUnstableChars(len(data) + o.pad); trim > 0 && len(trimmed) > trim {
			trimmed = trimmed[:len(trimmed)-trim]
		}
		if len(trimmed) > 0 {
			patterns = append(patterns, []byte(trimmed))
		}
	}

	return patterns
}

// trailingUnstableChars returns how many trailing base64 chars depend on
// what follows the data. When data length isn't a multiple of 3, the final
// base64 chars encode partial bytes that include bits from following data.
func trailingUnstableChars(dataLen int) int {
	switch dataLen % 3 {
	case 1:
		return 1 // last char encodes 2 bits of data + 4 bits of next byte
	case 2:
		return 1 // last char encodes 4 bits of data + 2 bits of next byte
	default:
		return 0 // complete 3-byte groups, fully stable
	}
}

func buildRE2Pattern(pattern string, mods ast.RegexModifiers) string {
	var prefix string
	if mods.CaseInsensitive {
		prefix = "(?i)"
	}
	if mods.DotMatchesAll {
		prefix += "(?s)"
	}
	if mods.Multiline {
		prefix += "(?m)"
	}
	return prefix + fixCommaQuantifiers(pattern)
}

// recoverCompile wraps a CompileFunc to recover from panics. go-re2's WASM
// backend panics on internal errors (e.g. OOM during compilation) instead of
// returning them, so we convert these to errors.
func recoverCompile(compile CompileFunc) CompileFunc {
	return func(pattern string) (re Regexp, err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("regex compile panic: %v", r)
			}
		}()
		return compile(pattern)
	}
}

func metaValue(r *ast.Rule, key string) string {
	for _, m := range r.Meta {
		if m.Key == key {
			if s, ok := m.Value.(string); ok {
				return s
			}
			return ""
		}
	}
	return ""
}
