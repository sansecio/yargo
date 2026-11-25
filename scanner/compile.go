package scanner

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
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

	// FullBufferRegex accepts regexes without a usable literal atom, and
	// case-insensitive ones, by running them over the whole buffer. Each
	// such regex costs one pass over every scanned buffer.
	FullBufferRegex bool

	// SkipSubtypes filters out rules whose meta "subtype" field matches
	// any of the given values. Rules without a "subtype" meta or with an
	// empty subtype value are never filtered.
	SkipSubtypes []string

	Externals []string

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
		rules:     make([]*compiledRule, 0, len(rs.Rules)),
		ruleIndex: make(map[string]int32, len(rs.Rules)),
		externals: declaredExternals(opts.Externals),
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
		if r.Condition == nil {
			continue
		}
		if reason := unsupportedReason(r, rules); reason != "" {
			rules.skipped = append(rules.skipped, SkippedRule{Rule: r.Name, Reason: reason})
			continue
		}

		if len(skipSubtypes) > 0 {
			if subtype := metaValue(r, "subtype"); subtype != "" && skipSubtypes[subtype] {
				continue
			}
		}

		preps := make([]*regexPrep, len(r.Strings))
		var prepErr error
		for si, s := range r.Strings {
			if _, isRegex := generatePatterns(s); !isRegex {
				continue
			}
			if preps[si], prepErr = prepareRegex(s, r.Name, opts); prepErr != nil {
				break
			}
		}
		if prepErr != nil {
			if !opts.SkipInvalidRegex {
				errs = append(errs, prepErr)
				continue
			}
			rules.skipped = append(rules.skipped, SkippedRule{Rule: r.Name, Reason: prepErr.Error()})
			continue
		}

		cr := &compiledRule{
			name:      r.Name,
			metas:     make([]Meta, len(r.Meta)),
			condition: r.Condition,
			private:   r.Private,
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
		rules.ruleIndex[r.Name] = int32(ruleIdx)
		if mayMatchWithoutHits(cr.condition) {
			rules.zeroHitRules = append(rules.zeroHitRules, int32(ruleIdx))
		}

		for si, s := range r.Strings {
			slot := cr.slotBase + int32(si)

			patterns, isRegex := generatePatterns(s)
			if isRegex {
				if preps[si] != nil {
					allPatterns = compileRegex(rules, s, preps[si], slot, allPatterns, opts)
				}
				continue
			}
			variants := withWideVariants(patterns, s.Modifiers)
			if isBase64(s) {
				variants = base64Variants([]byte(s.Value.(ast.TextString).Value), s.Modifiers)
			}
			for _, p := range variants {
				rules.patternMap = append(rules.patternMap, patternRef{
					slot:     slot,
					fullword: s.Modifiers.Fullword,
					wide:     p.wide,
					verify:   !s.Modifiers.Nocase && hasASCIILetter(p.bytes),
					regexIdx: -1,
				})
				allPatterns = append(allPatterns, p.bytes)
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

var builtinExternals = []string{"filename", "filepath", "extension", "filetype", "owner"}

func declaredExternals(extra []string) map[string]bool {
	m := make(map[string]bool, len(builtinExternals)+len(extra))
	for _, n := range builtinExternals {
		m[n] = true
	}
	for _, n := range extra {
		m[n] = true
	}
	return m
}

func unsupportedReason(r *ast.Rule, rules *Rules) string {
	if r.Global {
		return "global rule"
	}
	if hasUnsupportedModifier(r) {
		return "unsupported string modifier"
	}
	return conditionReason(r.Condition, rules)
}

func conditionReason(expr ast.Expr, rules *Rules) string {
	switch e := expr.(type) {
	case ast.Ident:
		if rules.externals[e.Name] {
			return ""
		}
		if strings.HasPrefix(e.Name, "pe.") {
			if supportedPEMember(e) {
				return ""
			}
			return "unsupported pe member " + e.Name
		}
		if _, ok := rules.ruleIndex[e.Name]; ok {
			return ""
		}
		return "unknown identifier " + e.Name
	case ast.BinaryExpr:
		if reason := conditionReason(e.Left, rules); reason != "" {
			return reason
		}
		return conditionReason(e.Right, rules)
	case ast.NotExpr:
		return conditionReason(e.Inner, rules)
	case ast.ParenExpr:
		return conditionReason(e.Inner, rules)
	case ast.AtExpr:
		return conditionReason(e.Pos, rules)
	case ast.UnaryExpr:
		return conditionReason(e.Inner, rules)
	case ast.OffsetOf:
		return optionalReason(e.Index, rules)
	case ast.LenOf:
		return optionalReason(e.Index, rules)
	case ast.InExpr:
		return firstReason(rules, e.Lo, e.Hi)
	case ast.ForExpr:
		if e.Var == "" {
			return conditionReason(e.Body, rules)
		}
		scoped := *rules
		scoped.externals = maps.Clone(rules.externals)
		scoped.externals[e.Var] = true
		if reason := firstReason(rules, e.Lo, e.Hi); reason != "" {
			return reason
		}
		return conditionReason(e.Body, &scoped)
	case ast.Field:
		if !supportedPEMember(e) {
			return "unsupported module member " + e.Name
		}
		return conditionReason(e.Base.(ast.Index).Index, rules)
	case ast.Index:
		if reason := conditionReason(e.Base, rules); reason != "" {
			return reason
		}
		return "unsupported module field index"
	case ast.FuncCall:
		if strings.HasPrefix(e.Name, "pe.") {
			if !supportedPEFunction(e.Name, len(e.Args)) {
				return "unsupported pe function " + e.Name
			}
			return firstReason(rules, e.Args...)
		}
		if !knownFunction(e.Name) {
			return "unsupported function " + e.Name
		}
		return firstReason(rules, e.Args...)
	}
	return ""
}

func optionalReason(expr ast.Expr, rules *Rules) string {
	if expr == nil {
		return ""
	}
	return conditionReason(expr, rules)
}

func firstReason(rules *Rules, exprs ...ast.Expr) string {
	for _, e := range exprs {
		if reason := conditionReason(e, rules); reason != "" {
			return reason
		}
	}
	return ""
}

func knownFunction(name string) bool {
	if _, ok := integerReaders[name]; ok {
		return true
	}
	_, ok := supportedFunctions[name]
	return ok
}

// hasUnsupportedModifier reports whether any of the rule's strings carries a
// modifier the scanner cannot honor. Such rules are skipped entirely: matching
// only the honorable strings could flip negated conditions and cause false
// positives, and matching without a modifier like xor would be plain wrong.
func hasUnsupportedModifier(r *ast.Rule) bool {
	for _, s := range r.Strings {
		if len(s.Modifiers.Unsupported) > 0 || unsupportedWide(s) {
			return true
		}
	}
	return false
}

func isBase64(s *ast.StringDef) bool {
	return s.Modifiers.Base64 || s.Modifiers.Base64Wide
}

func unsupportedWide(s *ast.StringDef) bool {
	if isBase64(s) {
		_, text := s.Value.(ast.TextString)
		return !text || s.Modifiers.Xor != nil
	}
	if !s.Modifiers.Wide && s.Modifiers.Xor == nil {
		return false
	}
	_, ok := s.Value.(ast.TextString)
	return !ok
}

type variant struct {
	bytes []byte
	wide  bool
}

func withWideVariants(patterns [][]byte, m ast.StringModifiers) []variant {
	out := make([]variant, 0, len(patterns)*2)
	if !m.Wide || m.Ascii {
		for _, p := range patterns {
			out = append(out, variant{bytes: p})
		}
	}
	if m.Wide {
		for _, p := range patterns {
			w := make([]byte, 0, len(p)*2)
			for _, b := range p {
				w = append(w, b, 0)
			}
			out = append(out, variant{bytes: w, wide: true})
		}
	}
	if m.Xor == nil {
		return out
	}
	keys := int(m.Xor.Max) - int(m.Xor.Min) + 1
	xored := make([]variant, 0, len(out)*keys)
	for _, v := range out {
		for key := int(m.Xor.Min); key <= int(m.Xor.Max); key++ {
			b := make([]byte, len(v.bytes))
			for i, c := range v.bytes {
				b[i] = c ^ byte(key)
			}
			xored = append(xored, variant{bytes: b, wide: v.wide})
		}
	}
	return xored
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

type regexPrep struct {
	pattern  string
	atoms    [][]byte
	fullScan bool
}

func prepareRegex(s *ast.StringDef, ruleName string, opts CompileOptions) (*regexPrep, error) {
	var rePattern string
	var caseInsensitive bool

	switch v := s.Value.(type) {
	case ast.RegexString:
		if s.Modifiers.Nocase {
			v.Modifiers.CaseInsensitive = true
		}
		rePattern = buildRE2Pattern(v.Pattern, v.Modifiers)
		caseInsensitive = v.Modifiers.CaseInsensitive
	case ast.HexString:
		rePattern = "(?s)" + hexStringToRegex(v)
	default:
		return nil, nil
	}
	if err := checkRegex(rePattern, opts.RegexCompiler); err != nil {
		return nil, fmt.Errorf("rule %q string %s: invalid regex: %w", ruleName, s.Name, err)
	}
	atoms, hasAtoms := extractAtoms(rePattern, minAtomLength)
	if !hasAtoms || caseInsensitive {
		if opts.FullBufferRegex {
			return &regexPrep{pattern: rePattern, fullScan: true}, nil
		}
		return nil, fmt.Errorf("rule %q string %s: regex requires full buffer scan", ruleName, s.Name)
	}
	return &regexPrep{pattern: rePattern, atoms: atoms}, nil
}

func compileRegex(rules *Rules, s *ast.StringDef, prep *regexPrep, slot int32, allPatterns [][]byte, opts CompileOptions) [][]byte {
	rp := &regexPattern{
		pattern:  prep.pattern,
		compile:  opts.RegexCompiler,
		slot:     slot,
		fullword: s.Modifiers.Fullword,
	}
	regexIdx := len(rules.regexPatterns)
	rules.regexPatterns = append(rules.regexPatterns, rp)
	if prep.fullScan {
		rules.fullBufferRegexes = append(rules.fullBufferRegexes, regexIdx)
		return allPatterns
	}
	for _, atom := range prep.atoms {
		rules.patternMap = append(rules.patternMap, patternRef{
			regexIdx: regexIdx,
			verify:   hasASCIILetter(atom),
		})
		allPatterns = append(allPatterns, atom)
	}
	return allPatterns
}

func generatePatterns(s *ast.StringDef) ([][]byte, bool) {
	switch v := s.Value.(type) {
	case ast.TextString:
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
	writeHexTokens(&sb, h.Tokens)
	return sb.String()
}

func writeHexTokens(sb *strings.Builder, tokens []ast.HexToken) {
	// Coalesce consecutive wildcards into a single .{n}
	i := 0
	for i < len(tokens) {
		switch t := tokens[i].(type) {
		case ast.HexByte:
			fmt.Fprintf(sb, "\\x%02x", t.Value)
		case ast.HexMasked:
			writeMasked(sb, t)
		case ast.HexWildcard:
			// Count consecutive wildcards
			count := 1
			for i+count < len(tokens) {
				if _, ok := tokens[i+count].(ast.HexWildcard); ok {
					count++
				} else {
					break
				}
			}
			if count == 1 {
				sb.WriteByte('.')
			} else {
				fmt.Fprintf(sb, ".{%d}", count)
			}
			i += count - 1 // -1 because the loop will increment
		case ast.HexJump:
			writeJump(sb, t)
		case ast.HexAlt:
			writeAlt(sb, t)
		}
		i++
	}
}

func writeMasked(sb *strings.Builder, m ast.HexMasked) {
	sb.WriteByte('[')
	if m.Mask == 0xF0 {
		fmt.Fprintf(sb, "\\x%02x-\\x%02x", m.Value, m.Value|0x0F)
	} else {
		for hi := 0; hi < 16; hi++ {
			fmt.Fprintf(sb, "\\x%02x", byte(hi<<4)|m.Value)
		}
	}
	sb.WriteByte(']')
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
	for i, branch := range a.Alternatives {
		if i > 0 {
			sb.WriteByte('|')
		}
		writeHexTokens(sb, branch)
	}
	sb.WriteByte(')')
}

func base64Variants(text []byte, m ast.StringModifiers) []variant {
	enc := base64.StdEncoding.WithPadding(base64.NoPadding)
	if m.Base64Alphabet != "" {
		enc = base64.NewEncoding(m.Base64Alphabet).WithPadding(base64.NoPadding)
	}
	var sources [][]byte
	if m.Wide {
		sources = append(sources, widenBytes(text))
	}
	if m.Ascii || !m.Wide {
		sources = append(sources, text)
	}
	var out []variant
	for _, src := range sources {
		if m.Base64 {
			for _, p := range base64Patterns(src, enc) {
				out = append(out, variant{bytes: p})
			}
		}
		if m.Base64Wide {
			for _, p := range base64Patterns(src, enc) {
				out = append(out, variant{bytes: widenBytes(p)})
			}
		}
	}
	return out
}

func widenBytes(b []byte) []byte {
	w := make([]byte, 0, len(b)*2)
	for _, c := range b {
		w = append(w, c, 0)
	}
	return w
}

// base64Patterns returns the encodings of data at the three possible
// alignments within a base64 group, without the leading and trailing
// characters that depend on neighboring bytes (the scheme of YARA's
// libyara/base64.c, BSD-3-Clause).
func base64Patterns(data []byte, enc *base64.Encoding) [][]byte {
	patterns := make([][]byte, 0, 3)
	for lead := range 3 {
		if lead == 1 && len(data) == 1 {
			continue
		}
		padded := append(bytes.Repeat([]byte{'A'}, lead), data...)
		encoded := enc.EncodeToString(padded)
		skip := 0
		if lead > 0 {
			skip = lead + 1
		}
		if len(padded)%3 != 0 {
			encoded = encoded[:len(encoded)-1]
		}
		if len(encoded) > skip {
			patterns = append(patterns, []byte(encoded[skip:]))
		}
	}
	return patterns
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
