// Package scanner provides YARA rule scanning using Aho-Corasick algorithm.
package scanner

import (
	"bytes"
	"context"
	"slices"
	"sync"
	"time"

	"github.com/sansecio/yargo/ahocorasick"

	"github.com/sansecio/yargo/ast"
)

type (
	// Regexp is the interface for a compiled regular expression.
	// It is satisfied by *regexp.Regexp from the standard library,
	// go-re2, and coregex.
	Regexp interface {
		FindIndex(b []byte) []int
	}

	// CompileFunc compiles a regex pattern string into a Regexp.
	CompileFunc func(string) (Regexp, error)

	// ScanFlags controls scanning behavior.
	ScanFlags int

	// ScanCallback is the interface for receiving match notifications.
	ScanCallback interface {
		RuleMatching(r *MatchRule) (abort bool, err error)
	}

	// MatchString represents a matched string within a rule.
	MatchString struct {
		Name string
		Data []byte
	}

	// Meta represents a metadata entry from a rule.
	Meta struct {
		Identifier string
		Value      any
	}

	// MatchRule represents a rule that matched during scanning.
	MatchRule struct {
		Rule    string
		Metas   []Meta
		Strings []MatchString
	}

	// MatchRules collects matching rules and implements ScanCallback.
	MatchRules []MatchRule

	// Rules holds compiled YARA rules ready for scanning.
	Rules struct {
		rules         []*compiledRule
		matcher       *ahocorasick.AhoCorasick
		patterns      [][]byte
		patternMap    []patternRef
		origPatterns  [][]byte // original (non-lowered) patterns for case-sensitive verification
		hasNocase     bool     // skip toLowerASCII when no nocase patterns exist
		regexPatterns []*regexPattern
	}
)

type (
	// patternRef maps a pattern index back to its source rule and string.
	patternRef struct {
		ruleIndex   int
		stringIndex int
		fullword    bool
		nocase      bool
		regexIdx    int
	}

	// regexPattern holds a lazily compiled regex for complex regex matching.
	regexPattern struct {
		pattern     string
		compile     CompileFunc
		once        sync.Once
		re          Regexp
		ruleIndex   int
		stringIndex int
	}

	// compiledRule holds the compiled form of a single YARA rule.
	compiledRule struct {
		name        string
		metas       []Meta
		condition   ast.Expr
		stringNames []string
	}

	// matchInfo records the position and data of a single pattern match.
	matchInfo struct {
		pos  int
		data []byte
	}
)

// maxMatchLen is the window size around atom hits used for regex verification.
const maxMatchLen = 1024

// Meta returns the value of the meta field with the given identifier, or nil.
func (m *MatchRule) Meta(identifier string) any {
	for _, meta := range m.Metas {
		if meta.Identifier == identifier {
			return meta.Value
		}
	}
	return nil
}

// MetaString returns the string value of the meta field, or defValue if missing or not a string.
func (m *MatchRule) MetaString(identifier, defValue string) string {
	if val, ok := m.Meta(identifier).(string); ok {
		return val
	}
	return defValue
}

// RuleMatching implements ScanCallback, collecting all matching rules.
func (m *MatchRules) RuleMatching(r *MatchRule) (abort bool, err error) {
	*m = append(*m, *r)
	return false, nil
}

// Stats returns compilation statistics.
func (r *Rules) Stats() (acPatterns, regexPatterns int) {
	return len(r.patterns), len(r.regexPatterns)
}

// NumRules returns the number of compiled rules.
func (r *Rules) NumRules() int {
	return len(r.rules)
}

func isWordChar(b byte) bool {
	return (b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') ||
		b == '_'
}

func checkWordBoundary(buf []byte, start, end int) bool {
	if start > 0 && isWordChar(buf[start-1]) {
		return false
	}
	if end < len(buf) && isWordChar(buf[end]) {
		return false
	}
	return true
}

// ScanMem scans a byte buffer for matching rules.
func (r *Rules) ScanMem(buf []byte, flags ScanFlags, timeout time.Duration, cb ScanCallback) error {
	if r.matcher == nil && len(r.regexPatterns) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ruleMatches := r.collectMatches(buf)
	return r.evaluateRules(ctx, buf, ruleMatches, cb)
}

// toLowerASCII returns a copy with ASCII A-Z lowered. Unlike bytes.ToLower,
// it never changes buffer length (safe for binary/Latin-1 data).
func toLowerASCII(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			out[i] = c + 0x20
		} else {
			out[i] = c
		}
	}
	return out
}

// collectMatches runs AC matching, atom-based regex verification, and full-scan
// regex to collect all match positions per rule and string index.
func (r *Rules) collectMatches(buf []byte) map[int]map[int][]matchInfo {
	ruleMatches := make(map[int]map[int][]matchInfo)
	atomCandidates := make(map[int][]int)

	if r.matcher != nil {
		// when nocase patterns exist, AC runs on a lowercased buffer
		// and case-sensitive hits are verified against the original
		scanBuf := buf
		if r.hasNocase {
			scanBuf = toLowerASCII(buf)
		}

		iter := r.matcher.IterOverlappingByte(scanBuf)
		for match := iter.Next(); match != nil; match = iter.Next() {
			ref := r.patternMap[match.Pattern()]

			if ref.regexIdx >= 0 {
				atomCandidates[ref.regexIdx] = append(atomCandidates[ref.regexIdx], match.Start())
				continue
			}

			// case-sensitive patterns need verification against the original buffer
			if r.hasNocase && !ref.nocase {
				orig := r.origPatterns[match.Pattern()]
				if !bytes.Equal(buf[match.Start():match.End()], orig) {
					continue
				}
			}

			if ref.fullword && !checkWordBoundary(buf, match.Start(), match.End()) {
				continue
			}

			data := make([]byte, match.End()-match.Start())
			copy(data, buf[match.Start():match.End()])
			addMatch(ruleMatches, ref.ruleIndex, ref.stringIndex, match.Start(), data)
		}
	}

	halfWindow := maxMatchLen / 2
	for regexIdx, positions := range atomCandidates {
		rp := r.regexPatterns[regexIdx]
		re := rp.compiled()
		if re == nil {
			continue
		}
		positions = dedupe(positions)

		for _, pos := range positions {
			start := max(0, pos-halfWindow)
			end := min(len(buf), pos+halfWindow)

			if loc := recoverFindIndex(re, buf[start:end]); loc != nil {
				matchStart := start + loc[0]
				matchEnd := start + loc[1]
				data := make([]byte, matchEnd-matchStart)
				copy(data, buf[matchStart:matchEnd])
				addMatch(ruleMatches, rp.ruleIndex, rp.stringIndex, matchStart, data)
				break
			}
		}
	}

	return ruleMatches
}

// evaluateRules evaluates conditions for rules with matches, invokes the
// callback for matching rules, and handles abort/timeout.
func (r *Rules) evaluateRules(ctx context.Context, buf []byte, ruleMatches map[int]map[int][]matchInfo, cb ScanCallback) error {
	ruleIndices := make([]int, 0, len(ruleMatches))
	for ruleIdx := range ruleMatches {
		ruleIndices = append(ruleIndices, ruleIdx)
	}
	slices.Sort(ruleIndices)

	for _, ruleIdx := range ruleIndices {
		matchedStrings := ruleMatches[ruleIdx]
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		cr := r.rules[ruleIdx]

		matchPositions := make(map[int][]int, len(matchedStrings))
		for idx, infos := range matchedStrings {
			positions := make([]int, len(infos))
			for i, info := range infos {
				positions[i] = info.pos
			}
			matchPositions[idx] = positions
		}

		evalCtx := &evalContext{
			matches:     matchPositions,
			buf:         buf,
			stringNames: cr.stringNames,
		}
		if !evalExpr(cr.condition, evalCtx) {
			continue
		}

		strings := make([]MatchString, 0, len(matchedStrings))
		for idx, infos := range matchedStrings {
			name := cr.stringNames[idx]
			for _, info := range infos {
				strings = append(strings, MatchString{Name: name, Data: info.data})
			}
		}

		abort, err := cb.RuleMatching(&MatchRule{
			Rule:    cr.name,
			Metas:   cr.metas,
			Strings: strings,
		})
		if err != nil {
			return err
		}
		if abort {
			return nil
		}
	}

	return nil
}

// ScanFile scans a file for matching rules.
// The implementation is platform-specific:
//   - Unix (Linux, macOS, BSD): uses mmap for zero-copy file scanning
//   - Windows: uses CreateFileMapping/MapViewOfFile for native memory mapping
//   - WASM (js): not supported — use [Rules.ScanMem] with file content instead
//
// See scanfile_unix.go, scanfile_windows.go, and scanfile_js.go.

func addMatch(m map[int]map[int][]matchInfo, ruleIdx int, stringIndex int, pos int, data []byte) {
	if m[ruleIdx] == nil {
		m[ruleIdx] = make(map[int][]matchInfo)
	}
	m[ruleIdx][stringIndex] = append(m[ruleIdx][stringIndex], matchInfo{pos: pos, data: data})
}

// compiled returns the compiled Regexp, compiling it on first use.
// If compilation fails, it returns nil.
func (rp *regexPattern) compiled() Regexp {
	rp.once.Do(func() {
		re, err := rp.compile(rp.pattern)
		if err == nil {
			rp.re = re
		}
	})
	return rp.re
}

// recoverFindIndex wraps Regexp.FindIndex to recover from panics.
// go-re2's WASM backend can panic during regex execution (e.g. OOM),
// so we treat a panic as no match.
func recoverFindIndex(re Regexp, b []byte) (loc []int) {
	defer func() {
		if r := recover(); r != nil {
			loc = nil
		}
	}()
	return re.FindIndex(b)
}

func dedupe(positions []int) []int {
	if len(positions) <= 1 {
		return positions
	}
	slices.Sort(positions)
	j := 1
	for i := 1; i < len(positions); i++ {
		if positions[i] != positions[j-1] {
			positions[j] = positions[i]
			j++
		}
	}
	return positions[:j]
}
