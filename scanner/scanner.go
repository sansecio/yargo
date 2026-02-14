// Package scanner provides YARA rule scanning using Aho-Corasick algorithm.
package scanner

import (
	"context"
	"os"
	"slices"
	"time"

	"golang.org/x/sys/unix"

	"github.com/sansecio/yargo/ahocorasick"
	regexp "github.com/wasilibs/go-re2"

	"github.com/sansecio/yargo/ast"
)

type (
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
		regexPatterns []*regexPattern
	}
)

type (
	// patternRef maps a pattern index back to its source rule and string.
	patternRef struct {
		ruleIndex  int
		stringName string
		fullword   bool
		isAtom     bool
		regexIdx   int
	}

	// regexPattern holds a compiled regex for complex regex matching.
	regexPattern struct {
		re         *regexp.Regexp
		ruleIndex  int
		stringName string
		hasAtom    bool
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

// collectMatches runs AC matching, atom-based regex verification, and full-scan
// regex to collect all match positions per rule and string.
func (r *Rules) collectMatches(buf []byte) map[int]map[string][]matchInfo {
	ruleMatches := make(map[int]map[string][]matchInfo)
	atomCandidates := make(map[int][]int)

	if r.matcher != nil {
		iter := r.matcher.IterOverlappingByte(buf)
		for match := iter.Next(); match != nil; match = iter.Next() {
			ref := r.patternMap[match.Pattern()]

			if ref.isAtom {
				atomCandidates[ref.regexIdx] = append(atomCandidates[ref.regexIdx], match.Start())
				continue
			}

			if ref.fullword && !checkWordBoundary(buf, match.Start(), match.End()) {
				continue
			}

			data := make([]byte, match.End()-match.Start())
			copy(data, buf[match.Start():match.End()])
			addMatch(ruleMatches, ref.ruleIndex, ref.stringName, match.Start(), data)
		}
	}

	halfWindow := maxMatchLen / 2
	for regexIdx, positions := range atomCandidates {
		rp := r.regexPatterns[regexIdx]
		positions = dedupe(positions)

		for _, pos := range positions {
			start := max(0, pos-halfWindow)
			end := min(len(buf), pos+halfWindow)

			if loc := rp.re.FindIndex(buf[start:end]); loc != nil {
				matchStart := start + loc[0]
				matchEnd := start + loc[1]
				data := make([]byte, matchEnd-matchStart)
				copy(data, buf[matchStart:matchEnd])
				addMatch(ruleMatches, rp.ruleIndex, rp.stringName, matchStart, data)
				break
			}
		}
	}

	for _, rp := range r.regexPatterns {
		if rp.hasAtom {
			continue
		}
		if loc := rp.re.FindIndex(buf); loc != nil {
			data := make([]byte, loc[1]-loc[0])
			copy(data, buf[loc[0]:loc[1]])
			addMatch(ruleMatches, rp.ruleIndex, rp.stringName, loc[0], data)
		}
	}

	return ruleMatches
}

// evaluateRules evaluates conditions for rules with matches, invokes the
// callback for matching rules, and handles abort/timeout.
func (r *Rules) evaluateRules(ctx context.Context, buf []byte, ruleMatches map[int]map[string][]matchInfo, cb ScanCallback) error {
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

		matchPositions := make(map[string][]int, len(matchedStrings))
		for name, infos := range matchedStrings {
			positions := make([]int, len(infos))
			for i, info := range infos {
				positions[i] = info.pos
			}
			matchPositions[name] = positions
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
		for name, infos := range matchedStrings {
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

// ScanFile scans a file for matching rules using memory mapping for efficiency.
// This allows scanning large files without loading them entirely into memory.
func (r *Rules) ScanFile(filename string, flags ScanFlags, timeout time.Duration, cb ScanCallback) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	fi, err := f.Stat()
	if err != nil {
		return err
	}

	size := fi.Size()
	if size == 0 {
		return r.ScanMem(nil, flags, timeout, cb)
	}

	data, err := unix.Mmap(int(f.Fd()), 0, int(size), unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Munmap(data) }()

	return r.ScanMem(data, flags, timeout, cb)
}

func addMatch(m map[int]map[string][]matchInfo, ruleIdx int, stringName string, pos int, data []byte) {
	if m[ruleIdx] == nil {
		m[ruleIdx] = make(map[string][]matchInfo)
	}
	m[ruleIdx][stringName] = append(m[ruleIdx][stringName], matchInfo{pos: pos, data: data})
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
