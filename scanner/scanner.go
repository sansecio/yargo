// Package scanner provides YARA rule scanning using Aho-Corasick algorithm.
package scanner

import (
	"cmp"
	"context"
	"os"
	"slices"
	"sort"
	"time"

	"golang.org/x/sys/unix"

	"github.com/sansecio/yargo/ahocorasick"
	regexp "github.com/wasilibs/go-re2"

	"github.com/sansecio/yargo/ast"
)

// ScanFlags controls scanning behavior.
type ScanFlags int

// ScanCallback is the interface for receiving match notifications.
type ScanCallback interface {
	RuleMatching(r *MatchRule) (abort bool, err error)
}

// MatchString represents a matched string within a rule.
type MatchString struct {
	Name string
	Data []byte
}

// Meta represents a metadata entry from a rule.
type Meta struct {
	Identifier string
	Value      any
}

// MatchRule represents a rule that matched during scanning.
type MatchRule struct {
	Rule    string
	Metas   []Meta
	Strings []MatchString
}

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

// MatchRules collects matching rules and implements ScanCallback.
type MatchRules []MatchRule

// RuleMatching implements ScanCallback, collecting all matching rules.
func (m *MatchRules) RuleMatching(r *MatchRule) (abort bool, err error) {
	*m = append(*m, *r)
	return false, nil
}

// patternRef maps a pattern index back to its source rule and string.
type patternRef struct {
	ruleIndex  int
	stringName string
	fullword   bool
	isAtom     bool
	regexIdx   int
}

// regexPattern holds a compiled regex for complex regex matching.
type regexPattern struct {
	re         *regexp.Regexp
	ruleIndex  int
	stringName string
	hasAtom    bool
}

// compiledRule holds the compiled form of a single YARA rule.
type compiledRule struct {
	name        string
	metas       []Meta
	condition   ast.Expr
	stringNames []string
}

// Rules holds compiled YARA rules ready for scanning.
type Rules struct {
	rules         []*compiledRule
	matcher       *ahocorasick.AhoCorasick
	patterns      [][]byte
	patternMap    []patternRef
	regexPatterns []*regexPattern
}

// Stats returns compilation statistics.
func (r *Rules) Stats() (acPatterns, regexPatterns int) {
	return len(r.patterns), len(r.regexPatterns)
}

// NumRules returns the number of compiled rules.
func (r *Rules) NumRules() int {
	return len(r.rules)
}

const maxMatchLen = 1024

type matchInfo struct {
	pos  int
	data []byte
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

	// Track match positions and data per rule and string
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

	// Collect rule indices and sort for deterministic iteration order
	ruleIndices := make([]int, 0, len(ruleMatches))
	for ruleIdx := range ruleMatches {
		ruleIndices = append(ruleIndices, ruleIdx)
	}
	slices.Sort(ruleIndices)

	// Evaluate conditions for each rule with matches
	for _, ruleIdx := range ruleIndices {
		matchedStrings := ruleMatches[ruleIdx]
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		cr := r.rules[ruleIdx]

		// Convert matchInfo to positions for condition evaluation
		matchPositions := make(map[string][]int, len(matchedStrings))
		for name, infos := range matchedStrings {
			positions := make([]int, len(infos))
			for i, info := range infos {
				positions[i] = info.pos
			}
			matchPositions[name] = positions
		}

		// Evaluate condition
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

// RegexTiming holds the timing result for a single regex pattern.
type RegexTiming struct {
	Rule           string
	String         string
	Pattern        string
	MatchedAtoms   []string // Atoms that actually matched in the buffer
	ExtractedAtoms []string // All atoms extracted from the regex
	Duration       time.Duration
	Calls          int
}

type atomCandidate struct {
	positions []int
	atoms     map[string]struct{}
}

// RegexProfile scans a buffer and returns per-regex timing information,
// sorted slowest first.
func (r *Rules) RegexProfile(buf []byte) []RegexTiming {
	atomCandidates := make(map[int]*atomCandidate)

	if r.matcher != nil {
		iter := r.matcher.IterOverlappingByte(buf)
		for match := iter.Next(); match != nil; match = iter.Next() {
			ref := r.patternMap[match.Pattern()]
			if ref.isAtom {
				ac := atomCandidates[ref.regexIdx]
				if ac == nil {
					ac = &atomCandidate{atoms: make(map[string]struct{})}
					atomCandidates[ref.regexIdx] = ac
				}
				ac.atoms[string(r.patterns[match.Pattern()])] = struct{}{}
				ac.positions = append(ac.positions, match.Start())
			}
		}
	}

	halfWindow := maxMatchLen / 2
	timings := make([]RegexTiming, 0, len(atomCandidates))

	for regexIdx, ac := range atomCandidates {
		rp := r.regexPatterns[regexIdx]
		positions := dedupe(ac.positions)

		start := time.Now()
		calls := 0
		for _, pos := range positions {
			s := max(0, pos-halfWindow)
			e := min(len(buf), pos+halfWindow)
			rp.re.FindIndex(buf[s:e])
			calls++
		}
		dur := time.Since(start)

		matchedAtoms := make([]string, 0, len(ac.atoms))
		for atom := range ac.atoms {
			matchedAtoms = append(matchedAtoms, atom)
		}
		sort.Strings(matchedAtoms)

		var extractedAtoms []string
		if atoms, ok := extractAtoms(rp.re.String(), minAtomLength); ok {
			extractedAtoms = make([]string, len(atoms))
			for i, a := range atoms {
				extractedAtoms[i] = string(a)
			}
		}

		timings = append(timings, RegexTiming{
			Rule:           r.rules[rp.ruleIndex].name,
			String:         rp.stringName,
			Pattern:        rp.re.String(),
			MatchedAtoms:   matchedAtoms,
			ExtractedAtoms: extractedAtoms,
			Duration:       dur,
			Calls:          calls,
		})
	}

	slices.SortFunc(timings, func(a, b RegexTiming) int {
		return cmp.Compare(b.Duration, a.Duration)
	})
	return timings
}
