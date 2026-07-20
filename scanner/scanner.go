// Package scanner provides YARA rule scanning using Aho-Corasick algorithm.
package scanner

import (
	"bytes"
	"cmp"
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
		zeroHitRules  []int32 // sorted indexes of rules that may match without hits
		matcher       *ahocorasick.AhoCorasick
		patterns      [][]byte
		patternMap    []patternRef
		slotRule      []int32 // string slot -> rule index
		regexPatterns []*regexPattern
	}
)

type (
	// patternRef maps a pattern index back to the string slot it belongs to.
	patternRef struct {
		slot     int32
		fullword bool
		verify   bool // confirm the hit against the original buffer (case-folded scan)
		regexIdx int
	}

	// regexPattern holds a lazily compiled regex for complex regex matching.
	regexPattern struct {
		pattern  string
		compile  CompileFunc
		once     sync.Once
		re       Regexp
		slot     int32
		fullword bool
	}

	// compiledRule holds the compiled form of a single YARA rule.
	compiledRule struct {
		name        string
		metas       []Meta
		condition   ast.Expr
		stringNames []string
		slotBase    int32 // slot of this rule's first string
	}

	// hit records one confirmed match. Every string of every rule owns a
	// distinct slot, and slots are handed out per rule in order, so sorting
	// hits by slot groups them by rule and then by string in one pass. The
	// matched bytes are only copied out of the buffer for rules that pass.
	hit struct {
		pos  int
		slot int32
		n    int32
	}

	// atomHit records a regex atom hit, to be verified against the full regex.
	atomHit struct {
		pos      int
		regexIdx int32
	}
)

// maxMatchLen is the window size around atom hits used for regex verification.
const maxMatchLen = 1024

// canPrefilterMergedWindows reports whether a match remains a match when its
// input window grows. Anchors and word-boundary assertions can depend on an
// individual window's edges, so those patterns must use the original windows.
func canPrefilterMergedWindows(pattern string) bool {
	inClass := false
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '\\':
			i++
			if i >= len(pattern) || inClass {
				continue
			}
			switch pattern[i] {
			case 'A', 'z', 'Z', 'b', 'B':
				return false
			}
		case '[':
			if !inClass {
				inClass = true
			}
		case ']':
			inClass = false
		case '^', '$':
			if !inClass {
				return false
			}
		}
	}
	return true
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

// ScanMem scans a byte buffer for matching rules. A timeout of zero or less
// means no timeout.
func (r *Rules) ScanMem(buf []byte, flags ScanFlags, timeout time.Duration, cb ScanCallback) error {
	if len(r.rules) == 0 {
		return nil
	}

	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	hits, err := r.collectMatches(ctx, buf)
	if err != nil {
		return err
	}
	return r.evaluateRules(ctx, buf, hits, cb)
}

// ctxCheckInterval is how many AC matches (or regex verification windows)
// are processed between context cancellation checks.
const ctxCheckInterval = 4096

// collectMatches runs AC matching and atom-based regex verification, returning
// every hit sorted by slot (and so grouped by rule) and then by position.
func (r *Rules) collectMatches(ctx context.Context, buf []byte) ([]hit, error) {
	var hits []hit
	var atoms []atomHit

	if r.matcher != nil {
		iter := r.matcher.IterOverlappingByte(buf)
		steps := 0
		for match := iter.Next(); match != nil; match = iter.Next() {
			steps++
			if steps%ctxCheckInterval == 0 && ctx.Err() != nil {
				return nil, ctx.Err()
			}
			ref := r.patternMap[match.Pattern()]

			// the automaton folds case when any nocase pattern exists, so
			// case-sensitive hits (including every regex atom) are confirmed
			// against the original buffer before doing any further work
			if ref.verify && !bytes.Equal(buf[match.Start():match.End()], r.patterns[match.Pattern()]) {
				continue
			}

			if ref.regexIdx >= 0 {
				atoms = append(atoms, atomHit{pos: match.Start(), regexIdx: int32(ref.regexIdx)})
				continue
			}

			if ref.fullword && !checkWordBoundary(buf, match.Start(), match.End()) {
				continue
			}

			hits = append(hits, hit{pos: match.Start(), slot: ref.slot, n: int32(match.End() - match.Start())})
		}
	}

	hits, err := r.verifyAtoms(ctx, buf, atoms, hits)
	if err != nil {
		return nil, err
	}
	return groupBySlot(hits), nil
}

// countingSortMinHits is where a linear counting sort starts beating a
// comparison sort, given the counts array it has to allocate.
const countingSortMinHits = 64

// countingSortMaxSpread caps how much wider than the hit count the counts
// array may get. A big ruleset spans a huge slot range, and zeroing an array
// that dwarfs the hits costs far more than just comparing them.
const countingSortMaxSpread = 8

// groupBySlot arranges hits so that each slot's hits are contiguous, which
// also makes each rule's hits contiguous. It is stable, so hits keep the
// ascending position order the automaton produced them in.
func groupBySlot(hits []hit) []hit {
	if len(hits) < 2 {
		return hits
	}

	lo, hi := hits[0].slot, hits[0].slot
	for _, h := range hits {
		lo = min(lo, h.slot)
		hi = max(hi, h.slot)
	}
	span := int(hi-lo) + 2

	if len(hits) < countingSortMinHits || span > countingSortMaxSpread*len(hits) {
		slices.SortStableFunc(hits, func(a, b hit) int { return cmp.Compare(a.slot, b.slot) })
		return hits
	}

	counts := make([]int32, span)
	for _, h := range hits {
		counts[h.slot-lo+1]++
	}
	for i := 1; i < len(counts); i++ {
		counts[i] += counts[i-1]
	}

	out := make([]hit, len(hits))
	for _, h := range hits {
		out[counts[h.slot-lo]] = h
		counts[h.slot-lo]++
	}
	return out
}

// verifyAtoms runs the full regex around each atom hit, appending every
// distinct match it confirms.
func (r *Rules) verifyAtoms(ctx context.Context, buf []byte, atoms []atomHit, hits []hit) ([]hit, error) {
	if len(atoms) == 0 {
		return hits, nil
	}

	// group by regex, and within a regex try candidate positions in order
	slices.SortFunc(atoms, func(a, b atomHit) int {
		if a.regexIdx != b.regexIdx {
			return cmp.Compare(a.regexIdx, b.regexIdx)
		}
		return cmp.Compare(a.pos, b.pos)
	})

	halfWindow := maxMatchLen / 2
	windows := 0
	for i := 0; i < len(atoms); {
		j := i
		for j < len(atoms) && atoms[j].regexIdx == atoms[i].regexIdx {
			j++
		}
		group := atoms[i:j]
		i = j

		rp := r.regexPatterns[group[0].regexIdx]
		re := rp.compiled()
		if re == nil {
			continue
		}

		// Most atom candidates are false positives, and their verification
		// windows frequently overlap. Coalesce those windows as a prefilter:
		// a regex that does not match their union cannot match any individual
		// window. If the union does match, verify the original windows so
		// widening a window cannot change a greedy match.
		lastEnd := 0
		canPrefilter := canPrefilterMergedWindows(rp.pattern)
		for k := 0; k < len(group); {
			runFirst := k
			runStart := max(0, group[k].pos-halfWindow)
			runEnd := min(len(buf), group[k].pos+halfWindow)
			uniqueCandidates := 1
			lastPos := group[k].pos
			k++

			for k < len(group) {
				candidateStart := max(0, group[k].pos-halfWindow)
				if candidateStart > runEnd {
					break
				}
				runEnd = max(runEnd, min(len(buf), group[k].pos+halfWindow))
				if group[k].pos != lastPos {
					uniqueCandidates++
					lastPos = group[k].pos
				}
				k++
			}

			run := group[runFirst:k]
			if uniqueCandidates > 1 && canPrefilter {
				windows++
				if windows%ctxCheckInterval == 0 && ctx.Err() != nil {
					return nil, ctx.Err()
				}
				loc, completed := tryFindIndex(re, buf[runStart:runEnd])
				if completed && loc == nil {
					continue
				}
			}

			// Record each distinct match using the original candidate windows.
			// Candidates inside an already verified match are skipped and
			// windows start after it (non-overlapping, like RE2's FindAll).
			for candidate, a := range run {
				// different atoms of one regex can land on the same position
				if candidate > 0 && a.pos == run[candidate-1].pos {
					continue
				}
				if a.pos < lastEnd {
					continue
				}
				windows++
				if windows%ctxCheckInterval == 0 && ctx.Err() != nil {
					return nil, ctx.Err()
				}
				start := max(max(0, a.pos-halfWindow), lastEnd)
				end := min(len(buf), a.pos+halfWindow)

				loc := recoverFindIndex(re, buf[start:end])
				if loc == nil {
					continue
				}
				matchStart := start + loc[0]
				matchEnd := start + loc[1]
				lastEnd = matchEnd
				if rp.fullword && !checkWordBoundary(buf, matchStart, matchEnd) {
					continue
				}
				hits = append(hits, hit{pos: matchStart, slot: rp.slot, n: int32(matchEnd - matchStart)})
			}
		}
	}

	return hits, nil
}

// evaluateRules evaluates hit-bearing rules and rules whose conditions may
// match without hits, invokes the callback, and handles abort/timeout.
func (r *Rules) evaluateRules(ctx context.Context, buf []byte, hits []hit, cb ScanCallback) error {
	// Both inputs are sorted by rule index. Merge them so the common case stays
	// hit-driven while zero-hit-capable conditions are still evaluated in rule
	// order. A rule present in both inputs is evaluated only once.
	hitIdx := 0
	zeroHitIdx := 0
	for hitIdx < len(hits) || zeroHitIdx < len(r.zeroHitRules) {
		ruleIdx := int32(len(r.rules))
		if hitIdx < len(hits) {
			ruleIdx = r.slotRule[hits[hitIdx].slot]
		}
		if zeroHitIdx < len(r.zeroHitRules) && r.zeroHitRules[zeroHitIdx] < ruleIdx {
			ruleIdx = r.zeroHitRules[zeroHitIdx]
		}

		start := hitIdx
		for hitIdx < len(hits) && r.slotRule[hits[hitIdx].slot] == ruleIdx {
			hitIdx++
		}
		ruleHits := hits[start:hitIdx]
		if zeroHitIdx < len(r.zeroHitRules) && r.zeroHitRules[zeroHitIdx] == ruleIdx {
			zeroHitIdx++
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		cr := r.rules[ruleIdx]
		evalCtx := &evalContext{
			hits:        ruleHits,
			slotBase:    cr.slotBase,
			buf:         buf,
			stringNames: cr.stringNames,
		}
		if !evalExpr(cr.condition, evalCtx) {
			continue
		}

		// hits are grouped by slot, so strings come out ordered by string
		// index and then by position. Only rules that actually match pay
		// for copying their match data out of the buffer.
		strings := make([]MatchString, len(ruleHits))
		for k, h := range ruleHits {
			strings[k] = MatchString{
				Name: cr.stringNames[h.slot-cr.slotBase],
				Data: bytes.Clone(buf[h.pos : h.pos+int(h.n)]),
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
func recoverFindIndex(re Regexp, b []byte) []int {
	loc, _ := tryFindIndex(re, b)
	return loc
}

// tryFindIndex also reports whether FindIndex completed. A coalesced prefilter
// window can be larger than an ordinary verification window, so its panic must
// fall back to the ordinary windows rather than suppressing their matches.
func tryFindIndex(re Regexp, b []byte) (loc []int, completed bool) {
	defer func() {
		if r := recover(); r != nil {
			loc = nil
			completed = false
		}
	}()
	return re.FindIndex(b), true
}
