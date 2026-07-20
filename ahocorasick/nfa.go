package ahocorasick

import "slices"

type iNFA struct {
	startID       stateID
	maxPatternLen int
	prefil        *prefilter
	anchored      bool
	states        []state
	denseTable    []stateID
	matches       map[stateID][]pattern
}

// foldByte lowers ASCII A-Z. It never changes the byte's width, so match
// offsets stay valid for binary and Latin-1 haystacks.
func foldByte(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 0x20
	}
	return b
}

func (n *iNFA) NextStateNoFail(id stateID, b byte) stateID {
	return n.nextStateNoFail(id, b) &^ matchStateBit
}

func (n *iNFA) nextStateNoFail(id stateID, b byte) stateID {
	for {
		next := n.nextState(id, b)
		if next != failedStateID {
			return next
		}
		id = n.states[id].fail
	}
}

func (n *iNFA) nextState(id stateID, input byte) stateID {
	s := &n.states[id]
	if s.dense >= 0 {
		return n.denseTable[int(s.dense)+int(input)]
	}
	switch len(s.sparse) {
	case 0:
		return failedStateID
	case 1:
		if s.sparse[0].b == input {
			return s.sparse[0].s
		}
		return failedStateID
	}
	lo, hi := 0, len(s.sparse)
	for lo < hi {
		mid := lo + (hi-lo)/2
		if s.sparse[mid].b < input {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo < len(s.sparse) && s.sparse[lo].b == input {
		return s.sparse[lo].s
	}
	return failedStateID
}

func (n *iNFA) setNextState(id stateID, input byte, next stateID) {
	s := &n.states[id]
	if s.dense >= 0 {
		n.denseTable[int(s.dense)+int(input)] = next
		return
	}
	lo, hi := 0, len(s.sparse)
	for lo < hi {
		mid := lo + (hi-lo)/2
		if s.sparse[mid].b < input {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo < len(s.sparse) && s.sparse[lo].b == input {
		s.sparse[lo].s = next
	} else {
		is := innerSparse{b: input, s: next}
		if lo == len(s.sparse) {
			s.sparse = append(s.sparse, is)
		} else {
			s.sparse = append(s.sparse[:lo+1], s.sparse[lo:]...)
			s.sparse[lo] = is
		}
	}
}

func (n *iNFA) MaxPatternLen() int {
	return n.maxPatternLen
}

// getMatch writes the match at matchIndex into dst, reporting whether one
// exists. It fills a caller-owned Match so that scanning a haystack with many
// hits does not allocate once per hit.
func (n *iNFA) getMatch(id stateID, matchIndex int, end int, dst *Match) bool {
	m := n.matches[id]
	if matchIndex >= len(m) {
		return false
	}
	pat := m[matchIndex]
	dst.pattern = pat.PatternID
	dst.len = pat.PatternLength
	dst.end = end
	return true
}

func (n *iNFA) addMatch(id stateID, patternID, patternLength int) {
	n.matches[id] = append(n.matches[id], pattern{
		PatternID:     patternID,
		PatternLength: patternLength,
	})
}

func (n *iNFA) addDenseState() stateID {
	id := stateID(len(n.states))

	fail := n.startID
	if n.anchored {
		fail = deadStateID
	}

	denseIdx := int32(len(n.denseTable))
	n.denseTable = append(n.denseTable, make([]stateID, 256)...)
	n.states = append(n.states, state{
		fail:  fail,
		dense: denseIdx,
	})
	return id
}

func (n *iNFA) addSparseState() stateID {
	id := stateID(len(n.states))

	fail := n.startID
	if n.anchored {
		fail = deadStateID
	}

	n.states = append(n.states, state{
		fail:  fail,
		dense: -1,
	})
	return id
}

type compiler struct {
	builder   iNFABuilder
	prefilter prefilterBuilder
	nfa       iNFA
}

// adaptiveDenseThreshold is the sparse degree at which a 256-entry dense row
// pays for itself in scan speed without materially increasing automaton size.
const adaptiveDenseThreshold = 4

func (c *compiler) compile(patterns [][]byte) *iNFA {
	totalBytes := 0
	for _, pat := range patterns {
		totalBytes += len(pat)
	}
	// Trie prefix sharing means actual states ≈ 2/3 of totalBytes.
	// 3/4 gives headroom to avoid reallocations while using 25% less memory.
	c.nfa.states = make([]state, 0, max(256, totalBytes*3/4))

	c.addState(0)
	c.addState(0)
	c.addState(0)

	c.buildTrie(patterns)
	c.densifyHighDegreeStates()

	c.addStartStateLoop()
	c.addDeadStateLoop()

	if !c.builder.anchored {
		c.fillFailureTransitionsStandard()
	}
	c.closeStartStateLoop()

	if !c.builder.anchored {
		c.nfa.prefil = c.prefilter.build()
		if c.nfa.prefil != nil {
			// the prefilter was built from folded patterns, so it must
			// fold the haystack as it scans for candidates
			c.nfa.prefil.fold = c.builder.fold
		}
	}

	c.premultiplyDense()
	if c.builder.fold {
		c.mirrorFoldedEdges()
	}
	c.compactSparse()

	c.tagMatchingTransitions()

	return &c.nfa
}

// tagMatchingTransitions stores the target state's match status in the high
// bit of each transition. Scanning can then detect matches without a separate
// random bitset lookup for every input byte.
func (c *compiler) tagMatchingTransitions() {
	matching := make([]uint64, (len(c.nfa.states)+63)/64)
	for id := range c.nfa.matches {
		matching[uint(id)/64] |= 1 << (uint(id) % 64)
	}
	isMatching := func(id stateID) bool {
		return matching[uint(id)/64]&(1<<(uint(id)%64)) != 0
	}

	for i, target := range c.nfa.denseTable {
		if isMatching(target) {
			c.nfa.denseTable[i] = target | matchStateBit
		}
	}
	for i := range c.nfa.states {
		for j := range c.nfa.states[i].sparse {
			target := c.nfa.states[i].sparse[j].s
			if isMatching(target) {
				c.nfa.states[i].sparse[j].s = target | matchStateBit
			}
		}
	}
}

// densifyHighDegreeStates converts highly branched trie states to dense rows.
// Most deep states stay sparse, while the few branch points frequently visited
// during failure traversal get constant-time transitions.
func (c *compiler) densifyHighDegreeStates() {
	denseStates := 0
	for i := range c.nfa.states {
		if c.nfa.states[i].dense < 0 && len(c.nfa.states[i].sparse) >= adaptiveDenseThreshold {
			denseStates++
		}
	}
	c.nfa.denseTable = slices.Grow(c.nfa.denseTable, denseStates*256)

	for id := range c.nfa.states {
		s := &c.nfa.states[id]
		if s.dense >= 0 || len(s.sparse) < adaptiveDenseThreshold {
			continue
		}

		denseIdx := int32(len(c.nfa.denseTable))
		c.nfa.denseTable = append(c.nfa.denseTable, make([]stateID, 256)...)
		for _, edge := range s.sparse {
			c.nfa.denseTable[int(denseIdx)+int(edge.b)] = edge.s
		}
		s.sparse = nil
		s.dense = denseIdx
	}
}

// premultiplyDense resolves the failure chain of every missing transition in
// dense states, turning their rows into full DFA rows. The scan then takes a
// single table lookup for the shallow states where it spends most of its time.
func (c *compiler) premultiplyDense() {
	for id := range c.nfa.states {
		d := c.nfa.states[id].dense
		if d < 0 {
			continue
		}
		row := c.nfa.denseTable[d : int(d)+256]
		for b, next := range row {
			if next == failedStateID {
				row[b] = c.nfa.NextStateNoFail(c.nfa.states[id].fail, byte(b))
			}
		}
	}
}

// mirrorFoldedEdges copies every a-z transition to its A-Z twin. The folded
// automaton only has edges on folded bytes, so after mirroring the scan can
// feed it raw haystack bytes without folding each one.
func (c *compiler) mirrorFoldedEdges() {
	for id := range c.nfa.states {
		s := &c.nfa.states[id]
		if s.dense >= 0 {
			row := c.nfa.denseTable[s.dense : int(s.dense)+256]
			for b := byte('a'); b <= 'z'; b++ {
				row[b-0x20] = row[b]
			}
			continue
		}
		for _, e := range slices.Clone(s.sparse) {
			if e.b >= 'a' && e.b <= 'z' {
				c.nfa.setNextState(stateID(id), e.b-0x20, e.s)
			}
		}
	}
}

// compactSparse repacks every state's sparse transitions into one shared
// arena. States created while inserting a pattern are consecutive, so walking
// a trie chain reads the arena sequentially instead of chasing per-state
// allocations, and the exact-fit arena drops append slack.
func (c *compiler) compactSparse() {
	total := 0
	for i := range c.nfa.states {
		total += len(c.nfa.states[i].sparse)
	}
	arena := make([]innerSparse, 0, total)
	for i := range c.nfa.states {
		s := &c.nfa.states[i]
		if len(s.sparse) == 0 {
			continue
		}
		off := len(arena)
		arena = append(arena, s.sparse...)
		s.sparse = arena[off:len(arena):len(arena)]
	}
}

func (c *compiler) closeStartStateLoop() {
	if c.builder.anchored {
		startId := c.nfa.startID
		for b := range 256 {
			if c.nfa.nextState(startId, byte(b)) == startId {
				c.nfa.setNextState(startId, byte(b), deadStateID)
			}
		}
	}
}

func (c *compiler) fillFailureTransitionsStandard() {
	queue := make([]stateID, 0, len(c.nfa.states))
	seen := c.queuedSet()

	for b := range 256 {
		next := c.nfa.nextState(c.nfa.startID, byte(b))
		if next != c.nfa.startID {
			if !seen.contains(next) {
				queue = append(queue, next)
				seen.insert(next)
			}
		}
	}

	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		it := newIterTransitions(&c.nfa, id)

		for tr, ok := it.next(); ok; tr, ok = it.next() {
			if seen.contains(tr.id) {
				continue
			}
			queue = append(queue, tr.id)
			seen.insert(tr.id)

			fail := it.nfa.states[id].fail
			for it.nfa.nextState(fail, tr.key) == failedStateID {
				fail = it.nfa.states[fail].fail
			}
			fail = it.nfa.nextState(fail, tr.key)
			it.nfa.states[tr.id].fail = fail
			it.nfa.copyMatches(fail, tr.id)
		}
		it.nfa.copyEmptyMatches(id)
	}
}

func (n *iNFA) copyEmptyMatches(dst stateID) {
	n.copyMatches(n.startID, dst)
}

func (n *iNFA) copyMatches(src stateID, dst stateID) {
	srcMatches := n.matches[src]
	if len(srcMatches) == 0 {
		return
	}
	n.matches[dst] = append(n.matches[dst], srcMatches...)
}

func newIterTransitions(nfa *iNFA, stateId stateID) iterTransitions {
	s := &nfa.states[int(stateId)]
	var dense []stateID
	if s.dense >= 0 {
		off := int(s.dense)
		dense = nfa.denseTable[off : off+256]
	}
	return iterTransitions{
		nfa:    nfa,
		sparse: s.sparse,
		dense:  dense,
		cur:    0,
	}
}

type iterTransitions struct {
	nfa    *iNFA
	sparse []innerSparse
	dense  []stateID
	cur    int
}

type next struct {
	key byte
	id  stateID
}

func (i *iterTransitions) next() (next, bool) {
	if i.dense == nil {
		if i.cur >= len(i.sparse) {
			return next{}, false
		}
		ii := i.cur
		i.cur += 1
		return next{
			key: i.sparse[ii].b,
			id:  i.sparse[ii].s,
		}, true
	}

	for i.cur < 256 {
		b := byte(i.cur)
		id := i.dense[b]
		i.cur += 1
		if id != failedStateID {
			return next{
				key: b,
				id:  id,
			}, true
		}
	}
	return next{}, false
}

type queuedSet struct {
	seen []uint64
}

func newInertQueuedSet(capacity int) queuedSet {
	return queuedSet{
		seen: make([]uint64, (capacity+63)/64),
	}
}

func (q *queuedSet) contains(s stateID) bool {
	word := uint(s) / 64
	if word >= uint(len(q.seen)) {
		return false
	}
	return q.seen[word]&(1<<(uint(s)%64)) != 0
}

func (q *queuedSet) insert(s stateID) {
	word := uint(s) / 64
	if word >= uint(len(q.seen)) {
		grown := make([]uint64, word+1)
		copy(grown, q.seen)
		q.seen = grown
	}
	q.seen[word] |= 1 << (uint(s) % 64)
}

func (c *compiler) queuedSet() queuedSet {
	n := len(c.nfa.states)
	return newInertQueuedSet(n)
}

func (c *compiler) addStartStateLoop() {
	startId := c.nfa.startID
	for b := range 256 {
		if c.nfa.nextState(startId, byte(b)) == failedStateID {
			c.nfa.setNextState(startId, byte(b), startId)
		}
	}
}

func (c *compiler) addDeadStateLoop() {
	for b := range 256 {
		c.nfa.setNextState(deadStateID, byte(b), deadStateID)
	}
}

func (c *compiler) buildTrie(patterns [][]byte) {
	for pati, pat := range patterns {
		c.nfa.maxPatternLen = max(c.nfa.maxPatternLen, len(pat))

		prev := c.nfa.startID

		for depth, b := range pat {
			next := c.nfa.nextState(prev, b)

			if next != failedStateID {
				prev = next
			} else {
				next := c.addState(depth + 1)
				c.nfa.setNextState(prev, b, next)
				prev = next
			}
		}
		c.nfa.addMatch(prev, pati, len(pat))

		if c.builder.prefilter {
			c.prefilter.add(pat)
		}
	}
}

func (c *compiler) addState(depth int) stateID {
	if depth < c.builder.denseDepth {
		return c.nfa.addDenseState()
	}
	return c.nfa.addSparseState()
}

func newCompiler(builder iNFABuilder) compiler {
	p := newPrefilterBuilder()

	return compiler{
		builder:   builder,
		prefilter: p,
		nfa: iNFA{
			startID:       2,
			maxPatternLen: 0,
			prefil:        nil,
			anchored:      builder.anchored,
			matches:       make(map[stateID][]pattern),
		},
	}
}

type iNFABuilder struct {
	denseDepth int
	prefilter  bool
	anchored   bool
	fold       bool
}

func newNFABuilder() *iNFABuilder {
	return &iNFABuilder{
		denseDepth: 3,
		prefilter:  true,
		anchored:   false,
	}
}

func (b *iNFABuilder) build(patterns [][]byte) *iNFA {
	if b.fold {
		patterns = foldPatterns(patterns)
	}
	c := newCompiler(*b)
	return c.compile(patterns)
}

func foldPatterns(patterns [][]byte) [][]byte {
	folded := make([][]byte, len(patterns))
	for i, p := range patterns {
		f := make([]byte, len(p))
		for j, b := range p {
			f[j] = foldByte(b)
		}
		folded[i] = f
	}
	return folded
}

type pattern struct {
	PatternID     int
	PatternLength int
}

type state struct {
	sparse []innerSparse
	fail   stateID
	dense  int32
}

type innerSparse struct {
	b byte
	s stateID
}
