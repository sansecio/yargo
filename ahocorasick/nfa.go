package ahocorasick

type iNFA struct {
	startID       stateID
	maxPatternLen int
	prefil        *prefilter
	anchored      bool
	states        []state
	denseTable    []stateID
	matches       map[stateID][]pattern
	matchBitset   []uint64
}

func (n *iNFA) hasMatch(id stateID) bool {
	return n.matchBitset[uint(id)/64]&(1<<(uint(id)%64)) != 0
}

func (n *iNFA) NextStateNoFail(id stateID, b byte) stateID {
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

func (n *iNFA) GetMatch(id stateID, matchIndex int, end int) *Match {
	m := n.matches[id]
	if matchIndex >= len(m) {
		return nil
	}
	pat := m[matchIndex]
	return &Match{
		pattern: pat.PatternID,
		len:     pat.PatternLength,
		end:     end,
	}
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

	c.addStartStateLoop()
	c.addDeadStateLoop()

	if !c.builder.anchored {
		c.fillFailureTransitionsStandard()
	}
	c.closeStartStateLoop()

	if !c.builder.anchored {
		c.nfa.prefil = c.prefilter.build()
	}

	c.nfa.matchBitset = make([]uint64, (len(c.nfa.states)+63)/64)
	for id := range c.nfa.matches {
		c.nfa.matchBitset[uint(id)/64] |= 1 << (uint(id) % 64)
	}

	return &c.nfa
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
}

func newNFABuilder() *iNFABuilder {
	return &iNFABuilder{
		denseDepth: 3,
		prefilter:  true,
		anchored:   false,
	}
}

func (b *iNFABuilder) build(patterns [][]byte) *iNFA {
	c := newCompiler(*b)
	return c.compile(patterns)
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
