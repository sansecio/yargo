package ahocorasick

type iNFA struct {
	startID       stateID
	maxPatternLen int
	patternCount  int
	prefil        prefilter
	anchored      bool
	states        []state
	matchBitset   []uint64
}

func (n *iNFA) hasMatch(id stateID) bool {
	return n.matchBitset[uint(id)/64]&(1<<(uint(id)%64)) != 0
}

func (n *iNFA) NextStateNoFail(id stateID, b byte) stateID {
	for {
		state := &n.states[id]
		next := state.nextState(b)
		if next != failedStateID {
			return next
		}
		id = state.fail
	}
}

func (n *iNFA) MaxPatternLen() int {
	return n.maxPatternLen
}

func (n *iNFA) PatternCount() int {
	return n.patternCount
}

func (n *iNFA) GetMatch(id stateID, matchIndex int, end int) *Match {
	if int(id) >= len(n.states) {
		return nil
	}
	state := &n.states[id]
	if matchIndex >= len(state.matches) {
		return nil
	}
	pat := state.matches[matchIndex]
	return &Match{
		pattern: pat.PatternID,
		len:     pat.PatternLength,
		end:     end,
	}
}

func (n *iNFA) addDenseState(depth int) stateID {
	id := stateID(len(n.states))

	fail := n.startID

	if n.anchored {
		fail = deadStateID
	}

	n.states = append(n.states, state{
		trans:   transitions{dense: make([]stateID, 256)},
		fail:    fail,
		matches: nil,
		depth:   depth,
	})
	return id
}

func (n *iNFA) addSparseState(depth int) stateID {
	id := stateID(len(n.states))

	fail := n.startID

	if n.anchored {
		fail = deadStateID
	}

	n.states = append(n.states, state{
		trans:   transitions{},
		fail:    fail,
		matches: nil,
		depth:   depth,
	})
	return id
}

func (n *iNFA) state(id stateID) *state {
	return &n.states[int(id)]
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
	c.nfa.states = make([]state, 0, 3+totalBytes)

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
	for i, s := range c.nfa.states {
		if len(s.matches) > 0 {
			c.nfa.matchBitset[uint(i)/64] |= 1 << (uint(i) % 64)
		}
	}

	return &c.nfa
}

func (c *compiler) closeStartStateLoop() {
	if c.builder.anchored {
		startId := c.nfa.startID
		start := c.nfa.state(startId)

		for b := 0; b < 256; b++ {
			if start.nextState(byte(b)) == startId {
				start.setNextState(byte(b), deadStateID)
			}
		}
	}
}

func (c *compiler) fillFailureTransitionsStandard() {
	queue := make([]stateID, 0, len(c.nfa.states))
	seen := c.queuedSet()

	for b := 0; b < 256; b++ {
		next := c.nfa.state(c.nfa.startID).nextState(byte(b))
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

			fail := it.nfa.state(id).fail
			failState := it.nfa.state(fail)
			for failState.nextState(tr.key) == failedStateID {
				fail = failState.fail
				failState = it.nfa.state(fail)
			}
			fail = failState.nextState(tr.key)
			it.nfa.state(tr.id).fail = fail
			it.nfa.copyMatches(fail, tr.id)
		}
		it.nfa.copyEmptyMatches(id)
	}
}

func (n *iNFA) copyEmptyMatches(dst stateID) {
	n.copyMatches(n.startID, dst)
}

func (n *iNFA) copyMatches(src stateID, dst stateID) {
	if len(n.states[src].matches) == 0 {
		return
	}
	srcState, dstState := n.getTwo(src, dst)
	dstState.matches = append(dstState.matches, srcState.matches...)
}

func (n *iNFA) getTwo(i stateID, j stateID) (*state, *state) {
	if i == j {
		panic("src and dst should not be equal")
	}

	if i < j {
		before, after := n.states[0:j], n.states[j:]
		return &before[i], &after[0]
	}

	before, after := n.states[0:i], n.states[i:]
	return &after[0], &before[j]
}

func newIterTransitions(nfa *iNFA, stateId stateID) iterTransitions {
	trans := &nfa.states[int(stateId)].trans
	return iterTransitions{
		nfa:    nfa,
		sparse: trans.sparse,
		dense:  trans.dense,
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
	start := c.nfa.state(startId)
	for b := 0; b < 256; b++ {
		if start.nextState(byte(b)) == failedStateID {
			start.setNextState(byte(b), startId)
		}
	}
}

func (c *compiler) addDeadStateLoop() {
	dead := c.nfa.state(deadStateID)
	for b := 0; b < 256; b++ {
		dead.setNextState(byte(b), deadStateID)
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (c *compiler) buildTrie(patterns [][]byte) {
	for pati, pat := range patterns {
		c.nfa.maxPatternLen = max(c.nfa.maxPatternLen, len(pat))
		c.nfa.patternCount += 1

		prev := c.nfa.startID

		for depth, b := range pat {
			next := c.nfa.state(prev).nextState(b)

			if next != failedStateID {
				prev = next
			} else {
				next := c.addState(depth + 1)
				c.nfa.state(prev).setNextState(b, next)
				prev = next
			}
		}
		c.nfa.state(prev).addMatch(pati, len(pat))

		if c.builder.prefilter {
			c.prefilter.add(pat)
		}
	}
}

func (c *compiler) addState(depth int) stateID {
	if depth < c.builder.denseDepth {
		return c.nfa.addDenseState(depth)
	}
	return c.nfa.addSparseState(depth)
}

func newCompiler(builder iNFABuilder) compiler {
	p := newPrefilterBuilder()

	return compiler{
		builder:   builder,
		prefilter: p,
		nfa: iNFA{
			startID:       2,
			maxPatternLen: 0,
			patternCount:  0,
			prefil:        nil,
			anchored:      builder.anchored,
			states:        nil,
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
	trans   transitions
	fail    stateID
	matches []pattern
	depth   int
}

func (s *state) addMatch(patternID, patternLength int) {
	s.matches = append(s.matches, pattern{
		PatternID:     patternID,
		PatternLength: patternLength,
	})
}

func (s *state) isMatch() bool {
	return len(s.matches) > 0
}

func (s *state) nextState(input byte) stateID {
	return s.trans.nextState(input)
}

func (s *state) setNextState(input byte, next stateID) {
	s.trans.setNextState(input, next)
}

type transitions struct {
	sparse []innerSparse
	dense  []stateID
}

func (t *transitions) nextState(input byte) stateID {
	if t.dense == nil {
		lo, hi := 0, len(t.sparse)
		for lo < hi {
			mid := lo + (hi-lo)/2
			if t.sparse[mid].b < input {
				lo = mid + 1
			} else {
				hi = mid
			}
		}
		if lo < len(t.sparse) && t.sparse[lo].b == input {
			return t.sparse[lo].s
		}
		return failedStateID
	}
	return t.dense[input]
}

func (t *transitions) setNextState(input byte, next stateID) {
	if t.dense == nil {
		lo, hi := 0, len(t.sparse)
		for lo < hi {
			mid := lo + (hi-lo)/2
			if t.sparse[mid].b < input {
				lo = mid + 1
			} else {
				hi = mid
			}
		}

		if lo < len(t.sparse) && t.sparse[lo].b == input {
			t.sparse[lo].s = next
		} else {
			is := innerSparse{
				b: input,
				s: next,
			}
			if lo == len(t.sparse) {
				t.sparse = append(t.sparse, is)
			} else {
				t.sparse = append(
					t.sparse[:lo+1],
					t.sparse[lo:]...)
				t.sparse[lo] = is
			}
		}
		return
	}
	t.dense[int(input)] = next
}

type innerSparse struct {
	b byte
	s stateID
}
