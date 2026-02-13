package ahocorasick

import (
	"math"
	"slices"
)

type startBytes struct {
	bytes [3]byte
	count int
}

func (s startBytes) NextCandidate(_ *prefilterState, haystack []byte, at int) int {
	rare := s.bytes[:s.count]
	for i, b := range haystack[at:] {
		if slices.Contains(rare, b) {
			return at + i
		}
	}
	return noneCandidate
}

type byteSet [256]bool

func (b *byteSet) contains(bb byte) bool {
	return b[int(bb)]
}

func (b *byteSet) insert(bb byte) bool {
	n := !b.contains(bb)
	b[int(bb)] = true
	return n
}

type rareByteOffset struct {
	max byte
}

type rareByteOffsets struct {
	rbo [256]rareByteOffset
}

func (r *rareByteOffsets) set(b byte, off rareByteOffset) {
	m := byte(max(int(r.rbo[int(b)].max), int(off.max)))
	r.rbo[int(b)].max = m
}

type prefilterBuilder struct {
	startBytes startBytesBuilder
	rareBytes  rareBytesBuilder
}

func (p *prefilterBuilder) build() prefilter {
	startBytes := p.startBytes.build()
	rareBytes := p.rareBytes.build()

	switch true {
	case startBytes != nil && rareBytes != nil:
		hasFewerBytes := p.startBytes.count < p.rareBytes.count

		hasRarerBytes := p.startBytes.rankSum <= p.rareBytes.rankSum+50
		if hasFewerBytes || hasRarerBytes {
			return startBytes
		} else {
			return rareBytes
		}
	case startBytes != nil:
		return startBytes
	case rareBytes != nil:
		return rareBytes
	default:
		return nil
	}
}

func (p *prefilterBuilder) add(bytes []byte) {
	p.startBytes.add(bytes)
	p.rareBytes.add(bytes)
}

func newPrefilterBuilder() prefilterBuilder {
	return prefilterBuilder{
		startBytes: newStartBytesBuilder(),
		rareBytes:  newRareBytesBuilder(),
	}
}

type rareBytesBuilder struct {
	rareSet     byteSet
	byteOffsets rareByteOffsets
	available   bool
	count       int
	rankSum     uint16
}

type rareBytes struct {
	offsets rareByteOffsets
	bytes   [3]byte
	count   int
}

func (r rareBytes) NextCandidate(state *prefilterState, haystack []byte, at int) int {
	rare := r.bytes[:r.count]
	for i, b := range haystack[at:] {
		if slices.Contains(rare, b) {
			pos := at + i
			state.updateAt(pos)
			return max(at, max(pos-int(r.offsets.rbo[haystack[pos]].max), 0))
		}
	}
	return noneCandidate
}

func (r *rareBytesBuilder) build() prefilter {
	if !r.available || r.count > 3 {
		return nil
	}
	var length int
	bytes := [3]byte{}

	for b := range 256 {
		if r.rareSet.contains(byte(b)) {
			bytes[length] = byte(b)
			length += 1
		}
	}

	if length == 0 {
		return nil
	}
	return &rareBytes{
		offsets: r.byteOffsets,
		bytes:   bytes,
		count:   length,
	}
}

func (r *rareBytesBuilder) add(bytes []byte) {
	if !r.available {
		return
	}

	if r.count > 3 {
		r.available = false
		return
	}

	if len(bytes) >= 256 {
		r.available = false
		return
	}

	if len(bytes) == 0 {
		return
	}

	rarest1, rarest2 := bytes[0], freqRank(bytes[0])
	found := false

	for pos, b := range bytes {
		r.setOffset(pos, b)
		if found {
			continue
		}
		if r.rareSet.contains(b) {
			found = true
		}
		rank := freqRank(b)
		if rank < rarest2 {
			rarest1 = b
			rarest2 = rank
		}

		if !found {
			r.addRareByte(rarest1)
		}
	}
}

func (r *rareBytesBuilder) addRareByte(b byte) {
	if r.rareSet.insert(b) {
		r.count += 1
		r.rankSum += uint16(freqRank(b))
	}
}

func newRareByteOffset(i int) rareByteOffset {
	if i > math.MaxUint8 {
		return rareByteOffset{max: 0}
	}
	b := byte(i)
	return rareByteOffset{max: b}
}

func (r *rareBytesBuilder) setOffset(pos int, b byte) {
	offset := newRareByteOffset(pos)
	r.byteOffsets.set(b, offset)
}

func newRareBytesBuilder() rareBytesBuilder {
	return rareBytesBuilder{
		rareSet:     byteSet{},
		byteOffsets: rareByteOffsets{},
		available:   true,
		count:       0,
		rankSum:     0,
	}
}

type startBytesBuilder struct {
	byteset []bool
	count   int
	rankSum uint16
}

func (s *startBytesBuilder) build() prefilter {
	if s.count > 3 {
		return nil
	}
	var length int
	bytes := [3]byte{}

	for b := range 256 {
		if !s.byteset[b] {
			continue
		}
		if b > 0x7F {
			return nil
		}
		bytes[length] = byte(b)
		length += 1
	}

	if length == 0 {
		return nil
	}
	return &startBytes{bytes: bytes, count: length}
}

func (s *startBytesBuilder) add(bytes []byte) {
	if s.count > 3 || len(bytes) == 0 {
		return
	}

	b := bytes[0]
	if !s.byteset[int(b)] {
		s.byteset[int(b)] = true
		s.count += 1
		s.rankSum += uint16(freqRank(b))
	}
}

func freqRank(b byte) byte {
	return byteFrequencies[int(b)]
}

func newStartBytesBuilder() startBytesBuilder {
	return startBytesBuilder{
		byteset: make([]bool, 256),
		count:   0,
		rankSum: 0,
	}
}

const (
	minSkips     int = 40
	minAvgFactor int = 2
)

type prefilterState struct {
	skips       int
	skipped     int
	maxMatchLen int
	inert       bool
	lastScanAt  int
}

func (p *prefilterState) updateAt(at int) {
	if at > p.lastScanAt {
		p.lastScanAt = at
	}
}

func (p *prefilterState) IsEffective(at int) bool {
	if p.inert || at < p.lastScanAt {
		return false
	}

	if p.skips < minSkips {
		return true
	}

	minAvg := minAvgFactor * p.maxMatchLen

	if p.skipped >= minAvg*p.skips {
		return true
	}

	p.inert = true
	return false
}

func (p *prefilterState) updateSkippedBytes(skipped int) {
	p.skips += 1
	p.skipped += skipped
}

const noneCandidate = -1

type prefilter interface {
	NextCandidate(state *prefilterState, haystack []byte, at int) int
}

func nextPrefilter(state *prefilterState, prefilter prefilter, haystack []byte, at int) int {
	cand := prefilter.NextCandidate(state, haystack, at)
	if cand < 0 {
		state.updateSkippedBytes(len(haystack) - at)
	} else {
		state.updateSkippedBytes(cand - at)
	}
	return cand
}
