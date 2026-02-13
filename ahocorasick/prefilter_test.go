package ahocorasick

import "testing"

func newState() *prefilterState {
	return &prefilterState{maxMatchLen: 1}
}

func TestStartBytes_NextCandidate(t *testing.T) {
	tests := []struct {
		name     string
		bytes    [3]byte
		count    int
		haystack []byte
		at       int
		want     int
	}{
		{
			name:     "single byte found at start",
			bytes:    [3]byte{'a'},
			count:    1,
			haystack: []byte("abc"),
			at:       0,
			want:     0,
		},
		{
			name:     "single byte found in middle",
			bytes:    [3]byte{'b'},
			count:    1,
			haystack: []byte("abc"),
			at:       0,
			want:     1,
		},
		{
			name:     "single byte not found",
			bytes:    [3]byte{'z'},
			count:    1,
			haystack: []byte("abc"),
			at:       0,
			want:     noneCandidate,
		},
		{
			name:     "two bytes finds first occurrence",
			bytes:    [3]byte{'b', 'c'},
			count:    2,
			haystack: []byte("abc"),
			at:       0,
			want:     1,
		},
		{
			name:     "three bytes finds first occurrence",
			bytes:    [3]byte{'b', 'c', 'd'},
			count:    3,
			haystack: []byte("abcd"),
			at:       0,
			want:     1,
		},
		{
			name:     "at skips prefix",
			bytes:    [3]byte{'a'},
			count:    1,
			haystack: []byte("axa"),
			at:       1,
			want:     2,
		},
		{
			name:     "empty haystack",
			bytes:    [3]byte{'a'},
			count:    1,
			haystack: []byte{},
			at:       0,
			want:     noneCandidate,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := startBytes{bytes: tt.bytes, count: tt.count}
			got := s.NextCandidate(newState(), tt.haystack, tt.at)
			if got != tt.want {
				t.Errorf("NextCandidate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRareBytes_NextCandidate(t *testing.T) {
	makeOffsets := func(m map[byte]byte) rareByteOffsets {
		var offsets rareByteOffsets
		for b, max := range m {
			offsets.rbo[b] = rareByteOffset{max: max}
		}
		return offsets
	}

	tests := []struct {
		name     string
		bytes    [3]byte
		count    int
		offsets  rareByteOffsets
		haystack []byte
		at       int
		want     int
	}{
		{
			name:     "single byte no offset",
			bytes:    [3]byte{'x'},
			count:    1,
			offsets:  makeOffsets(map[byte]byte{'x': 0}),
			haystack: []byte("abxcd"),
			at:       0,
			want:     2,
		},
		{
			name:     "single byte with offset rewinds",
			bytes:    [3]byte{'x'},
			count:    1,
			offsets:  makeOffsets(map[byte]byte{'x': 2}),
			haystack: []byte("abxcd"),
			at:       0,
			want:     0,
		},
		{
			name:     "offset clamped to at",
			bytes:    [3]byte{'x'},
			count:    1,
			offsets:  makeOffsets(map[byte]byte{'x': 10}),
			haystack: []byte("abxcd"),
			at:       1,
			want:     1,
		},
		{
			name:     "two bytes finds first",
			bytes:    [3]byte{'x', 'y'},
			count:    2,
			offsets:  makeOffsets(map[byte]byte{'x': 1, 'y': 0}),
			haystack: []byte("abycxd"),
			at:       0,
			want:     2,
		},
		{
			name:     "three bytes finds first",
			bytes:    [3]byte{'x', 'y', 'z'},
			count:    3,
			offsets:  makeOffsets(map[byte]byte{'x': 0, 'y': 0, 'z': 0}),
			haystack: []byte("abzcd"),
			at:       0,
			want:     2,
		},
		{
			name:     "no match",
			bytes:    [3]byte{'x'},
			count:    1,
			offsets:  makeOffsets(map[byte]byte{'x': 0}),
			haystack: []byte("abcde"),
			at:       0,
			want:     noneCandidate,
		},
		{
			name:     "offset larger than position clamps to zero then at",
			bytes:    [3]byte{'b'},
			count:    1,
			offsets:  makeOffsets(map[byte]byte{'b': 255}),
			haystack: []byte("ab"),
			at:       0,
			want:     0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := rareBytes{offsets: tt.offsets, bytes: tt.bytes, count: tt.count}
			state := newState()
			got := r.NextCandidate(state, tt.haystack, tt.at)
			if got != tt.want {
				t.Errorf("NextCandidate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStartBytesBuilder_Build(t *testing.T) {
	t.Run("single pattern", func(t *testing.T) {
		b := newStartBytesBuilder()
		b.add([]byte("hello"))
		pf := b.build()
		if pf == nil {
			t.Fatal("expected non-nil prefilter")
		}
		got := pf.NextCandidate(newState(), []byte("xxhello"), 0)
		if got != 2 {
			t.Errorf("NextCandidate() = %v, want 2", got)
		}
	})

	t.Run("multiple patterns", func(t *testing.T) {
		b := newStartBytesBuilder()
		b.add([]byte("abc"))
		b.add([]byte("xyz"))
		pf := b.build()
		if pf == nil {
			t.Fatal("expected non-nil prefilter")
		}
		got := pf.NextCandidate(newState(), []byte("__x__a"), 0)
		if got != 2 {
			t.Errorf("NextCandidate() = %v, want 2", got)
		}
	})

	t.Run("too many distinct start bytes returns nil", func(t *testing.T) {
		b := newStartBytesBuilder()
		b.add([]byte("a"))
		b.add([]byte("b"))
		b.add([]byte("c"))
		b.add([]byte("d"))
		pf := b.build()
		if pf != nil {
			t.Error("expected nil prefilter for >3 distinct bytes")
		}
	})

	t.Run("empty pattern skipped", func(t *testing.T) {
		b := newStartBytesBuilder()
		b.add([]byte{})
		pf := b.build()
		if pf != nil {
			t.Error("expected nil prefilter for no bytes")
		}
	})
}

func TestRareBytesBuilder_Build(t *testing.T) {
	t.Run("single pattern", func(t *testing.T) {
		b := newRareBytesBuilder()
		b.add([]byte("hello"))
		pf := b.build()
		if pf == nil {
			t.Fatal("expected non-nil prefilter")
		}
	})

	t.Run("too many rare bytes returns nil", func(t *testing.T) {
		b := newRareBytesBuilder()
		// Add patterns that produce >3 distinct rare bytes
		b.add([]byte("w"))
		b.add([]byte("x"))
		b.add([]byte("y"))
		b.add([]byte("z"))
		pf := b.build()
		if pf != nil {
			t.Error("expected nil prefilter for >3 rare bytes")
		}
	})
}

func TestPrefilterState_IsEffective(t *testing.T) {
	t.Run("effective when few skips", func(t *testing.T) {
		state := &prefilterState{maxMatchLen: 1}
		if !state.IsEffective(0) {
			t.Error("expected effective with no skips")
		}
	})

	t.Run("becomes inert after many skips with low skip rate", func(t *testing.T) {
		state := &prefilterState{maxMatchLen: 1}
		for range minSkips + 1 {
			state.updateSkippedBytes(0)
		}
		if state.IsEffective(0) {
			t.Error("expected inert after many zero-distance skips")
		}
	})
}
