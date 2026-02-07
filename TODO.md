# TODO

## Completed

- [x] Remove DFA implementation (dfa.go)
- [x] Remove unused stateful automaton methods (leftmostFindAt, leftmostFindAtImp, findAt, etc.)
- [x] Remove unused NFA methods (IsValid, IsMatchState, NextState, UsePrefilter, etc.)
- [x] Remove unused matchKind methods (supportsOverlapping, supportsStream, isStandard)
- [x] Modernize interface{} to any
- [x] Modernize sort.Slice to slices.SortFunc

## Remaining

- [x] Review if IterOverlapping can be replaced with simpler implementation
- [x] Consider inlining small automaton interface methods directly into NFA
- [x] The prefilter system is complex and may have unused code paths
