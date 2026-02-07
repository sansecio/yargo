# Go Code Review: github.com/sansecio/yargo

**Scope**: entire module
**Go version**: 1.25.6
**Files reviewed**: 41
**Total findings**: 6

## Critical Findings

*No critical findings*

## Important Findings

| # | File:Line | Category | Issue | Suggested Fix |
|---|-----------|----------|-------|---------------|
| 1 | ahocorasick/automaton.go:95 | Discarded return value | In `leftmostFindAtImp()`, the call to `a.GetMatch(*sID, 0, at)` returns a `*Match` that should update `lastMatch`, but the return value is discarded. This causes the function to potentially return stale or incorrect match data. Compare with line 138 in `leftmostFindAtNoStateImp()` where the result is properly assigned. | Change from `a.GetMatch(*sID, 0, at)` to `lastMatch = a.GetMatch(*sID, 0, at)` |
| 2 | ahocorasick/dfa.go:127-557 | Code duplication | Excessive duplication across four implementation types (`iStandard`, `iByteClass`, `iPremultiplied`, `iPremultipliedByteClass`). Each type repeats 16+ identical wrapper methods that simply delegate to module-level functions. | Use composition or embedded structs with a common interface wrapper to reduce the 4×16 method implementations to a single set. |

## Nice-to-Have Findings

| # | File:Line | Category | Issue | Suggested Fix |
|---|-----------|----------|-------|---------------|
| 1 | ahocorasick/ahocorasick.go:164 | interface{} vs any | Uses `interface{}` instead of modern `any` alias | Change `New: func() interface{}` to `New: func() any` |
| 2 | scanner/scanner_test.go:250 | interface{} vs any | Uses `interface{}` instead of modern `any` alias | Change `make(map[string]interface{})` to `make(map[string]any)` |
| 3 | scanner/profile.go:87 | sort.Slice modernization | Uses `sort.Slice` instead of `slices.SortFunc` | Use `slices.SortFunc(timings, func(a, b RegexTiming) int { return cmp.Compare(b.Duration, a.Duration) })` |
| 4 | cmd/internal/diff.go:18 | sort.Slice modernization | Uses `sort.Slice` instead of `slices.SortFunc` | Use `slices.SortFunc(keys, func(a, b string) int { return cmp.Compare(m[b], m[a]) })` |

## Summary

| Category | Critical | Important | Nice-to-Have |
|----------|----------|-----------|--------------|
| Idioms & Modernization | 0 | 0 | 4 |
| Architecture & Design | 0 | 1 | 0 |
| Correctness, Safety & Defensive Programming | 0 | 1 | 0 |
| Package API Surface & Boundaries | 0 | 0 | 0 |
| **Total** | **0** | **2** | **4** |

## Recommended Refactoring Order

1. **[Important]** Fix discarded return value in `leftmostFindAtImp()` — ahocorasick/automaton.go:95. This is a potential correctness bug that could cause incorrect match results.

2. **[Important]** Reduce code duplication in DFA implementations — ahocorasick/dfa.go:127-557. This is a maintainability concern that will make future changes error-prone.

3. **[Nice-to-Have]** Modernize `interface{}` to `any` — ahocorasick/ahocorasick.go:164, scanner/scanner_test.go:250

4. **[Nice-to-Have]** Modernize `sort.Slice` to `slices.SortFunc` — scanner/profile.go:87, cmd/internal/diff.go:18
