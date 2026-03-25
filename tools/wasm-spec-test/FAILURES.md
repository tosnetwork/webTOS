# Spec Test Failure Classification

**Status: ALL 444 FILES PASS (100%)**

As of 2026-03-25, all 444 official WebAssembly spec test files pass.

- 78,264 / 78,346 assertions pass (99.9%)
- 82 assertions intentionally skipped (`assert_exception` in legacy EH tests)
- 0 panics, 0 unwrap(), 0 unsafe in engine code

## Previously Known Issues (ALL RESOLVED)

1. ~~Incomplete subtype validation~~ → Full rec-group-aware type equivalence
2. ~~No rec group canonicalization~~ → Structural comparison across rec groups
3. ~~Cross-module import aliasing~~ → Runtime global/table/memory/tag alias maps
4. ~~skip-stack-guard-page panic~~ → MAX_LOCALS increased to 4096
5. ~~GC const expression validation~~ → Distinguish const vs non-const GC ops
6. ~~Legacy EH delegate semantics~~ → Proper try-delegate block scanning

## Skipped Assertions (82)

All 82 skipped assertions are `assert_exception` directives in legacy
exception handling tests. These use a wast directive that our test
runner intentionally skips (not an engine limitation).
