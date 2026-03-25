# Remaining Spec Test Failures

Classified as of 2026-03-25. Current results: **436/444 files passing, 78,170/78,346 assertions passing, 82 skipped, 0 panics**.

## 1. `gc/type-subtyping.wast` -- engine bug: incomplete subtype validation

**18 assertion failures** (29/47 passing)

The validator does not perform structural subtype checking for function types
within recursive type groups. Modules that should be rejected by `assert_invalid`
(expected `type mismatch`) are validated successfully. Some `assert_return` and
`assert_trap` cases fail due to incorrect indirect call type matching.

Root cause: `src/wasm/validator.rs` lacks structural subtype comparison for
concrete type indices in rec groups.

## 2. `gc/type-rec.wast` -- engine bug: no rec group canonicalization

**2 assertion failures** (9/11 passing)

Recursive type groups are not canonicalized. Two structurally identical rec groups
defined separately get distinct type indices. This causes:
- `assert_invalid` modules to validate when they should be rejected
- `assert_trap` for `indirect call type mismatch` to fail because the engine
  treats structurally identical types as distinct

Root cause: `src/wasm/decode/mod.rs` does not implement rec group hash-consing
or structural equivalence for canonicalization.

## 3. `wasm-3.0/type-subtyping.wast` -- engine bug: same as gc/type-subtyping

**18 assertion failures** (37/55 passing)

Same root cause as (1). The `wasm-3.0` proposal directory contains a superset of
the GC tests. The additional passing tests come from basic subtyping cases that
do not involve rec groups.

## 4. `wasm-3.0/type-rec.wast` -- engine bug: same as gc/type-rec

**2 assertion failures** (9/11 passing)

Same root cause as (2). Identical test content under the `wasm-3.0` proposal
directory.

## 5. `wasm-3.0/instance.wast` -- engine/runner limitation: no cross-module aliasing

**6 assertion failures** (6/12 passing)

Tests that re-export a function from one module and re-import it in another fail.
The engine/runner does not preserve function references across module boundaries:
`ref.func` returns `NullRef` instead of a valid function reference, and
re-imported globals do not carry their values across instances.

Root cause: The spec-test runner instantiates each module independently. There is
no shared store that would allow function references and globals to be aliased
across instances. This is partly an engine limitation (no cross-instance ref
tracking) and partly a runner limitation (no shared store model).

## 6. `skip-stack-guard-page.wast` -- engine bug: stack overflow on instantiation

**10 assertion failures** (0/10 passing)

The module defines functions with ~2000 locals, exceeding `MAX_LOCALS=1024` in
`src/wasm/types.rs`. The decoder returns `OutOfBounds` during instantiation
instead of successfully loading the module. All subsequent `assert_exhaustion`
directives fail with `no current instance available`.

Root cause: The fixed-size local array in `FuncDef` (`locals: [ValType; MAX_LOCALS]`)
cannot hold 2000+ locals. The spec allows up to 50,000 locals.

## 7. `gc/array_init_elem.wast` -- engine bug: incomplete array.init_elem

**19 assertion failures** (3/22 passing)

GC proposal test for the `array.init_elem` instruction. The engine does not
fully implement this instruction's semantics for element-segment-based array
initialization.

Root cause: `src/wasm/runtime.rs` -- incomplete GC instruction dispatch.

## 8. `wasm-3.0/array_init_elem.wast` -- engine bug: same as gc/array_init_elem

**19 assertion failures** (3/22 passing)

Same root cause as (7). Identical test content under the `wasm-3.0` proposal
directory.
