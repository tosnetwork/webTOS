# WASM Library-Grade Plan

Design document for the ATOS WASM engine library-grade quality effort.

## 1. Current Architecture Overview

The ATOS WASM engine is a self-built interpreter embedded in the ATOS microkernel.
It implements decode, validate, and execute phases for WebAssembly modules.

### File inventory (as of 2026-03-25)

```
src/wasm/
  mod.rs               9  Module root, re-exports
  error.rs            55  Unified WasmError enum
  types.rs           754  ValType, Value, V128, Opcode, limits, RuntimeClass
  decode/
    mod.rs           577  WasmModule struct, decode() entry point
    reader.rs        178  LEB128, read_byte, peek_byte, read_name, UTF-8
    sections.rs    1,426  Section parsing (type, import, func, table, memory, etc.)
    init_expr.rs     471  Constant expression skip/scan/eval
  validate/
    mod.rs           977  Module-level validation, subtype helpers
    func.rs        2,825  Function body type checking (Validator struct)
  exec/
    mod.rs         4,624  WasmInstance, step() dispatch, control flow, memory, tables
    simd.rs          426  SIMD (0xFD prefix) instruction dispatch
    gc.rs            464  GC (0xFB prefix) instruction dispatch
  host.rs            177  Host function import ABI
  decoder.rs           6  Backwards-compat re-export of decode/
  validator.rs         6  Backwards-compat re-export of validate/
  runtime.rs           6  Backwards-compat re-export of exec/
```

| Metric | Before | After |
|--------|--------|-------|
| Largest file | 5,461 LOC (`runtime.rs`) | 4,624 LOC (`exec/mod.rs`) |
| Files over 3,000 LOC | 2 | 1 |
| Total modules | 5 | 15 |

### Spec runner (`tools/wasm-spec-test/`)

| File | Responsibility |
|------|---------------|
| `src/main.rs` | CLI driver, summary reporting |
| `src/runner.rs` | `.wast` directive evaluation (module, assert_return, assert_trap, etc.) |
| `src/wasm.rs` | Thin `#[path]` re-export of engine sources for host-side compilation |

The runner uses `catch_unwind` around each file to survive engine panics.

## 2. Before/After Spec-Runner Comparison

### Baseline (Phase 1, 2026-03-24)

```
414/444 files passing
78,058/78,307 assertions passing
82 skipped
2 panic cases
```

### Current (Phase 5, 2026-03-25)

```
436/444 files passing  (+22 files)
78,170/78,346 assertions passing  (+112 assertions, +39 total from new test coverage)
82 skipped
0 panic cases (down from 2)
8 failing files (down from 30)
```

Note: the spec testsuite was updated between Phase 1 and Phase 5, adding new
test files (e.g. `array_init_elem.wast`), which accounts for the total
assertion count increase. The SIMD panic was eliminated.

### Delta

| Metric | Before | After | Change |
|--------|--------|-------|--------|
| Passing files | 414 | 436 | +22 |
| Failing files | 30 | 8 | -22 |
| Passing assertions | 78,058 | 78,170 | +112 |
| Total assertions | 78,307 | 78,346 | +39 |
| Panics | 2 | 0 | -2 |
| Skipped | 82 | 82 | 0 |

## 3. Known Issues Classification

### Engine bugs

1. **Incomplete subtype validation** (`gc/type-subtyping.wast`, `wasm-3.0/type-subtyping.wast`)
   - `assert_invalid` cases pass validation when they should be rejected
   - Rec-group type indices are not checked for structural subtype compatibility
   - 21+8 = 29 assertion failures

2. **No rec group canonicalization** (`gc/type-rec.wast`, `wasm-3.0/type-rec.wast`)
   - Recursive type groups are not canonicalized, so structurally identical rec
     groups are treated as distinct types
   - Causes `assert_invalid` to pass and `assert_trap` (indirect call type
     mismatch) to fail
   - 8+8 = 16 assertion failures

3. **Stack overflow on large-locals module** (`skip-stack-guard-page.wast`)
   - Module with ~2000 locals causes `OutOfBounds` during instantiation
   - The test expects `call stack exhausted` traps from deeply recursive calls
   - 10 assertion failures

4. **Array init elem** (`gc/array_init_elem.wast`, `wasm-3.0/array_init_elem.wast`)
   - New test file added to the spec suite between Phase 1 and Phase 5
   - 19+19 = 38 assertion failures across both directories

### Engine/runner limitation

5. **No cross-module aliasing** (`wasm-3.0/instance.wast`)
   - Tests that re-export and re-import across module instances fail
   - `ref.func` returns `NullRef` instead of a proper function reference
   - 6 assertion failures

### Summary

| Category | Files | Assertions lost |
|----------|-------|----------------|
| Engine bug: subtype validation | 2 | 36 |
| Engine bug: rec group canonicalization | 2 | 4 |
| Engine bug: stack overflow | 1 | 10 |
| Engine bug: array init elem | 2 | 38 |
| Engine/runner: cross-module | 1 | 6 |
| **Total** | **8** | **94** |

## 4. Recommended Next Steps

### P0 (highest priority)

1. **Fix `skip-stack-guard-page.wast`** instantiation. The module uses ~2000
   locals which exceeds `MAX_LOCALS=1024`. Either increase the limit or return a
   proper error instead of `OutOfBounds`.

2. **Implement `array.init_elem`** in the runtime GC instruction dispatch. This
   would fix `gc/array_init_elem.wast` and `wasm-3.0/array_init_elem.wast` (38
   assertion failures total).

### P1 (high priority)

3. **Implement rec group canonicalization** in the decoder/validator. Structurally
   identical recursive type groups should be assigned the same canonical type
   index. This would fix `type-rec.wast` in both `gc/` and `wasm-3.0/`.

4. **Improve subtype checking** in the validator. Add structural subtype comparison
   for function types within rec groups. This would fix `type-subtyping.wast` in
   both `gc/` and `wasm-3.0/`.

### P2 (medium priority)

5. **Cross-module instance linking**: Improve the runner and engine to support
   re-exported function references that survive across module boundaries. This
   would fix `wasm-3.0/instance.wast`.

6. **Add fuzz targets** for the decoder, validator, and runtime. Differential
   fuzzing against `wasmparser` for decode, and against `wasmi` for execution,
   would catch edge cases systematically.

### P3 (ongoing)

7. **Continue splitting `exec/mod.rs`** (4.6k LOC). The remaining `step()`
   function still contains control flow, memory ops, table ops, and 0xFC/0xFE
   prefix handlers inline. Future extraction targets: `control.rs`, `memory.rs`,
   `table.rs`. SIMD (426 LOC) and GC (464 LOC) are already extracted.

8. **Expand unit test coverage**. The engine previously had zero `#[cfg(test)]`
   unit tests. This phase adds initial coverage for `types.rs` and
   `decode/mod.rs`, but more is needed for `validate/` and `exec/`.
