# Preliminary Engine Findings

These findings come from representative runs of the ATOS spec runner on 2026-03-24.
They are intentionally descriptive only; this tool does not patch the engine.

## Sample Results

- `tests/spec/i32.wast`: 376 / 459 assertions passed
- `tests/spec/i64.wast`: 386 / 415 assertions passed
- `tests/spec/proposals/extended-const/data.wast`: 9 / 36 assertions passed
- `tests/spec/proposals/extended-const/elem.wast`: 27 / 73 assertions passed
- `tests/spec/proposals/extended-const/global.wast`: 14 / 109 assertions passed

## Repeated Failure Patterns

### 1. Validation is too weak for many `assert_invalid` cases

Observed in both `i32.wast` and `i64.wast`.

Typical failure:

```text
assert_invalid ... expected `type mismatch`
module unexpectedly validated successfully
```

Implication:

- `src/wasm/validator.rs` currently misses a large set of stack typing and instruction validation rules that the spec suite expects.

### 2. Imported table/memory style linking is not supported by the ATOS host ABI

Observed in `proposals/extended-const/elem.wast`.

Typical failure:

```text
spectest import `table` is not a function and cannot be linked by the ATOS engine
```

Implication:

- The current host-side import path can dispatch function imports and synthesize global imports.
- It cannot satisfy imported tables or memories without deeper engine support.

### 3. Some proposal modules fail during decode/instantiate with structural errors

Observed in `proposals/extended-const/data.wast` and `proposals/extended-const/elem.wast`.

Typical failures:

```text
instantiate failed: FunctionNotFound(0)
instantiate failed: InvalidSection
instantiate failed: TypeMismatch
```

Implication:

- Proposal coverage in the decoder/runtime is incomplete or inconsistent for these modules.
- The current import/index-space model likely breaks for some non-MVP linking cases.

### 4. Failed module instantiation cascades into later `assert_return` failures

Observed in `proposals/extended-const/global.wast`.

Typical failure:

```text
assert_return: no current instance available
```

Implication:

- Once an earlier module directive fails, later directives that rely on that instantiated module naturally fail too.
- This is expected runner behavior, but it indicates the earlier instantiation failure is the primary bug to fix.

## Runner-Side Limits To Keep Separate From Engine Bugs

These are current host-runner constraints and should not be confused with kernel engine defects:

- imported functions with more than one result are rejected by the host-call adapter
- re-entrant cross-instance imports are rejected by the host-side driver
- reference-type arguments/results are reported as unsupported in the runner
