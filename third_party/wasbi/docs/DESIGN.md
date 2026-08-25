# Wasbi Design Overview

## Architecture

Wasbi is a direct bytecode interpreter — it executes WASM instructions
one at a time from the binary encoding, without translating to an
intermediate representation first.

### Why Direct Interpretation

- **Simplicity**: No translation pass means less code, fewer bugs, and
  a smaller binary. The entire engine is ~12k LOC.
- **Startup latency**: Modules begin executing immediately after
  decode + validate. No compilation delay.
- **Memory**: No need to store a second representation of the code.
- **Portability**: No platform-specific codegen. Runs anywhere Rust
  compiles, including `no_std` bare-metal targets.

The tradeoff is lower peak throughput compared to translating
interpreters (like wasmi) or JIT compilers (like wasmtime). For
embedded systems and metered execution this is acceptable.

### Pipeline

```
   bytes: &[u8]
       │
       ▼
   ┌──────────┐
   │ Decoder   │  decoder.rs (~2k LOC)
   │           │  Parses binary format, produces WasmModule
   └──────────┘
       │
       ▼
   ┌──────────┐
   │ Validator │  validator.rs + validator/func.rs (~3k LOC)
   │           │  Type-checks every instruction, rejects invalid modules
   └──────────┘
       │
       ▼
   ┌──────────┐
   │ Runtime   │  runtime.rs + runtime/*.rs (~5k LOC)
   │           │  Instantiates module, executes instructions with fuel metering
   └──────────┘
       │
       ▼
   ExecResult: Ok | Returned(Value) | Trap(WasmError) | HostCall | OutOfFuel
```

### Public API Layer

The public API wraps the internal pipeline:

- **`Engine`** — holds `Config` (limits, fuel, RuntimeClass)
- **`Module`** — decode + validate in one step via `Module::new(engine, bytes)`
- **`Instance`** — runtime state, created from Module + Engine
- **`Linker`** — register host functions by (module, field) name
- **`Caller`** — narrow host-side view for memory/global/fuel access during imports

Internal types (`WasmModule`, `WasmInstance`) remain crate-private implementation
details. The public API is centered on `Engine`, `Module`, `Instance`,
`Linker`, and `Caller`.

## Decoder

The decoder (`decoder.rs`) reads the WASM binary format section by
section in a single pass. It produces a `WasmModule` struct containing:

- **Type section** → `func_types: Vec<FuncTypeDef>` (fixed-size param/result arrays)
- **Import section** → `imports: Vec<ImportDef>`
- **Function section** → `functions: Vec<FuncDef>` (type index + code offset)
- **Table/Memory/Global sections** → `tables`, `memories`, `globals`
- **Export section** → `exports: Vec<ExportDef>`
- **Element/Data sections** → `element_segments`, `data_segments`
- **Code section** → raw bytes stored in `code: Vec<u8>`
- **Names** → import/export name strings stored in `names: Vec<u8>`

Key design decisions:
- Function signatures use fixed-size arrays (`[ValType; 128]`) to avoid
  heap allocation for small signatures.
- Code bytes are stored as-is — no parsing of instruction bodies during
  decode. The validator and runtime read them directly.
- LEB128 decoding includes overflow and bounds checks.

## Validator

The validator (`validator.rs` + `validator/func.rs`) performs:

1. **Module-level validation**: export uniqueness, index bounds, memory
   limits, data count consistency.
2. **Function body validation**: stack-based type checking for every
   instruction. Tracks an operand type stack and control flow stack.
   Handles polymorphic typing after `unreachable`.
3. **Feature gating**: proposal opcodes guarded by Cargo features are
   rejected during validation when the corresponding feature is disabled.

The validator runs on the decoded `WasmModule` before instantiation.
It never modifies the module.

## Runtime

The runtime (`runtime.rs`) is a fuel-metered stack machine:

- **Operand stack**: `Vec<Value>` with explicit `stack_ptr`
- **Call stack**: `Vec<CallFrame>` tracking return addresses and locals
- **Block stack**: `Vec<BlockFrame>` for structured control flow
- **Fuel**: decremented once per instruction; returns `OutOfFuel` when exhausted

### Execution Model

```
loop {
    if fuel == 0 → return OutOfFuel
    opcode = code[pc++]
    match opcode {
        // dispatch to handler
    }
}
```

When a host import is called, the runtime returns
`ExecResult::HostCall(func_idx, args, count)`. The embedder resolves
the call and resumes with `instance.resume(return_value)`.

### Proposal Dispatch

Proposals are isolated into separate files gated by Cargo features:

| Prefix | File | Feature |
|--------|------|---------|
| `0xFC` | `fc_ops.rs` | always on (bulk memory, sat trunc) |
| `0xFD` | `simd.rs` | `simd` |
| `0xFB` | `gc_ops.rs` + `gc_helpers.rs` | `gc` |
| `0xFE` | `atomic.rs` | `threads` |

### RuntimeClass

The `RuntimeClass` enum controls feature availability for
deterministic execution:

- **BestEffort** — all features enabled
- **ReplayGrade** — floats and SIMD allowed, no threads
- **ProofGrade** — no floats, no SIMD, no threads; strict determinism

Checked at runtime before executing float/SIMD/atomic instructions.
Feature-disabled proposals are rejected earlier during `Module::new`.

## Host Integration

Host functions are registered via `Linker::func_wrap(module, field, closure)`.
When the runtime encounters an imported function call, it pauses and
returns `ExecResult::HostCall`. The embedder dispatches via
`linker.dispatch(instance, func_idx, args)` and resumes.

The host closure receives `(Caller<'_>, &[Value])` and returns
`Result<Option<Value>, WasmError>`.

## Error Model

`WasmError` is a flat enum with 40+ variants, classified into four
layers via `WasmError::layer()`:

- **Decode** — malformed binary
- **Validation** — type errors, constraint violations
- **Instantiation** — unresolved imports
- **Trap** — runtime errors (division by zero, out of bounds, etc.)

## Resource Limits

All limits are configurable via `Config`:

| Limit | Default | Purpose |
|-------|---------|---------|
| `max_functions` | 10,000 | Per-module function count |
| `max_locals` | 4,096 | Per-function local count |
| `max_stack` | 65,536 | Operand stack depth |
| `max_memory_pages` | 65,536 | Linear memory (4 GiB max) |
| `max_call_depth` | 1,000 | Call stack depth |
| `max_code_size` | 10 MB | Code section size |
| `fuel` | 1,000,000 | Instruction budget |

Module-level limits are enforced during `Module::new`. Execution limits such
as `max_stack`, `max_call_depth`, `max_memory_pages`, and `max_table_size`
are also enforced by the runtime during execution and growth operations.

## Safety

- Zero `unsafe` blocks in the engine
- Zero `unwrap()` calls in production paths
- Zero panics — all errors return `WasmError` or `ExecResult::Trap`
- Bounds checks on every memory, table, and stack access
- LEB128 decoding with overflow protection
- Checked arithmetic for address calculations
