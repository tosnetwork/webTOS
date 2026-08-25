<p align="center">
  <img src="wasbi.png" alt="Wasbi Logo" width="200">
</p>

# Wasbi - WebAssembly (Wasm) Interpreter

[![license-badge]][license-url]

[license-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[license-url]: LICENSE

Wasbi is a lightweight and self-contained WebAssembly interpreter with a focus on embedded systems, OS kernels, and deterministic execution.

## Features

- Pure Rust, `no_std` + `alloc` — runs on bare-metal, embedded systems, and OS kernels.
- ~12k LOC engine — small footprint, easy to audit.
- Zero `unsafe`, zero `unwrap`, zero panics in production code.
- Self-contained decoder, validator, and executor — no dependency on `wasmparser` or `wasmtime`.
- 100% hand-written from scratch — not a fork of any existing interpreter.
- Built-in fuel metering for execution budgets.
- RuntimeClass tiers for deterministic execution (BestEffort / ReplayGrade / ProofGrade).
- Modular proposal support — SIMD, GC, exception handling, threads, memory64 each behind a Cargo feature gate.
- Engine `Config` is enforced during module load, instantiation, and runtime growth operations.
- Feature-disabled proposals are rejected during `Module::new`, not only after execution starts.
- Layered error model — decode, validation, instantiation, and trap errors classified via `WasmError::layer()`.
- Full WebAssembly spec compliance: 444/444 official spec test files passing (78,346 assertions).

## Getting Started

Add `wasbi` to your `Cargo.toml`:

```toml
[dependencies]
wasbi = "0.1"
```

### Minimal Example

```rust
use wasbi::prelude::*;

// 1. Create an engine with default configuration
let engine = Engine::default();

// 2. Decode and validate a WASM binary in one step
let module = Module::new(&engine, &wasm_bytes)?;

// 3. Instantiate
let mut instance = Instance::new(module, &engine)?;

// 4. Call an exported function
match instance.call("add", &[Value::I32(2), Value::I32(3)]) {
    ExecResult::Returned(value) => { /* value == Value::I32(5) */ }
    ExecResult::Trap(err) => { /* runtime error */ }
    ExecResult::OutOfFuel => { /* execution budget exhausted */ }
    _ => {}
}
```

### Host Functions

Register host functions via `Linker` to handle WASM imports:

```rust
use wasbi::prelude::*;
use wasbi::linker::Linker;

let engine = Engine::default();
let module = Module::new(&engine, &wasm_bytes)?;
let mut instance = Instance::new(module, &engine)?;

// Register host functions
let mut linker = Linker::new();
linker
    .func_wrap("env", "log_i32", |_inst, args| {
        println!("wasm says: {}", args[0].as_i32());
        Ok(None)
    })
    .func_wrap("env", "get_time", |_inst, _args| {
        Ok(Some(Value::I64(42)))
    });

// Run with explicit host call dispatch
let mut result = instance.call("main", &[]);
loop {
    match result {
        ExecResult::HostCall(idx, ref args, count) => {
            let ret = linker.dispatch(&mut instance, idx, &args[..count as usize])?;
            result = instance.resume(ret);
        }
        ExecResult::Returned(_) | ExecResult::Ok => break,
        ExecResult::Trap(err) => return Err(err),
        ExecResult::OutOfFuel => break,
        _ => break,
    }
}
```

## Configuration

```rust
use wasbi::prelude::*;

let mut config = Config::default();
config.fuel = 500_000;
config.runtime_class = RuntimeClass::ProofGrade;
config.max_memory_pages = 256; // 16 MiB max

let engine = Engine::new(config);
```

`max_functions`, `max_locals`, `max_imports`, `max_exports`, `max_memory_pages`,
`max_table_size`, `max_globals`, `max_data_segments`, and `max_element_segments`
are enforced during `Module::new`. `max_stack`, `max_call_depth`,
`max_memory_pages`, and `max_table_size` are also enforced by the runtime.

## RuntimeClass

Wasbi provides three execution tiers to balance features against determinism guarantees:

| Class | Floats | SIMD | Threads | Use Case |
|-------|--------|------|---------|----------|
| **BestEffort** | Yes | Yes | Yes | General workloads, AI inference |
| **ReplayGrade** | Yes | Yes | No | Deterministic replay on same hardware |
| **ProofGrade** | No | No | No | Cryptographic verification, execution receipts |

## WebAssembly Features

| | WebAssembly Proposal | Status |
|:-:|:--|:--|
| ✅ | [`mutable-global`] | Full |
| ✅ | [`saturating-float-to-int`] | Full |
| ✅ | [`sign-extension`] | Full |
| ✅ | [`multi-value`] | Full |
| ✅ | [`bulk-memory`] | Full |
| ✅ | [`reference-types`] | Full |
| ✅ | [`tail-calls`] | Full |
| ✅ | [`extended-const`] | Full |
| ✅ | [`multi-memory`] | Full |
| ✅ | [`custom-page-sizes`] | Full |
| ✅ | [`memory64`] | Full |
| ✅ | [`simd`] | Full |
| ✅ | [`typed-function-references`] | Full |
| ✅ | [`gc`] | Full |
| ✅ | [`exception-handling`] | Full |
| 🔨 | [`threads`] | Partial |

[`mutable-global`]: https://github.com/WebAssembly/mutable-global
[`saturating-float-to-int`]: https://github.com/WebAssembly/nontrapping-float-to-int-conversions
[`sign-extension`]: https://github.com/WebAssembly/sign-extension-ops
[`multi-value`]: https://github.com/WebAssembly/multi-value
[`reference-types`]: https://github.com/WebAssembly/reference-types
[`bulk-memory`]: https://github.com/WebAssembly/bulk-memory-operations
[`simd`]: https://github.com/webassembly/simd
[`tail-calls`]: https://github.com/WebAssembly/tail-call
[`extended-const`]: https://github.com/WebAssembly/extended-const
[`gc`]: https://github.com/WebAssembly/gc
[`multi-memory`]: https://github.com/WebAssembly/multi-memory
[`threads`]: https://github.com/WebAssembly/threads
[`exception-handling`]: https://github.com/WebAssembly/exception-handling
[`custom-page-sizes`]: https://github.com/WebAssembly/custom-page-sizes
[`memory64`]: https://github.com/WebAssembly/memory64
[`typed-function-references`]: https://github.com/WebAssembly/function-references

## Cargo Features

All proposals are enabled by default. Disable unused ones to reduce binary size:

```toml
[dependencies]
wasbi = { version = "0.1", default-features = false, features = ["gc"] }
```

| Feature | Default | Controls |
|---------|:-------:|----------|
| `simd` | Yes | SIMD v128 instructions (0xFD prefix) |
| `gc` | Yes | GC proposal: structs, arrays, i31ref (0xFB prefix) |
| `exceptions` | Yes | Exception handling: try/catch/throw |
| `threads` | Yes | Atomics and shared memory (0xFE prefix) |
| `memory64` | Yes | 64-bit memory addressing |

## Architecture

```
wasm bytes
    │
    ▼
 Decoder   ──▶  WasmModule (parsed representation)
    │
    ▼
 Validator ──▶  Ok / WasmError
    │
    ▼
 Runtime   ──▶  WasmInstance
    │               ├── MemoryStore   (linear memories + aliases)
    │               ├── TableStore    (function tables + aliases)
    │               ├── GlobalStore   (global variables + aliases)
    │               ├── GcStore       (GC heap + element values)
    │               └── FuelState     (fuel budget + finished flag)
    ▼
 ExecResult: Ok │ Returned(Value) │ Trap │ HostCall │ OutOfFuel
```

The public API provides `Engine`, `Module`, `Instance`, and `Linker` as
high-level wrappers around the internal decoder/validator/runtime pipeline.

## Error Handling

Errors are classified into four layers via `WasmError::layer()`:

| Layer | Examples |
|-------|----------|
| **Decode** | Malformed binary, bad magic, truncated sections, invalid LEB128 |
| **Validation** | Type mismatches, undeclared references, invalid block types |
| **Instantiation** | Unresolved imports, missing functions |
| **Trap** | Division by zero, out of bounds, stack overflow, fuel exhaustion |

## Resource Limits

All resource limits are configurable via `Config`:

| Limit | Default |
|-------|---------|
| `max_functions` | 10,000 |
| `max_locals` | 4,096 |
| `max_stack` | 65,536 |
| `max_memory_pages` | 65,536 (4 GiB) |
| `max_call_depth` | 1,000 |
| `max_code_size` | 10 MB |
| `fuel` | 1,000,000 |

## Documentation

- [Design Overview](docs/DESIGN.md) -- architecture, execution model, design decisions
- [Embedding Guide](docs/EMBEDDING.md) -- how to use wasbi in your application
- [Known Limitations](docs/LIMITATIONS.md) -- engine vs runner gaps
- [Versioning Policy](docs/SEMVER.md) -- semver, MSRV, compatibility rules
- [Contributing](docs/CONTRIBUTING.md) -- project structure, invariants, release checklist
- [Security Policy](SECURITY.md) -- vulnerability reporting
- [Spec Runner](tools/wasm-spec-test/README.md) -- official WebAssembly testsuite harness used for the 444/444 compliance claim

## Verification

Run the crate tests:

```bash
cargo test
```

Run the official spec runner:

```bash
cargo test --manifest-path tools/wasm-spec-test/Cargo.toml
cargo run --release --manifest-path tools/wasm-spec-test/Cargo.toml -- tools/wasm-spec-test/tests/spec
```

## License

Licensed under the [MIT license](LICENSE).
