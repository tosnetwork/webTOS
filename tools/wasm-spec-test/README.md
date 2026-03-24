# wasm-spec-test

Host-side WebAssembly spec testsuite runner for the ATOS WASM engine.

## What It Does

- Parses `.wast` files with the `wast` crate
- Encodes WAT/quoted modules to Wasm bytes
- Reuses ATOS engine sources directly from [`src/wasm`](../../../src/wasm)
- Executes modules with `WasmInstance::with_class(..., RuntimeClass::BestEffort)`
- Evaluates `assert_return`, `assert_trap`, `assert_invalid`, `assert_malformed`, `assert_unlinkable`, and `assert_exhaustion`

## Layout

- [`src/main.rs`](./src/main.rs): CLI and summary output
- [`src/runner.rs`](./src/runner.rs): `.wast` directive runner
- [`src/wasm.rs`](./src/wasm.rs): thin read-only wrapper over the ATOS engine sources
- [`tests/spec`](./tests/spec): symlink to the official spec testsuite

## Usage

```bash
cargo run
cargo run -- tests/spec/i32.wast
cargo run -- tests/spec/
cargo run -- --verbose tests/spec/f32.wast
```

## Current Host-Side Limits

These are runner-side or engine-ABI limits that the tool reports but does not fix:

- imported memories/tables are not linkable through the current ATOS engine ABI
- imported functions with more than one result are not linkable
- re-entrant cross-instance imports are not supported by the host-side runner
- reference-type values are reported as unsupported when encountered in assertions

The goal of this tool is to expose spec compliance gaps, not mask them.

## Findings

Initial representative runs are tracked in [`ENGINE-BUGS.md`](./ENGINE-BUGS.md).
