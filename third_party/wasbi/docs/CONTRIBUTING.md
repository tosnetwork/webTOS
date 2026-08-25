# Contributing to Wasbi

## Project Structure

```
src/
├── lib.rs              # Crate root, API stability declarations
├── config.rs           # Engine configuration (Config)
├── engine.rs           # Engine (shared config holder)
├── module.rs           # Module (decoded + validated WASM)
├── instance.rs         # Instance (running WASM, public API wrapper)
├── linker.rs           # Linker (host function registration)
├── types/              # Value types, error types, index types, opcodes, limits
├── decoder.rs          # Binary format decoder
├── decoder/            # Decoder submodules (reader, init_expr, gc_types)
├── validator.rs        # Module-level validation
├── validator/          # Validator submodules (func body, subtype checking)
├── runtime.rs          # Execution engine (WasmInstance, step dispatch)
├── runtime/            # Runtime submodules (numeric, memory, control, simd, gc, atomic, fc_ops)
├── instance_utils.rs   # Export/import query utilities
├── linker_utils.rs     # Cross-module type checking
└── store.rs            # Import injection, cross-instance sync
```

## Subsystem Ownership

| Subsystem | Primary File | Responsibility |
|-----------|-------------|----------------|
| Decode | decoder.rs | Binary format parsing |
| Validate | validator.rs, validator/func.rs | Type checking |
| Execute | runtime.rs, runtime/*.rs | Instruction dispatch |
| Public API | config.rs, engine.rs, module.rs, instance.rs, linker.rs | Embedding interface |

## Invariant Expectations

- The engine must never panic on any WASM input (malformed, invalid, or adversarial)
- All memory, table, stack, and GC heap accesses must be bounds-checked
- Fuel must be decremented before each instruction, never after
- The validator must never modify the module
- After successful validation, all function bodies are type-safe

## Test Expectations

- All changes must pass `cargo test`
- All changes must pass `cargo clippy -- -D warnings`
- The spec test suite (444/444 files) must not regress
- New features should include tests in the appropriate test file
- Bug fixes should include a regression test

## Adding a New Proposal

1. Create a new runtime submodule (e.g., `runtime/new_proposal.rs`)
2. Add a Cargo feature gate in `Cargo.toml`
3. Add `#[cfg(feature = "new_proposal")]` to the module declaration and dispatch
4. Add tests in `tests/`
5. Update the proposal matrix in `README.md`

## Release Checklist

1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md`
3. Run full test suite including spec tests
4. Run `cargo clippy -- -D warnings`
5. Run `cargo fmt --check`
6. Tag the release
