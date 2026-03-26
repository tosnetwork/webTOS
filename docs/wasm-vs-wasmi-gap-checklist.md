# ATOS WASM vs wasmi: Gap Checklist

This document lists the remaining gaps between the current ATOS custom WASM implementation and a `wasmi`-grade library runtime.

The goal is not to replace the custom decoder / validator / executor path. The goal is to make the existing implementation comparable to `wasmi` in library quality, embeddability, engineering discipline, and release readiness.

## Current Baseline

- The engine and local spec runner currently pass all `444` official spec test files.
- The runner still intentionally skips `82` legacy `assert_exception` directives.
- The current engine code path is documented as having `0` panics, `0` `unwrap()` calls, and `0` `unsafe` in engine code.
- The WASM subsystem has already been refactored into narrower modules, but it still behaves primarily like an in-tree subsystem, not a standalone public crate.
- Proposal coverage is ambitious and already extends beyond current `wasmi` support in some areas, especially around GC, function references, legacy EH, and related `wasm-3.0` coverage.

## Target Definition

To be "wasmi-grade", the project should be able to claim all of the following:

- It can be consumed as a standalone Rust library, not only from inside ATOS.
- It has a stable and documented embedding API.
- It is warning-free under normal host builds without relying on subsystem-wide lint suppression.
- It has strong unit, integration, spec, regression, and differential fuzz coverage.
- It has release discipline: versioning, docs, CI, compatibility policy, and security process.

## 1. API

- [ ] Extract the WASM engine into a standalone crate with a clear public root module.
- [ ] Define a user-facing API centered on concepts like `Engine`, `Module`, `Store`, `Instance`, and `Linker` or equivalent abstractions.
- [ ] Stop exposing runtime internals as the primary integration surface.
- [ ] Replace direct access to `WasmInstance` fields with typed methods and handle-based APIs.
- [ ] Replace the ATOS-specific host import bridge with a generic host function registration and linking API.
- [ ] Separate user-facing error layers:
  - validation errors
  - instantiation/linking errors
  - execution traps
  - host errors
- [ ] Add typed export lookup and typed function invocation helpers.
- [ ] Add resource limit APIs for memory, tables, instances, stack depth, and fuel.
- [ ] Make `RuntimeClass` part of a documented policy/configuration API instead of an internal integration detail.
- [ ] Introduce cargo features for optional proposal support instead of treating every supported proposal as always-on behavior.
- [ ] Define API stability rules:
  - what is public and semver-stable
  - what is internal and allowed to change

## 2. Architecture

- [ ] Make module representation, validation, instantiation, and execution separate top-level responsibilities.
- [ ] Reduce `WasmInstance` so it is no longer the owner of nearly all runtime concerns at once.
- [ ] Split stateful subsystems into narrower components:
  - globals
  - tables
  - memories
  - references / GC heap
  - tags / exceptions
  - fuel / limits
- [ ] Move runner-specific compatibility code fully out of the engine crate.
- [ ] Introduce stronger internal type boundaries for indexes and handles where confusion is still possible.
- [ ] Keep proposal-specific logic isolated so that GC, EH, threads, memory64, SIMD, and function references do not cross-contaminate core paths unnecessarily.
- [ ] Document all non-obvious invariants at the point they matter.
- [ ] Remove the need for subsystem-wide `#[allow(dead_code)]` just to keep normal builds clean.
- [ ] Keep the core engine warning-free when built as its own primary crate.
- [ ] Decide explicitly whether the long-term engine should remain a direct interpreter or evolve toward a translated bytecode architecture.
- [ ] If remaining a direct interpreter:
  - codify why that is the chosen design
  - define the intended performance and memory tradeoffs
- [ ] If moving toward translation later:
  - preserve the current validator and module boundaries so the migration path stays incremental

## 3. Testing

- [ ] Keep the full official spec suite as a required CI gate.
- [ ] Publish a machine-readable spec summary for every release candidate.
- [ ] Expand direct engine-level unit tests that do not go through the `.wast` runner.
- [ ] Add dedicated tests for:
  - decoding
  - validation
  - instantiation
  - execution
  - host calls
  - GC operations
  - exception handling
  - aliasing behavior
- [ ] Add regression tests for every engine bug fixed so far.
- [ ] Keep a living failure-classification document for:
  - engine bugs
  - runner limitations
  - unsupported directives
  - infra issues
- [ ] Add differential fuzzing against `wasmi`, `wasmtime`, or both.
- [ ] Add property-based tests for invariants such as:
  - decode/validate consistency
  - type equivalence relations
  - alias preservation
  - memory/table bounds behavior
- [ ] Keep existing fuzz targets for decode / validate / execute and grow them with regression corpora.
- [ ] Add coverage for public API behavior, not only internal engine behavior.
- [ ] Add host-target warning-free build/test jobs for the engine crate itself.
- [ ] Add stress tests for untrusted-input hardening and large-module behavior.

## 4. Documentation

- [ ] Add a top-level engine README that explains:
  - what the runtime is
  - what it is not
  - which proposals are supported
  - what guarantees exist around determinism and safety
- [ ] Add a public usage guide for embedding the runtime in another Rust application.
- [ ] Add a design overview describing:
  - decode pipeline
  - validation pipeline
  - instantiation model
  - execution model
  - host integration model
- [ ] Add a proposal support matrix that is kept in sync with CI.
- [ ] Add a runner-vs-engine limitation note so users do not misread runner gaps as engine gaps.
- [ ] Document the semantics of `RuntimeClass` and how it affects correctness, replay, and policy.
- [ ] Add API examples for:
  - loading a module
  - linking imports
  - invoking exports
  - trapping and error handling
  - fuel metering
- [ ] Add a maintenance guide for contributors:
  - file ownership or subsystem map
  - invariant expectations
  - test expectations
  - release checklist
- [ ] Add a compatibility note covering what would count as a breaking change.

## 5. Release

- [ ] Choose and reserve the final public crate/repository name before treating the runtime as a reusable library.
- [ ] Extract the engine into a publishable crate with proper `Cargo.toml` metadata.
- [ ] Define semver policy and a minimum supported Rust version.
- [ ] Define supported targets:
  - `std`
  - `no_std`
  - host-side test targets
  - ATOS kernel integration target
- [ ] Add CI for:
  - formatting
  - clippy
  - cargo check
  - cargo test
  - spec suite
  - fuzz smoke jobs
- [ ] Publish docs on docs.rs or an equivalent hosted docs site.
- [ ] Add a changelog and release notes process.
- [ ] Add a security policy and vulnerability disclosure path.
- [ ] Add fuzz-crash triage rules and corpus retention policy.
- [ ] Add benchmark baselines and track performance regressions across releases.
- [ ] Define what evidence is required before claiming the runtime is suitable for untrusted third-party WASM inputs.
- [ ] Plan at least one external audit before positioning the project as "wasmi-grade" for production embedders.

## Recommended Order

1. API isolation
2. Architecture cleanup that supports standalone-crate extraction
3. Differential fuzzing and API-level testing
4. Public docs and feature matrix
5. Release process, metadata, CI, and audit preparation

## Bottom Line

Today, the ATOS WASM implementation is already a strong internal engine:

- correctness is strong
- proposal coverage is ambitious
- the spec runner is real and valuable

What still separates it from `wasmi` is not raw competence. It is library maturity:

- public API quality
- standalone embeddability
- documentation depth
- release discipline
- audit and security posture

That is the gap this checklist is intended to close.
