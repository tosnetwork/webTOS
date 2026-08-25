# webTOS Wasm Engine Integration

**Status: available in the native reference kernel; browser host integration
is in progress.**

webTOS uses the standalone [`wasbi`](https://github.com/tosnetwork/wasbi)
engine for WebAssembly decoding, validation, instantiation, and execution. The
kernel owns policy and operating-system integration; the engine remains a
general execution component.

## Current Boundary

```text
Wasm module
    |
    v
wasbi
  - decode and validate
  - instantiate and execute
  - memories, tables, globals, references, and traps
  - fuel accounting
    |
    v
webTOS Wasm bridge
  - resolve the `tos` import namespace
  - translate host calls into kernel operations
  - enforce capabilities and agent policy
  - connect execution to events and receipts
    |
    v
webTOS kernel
```

The dependency is declared in [`Cargo.toml`](../Cargo.toml). The kernel-facing
re-exports live in [`src/wasm/mod.rs`](../src/wasm/mod.rs), and TOS host-import
resolution lives in [`src/wasm/host.rs`](../src/wasm/host.rs).

## Responsibility Split

### Engine

The standalone engine is responsible for:

- WebAssembly binary decoding and structural validation
- Module instantiation, linking primitives, and export lookup
- Instruction execution and traps
- Linear memories, tables, globals, references, and proposal semantics
- Deterministic fuel consumption at the instruction boundary
- Engine-level conformance, regression, and fuzz testing

Engine proposal coverage and spec-suite pass counts belong in the engine
repository. They should not be duplicated here because they can drift from the
dependency revision used by webTOS.

### Kernel Bridge

webTOS is responsible for:

- Mapping the `tos` import namespace to kernel services
- Validating user-memory ranges before host access
- Capability checks for state, mailbox, network, and spawn operations
- Translating fuel consumption into agent energy accounting
- Suspending, resuming, and terminating Wasm agents
- Recording deterministic events, checkpoints, and execution receipts
- Defining which engine features are permitted for each runtime class

## Host ABI

The current bridge recognizes these imports from the `tos` module:

| Import | Purpose |
|--------|---------|
| `sys_yield` | Yield the current agent's execution slice |
| `sys_send` | Send a message through a mailbox |
| `sys_recv` | Receive a mailbox message |
| `sys_exit` | Finish the current Wasm agent |
| `sys_energy_get` | Read the remaining execution budget |
| `log` | Emit guest log bytes through the host |

The import namespace is an ABI name and remains `tos` even though the product
name is webTOS. Renaming it would be a compatibility change for existing Wasm
modules.

The bridge currently contains partial host-call behavior. In particular,
mailbox and logging paths validate guest memory but still need to connect all
effects to the corresponding kernel services. Documentation and examples must
not present these imports as a stable public SDK until that work is complete.

## Determinism and Runtime Classes

Wasm execution is intended to provide instruction-level fuel accounting and
deterministic behavior. The kernel must still control every external input:

- time comes from the logical kernel clock
- randomness comes from a recorded or deterministic source
- mailbox delivery follows kernel ordering rules
- network input is recorded before it reaches the guest
- persistent state changes are committed through keyspaces

An engine conformance result alone does not establish webTOS determinism. The
host bridge, scheduler, storage adapter, and browser event boundary are part of
the determinism claim.

## Browser Integration

The engine is portable Rust, but browser delivery requires more than compiling
the engine to WebAssembly. The webTOS browser host must provide:

- a worker-based execution lifecycle that does not block the UI thread
- deterministic scheduling between runnable agents
- persistent storage adapters for packages, keyspaces, and checkpoints
- explicit network mediation and input recording
- terminal and control-channel adapters
- snapshot and restore of engine plus kernel state
- browser tests for reload, suspension, storage failure, and worker failure

The Wasm guest path does not require the x86-64 execution engine. Linux x86-64
ELF workloads do require that additional layer before they can run in the
browser.

## Integration Checklist

- [x] Keep the Wasm engine in a standalone repository and crate.
- [x] Consume the engine through an explicit Cargo dependency.
- [x] Keep kernel-specific imports in a narrow bridge module.
- [ ] Pin browser releases to an immutable engine revision.
- [ ] Replace use of engine `internal` modules with a stable public API.
- [ ] Connect mailbox and logging imports to real kernel operations.
- [ ] Document and test the stable guest host ABI.
- [ ] Add capability checks to every effectful host call.
- [ ] Add browser-worker integration and lifecycle tests.
- [ ] Add end-to-end receipt and replay tests for Wasm agents in the browser.
- [ ] Define supported engine features for each runtime class.
- [ ] Publish a compatibility policy for existing Wasm packages.

## Validation

Changes to this integration should verify, at minimum:

1. The native kernel still builds against the pinned engine revision.
2. Host calls reject invalid guest addresses without panicking.
3. Fuel exhaustion suspends or traps according to the selected runtime policy.
4. Identical code, input, and recorded external events produce identical
   state roots and receipts.
5. Browser reload and worker restart do not silently lose committed state.

## Related Documentation

- [WebAssembly runtime specification](specs/WASM-runtime-spec.md)
- [Smart contract example](contract-example.md)
- [Documentation index](README.md)
