# Wiring the JIT into the browser

The native wasmi measurement settled the backend question: wasmi is an
interpreter and cannot speed anything up (`jit_native_wasmi.md`). The speedup
lives where wasm is *compiled to native* — the browser's WebAssembly engine —
so that is where the JIT is wired. This is the plan.

## What the boundary already gives us

- The engine runs as one wasm module (`webtos-web`) with its linear memory
  **exported** as `memory`; `web/worker.js` already reads it as
  `exports.memory.buffer`.
- JS instantiates the engine with **empty imports** today, so adding a small
  set of `env.jit_*` imports the engine declares and JS supplies is a clean
  extension, not a rework.
- The VM lives in a `Machine` in a `thread_local` `STATE`; execution is
  `wtw_run(fuel)` driving `InterpVm::run()` (in `x64-engine/src/vm.rs`), which
  loops over blocks calling `interpret_block_unchecked`. There is already a
  hotness tier there (`promote_after`/`entries`/`promoted`) — the natural place
  to add a "compile this block" tier.

## The compile/dispatch protocol

Two imports the engine declares, JS implements:

- `env.jit_compile(bytes_ptr, bytes_len) -> handle`: JS reads the module bytes
  from the engine's memory, does `new WebAssembly.Instance(new WebAssembly.Module(bytes), imports)`,
  and returns a small integer handle into a JS-side table. Synchronous
  compilation is allowed for the module sizes we emit; if a size ever exceeds
  the sync limit the call returns a "not compiled" sentinel and the block stays
  interpreted — tiered-by-construction, exactly like an untranslated op.
- `env.jit_call(handle) -> resume`: JS calls that instance's exported `run` and
  returns the resume index (see faults below).

The engine keeps a cache `block_id -> Option<handle>` (`None` = tried and
bailed). On a hot block with a handle, `run()` calls `jit_call` instead of
`interpret_block_unchecked`; the two must be interchangeable, which the rest of
this note makes true.

## The register file: absolute addressing into the shared memory

A compiled block imports `env.regs` as memory. JS binds that to the **engine's
own exported memory**, so the block reads and writes the very bytes the
interpreter does — no copy. The catch: `cpu.regs` sits at a runtime offset
`regs_base` inside the engine's memory, while `translate_block` currently emits
`var_offset` relative to the register array. So the emitter must add `regs_base`
to every register address (and to the `dst_off` it hands the load import).

`regs_base` is stable for the engine's life, known when JIT is first armed, so
it is baked at translate time: `translate_block(block, regs_base)`. The emitted
addresses become `var_offset + regs_base`. The gate and `jit_bench` pass
`regs_base = 0` (their register memory starts at 0) and are unaffected; a new
gate case runs a block with a non-zero base against a larger memory to prove the
offset arithmetic. This is the one change that touches the emitter's address
sites, so it lands first, on its own, fully gated.

(The alternative — a dedicated 2-page register memory kept in sync with
`cpu.regs` by copying only each block's live varnode set — was considered. It
keeps blocks position-independent but adds a dataflow pass and per-call copies.
Absolute addressing into the shared memory is simpler and copy-free, so it wins;
the live-set idea is the fallback if a shared-memory hazard appears.)

## Guest memory, faults, exceptions: JS shims over engine exports

The block's other imports — `load`, `store`, `fault`, `raise` — are JS
functions that call **engine-exported** helpers (`wtw_jit_load`, …) which run
the real MMU access against `cpu.mem`, set `cpu.exception`, and record the
resume index, exactly as the gate's host closures do but against the live VM.
On a fault the block reports the faulting instruction index; `jit_call` returns
it; the dispatcher does what `interpret_block_unchecked` returning `Some(i)`
does — sets `block_offset` and breaks to the exception path. No new exception
handling, just the same one reached a second way.

## InstructionMarker: the deferred correctness item comes due

Interpreted, each `InstructionMarker` writes PC and decrements fuel, and can
raise `InstructionLimit` mid-block. The JIT emits nothing for it, which was fine
for the straight-line gate blocks. Wired into `run()` it must be made faithful:

- **Fuel** is handled at block granularity — the dispatcher checks
  `fuel.remaining >= block_instruction_count` before dispatching to the compiled
  block and subtracts the count after; a block that would cross the limit is
  interpreted instead, so the limit fires exactly where it should.
- **PC** matters only on a fault or for an instruction that reads the live PC.
  RIP-relative addressing is resolved to constants at lift time, so the common
  case never reads PC. For the fault case, the `raise`/`fault` shims write PC to
  the faulting instruction's address (the emitter passes it alongside the
  index). Blocks whose lifting shows a live PC read bail until this is complete.

## Increment order

1. `regs_base` in `translate_block` + a non-zero-base gate case. (emitter only)
2. Engine-side JIT cache, the `env.jit_*` import declarations, and the
   `wtw_jit_*` MMU-shim exports, with a `jit_selftest` export that compiles one
   fixed block and calls it — proving the round trip and shared-memory access in
   Node before touching `run()`.
3. JS shim in `worker.js` (and `test_node.mjs`): the handle table, `jit_compile`,
   `jit_call`, and the load/store/fault/raise callbacks.
4. Dispatch in `run()` behind a flag, with the fuel check; measure a real guest
   workload against the interpreter.
5. InstructionMarker PC-on-fault; widen the set of blocks that qualify.

Each step is testable on its own (Node drives the wasm exports directly), so the
speedup can be measured at step 4 without the full terminal stack.
