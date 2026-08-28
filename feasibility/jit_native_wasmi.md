# Native measurement: wasmi is not the speedup backend

`examples/jit_bench.rs` runs a representative hot block many times two ways —
through `interpret_block_unchecked`, and as the wasm `translate_block` emits,
executed by wasmi — over resident register state (no per-iteration copy), and
checks the two final register spaces agree before believing the time. It runs a
one-step block (call overhead dominates) and a 64x-unrolled block (call
overhead amortised), for a pure-register mixing step and a memory-scanning step.

Measured on the macOS arm64 dev machine, 20M steps each:

| block | interp ns/step | wasmi ns/step | ratio |
|---|---|---|---|
| register splitmix, x1 | 22.9 | 50.6 | 0.45x |
| memory FNV scan, x1 | 37.8 | 104.7 | 0.36x |
| register splitmix, x64 | 20.8 | 30.5 | 0.68x |
| memory FNV scan, x64 | 36.2 | 79.0 | 0.46x |

Every run's checksum matched — the emitted blocks execute correctly end to end,
including the softmmu load import over the real MMU. But **wasmi is 1.5–2x
slower than the p-code interpreter**, and unrolling only narrows the gap (it
removes per-call setup, not per-op cost). The memory block is worse because each
load crosses the wasmi -> Rust import boundary.

This is the expected result, and it is worth stating plainly: **wasmi is itself
a wasm interpreter.** Swapping the p-code interpreter (already a tight dispatch
loop) for wasmi interpreting our wasm trades one interpreter for another and
adds a boundary — it cannot deliver a speedup. The ~490x in `feasibility/`
(README) came from wasm *compiled to native* by V8; the win is the compilation,
which wasmi does not do.

So the native "does the JIT run and is it correct" question is answered — yes —
but the speedup requires a **compiling** wasm backend:

- **The browser** (production target) JIT-compiles wasm to native. This is where
  the JIT actually pays off, and where it should be wired next: the engine emits
  module bytes, JS instantiates them, and the block dispatches through an
  imported callable.
- **A native compiling runtime** (e.g. wasmtime/Cranelift, Apache-2.0) would
  confirm the same win natively and give a fast native path; it is a heavier
  dependency than the wasmi we already vendor for the gate.

wasmi keeps its role as the correctness oracle for the gate. It is not the
execution backend.
