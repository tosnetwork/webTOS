# JIT hot-block translation — feasibility

Exploratory, not part of the build or the gates. Answers one question before
committing to a hot-block WebAssembly translator: in a browser wasm sandbox,
is runtime-generated wasm fast enough, called often enough, to beat the
p-code interpreter on a hot block?

## Upstream research (done first, per the ask)

The vendored engine is `icicle`. Upstream icicle HAS a JIT — `JitContext`
(raw pointers, `#[repr(C)]`, direct TLB-pointer access), an `enable_jit`
config defaulting true, and a `JitError` exception code are all in the
vendored `icicle-cpu`. But:

- It is a **native** JIT: it generates host machine code and calls back
  through those raw pointers. A browser wasm sandbox cannot execute
  runtime-generated native code, so it is architecturally unusable for us.
- The JIT backend crate (`icicle-jit`) was **not vendored** — we took only the
  interpreter path (`icicle-cpu` p-code interpreter + `icicle-mem`). Our
  `x64-engine` is interpreter-only by construction (`vm.rs`: "Interpreter-only
  VM loop"); `JitContext` sits unused in the `Cpu` struct.

So there is nothing to reuse. Browser hot-block acceleration means a different
mechanism: translate a hot block's p-code to **WebAssembly** at runtime,
instantiate it as a new module sharing the guest's linear memory, and dispatch
to it on subsequent executions. This experiment measures whether that
mechanism pays.

## Measured

### The ceiling — how much is on the table (`measure.mjs`)

md5 compiled to wasm by rustc, run in the same wasm engine, versus the p-code
interpreter's measured rate on the same md5sum workload:

| | rate | note |
|---|---|---|
| md5 interpreted (p-code) | 0.86 MiB/s | `bench.rs`: 4 MiB in 4.66 s |
| md5 compiled to wasm | 420 MiB/s | 84 MiB in 0.20 s, guard non-zero |
| **ceiling ratio** | **~490x** | upper bound for this workload |

The 490x is a ceiling, not a promise: a per-block JIT compiles blocks (not the
whole program), pays a per-block dispatch, cannot optimize across blocks the
way rustc does, and the guest's loop control and I/O stay interpreted. A real
JIT captures a fraction. But the fraction is against 490x, so even a tenth of
it turns a 4.2 s hash into 0.4 s.

### The mechanism — can we generate wasm at runtime (`runtime_gen.mjs`)

The risk the ceiling measurement did not cover: the ceiling used AOT-compiled
wasm, but a JIT generates wasm at *runtime*. This hand-encodes a 100-byte wasm
module at runtime — a rotate-add reduction over shared memory, the shape of a
hot block — instantiates it sharing the memory, and compares it to a JS loop
that dispatches per operation through an op array, the shape of the p-code
interpreter. Both are asserted to compute the identical result before the
ratio is trusted.

| | rate |
|---|---|
| per-op-dispatch loop (interpreter shape) | 365 MiB/s |
| runtime-generated wasm (JIT shape) | 6571 MiB/s |
| **dispatch-elimination win** | **~18x** |

Generation + instantiation cost 0.29 ms for the block — paid once per hot
block, amortized over its billions of executions.

## Conclusion

- Upstream's JIT is native and unusable in a browser; a p-code→WebAssembly
  translator is required, and is a new subsystem, not a port.
- The win is real and large for compute-bound work: the interpreter leaves
  ~490x on the table, and eliminating per-op dispatch alone — the core of what
  a JIT does — is worth ~18x in a runtime-generated-wasm proof.
- The browser mechanism works: wasm can be generated and instantiated at
  runtime, sharing the guest's linear memory, in well under a millisecond,
  and the correctness of the generated code is checkable against the
  interpreter (the same register-for-register standard the trace suite uses).
- Not worth it for agent workloads (lifting/syscall-bound, no execution peak);
  clearly worth it for a runtime that runs compute-heavy native programs.

The next step is a scoped p-code→wasm translator for the hot-block subset the
profiler already identifies, gated the only honest way: a hot block run
through the JIT must produce the interpreter's result bit for bit — which is
exactly the "optimized and interpreter modes pass the same trace suite" gate.
