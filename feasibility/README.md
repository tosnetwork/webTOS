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

## How the field does it

We are not the first to run x86 in a browser. What the leading systems do
confirms the approach above and adds three constraints the prototype did not
hit.

### WebVM / CheerpX (proprietary)

WebVM's engine is CheerpX (Leaning Technologies). Its core is exactly
"translate to WebAssembly": a tiered engine that interprets cold code and
JIT-compiles hot code to wasm modules generated at runtime — the "interpret
cold, JIT hot" shape we already have the first half of (tiered lifting).
Proprietary, so no code to reuse, but the architecture is described publicly.

### v86 (open source)

copy.sh's v86 is an open x86 emulator with a JIT that emits wasm modules for
hot loops — a readable reference for the runtime-wasm-generation mechanism
CheerpX does not expose.

### Constraints their experience adds

- **Compile regions, not single blocks.** Each generated wasm module costs a
  fixed instantiate (0.29 ms measured). One-module-per-block does not amortize
  it; CheerpX and v86 compile a larger region — a function or a hot loop nest —
  into one module.
- **Synchronous main-thread compilation is size-limited.** `new
  WebAssembly.Module` (sync) is capped on the browser main thread to avoid
  jank. The 100-byte prototype cleared it; a real region will not. Real JITs
  use `WebAssembly.compile` (async, off the main thread or in a worker), keep
  interpreting while it compiles, and swap the compiled region in when ready.
- **Self-modifying code invalidates compiled regions** — the same problem as
  our `SelfModifyingCode` flush, which we already handle for the lift cache.

### Where we differ, and where it helps

CheerpX and v86 translate x86 directly to wasm. We already lift to p-code — a
clean typed IR (the 72-op enum), closer to wasm's semantics than raw x86. The
decode, prefix, and addressing complexity SLEIGH already digested is
complexity a p-code→wasm translator does not re-solve, so our JIT may be
simpler than theirs: it walks regular p-code, not x86.

### The refined architecture

The prototype's direction — interpret cold, JIT hot blocks to wasm, share the
guest memory, verify against the interpreter with the trace-suite gate —
matches the field. The engineering to add, learned from theirs:

1. Compile a hot *region*, not a single block, to amortize instantiation.
2. Compile asynchronously; keep interpreting; swap in when ready.
3. Translate from p-code, not x86 — our advantage over CheerpX and v86.

## What is on GitHub — reuse survey

Searched for anyone doing what we need, and for pieces we can reuse.

| Project | Approach | To us |
|---|---|---|
| **icicle-emu** (our upstream) | p-code → native via **Cranelift** JIT | Confirms the native path is unusable in a browser; the Cranelift backend was not vendored, by design |
| **ktock/qemu-wasm** | **TCG IR → wasm at runtime**, one TB per module, browser `WebAssembly.Module/Instance`, tiered (interpret cold, compile TBs seen ~1000×) | A *working* precedent for exactly our problem — but **GPL**. Learn the architecture, do not copy the code (the architecture is public and matches CheerpX anyway) |
| **CheerpX / WebVM** | tiered interpreter + JIT-to-wasm | Proprietary; same architecture, no code |
| **v86** | x86 → wasm JIT for hot loops | Open reference for the mechanism |
| **ghidra-wasm-plugin** | **wasm → p-code** (loads wasm into Ghidra) | Opposite direction; not useful |
| **bytecodealliance `wasm-encoder`** | Rust library that emits wasm bytes programmatically | **The reusable codegen base.** Apache-2.0 WITH LLVM-exception — on our license allowlist. Our engine (itself wasm) uses it to emit a hot region's wasm bytes; the JS host instantiates and exposes it back through a table |

### Findings

- **No one has done p-code → wasm.** That direction is novel — the existing
  Ghidra/wasm work goes the other way. So the translator is ours to write.
- **The approach is validated by every browser-x86 system that exists.**
  qemu-wasm (TCG→wasm), CheerpX (proprietary), and v86 (x86→wasm) are all the
  same shape my prototype measured: tiered, runtime wasm generation, browser
  instantiate, memory shared. qemu-wasm is the closest and it works — but it
  is GPL, so it is a reference, not a dependency.
- **We reuse one permissively-licensed piece:** `wasm-encoder` for emitting
  the bytes. Everything above it — deciding which region is hot, walking its
  p-code, mapping p-code ops to wasm — is ours, and it is where our p-code
  input makes us simpler than the x86/TCG translators.
- **License discipline:** qemu-wasm and QEMU are GPL; nothing from them may be
  copied into this MIT tree. The architecture we would follow is the one
  CheerpX and my own measurements already establish independently.

## The reusable codegen base, verified (`encoder_probe/`)

`wasm-encoder` is the one piece we reuse, and "can we use it" was answered by
testing, not asserting.

- **License:** Apache-2.0 WITH LLVM-exception — already on the project's
  allowlist (`LICENSES.tsv`), compatible with MIT. No relicensing.
- **Compiles to wasm32:** yes. A probe crate depending on it built for
  `wasm32-unknown-unknown` (174 KB, `opt-level="s"`) — the engine's own target.
- **Emits runnable wasm at runtime, from inside a wasm module:** yes. The probe
  built an `add` module *inside* the wasm sandbox (41 bytes), the JS host
  instantiated it and called `add(40,2)` → 42. That is the whole JIT path in
  miniature: engine emits bytes → host instantiates → call returns the right
  answer.

So the split is clean: `wasm-encoder` (permissive) emits the bytes; the
p-code→wasm mapping above it is ours; the browser instantiates. Nothing GPL,
no relicensing, and our p-code input keeps the mapping simpler than the
x86/TCG translators the field built.
