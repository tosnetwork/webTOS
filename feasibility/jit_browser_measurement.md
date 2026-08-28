# Browser JIT measurement: the payoff, and its ceiling

With the JIT wired into the browser (`jit_browser_wiring.md`, increments
3a–3c), `web/bench_jit.mjs` runs a compute loop through the full engine loop
twice — interpreted, and with the JIT enabled — in Node's V8, and times it.

The guest is `add rax,rbx ; add rax,rcx ; dec rdx ; jnz` looped 20M times
(80M guest instructions). Measured on the macOS arm64 dev machine, Node V8:

| | time | throughput | |
|---|---|---|---|
| interpreter | 6083 ms | 13.2 M-insn/s | |
| browser JIT | 2205 ms | 36.3 M-insn/s | 20M dispatches |
| **speedup** | | | **2.76x** |

Real, and correct (identical exit code). The compiled block runs as native
code the browser's WebAssembly engine produced, with none of the interpreter's
per-p-code-op decode-and-dispatch.

**Why not more.** The loop body is a single three-instruction basic block, so
every iteration pays one `jit_call` — a wasm→JS→wasm→JS→wasm round trip — plus
the run loop's own bookkeeping (cache lookup, fuel, block-exit) to run three
native instructions. That per-dispatch overhead is the ceiling here, not the
compiled code. 2.76x is the win from compiling a *small* block, ~20M times.

**The path past it: region/trace compilation.** The large win — the ~490x the
early `feasibility/` measurements showed for native-compiled wasm — needs the
hot loop's *back-edge* compiled inside one wasm function, so 20M iterations are
one `jit_call`, not 20M. That means translating across block boundaries
(following the branch), which the current block-at-a-time translator
deliberately does not do (`PcodeBranch`/control flow bail). It is the clear
next optimization, and it is where the dispatch overhead this measurement
isolates goes to zero.

Also relevant to real workloads: many hot blocks bail today on 16-byte / i128
ops (see the memory note on the wide-op coverage wall), so the fraction of hot
blocks that qualify — not this micro-loop's speedup — is what a real guest's
end-to-end number will turn on. Measure the bail-cause histogram over node /
claude hot blocks before optimizing further.
