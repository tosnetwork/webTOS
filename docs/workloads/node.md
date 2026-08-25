# Workload profile: Node.js (milestone 7 groundwork)

**Status: not yet passing. Node.js (and therefore Codex and Claude Code,
which run on it) starts, initializes V8's heap, and progresses into glibc's
CPU-feature detection before hitting an instruction-decode gap. This file
records how far it gets and what is left.**

Milestone 7 targets the Codex and Claude Code CLIs. Both are Node.js
applications, so a stock `node` is the reduction: if `node script.js` runs,
the CLIs become a packaging and syscall-coverage problem rather than a
runtime-bring-up problem.

## How far Node gets today

A dynamically linked host `node` (glibc) mounted into the guest, running a
trivial script, currently:

1. loads through the glibc dynamic loader (milestone 3 path),
2. reserves V8's 256 MiB sandbox and initializes the segmented heap,
3. runs into glibc `init_cpu_features`, which walks CPUID leaves 2..=max
   parsing cache/topology descriptors.

## Fixed on the way (kept)

- **mmap now finds real holes.** The allocator was a linear bump pointer, so
  once the guest reserved a large region (V8's 256 MiB `PROT_NONE` sandbox),
  the next allocation collided with it and returned `ENOMEM`. `sys_mmap`
  now uses the memory subsystem's `find_free_memory` from an allocation
  hint. Gated by `large_anonymous_reservation_then_allocations_do_not_collide`.

## The remaining blocker, now precisely identified: AVX-512

A differential-decode harness (`cargo run -p x64-engine --example
decode_diff -- FILE`) settled what the blocker is. It walks a binary's
`.text`, decoding every instruction with both iced-x86 (the reference) and
this engine's SLEIGH lifter, and compares the decoded length — a one-byte
disagreement is what misaligns every later fetch.

Results are unambiguous:

| binary | instructions | length mismatches | rejected (all AVX/VEX) |
|--------|-------------:|------------------:|-----------------------:|
| glibc  |      395,499 |            **0**  |     2,343 (0.59%)      |
| node   |   10,263,936 |            **0**  |   104,299 (1.02%)      |

There are **zero** length mismatches and **zero** rejections of ordinary
integer, memory, or control-flow instructions. Every rejected instruction
carries a VEX/EVEX/XOP prefix (0xC4/0xC5, 0x62, 0x8F) — the AVX, AVX2,
AVX-512, and mask-register families (`vpxorq`, `vaesenc`, `kmovq`,
`vpternlogq`, …). The vendored SLEIGH specification does not lift them.

Node crashes because glibc's ifunc resolvers dispatch string/memory
routines (memcpy, memcmp) to AVX-512 implementations, and V8/OpenSSL take
AVX-512 code paths, once the CPU appears to support them. Two routes close
this:

1. **Advertise no AVX in CPUID** so userspace never selects those paths.
   This is the low-cost route (SSE2 baseline is enough for correctness) but
   requires fixing the CPUID max-leaf handling that currently regresses
   glibc/Go when raised — the regression is itself a symptom of code
   dispatched into the unlifted vector families, so suppressing AVX in
   CPUID and keeping the max-leaf high should be self-consistent.
2. **Lift the AVX families** in the SLEIGH spec (they exist in Ghidra's
   `avx*.sinc`; the icicle fork may need them enabled/completed). This is
   the thorough route and is also needed for performance-sensitive
   workloads, but it is a large undertaking.

The decoder itself is sound: `decode_diff` and its regression test
(`x64-engine/tests/decode_diff.rs`) assert zero non-AVX gaps.

## The spec-upgrade route and its blocker

Route 2 — upgrade the vendored Ghidra x86 spec to a version that lifts the
AVX families — was carried far enough to know exactly what stops it:

- A parser fix (committed) lets the icicle SLEIGH compiler ingest a recent
  Ghidra x86 language set (it previously failed on `cmpccxadd.sinc`, which
  ends with `@endif` and no trailing newline).
- With the upgraded spec, the decode diff is essentially perfect: glibc has
  **zero** gaps and Node drops from ~1% to ~0.005% (a handful of VEX
  crypto/XOP variants remain).
- **But the upgraded spec regresses execution of milestone 1–6 workloads.**
  An execution-differential harness (`exec_diff`, below) runs the same
  static binary through the old and new specs in lockstep and reports the
  first architectural-state divergence. It pins the regression precisely:
  a short conditional jump (`75 f7`, `JNZ rel8`) computes a garbage target
  under the new spec. The new spec wraps the jump target through an extra
  `jccRel8: rel8 is rel8 { export rel8; }` sub-table; the icicle lifter
  handles that nested `export` of an already-dereferenced `*[ram]` operand
  differently from Ghidra's intent, so `goto` lands on a pointer-shaped
  garbage value — which is exactly the "PageFault to a huge address"
  symptom the milestone-1–6 tests showed.

So the spec upgrade is gated on the icicle lifter's handling of nested
`export` sub-tables, not on the AVX definitions themselves. That is a
focused lifter fix, verifiable end to end with `exec_diff` (old spec as the
reference), and is the concrete next step for AVX-512 support.

## Tools

- `x64-engine/examples/decode_diff.rs` — compares decoded *length* against
  iced-x86 over an ELF's `.text`; finds instructions the lifter sizes wrong
  or rejects.
- `x64-engine/examples/exec_diff.rs` — runs a static ELF through two specs
  in lockstep and reports the first execution-state divergence; finds
  instructions whose *semantics* differ between specs.

## Not started

- Codex and Claude Code images, PTY behavior, Git operations, authenticated
  HTTPS from the CLIs, and the per-agent regression data the roadmap asks
  for — all blocked on Node running first.
