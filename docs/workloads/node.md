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
- **But the upgraded (upstream master) spec regresses execution.** The
  upstream Ghidra x86 spec is not the fork icicle's helpers were written
  against: icicle's fork carries several *helper-compatibility* patches that
  upstream does not, and adopting master silently reverts every one of them.
  An execution-differential harness (`exec_diff`, below) and a per-workload
  trace pinned three so far, each a different failure once the earlier one
  is patched:

  1. **Lifter nested export** (`JNZ rel8`, `75 f7`). Master wraps the jump
     target as `jccRel8: rel8 is rel8 { export rel8; }`; the icicle lifter
     dereferenced that nested `export` of an `*[ram]` operand, so `goto`
     landed on pointer-shaped garbage — the "PageFault to a huge address"
     symptom. **Fixed** in `resolve_export` (vendored lifter patch #7); the
     `exec_diff` divergence at that instruction is gone.
  2. **CPUID** (`0f a2`). icicle's helpers write four dwords directly into a
     16-byte varnode; icicle's fork spec rewrote CPUID to `tmp:16 =
     cpuid_*(EAX, ECX); EAX = tmp[0,32]; …`. Master reverted to upstream's
     pointer form `tmpptr = cpuid(EAX); EAX = *tmpptr`, so the helper sees
     `dst.size != 16`, bails, leaves `tmpptr = 0`, and glibc's
     `init_cpu_features` reads null.
  3. **XGETBV** (`0f 01 d0`). Master's form calls an `xinuse()` pcodeop that
     icicle has no helper for; it returns 0, zeroing `XCR0`. icicle's fork
     reads `XCR0` directly.

  Porting patches 2 and 3 onto master lets glibc advance ~30× further
  (icount 2,900 → 91,000) but it then selects `_dl_runtime_resolve_fxsave`
  and executes `fxsave` (`0f ae /0`, no REX.W) — which *both* specs define
  only for `LONGMODE_OFF`, so it traps in 64-bit mode. Under the fork spec
  glibc instead selects the `xsave` resolver (defined for long mode) and
  runs to exit 0, which means yet another feature-detection instruction
  still diverges between the two specs. The list is open-ended.

So Route 2 is not one focused lifter fix; it is re-porting an unbounded set
of icicle's fork patches onto upstream master (and separately, master lacks
the fork's EVEX-decode infrastructure, so the reverse graft — adding just
`avx512.sinc` to the fork spec — fails to compile: `EVEX_NONE` / `vexMode=2`
and the mask/Zmm/broadcast operands live only in master's `ia.sinc`). The
lifter fix above is real and kept, but AVX-512 by spec upgrade is a large,
open-ended effort.

**Route 1 (advertise no AVX in CPUID) is the bounded alternative** and does
not touch the spec at all: keep the working fork spec, and make the CPUID
helper report an SSE2 baseline with no AVX/AVX-512/OSXSAVE bits so glibc
ifunc, V8, and OpenSSL never dispatch into the unlifted vector families.
This is the recommended next step for getting Node to run.

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
