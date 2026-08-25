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

## Next step

Route 1 above: advertise SSE2 but not AVX in CPUID, and make the higher
CPUID leaves safe so glibc's `init_cpu_features` completes without
dispatching into the AVX families. Then Node should progress past V8 init,
and Codex / Claude Code become a packaging plus syscall-coverage effort.

## Not started

- Codex and Claude Code images, PTY behavior, Git operations, authenticated
  HTTPS from the CLIs, and the per-agent regression data the roadmap asks
  for — all blocked on Node running first.
