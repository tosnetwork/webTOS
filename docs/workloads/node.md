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

## The remaining blocker: a SLEIGH instruction-decode gap

With the CPUID max-leaf raised so glibc probes leaf 2+, the guest faults
with an illegal instruction whose *disassembly does not match the actual
bytes* — the lifter had mis-decoded the length of an earlier instruction,
so a later fetch landed mid-instruction. This is an engine-level decode
accuracy problem, not a syscall or CPUID gap. CPUID leaf handling was
explored (SSE2 in EDX, higher max-leaf, graceful unknown leaves) but every
variant that lets glibc walk the higher leaves trips the same decode gap
and regresses glibc/Go, so those changes were reverted; only the mmap fix
remains.

Closing this needs a differential-decode harness: run a corpus of real
instruction bytes through the lifter and compare its decode length and
semantics against a reference (the native CPU via ptrace, or a second
decoder such as iced-x86). That is the next concrete step for milestone 7,
and it also de-risks the long tail of instructions Codex/Claude Code will
exercise.

## Not started

- Codex and Claude Code images, PTY behavior, Git operations, authenticated
  HTTPS from the CLIs, and the per-agent regression data the roadmap asks
  for — all blocked on Node running first.
