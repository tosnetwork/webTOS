# Workload profile: Node.js (milestone 7 groundwork)

**Status: Node.js starts and runs. A stock `node --version` executes to a
clean exit (`v24.13.0`); with the AVX-512-capable spec, `node -e <script>`
loads, initializes V8's heap and segmented sandbox, and runs ~21M
instructions into V8 startup. Full script execution is blocked on one
remaining item — a pre-existing SSE2-path semantics bug, described at the
end. This file records how far it gets and what is left.**

Milestone 7 targets the Codex and Claude Code CLIs. Both are Node.js
applications, so a stock `node` is the reduction: if `node script.js` runs,
the CLIs become a packaging and syscall-coverage problem rather than a
runtime-bring-up problem.

Run it with the debug runner:

```
GUEST_MOUNT="/lib/x86_64-linux-gnu:/lib/x86_64-linux-gnu,/lib64:/lib64" \
GUEST_EXE=/bin/node \
cargo run --release -p linux-compat --example run_guest -- \
  /path/to/node --version
```

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

## The original blocker (AVX-512 decode) — resolved by the spec upgrade

A differential-decode harness (`cargo run -p x64-engine --example
decode_diff -- FILE`) originally settled the first blocker: the older
vendored (icicle-fork) spec rejected every VEX/EVEX/XOP instruction —
2,343 on glibc (0.59%) and 104,299 on Node (1.02%) — with **zero** ordinary
integer/memory/control-flow gaps. glibc's ifunc resolvers dispatch
string/memory routines to AVX-512 and V8/OpenSSL take AVX-512 paths once the
CPU appears to support them, so those rejections misaligned the fetch stream.

**The spec was upgraded to the NSA master language set** (which lifts the
AVX families) and the icicle fork's helper-compatibility patches were
re-applied on top of it — see `third_party/ghidra-x86/PROVENANCE.md` for the
exact patch list (CPUID, XGETBV, SYSCALL flag packing, FXSAVE/FXRSTOR
macros) plus the companion lifter fix in `third_party/icicle/PROVENANCE.md`
(nested `export`). After the upgrade the decode diff is: glibc **0 gaps**,
Node **0.0049%** (505/10.3M — VEX-AES / VEX-PCLMULQDQ / XOP only, none on
the SSE path). All milestone 1–6 tests stay green, and glibc runs
instruction-for-instruction identically to the fork spec for 3M+
instructions (verified with `exec_diff_dyn`).

## How the patch set was found (bounded, not guesswork)

`exec_diff_dyn` runs the same dynamic glibc binary through the fork spec
(reference) and the patched master spec (candidate) in lockstep and reports
the first architectural-state divergence. Each divergence named exactly one
instruction whose master form the icicle interpreter could not execute; the
fork's construct for it was ported, and the harness was rerun. Four spec
patches plus one lifter patch took glibc from a fault at ~2,900 instructions
all the way to a clean exit with no divergence.

## The remaining blocker: a pre-existing SSE2-path semantics bug

Node's V8 aborts full initialization unless CPUID advertises SSE2
(`Check failed: cpu.has_sse2()`). But advertising SSE2 in the CPUID helper
makes glibc's ld.so fail during symbol resolution and exit 127 very early
(~83,400 instructions), because its ifunc resolver then selects an
SSE2-optimized `memcmp`/`strcmp`/`memcpy` variant that this engine executes
incorrectly. The bug is **pre-existing and spec-independent**: the fork spec
fails identically at the same instruction count with SSE2 advertised, so it
is a semantics error in one of the SSE2 vector instructions those routines
use (`pcmpeqb`, `pmovmskb`, `movdqu`, `pminub`, …), not a decode gap and not
caused by the spec upgrade.

Because the fault surfaces as a *wrong result* (not a trap), locating it
needs a reference the differential harnesses do not yet have — the two
specs agree, so `exec_diff_dyn` cannot see it. The next step is a real-CPU
reference (single-step the routine natively and compare XMM/flag state, or
unit-test the specific SSE2 ops against known vectors). Until then CPUID
advertises only a scalar/x87 baseline (no SSE2), so `node --version` runs to
a clean exit but a full `node -e <script>` stops at the `has_sse2` check.

## Tools

- `x64-engine/examples/decode_diff.rs` — compares decoded *length* against
  iced-x86 over an ELF's `.text`; finds instructions the lifter sizes wrong
  or rejects.
- `x64-engine/examples/exec_diff.rs` — runs a *static* ELF through two specs
  in lockstep and reports the first execution-state divergence.
- `linux-compat/examples/exec_diff_dyn.rs` — the same idea for a
  *dynamically linked* ELF, driving the real loader and syscall layer, so it
  reaches divergences deep in glibc/V8 startup. Used to find the spec patch
  set above.
- `linux-compat/examples/run_guest.rs` — runs a host ELF in the machine with
  `GUEST_MOUNT`/`GUEST_COPY`/`GUEST_EXE`; prints the faulting instruction on
  a non-clean exit.

## Not started

- Codex and Claude Code images, PTY behavior, Git operations, authenticated
  HTTPS from the CLIs, and the per-agent regression data the roadmap asks
  for — all blocked on Node running first.
