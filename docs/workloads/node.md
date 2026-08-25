# Workload profile: Node.js (milestone 7 groundwork)

**Status: Node.js runs. A stock `node -e "console.log(...)"` executes the
script and exits cleanly (~90M instructions); `node --version` prints
`v24.13.0`. Scripts exercising arrays, string methods, `JSON`, and `Math`
produce correct output. This was reached on the AVX-512-capable spec plus a
set of p-code-op helpers and a CPUID SSE2 baseline (below). This file records
how it works and what remains.**

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

## What brought Node up (after the spec upgrade)

Three things, each found by running Node and fixing the next fault:

1. **CPUID SSE2 baseline.** V8 aborts (`Check failed: cpu.has_sse2()`) unless
   it can read the SSE2 feature bit. Two changes in the CPUID helper: raise
   max-basic-leaf from 0 to 1 (so software reads leaf 1 at all), and set the
   SSE2 baseline in leaf 1 EDX. AVX is still not advertised, so V8/glibc stay
   on SSE paths. Max-leaf stays at 1 so the unimplemented cache/topology
   leaves are never queried. (Advertising SSE2 also makes glibc's ifunc
   resolver select SSE2 `memcmp`/`strcmp` — those are correct here; an earlier
   report of a wrong-result bug there was a harness artifact, since ruled out
   by the conformance probe below.)

2. **AES-NI helpers.** Node/V8 and OpenSSL issue `aeskeygenassist`/`aesenc`/…
   unconditionally (not gated on the CPUID AES bit). The spec leaves them as
   opaque pcodeops, so they trapped. Software implementations were added and
   verified against the native AES-NI intrinsics.

3. **`pshufb`, `psadbw`, `roundsd`/`roundss` helpers.** Surfaced the same way
   by the guest TLS client (`pshufb`) and by a Rust guest's float rounding
   (`roundsd`). `roundsd`/`roundss` round to nearest-ties-even because
   icicle's two-operand p-code drops the imm8 mode (see
   `third_party/icicle/PROVENANCE.md` patch 8).

AES-NI is deliberately **not** advertised in CPUID: the helpers exist for the
code that issues AES unconditionally, but leaving the bit clear keeps other
userspace (a guest TLS client) on its software-AES path rather than the
VEX-AES/PCLMULQDQ encodings that are still not lifted.

All the added SIMD helpers are covered by `x64-engine/examples/sse_probe.rs`,
which runs each instruction in the engine and compares it to the native
intrinsic over many random inputs.

## Remaining

- **AVX/AVX-512 execution.** The encodings decode (zero gaps on glibc) but
  their p-code semantics are unvalidated, so CPUID keeps userspace on SSE.
- **VEX-AES / PCLMULQDQ / XOP** are still unlifted (the ~0.0049% Node decode
  residual); reached only if AES-NI is advertised, which it is not.
- Codex and Claude Code images, PTY behavior, Git, and authenticated HTTPS
  from the CLIs — the next milestone-7 work now that Node runs.

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
- `x64-engine/examples/sse_probe.rs` — runs one SSE/AES-NI instruction in the
  engine and compares against the native intrinsic over random inputs;
  conformance-checks the added SIMD helpers.
