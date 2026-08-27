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

## In a browser: it runs, and it is two hundred times too slow

Measured 2026-08-27 on x86-64 Linux, against the same `webtos_web.wasm` a
browser loads. Every shared object was delivered as a *file* rather than
mounted, because `GUEST_MOUNT` has no browser equivalent — so this answers the
browser question, not just the native one.

`node --version` **works**: `v24.13.0`, exit 0.

| | native | wasm module |
|---|---|---|
| `node --version` (6,512,041 instructions) | ~3 s (2.2 M inst/s) | **159 s (0.04 M inst/s)** |
| BusyBox `md5sum` of 4 MiB (53.4 M instructions) | 17.3 M inst/s | 8.5 M inst/s |

Delivery is not the problem: 122 MB of Node and its seven shared objects
reached the guest in 284 ms, and the whole machine settled at 247 MB — guest
109, lifted code 16, files 122 — inside any tab's budget.

Two things it is **not**:

- **Not lifting.** A second `--version` in the same machine took 158.9 s
  against the first's 160.8 s, and the lifted-code figure did not move off
  16 MB. The work is steady state, not translation.
- **Not the module.** The same wasm build on the same host hashes 4 MiB at
  8.5 M inst/s, about half native. Node gets 1/200th of that.

### Narrowed to one line

Four probes, each differing in one property, separate the cause from
everything it might have been. Times are the same guest binary, native
against the wasm module:

| probe | native | wasm |
|---|---|---|
| 3 M-iteration compute loop | 2.29 s | 2.43 s |
| 200,000 `getpid` | 0.53 s | 0.50 s |
| 2,000 `mmap`, never touched | 0.32 s | **62 s** |
| 1 `mmap`, 2,000 first-touch faults | — | 0.13 s |

So it is the `mmap` call itself, not page faults, not syscall overhead, and
not interpretation. The cost is flat at about 30 ms per call and independent
of the mapping's size — 4 KiB, 64 KiB and 1 MiB all take the same — and it is
linear in the number of calls, not quadratic. It all happens inside a single
`wtw_run`, with the wasm linear memory never growing, no code-cache flush, and
the same number of lifted blocks as the fast probe.

Compiling out one line takes it from 62 s to **0.12 s**: the
`self.tlb.remove_range(start, len)` in `Mmu::map_memory_len`
(`third_party/icicle/icicle-mem/src/mmu.rs`). Removing `update_perm` instead
changes nothing, so the TLB invalidation on every mapping change is the whole
of it.

**What is not yet pinned** is why that call is expensive. `TranslationCache`
holds 1,024 entries and `remove_range` clears the whole thing when a range
covers more pages than that, so the per-page loop should be bounded at 1,024
iterations. Two instrumented runs disagreed about how many iterations actually
occur — one counted billions across 4,014 calls, another found no call
entering the loop with more than 210 pages — and those cannot both be right.
The counters were reused between runs with different meanings, which is the
likeliest explanation, so neither number should be relied on. The next step is
to measure that call cleanly rather than to reason about it.

Native runs the same code and does not show this, so whatever it is, it is a
constant factor that wasm makes ~200× worse rather than an algorithmic
difference.

Node is already about eight times slower than a compute loop natively — its
startup is syscall- and page-heavy rather than a tight loop — and this is what
multiplies that by another twenty-five.

What this settles: the browser milestone for both agent CLIs is not blocked on
bring-up, packaging, delivery, or memory. It is blocked on this number.

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

AES-NI **is** advertised in CPUID (the legacy, non-VEX encodings, which now
have helpers). The guest TLS client takes its hardware-AES path — which also
uses `pshufb` — and works. What stays unadvertised is AVX/AVX-512, so nothing
selects the VEX-AES/PCLMULQDQ/XOP encodings that are still not lifted.

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
