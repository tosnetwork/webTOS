# Workload profile: Node.js (milestone 7 groundwork)

**Status: Node.js runs. A stock `node -e "console.log(...)"` executes the
script and exits cleanly (~90M instructions); `node --version` prints
`v24.13.0`. Scripts exercising arrays, string methods, `JSON`, and `Math`
produce correct output. This was reached on the AVX-512-capable spec plus a
set of p-code-op helpers and a CPUID SSE2 baseline (below). This file records
how it works and what remains.**

Milestone 7 targets the Codex and Claude Code CLIs, and this file was written
believing both were Node.js applications, so that a stock `node` would be the
reduction. **Neither is**, measured against the binaries themselves:

| | runtime | evidence |
|---|---|---|
| Codex | **Rust** | 3,941 `cargo` strings, 296 `tokio`, 93 `rustc`; no `v8::internal`, no `JavaScriptCore`. Its nine "Node.js" mentions are text inside its own system prompt. |
| Claude Code | **Bun 1.4.1** | 541 `JavaScriptCore`/`WebKit` symbols, no `v8::internal`; a `.bun` section holding 156 MB of application JavaScript, against 57 MB of runtime code. |

Bringing Node up was still worth it. Nothing it required was V8-specific —
the AVX-512 lifting, the SIMD helpers, and the CPUID baseline are general
x86-64 coverage, and Bun needs them too — and it proved the dynamically
linked glibc path that Claude Code also takes. What was wrong was the reason
given, not the work.

Run it with the debug runner:

```
GUEST_MOUNT="/lib/x86_64-linux-gnu:/lib/x86_64-linux-gnu,/lib64:/lib64" \
GUEST_EXE=/bin/node \
cargo run --release -p linux-compat --example run_guest -- \
  /path/to/node --version
```

## In a browser: it runs

Measured 2026-08-27 on x86-64 Linux, against the same `webtos_web.wasm` a
browser loads. Every shared object was delivered as a *file* rather than
mounted, because `GUEST_MOUNT` has no browser equivalent — so this answers the
browser question, not just the native one.

`node --version` prints `v24.13.0` and exits 0 in **0.9 s** cold, 0.6 s warm.
122 MB of Node and its seven shared objects reach the guest in under half a
second, and the machine settles at 247 MB — guest 109, lifted code 16, files
122 — inside any tab's budget.

It took 159 s before the bug below.

### The bug: a 32-bit mask on a 64-bit address

The first measurement had `node --version` at 159 s against 3 s natively, and
finding out why took ruling out everything it wasn't. Four probes differing in
one property each:

| probe | native | wasm before | wasm after |
|---|---|---|---|
| 3 M-iteration compute loop | 2.29 s | 2.43 s | 2.4 s |
| 200,000 `getpid` | 0.53 s | 0.50 s | 0.5 s |
| 2,000 `mmap`, never touched | 0.32 s | 62 s | **0.12 s** |
| 1 `mmap`, 2,000 first-touch faults | — | 0.13 s | 0.13 s |

So it was the `mmap` call — not page faults, not syscall overhead, not
interpretation, not lifting, and not the module. Compiling out one line took it
from 62 s to 0.12 s: `self.tlb.remove_range(start, len)` in
`Mmu::map_memory_len`.

`TranslationCache::remove_range` page-aligned its start like this:

```rust
for addr in (start & !(PAGE_SIZE - 1) as u64..=end).step_by(PAGE_SIZE)
```

`PAGE_SIZE` is a `usize`. On a 64-bit host `!(PAGE_SIZE - 1)` is
`0xFFFF_FFFF_FFFF_F000` and the mask is right. On wasm32 it is
`0xFFFF_F000`, and widening it afterwards leaves the top half zero — so the
mask does not align the address, it **truncates** it. Invalidating one page at
`0x10_0000_0000` started the walk at 0 and stepped through 64 GiB of address
space: 16,777,217 iterations for a single 4 KiB page, measured.

That is why the cost was proportional to the *address* rather than the size,
why every mapping cost the same 30 ms whatever its length, and why only the
browser saw it. The mask is now built at the width of the address.

This is the same class as the `u64 as usize` narrowing found in the ELF
loader: 64-bit address arithmetic done at `usize` width, harmless on the host
where the tests run and wrong on the target that ships.

## The agent CLIs themselves

Measured 2026-08-27 against the same `webtos_web.wasm` a browser loads.

**Codex runs.** `codex-cli 0.150.1`, exit 0, in **0.8 s** — a 256 MB
static-pie binary delivered in one file, 531 MB resident. Nothing about it
needed changing.

**Claude Code does not, yet — and it is not a Node application.** Version
2.1.247 is a 239 MB **Bun** binary (Bun 1.4.1), dynamically linked. That
matters for the milestone: "both are Node applications, so a stock Node is
the reduction" holds for Codex and no longer holds here.

Three defects were in the way, all fixed and all general rather than
Bun-specific:

1. **Segments were mapped at `p_align`, not at page granularity.** `p_align`
   is the congruence a loader preserves between a segment's file offset and
   its virtual address, not how much address space it claims. Rounding the
   base down by it makes a segment reach below itself and take the pages of
   whatever is mapped there. Claude Code has an executable segment ending
   part-way through a page followed by a 16 KiB-aligned read-write segment
   whose rounded-down base covered the code's last two pages — which then
   stopped being executable, and the first call through the PLT faulted.
   Diagnosed by reporting the faulting page's permissions rather than only
   the exception: `mapped=true readable=true executable=false` inside an
   `R E` segment says where to look.
2. **`CPUID` faulted on extended leaves.** Leaf `0x8000_0000` reported no
   extended functions, which no x86-64 part does, and anything else raised an
   exception — but `CPUID` does not fault on real hardware. It now reports
   `0x8000_0001` as the highest extended leaf, advertises long mode and
   `syscall` there because those are implemented, and answers everything else
   with zeros.
3. **`sysinfo`, `getrusage`, and `close_range` were missing.** A runtime asks
   `sysinfo` before deciding how much memory it may use; the answer now comes
   from the guest's own budget, which is the only figure that means anything
   in a tab.

Together those took Claude Code from 195,792 instructions to 2,365,855, into
Bun's own startup — where it aborted. Bun's crash banner, once it could be
seen, named the machine correctly (`Bun v1.4.1 Linux x64`, `Features: jsc
no_avx2 no_avx standalone_executable claude_code`) and offered a hint about
AVX that is not the cause: the successful run below also has no AVX.

The cause was **`/proc/self/maps`**. Seeding it alone gets Bun through
startup; seeding every other file it probes and omitting only that one still
aborts. Both directions were checked.

**Claude Code runs**: `2.1.247 (Claude Code)`, exit 0, 184 M instructions in
16.6 s at 11.1 M inst/s, with the contents generated from the machine's own
mapping table rather than seeded by hand.

`/proc/self/statm`, `/proc/self/cmdline`, and `/proc/meminfo` are answered the
same way, from the same state. Nothing else in `/proc` exists, and that is
deliberate: a runtime acts on what it reads, so an absent file is a better
answer than an invented one. Bun also probes `/proc/self/cgroup`,
`/proc/stat`, `/proc/sys/vm/*`, and `/sys/devices/system/cpu/online`, and
carries on without them.

## What a session still cannot do

`--version` is not the product. Taking Codex further, on 2026-08-27:

**Credentials work.** Codex reports `Logged in using ChatGPT` inside the wasm
module in 2.2 s, with the real `auth.json` arriving as a scoped secret — the
guest file holds only `${CODEX_AUTH}`, and the snapshot afterwards holds the
placeholder, checked rather than assumed.

**A working session does not complete.** `codex exec` with a small task —
read a file, change a value, run a command, report — does not finish, and not
only in the browser:

- In the wasm module it runs steadily at ~13 M inst/s past 1.95 billion
  instructions, footprint flat at 567 MB, producing no output and issuing no
  network commands at all.
- Natively with the same arguments, memory raised to 3 GiB and a real broker
  attached, it produces no output in 400 s either.
- Natively with a bare prompt and no mounts it *does* progress: it spawns
  threads and `execve`s subprocesses, prints `ERROR: Reconnecting... waiting
  for network` as expected with no broker, and ends at 1.09 billion
  instructions with `OutOfMemory` under the 1 GiB default.

### What the syscall trail said

`recvmsg` failed 263,885 times with `EAGAIN` on one descriptor. The sequence
around it:

```
socket(AF_INET, SOCK_DGRAM|NONBLOCK) = 14
bind(14, …)                          = 0
sendto(14, …, 29)                    = 29      DNS query, sent
sendto(14, …, 29)                    = 29
recvmsg(14, …)                       = -EAGAIN  × 263,885
```

The query goes out and no answer comes back, so the agent spins. The cause is
that the guest had **no `/etc/resolv.conf`** — nothing told the resolver whom
to ask. The host's own copy does not help either: it names `127.0.0.53`, the
systemd stub, which does not exist inside the guest. A reachable nameserver
has to be supplied.

### A real session, end to end

With a resolver in place, Codex completed a session against the live API:

```
provider: openai   session id: 01a044ad-5bb2-7413-909c-1fd0e7547956
user   say hi
codex  Hi! 👋
tokens used 4,199        exit 0        2,745,666,480 instructions
```

That is a real model call from inside webTOS.

### A session that does work, end to end

On 2026-08-28, given the task *"read config.txt, change greeting from hello
to goodbye, then run cat config.txt and report exactly what it prints"*,
Codex did all four inside webTOS and exited 0:

```
diff --git a/config.txt b/config.txt
-greeting = hello
+greeting = goodbye

codex
greeting = goodbye

tokens used 24,573      exit 0      3,846,485,466 instructions
```

It read the file, called the live model, applied its own patch, ran `cat`
in a subprocess on a pty it allocated itself, and reported what that
subprocess printed. Three things had been in the way.

1. **The command runner is found by absolute path.** Codex spawns
   `/bin/codex-code-mode-host`, next to its own binary, not through `PATH` —
   which was the 256 `execve` failures in the trail. Delivered there, it
   spawns, and Codex issues `/bin/sh -lc 'cat config.txt'`.
2. **The agent sandboxes itself with bubblewrap**, which needs Linux
   namespaces this machine does not implement. Worth stating as an
   architectural point rather than a gap to close: webTOS *is* the sandbox,
   and a second one inside it is redundant. Codex's
   `--dangerously-bypass-approvals-and-sandbox` is the right setting here, and
   means something different inside a guest than on a host.
3. **Two engine defects, both of the same shape** — a case nobody had
   implemented, reported as an error the caller could not recover from:

   - The lifter kept a virtual-address-keyed map of disassembly text for a
     human to read, while lifted code beside it was keyed by address space
     too. Every `execve` puts a second image where the first was, so the two
     disagreed without either being wrong — and the mismatch aborted the lift
     and flushed every block. Sessions never finished. A diagnostic must not
     decide whether execution continues.
   - `tcsetattr(TCSAFLUSH)` arrives as `TCSETSF`, which was not in the ioctl
     table and so fell through to `ENOTTY`. Every program that changes
     terminal mode was told it had no terminal — including the one that runs
     a command on a pty of its own. `openpty` itself succeeded; the failure
     was one call later, which is why the symptom read as "failed to openpty".

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
