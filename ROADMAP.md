# webTOS Roadmap

## Mission

webTOS is a runtime that executes unmodified Linux x86-64 binaries inside a
browser tab. Its primary product goal is:

> Run unmodified Linux x86-64 AI agent software locally in the browser, with
> webTOS-owned isolation, scheduling, storage, networking policy, resource
> accounting, and execution records.

The first complete target is not a general PC emulator. It is a focused Linux
x86-64 userspace execution environment capable of progressing through these
workload gates:

```text
static hello
    -> static BusyBox
    -> dynamic Linux ELF
    -> threads and event-driven networking
    -> OpenFox
    -> Codex and Claude Code
```

The final coding-agent milestone must support real interactive sessions, child
processes, repository access, persistent configuration, authenticated HTTPS,
terminal behavior, and recovery after a browser reload.

## Status

**Updated 2026-08-29.** Legend: ✅ complete (gated by tests), 🔶 partial,
⬜ not started.

| Milestone | State | Completion | Evidence |
|-----------|-------|------------|----------|
| M0 Lock the baseline | ✅ | ~100% | reference traces reproduce natively and in all three browser engines; skips are visible and forbidden by `WEBTOS_REQUIRE_FIXTURES=1`; executable fixtures and traces are pinned by `test_data/FIXTURES.sha256`; and `docs/performance/` publishes a versioned native/Chromium/Firefox/WebKit dashboard whose CI verifier rejects runtime, fingerprint, schema, or rendered-report drift |
| M1 Static `hello` | ✅ | ~98% | native + wasm gates green; the three-browser matrix (Chromium/Firefox/WebKit) passes and the engines agree instruction for instruction |
| M2 Static BusyBox | ✅ | ~97% | applet gates green; reload persistence is verified where OPFS exists (Chromium and Firefox in the current matrix), while WebKit reports the capability unavailable and disables persistence controls instead of pretending to save |
| M3 Dynamic userland | ✅ | ~100% | musl and glibc loaders green, native + wasm; file-backed mappings, the initial ELF, and the dynamic loader demand-page from a content-addressed manifest; the pinned Alpine rootfs now has a generated 14-package license/source/redistribution inventory and fails closed on an undecided license |
| M4 Threads & processes | ✅ | ~97% | green on x86-64 Linux and macOS, including determinism, adversarial COW/fd-sharing/backpressure, and a signal blocked-then-unblocked gate added after the bug below. Signal dispositions are now consulted rather than assumed: default actions run, a process can signal itself (`tkill` was missing, so `raise` was `ENOSYS`), and `rt_sigprocmask` delivers what it just unblocked before the next guest instruction. A blocking syscall interrupted by a handler returns `EINTR` unless the handler asked for a restart — nothing returned `EINTR` before, so every wait restarted whether or not the handler wanted it, and the rule is now gated through a socket as well as a terminal. Multi-worker deferred |
| M5 Event loop & networking | ✅ | ~100% | HTTP/HTTPS (verified guest TLS)/DNS/epoll/sendmsg/denied-by-default green natively, and the browser reaches the network through a deny-by-default relay — gated in all three engines. Socket interruption obeys `EINTR`/`SA_RESTART`; bytes are metered and capped; recording/replay, reconnect, and suspension are gated. The last proxy-failure ambiguity is closed: policy/upgrade rejection, upstream refusal, abnormal relay failure before/after connect, and clean EOF map to distinct documented Linux outcomes, with native delivery-once and browser boundary gates |
| M6 OpenFox | ✅ | ~96% | all workload gates green natively (version/help/status, scripted network task, secret injection, crash bundles, bounded soak), **and the image now runs in a browser**: a 52 MB agent binary streams into the guest filesystem and an OPFS cache, reaches a shell prompt in about three seconds, and executes — gated in all three engines. The soak now bounds the filesystem, guest physical memory, and the lifted-block table, the last by a structural ceiling derived from the engine's own counters after an 80-round reading of the curve proved wrong at 1,000 rounds; the 60-minute run is green: 1,000 rounds in 3,673 s |
| M7 Codex & Claude Code | 🔶 | ~95% | **Both Codex modes run end to end.** Non-interactive: a real `exec` edits a file, runs a shell command, and prints the model's summary, exiting 0. Interactive: the real Codex TUI renders full-screen on a host-driven pty (capability probes, a bordered composer, `Ask Codex to do anything`), takes keystrokes, and quits cleanly on Ctrl-C. Getting here took real process groups, true 80-bit x87 software floating point, `mremap`, an argv/envp size fix, three network-ABI write-back fixes, keying the translated-block cache by address space, pseudoterminals with SIGWINCH-on-resize, and a host-driven stdio pty. The host `git` binary runs real repo ops (status/diff/add/commit/log) in the guest. The browser now has the terminal half of this: an interactive shell and a full-screen editor run on a pty in a tab in all three engines, and `/dev/tty` resolves to the controlling terminal so a shell's job control reaches the program it started. The terminal is now a terminal in the sense that matters for an agent: the input line discipline turns `^C` and `^Z` into signals on the foreground group, a stopped process group is a real scheduler state reported through `wait4(WUNTRACED)`, `fg` resumes it, and a background group that reads the terminal is stopped with SIGTTIN rather than competing for the user's keystrokes. A session checkpointed to browser storage resumes after a real reload, with the agent reading back its own profile. Image delivery to the browser is closed for both real agents: the 256 MB Codex standalone and the dynamically linked Claude Code — Bun runtime, loader, and glibc all manifest-delivered, every file lazy — answer version and help in a clean profile in all three engines, demand-paging 8% and 12% of their images, with retired instruction counts identical on every engine (Claude's 186-million-instruction run included). **A session that does work now finishes**: asked to change a value in a file and check it, Codex read the file, applied its own patch, ran `cat` on a pty it allocated, reported what that subprocess printed, and exited 0. Two engine defects of one shape were in the way, each an unimplemented case reported as an unrecoverable error — a vaddr-keyed disassembly map disagreeing with the asid-keyed block cache on every `execve`, and `TCSETSF` missing from the ioctl table |
| M8 Performance & release | 🔶 | ~99% | wasm opt pin, deterministic scheduling, a measured baseline with a control module (`docs/performance.md`) plus the versioned four-host dashboard (`docs/performance/`), and the first optimization landed: a content-addressed lift cache took `execve` from 48.8 ms to about 2 ms and fixed a block-sharing bug in the process, block profiling established that a real agent's startup has no hot path to translate, and tiered lifting cut a cold agent start from 5.3 s to 1.4 s at no cost to compute. Memory is now accounted by what it is spent on and can be capped, so a workload that will not fit a tab is refused at the request instead of dying part-way through. Storage and network now have ceilings of their own, and a guest over either sees an errno it already knows how to handle rather than a dead tab. Two surfaces are swept for corruption and fail closed — snapshot restore, where the sweep found a memory amplification and a 32-bit narrowing that only a browser could exhibit, and ELF loading, where it found five panics. Two more surfaces are now swept. Every argument position of every syscall number against a corpus of the ways a number breaks code that trusts it, singly and paired, against four page contents, 7,128,576 cases — which found five more defects, four of them wrapped arithmetic that only the `relcheck` profile can see, including an `align_up` that turned an address at the top of the space into page zero and an `mprotect` of length zero that took the host down. And the decoder, which the guest reaches without a syscall at all by mapping a page executable and jumping into it: every opcode in all four maps under seventeen prefix combinations, then again truncated against a mapping boundary, 365,568 sequences, clean. The host side of the boundary is swept too, from Node against the real module: thirty-two distinct traps, all from a `slice_arg` whose documented safety contract — that the pointer came from `wtw_alloc` — a caller breaks by passing a different number. Executing guest bytes found three defects the decoder pass could not: a family of SIMD helpers written for the 128-bit form of their instruction and handed the 64-bit MMX form, which reads a register at a size it does not have; the address after an instruction at the top of the address space, computed with an addition that overflowed; and a zero-length executable range whose last address underflowed. CPU and the event log now have ceilings of their own: a workload that computes without ever entering the kernel used to be outside every mechanism for stopping a task, and the trace could grow until the tab died. Hot-block translation to WebAssembly has landed: a p-code→wasm translator covers every op whose semantics wasm can reproduce, held bit-for-bit to the interpreter by a block-level gate, and is wired into the run loop both natively and in the browser — where a hot block compiles to native code the WebAssembly engine produces and runs against the engine's own memory with no copy, guest memory reached through a softmmu callback. Region compilation then landed — a hot self-loop's back-edge folded into one wasm function, so millions of iterations are one `jit_call`, not one each — taking a register compute loop to ~30x over the interpreter in V8 (up from 2.76x per block) and, once host self-loops were covered with fault-in-region accounting, a memory-scan loop to ~4.6x. A bail-cause histogram weighted by executed work then scoped the coverage work — ~100% JIT-able for scalar static-musl hot paths (sha/gzip), lower for glibc/Node — and the 128-bit move/widen/logic quartet took Node from 89.9 to 94.3% and codex to 97.6%. Then the inline softmmu fast path landed: a compiled load/store resolves entirely in wasm against icicle's live TLB and the resolved guest page in the shared linear memory, calling the host only on a miss, fault, or cross-page access, which took the memory-scan loop from 4.6x to ~30x — matching the compute loop — as host crossings fell from one-per-byte to one-per-page, and a native fastmem gate proves a warm hit makes zero host calls while stale, aliased, and no-permission entries defer. The whole JIT line is now verified on the x86-64 Linux host with the real fixtures under `WEBTOS_REQUIRE_FIXTURES=1` (no skips): the current strict test matrix is green across every test binary, the six softmmu correctness gates among them. The exit gate that optimized and interpreter modes reproduce the same architectural traces is now closed too — a JIT-mode trace suite holds each recorded workload byte-for-byte to the interpreter's reference, and building it found and fixed a real defect (a zero-instruction block was being JIT-dispatched, desyncing icount from state). The 128-bit arithmetic ops then landed — a full u128 multiply (the schoolbook mulhi plus cross terms, since wasm has no widening multiply) and the u128 shifts (two lanes with the boundary-crossing carry, selected on the count at run time) — gated against the interpreter over generative inputs, so the only wide op left to bail is the odd 16-byte rotate. The release tail now has deterministic locked workload images, detached signatures and OIDC attestation definitions, and a generated, verifier-gated 43/43-per-engine compatibility report. True multi-block regions are now closed; what remains is external release/key operations |

The M8 release slice now has a dated Rust toolchain, a committed Cargo lockfile,
a frozen and path-remapped build with a fixed compile-time random seed, an SPDX
SBOM, a canonical uncompressed tar with fixed metadata and a payload checksum
manifest, and a two-build byte-comparison gate. The x86-64 Linux fixture host
produced identical archives from separate target directories despite hostile
caller overrides. A separate noncanonical macOS validation build was also
internally reproducible, and its wasm passed the Node/message/manifest gates
and 33/33 checks in Chromium, Firefox, and WebKit. The manual GitHub workflow
now adds OIDC provenance and SBOM attestations, but has not yet run and no
supported release has been published. BusyBox, OpenFox, Codex, and Claude Code
images are built from exact locked bytes into canonical archives; two roots
and changed mtimes produce identical results, while OpenFox additionally
reproduces from pinned source with Go 1.26.6. Detached workload signing is
implemented without creating a production key. The compatibility dashboard
records 43/43 checks in Chromium, Firefox, and WebKit against all four locked
workloads. The separate performance authority in `docs/performance/` binds the
Linux native run, all three browser versions, control-module rates, memory
ceilings, exact cross-host instruction fingerprints, runtime SHA-256, source
commit, and measurement time; its workflow rebuilds the Linux Wasm and rejects
digest or Markdown drift. `docs/EXECUTION_RECORD_V1.md` and
`tools/execution_record.py` add the smallest portable run-evidence envelope:
runtime/workload/input identities, before/after checkpoints, policy, network
recording and receipts, terminal output/result, instruction count, trace
artifact/root, and the record itself are all digest-bound and reverified.

### Overall completion

Weighted by engineering effort, **roughly 98%**. The weights are a judgement
call, so here is the arithmetic rather than the assertion:

| Milestone | Weight | Done | Contribution |
|---|---|---|---|
| M0 Lock the baseline | 5% | 100% | 5.0 |
| M1 Static `hello` | 5% | 98% | 4.9 |
| M2 Static BusyBox | 8% | 97% | 7.8 |
| M3 Dynamic userland | 10% | 100% | 10.0 |
| M4 Threads & processes | 13% | 97% | 12.6 |
| M5 Event loop & networking | 13% | 100% | 13.0 |
| M6 OpenFox | 12% | 96% | 11.5 |
| M7 Codex & Claude Code | 20% | 95% | 19.0 |
| M8 Performance & release | 14% | 99% | 13.9 |
| **Total** | **100%** | | **97.7** |

The heaviest remaining items are the last M7 Claude Code product gates.
Release publication, the first OIDC workflow run, and
production workload-key custody are external maintainer gates rather than code
that can be truthfully marked complete in a local worktree.

The native test suites (98 cases, plus the soak, the nine measurement runs,
and trace regeneration, all invoked explicitly) gate every ✅ above, alongside
the wasm harness and the current
43-check-per-engine browser matrix; `crates/x64-engine` and `crates/linux-compat`
are the delivered engine and OS layers, `crates/webtos-web` + `web/` the current
browser host.

## What Remains

The milestone sections below carry the detail. This is the same work grouped
by what it unblocks, because the outstanding items do not line up with the
milestone numbering any more.

### Completed parallel queue outside the active Claude work

Coordination snapshot, 2026-08-29: Claude is working on the M7 Claude Code TUI
and long-run diagnosis in `crates/linux-compat/examples/run_guest.rs` and
`web/probe_claude_tui.mjs`. The queue below deliberately excludes those files
and that acceptance path.

| Status | Priority | Independent work | Closed by |
|---|---|---|---|
| ✅ | P0 | Name and gate the remaining M5 proxy-failure case | Native error-delivery-once test plus all-engine browser boundary mapping |
| ✅ | P0 | Make browser-worker cancellation storage-safe | Digest-checked dual generations; real mid-write Worker termination in Chromium and Firefox; WebKit reports OPFS unavailable |
| ✅ | P1 | Publish the M0 performance dashboard | Versioned JSON/Markdown for native and three engines; CI rejects runtime or render drift |
| ✅ | P1 | Close the M3 minimal-root licensing gap | Generated 14-package inventory; unknown expressions fail closed |
| ✅ | P1 | Specify Execution Record V1 and verifier | Runtime/workload/inputs/checkpoints/network/output/trace bindings all verified against tampering |
| ✅ | P2 | Implement true multi-block JIT regions | Bounded state-machine regions, exact fuel/fault resume, trace parity, and browser dispatch canary |
| ✅ | P2 | Replace file-delivered secrets with real host handles | Bytes stay outside VFS/snapshots; host principals reject cross-agent opens and inherited-fd reads |
| ✅ | P2 | Close background-terminal semantics | Linux fixture proves background `tcsetattr` and `tcsetpgrp` both stop with `SIGTTOU` |

External maintainer gates are not implementation work: run the OIDC release
workflow from the committed branch, choose and publish the production workload
trust root, and create the first supported release. Multi-worker execution,
energy accounting, and lift-cache body serialization remain deliberately
deferred and are not part of this queue. The real Claude Code browser task and
the multi-hour agent soak stay with the active Claude acceptance path rather
than being duplicated here.

### The agent goal (M7, and the M6 tail)

The product goal is a coding agent in a tab. Everything below it now works;
what is left is the agent itself.

- **Carry an agent CLI into the browser.** **Codex runs**: `codex-cli
  0.150.1` reports its version and exits 0 inside the wasm module a browser
  loads, in 0.8 s, from a 256 MB static binary delivered as one file, 531 MB
  resident. Node runs too, in 0.9 s. Delivery, memory, and speed are settled
  problems, and so are credentials: Codex reports `Logged in using ChatGPT`
  in 2.2 s with the real profile arriving as a scoped secret, the snapshot
  afterwards holding the placeholder. **A real model call works**: with a
  reachable nameserver in the guest, `codex exec "say hi"` reaches the live
  API and prints `Hi! 👋`, 4,199 tokens, exit 0, in 2.7 billion instructions.
  What hung before was DNS — no `/etc/resolv.conf`, so the resolver spun on
  `recvmsg` 263,885 times. **And a session that does work now finishes**:
  asked to edit a file and then run a command to check it, Codex read the
  file, applied its own patch, ran `cat` in a subprocess on a pty it
  allocated, reported what that subprocess printed, and exited 0 — 24,573
  tokens, 3.8 billion instructions. Two engine defects of one shape were in
  the way, each an unimplemented case reported as an unrecoverable error: a
  vaddr-keyed disassembly map disagreeing with the asid-keyed block cache on
  every `execve`, which flushed every block; and `TCSETSF` missing from the
  ioctl table, which told any program changing terminal mode that it had no
  terminal. See `docs/workloads/node.md`.
- **The Claude Code profile.** **It runs**: `2.1.247 (Claude Code)`, exit 0,
  inside the wasm module a browser loads — 184 M instructions in 16.6 s. It is
  a 239 MB **Bun** binary, not a Node one, so "both agents are Node
  applications" is only true of Codex. Four things were in the way, none of
  them Bun-specific: segments were mapped at `p_align` instead of page
  granularity and took the permissions of the segment below, `CPUID` faulted
  on extended leaves, `sysinfo`/`getrusage`/`close_range` were missing, and
  `/proc/self/maps` did not exist — that last one alone is what Bun aborts
  without. What remains is a session that does work rather than a version
  string. See `docs/workloads/node.md`.
- ~~**Repository access with real history.**~~ Done: `tests/git.rs` mounts a
  repository with a three-commit object database and proves the guest walks it
  newest-first, so this is real refs/history rather than a readable working
  tree alone.
- ~~**Cancellation and checkpoint resume.**~~ Done. `^C` and `^Z` are
  signals, a stopped group is a scheduler state, `fg` resumes it, a background
  reader is stopped with SIGTTIN rather than competing for keystrokes, and an
  interrupted syscall returns `EINTR` unless the handler asked for a restart —
  nothing did before, so every wait restarted. A checkpointed session resumes
  after a real browser reload with the agent reading back its own profile.
  Gated natively and in all three engines. A network call interrupted
  mid-flight is now gated too, rather than inferred from the shared machinery:
  a guest blocked in `recv` on a real connection, against a server holding its
  reply, ends with `EINTR` after its handler runs, and with `SA_RESTART`
  resumes and reads bytes the peer sent only afterwards. That gate needs a
  compiled C fixture, so it runs on the Linux host and skips on macOS.
- ~~**SIGTTOU on background terminal state changes.**~~ Closed: terminal
  writes still obey `TOSTOP`, while background `tcsetattr` and `tcsetpgrp`
  stop the calling process group with `SIGTTOU` regardless of `TOSTOP`.
  `tests/pty.rs` proves both operations independently with a native Linux C
  fixture.
- **The long soaks**: OpenFox's three-hour 8,000-round run and bounded event-log
  growth are done; a multi-hour Codex or Claude Code session is not. The soak
  asserts four
  invariants rather than one; the block-table invariant is a structural
  ceiling, because tiered lifting leaves a retired block group behind on
  promotion and a long run reaches the ceiling rather than converging short
  of it.

### Making it usable rather than possible (M8)

Measured, not guessed — see the analysis in
[`docs/performance.md`](docs/performance.md) and the current four-host evidence
in [`docs/performance/`](docs/performance/).

- ~~**Reuse lifted blocks across processes that share an image.**~~ Done: the
  engine indexes lifted groups by address and content as well as by address
  space, so a process reuses what another already lifted from the same bytes.
  An `execve` went from 48.8 ms to about 2 ms, and a five-stage shell pipeline from 1.06 s to 0.28 s. It also fixed a live bug — two
  images loaded into one machine shared a load address and so shared blocks,
  and the second one ran the first one's code.
- **Hot-block translation** landed (p-code→wasm, gated bit-for-bit, dispatched
  in the run loop natively and in the browser), then region compilation of hot
  self-loops on top of it — a loop's back-edge folded into one wasm function,
  register loops ~30x and memory-scan loops ~4.6x, both a handful of dispatches
  for millions of iterations — the 128-bit move/widen/logic quartet (codex
  95.9→97.6%, Node 89.9→94.3% JIT-able), and then the inline softmmu fast path:
  a compiled load/store resolves in wasm against icicle's live TLB and the
  resolved guest page in shared memory, calling the host only on a miss, fault,
  or cross-page access, which took the memory-scan loop from 4.6x to **~30x**
  (matching the compute loop) as host crossings dropped from one-per-byte to
  one-per-page. The 128-bit *arithmetic* ops then landed too — the full u128
  multiply and the u128 shifts, the cross-lane residue the quartet could not
  decompose, gated against the interpreter over generative inputs. Bounded
  multi-block regions now close the remaining dispatch gap: a hot CFG becomes
  one Wasm state-machine loop with static side exits and exact retired-count/
  fault-resume metadata. The two-block browser canary makes 100,000 iterations
  in one region dispatch (about 200,000 without it), while interpreter/JIT
  architectural traces remain identical and the existing code budget bounds
  compiled regions.
- **Persist the lift cache across sessions.** Worth about half a second on a
  cold agent start now that tiered lifting has taken the other four, so it
  ranks below the risk of serialising lifted code.
- **Split the interpreter's cold half** (float and 80-bit paths). A risk
  rather than a defect: no engine has been shown to decline the 61.8 KiB
  function, and the fix is mechanical if one ever does.
- **Quotas.** Memory is done: the footprint is accounted by what it is spent
  on — guest pages, lifted code (including the guest bytes the reuse index
  keeps), and guest files — and a budget refuses an image at the request
  rather than part-way through the delivery, naming what it would cost and
  what is free. Gated in all three engines. Storage and network now have
  ceilings too, and both refuse the guest with an errno rather than
  exhausting the tab: every path a guest can grow the filesystem by returns
  `ENOSPC` at the ceiling, and bytes across the host broker are metered in
  both directions, with a stream clipped to what is left and a datagram
  refused whole (`EPERM`). Both are exposed to the browser the way memory
  was. Two limits bound what they are worth. Storage is charged by
  allocated capacity, not written length, so a file grown a chunk at a time
  can hold up to twice what has been written to it and the ceiling arrives
  sooner than the number suggests. The network meter counts guest payload
  only; connection setup, host-side DNS, and TCP and TLS framing never cross
  the broker interface, so the figure is a floor on what the tab moves rather
  than a wire total. CPU and the event log have ceilings too: CPU stops a turn
  with `OutOfCpu` and can resume under a raised allowance, while the event log
  records how much it dropped after reaching its cap. All five quotas are
  exposed through the browser host and covered by their native/browser gates.
- **32-bit narrowing.** Three found so far, all the same shape: 64-bit
  address or size arithmetic done at `usize` width, which is correct on the
  64-bit host the tests run on and wrong on the 32-bit target that ships. A
  snapshot length that wrapped, a page-alignment mask that truncated instead
  of aligning, and a file offset that folded 2^32 onto zero so a write landed
  on the start of the file. Clippy's `cast_possible_truncation` enumerates the
  remaining `u64`-to-`usize` casts — 45 in these crates — and most are
  harmless; the ones on guest-supplied sizes have been narrowed deliberately.

  The vendored engine has now been swept the same way and came back clean:
  31 `u64`-to-`usize` casts across `icicle-mem`, `icicle-cpu`, `pcode`, and
  `sleigh-runtime`, every one of them bounded by construction — page-relative
  offsets, per-entry lengths inside an `overlapping_mut` closure, instruction
  lengths, shift amounts, and an ELF partial-write fallback whose truncation
  could only make a write shorter. A guest mapping 5 GiB and touching past the
  4 GiB mark works in a browser, which is the behaviour a truncated length
  would have broken. The one defect of this class in vendored code was the TLB
  alignment mask, already fixed.

  Reproducing that sweep needs one thing that is easy to get wrong: clippy
  invoked from `crates/` compiles a path dependency but emits no lints for it,
  silently. It has to be run from `third_party/icicle`, where those crates are
  the workspace. A deliberately truncating function added to the crate is how
  to tell the difference between "clean" and "not looking".
- **Fuzzing.** Two surfaces are swept rather than fuzzed: every truncation and
  every single-bit flip of a real input, asserting the parser fails closed.
  Snapshot restore found two things — a header could make a dozen bytes out of
  browser storage reserve for four million nodes, and a 64-bit length or
  index narrowed silently on wasm's 32-bit `usize`, so a corrupt image parsed
  into a plausible-looking filesystem. ELF loading found five, all panics: a
  header truncated after five bytes reached an `unwrap`; a `p_align` of zero
  was divided by, and one that is not a power of two tripped an assert inside
  `align_up`; a segment claiming the top of the address space, or 2^64 bytes,
  overflowed the span; an image with nothing to load became a region of zero
  length that underflowed the allocator; and an image naming itself as its own
  `PT_INTERP` recursed until the stack was gone — which the sweep could not
  even catch, because a stack overflow is not a panic. Each is now a refusal
  naming the claim it refused, and Linux's one-interpreter rule is enforced.
  The browser is where those panics cost the most: a Rust panic on wasm is an
  abort, so before the fix a nonsense alignment did not fail to load — the
  module trapped with `RuntimeError: unreachable` and every later call threw,
  leaving the tab with no machine at all. Two honest negatives: neither defect
  the snapshot sweep found is present here. Nothing is reserved on the
  strength of a header, because the loader maps a range and hands out pages
  when the guest touches them, so a segment claiming 64 TiB from an 8 KiB file
  costs a map entry; and nothing narrows on wasm32, because this path works in
  `u64` throughout, checked on the host and again in the wasm harness where a
  narrowing could show. Decoding, memory translation, syscalls, and host
  messages have no such sweep.
- **Signed manifests, reproducible images, dependency licenses**, and a
  security audit of credential boundaries and snapshot contents.

### Evidence the project does not yet keep (M0, and cross-cutting)

- ~~**An instruction trace format** and stored reference traces.~~ Done: four
  traces in `test_data/traces/`, and the browser matrix reproduces one of them
  register for register. Determinism is now gated against a recorded baseline
  rather than only against another run.
- ~~**Versioned fixtures.**~~ Done: `test_data/FIXTURES.sha256` is the formal
  pinned set and `tests/fixtures.rs` recomputes it, so corruption or accidental
  regeneration fails rather than silently changing the baseline.
- ~~**Native QEMU validation.**~~ Removed: it validated the Stage-1 kernel, which has been deleted from the repository; the trace suite is the native reference now, reproduced register for register in every browser engine.
- ~~**A Linux host in the loop.**~~ Partly done: a skip is no longer silent.
  Every fixture goes through one helper that prints `SKIP:` with the fixture
  and how to get it, and `WEBTOS_REQUIRE_FIXTURES=1` turns a skip into a
  failure. Run that way, the x86-64 Linux host covered everything — no skips,
  which is demonstrated rather than assumed, though that run has not been
  repeated since the suite grew to 98 cases. On macOS the same switch fails 26
  of them: every C fixture, which is most of the threads, processes, epoll,
  pty, and signal surface, and now the interrupted socket read as well.
  `.github/workflows/native.yml`
  runs the strict suite on x86-64 Linux, building the agent fixture from a
  pinned OpenFox commit so a failure means this repository changed rather than
  that one did. It is manual (`workflow_dispatch`) until it has run on a real
  runner, so the Linux host is still in the loop only when someone starts it.
- ~~**A compatibility dashboard** across engines and pinned workload
  versions.~~ Done: `docs/compatibility/compatibility.json` binds the runtime,
  exact workload bytes, browser versions, checks, and instruction
  fingerprints; its workflow rejects lock or rendered-dashboard drift. The
  separate performance dashboard remains in the parallel queue above.
- ~~**A suite that is only sound single-threaded.**~~ Fixed. The engine kept
  the current address space, block address, and instruction count in
  process-wide atomics, and the OS layer the current pid, so two tests running
  as threads in one binary overwrote each other's notion of which address
  space was executing — an intermittent engine-level `InternalError` that
  moved between tests, which is exactly what makes such a thing easy to
  mistake for a real regression. They are thread-locals now: about four
  failures in fourteen parallel runs before, none in fourteen after, at no
  measurable cost to the interpreter.

### A bug that only appeared where the tests ran

Two milestone-4 tests failed on x86-64 Linux with a current toolchain while
passing everywhere anyone had looked. The cause was real and is now fixed: a
signal raised while it was blocked was **discarded** rather than held pending.
`notify_parent_sigchld` only recorded SIGCHLD against a thread that did not
currently block it, and `posix_spawn` blocks every signal for its duration —
so a child that exited inside that window lost its notification, and the
parent waited forever for a child that had already gone.

It was a race, which is why it looked like an environment problem: whether the
child got there before the parent unblocked depended on how much work the
host libc's `posix_spawn` did. The same code passed on one machine and hung on
another.

What made it survivable for so long is the more useful lesson. Both tests
compile their fixture with the host `gcc`, which cannot produce a static Linux
binary on macOS — where the browser work happens — so they returned early and
reported success. A green suite on a Mac was not a green suite.

Fixed by recording a pending signal regardless of the mask, in both the
SIGCHLD and terminal-signal paths, and by making a parked task runnable only
for a signal it does not block. `a_signal_raised_while_blocked_is_delivered_when_unblocked`
opens the window deliberately instead of racing for it.

**Deviation since resolved:** delivery used to happen at the next scheduling
point, not on the way out of the `sigprocmask` that unblocked it. That gap had
a visible casualty: musl's `raise` blocks every signal around its `tkill`, so
a shell's own SIGINT handler never ran before `raise` returned, and BusyBox
`sh` read `^C` at its prompt as end-of-file and exited 130. `rt_sigprocmask`
now delivers what it just unblocked before another guest instruction runs —
writing the syscall's return value and resume point first, so the state the
handler saves (and may `longjmp` away from) is a clean instruction boundary.
The earlier broad attempt failed because it delivered from every syscall
return without that context repair; the narrow exit-path fix keeps the two
tests above green. A task that unblocks a pending signal by some means other
than `sigprocmask`/`sigreturn` and never parks still waits for its next
kernel entry.

### Not scoped by any milestone

The mission promises "webTOS-owned isolation, scheduling, storage, networking
policy, resource accounting, and execution records". The first five are
delivered on the browser line. End-to-end, third-party-verifiable execution
records are not, and no milestone from M0 to M8 fully covers them:

- **Resource accounting.** M8's quotas cap memory, CPU, storage, network, and
  the event log per agent. Energy accounting per agent — the TOS agent
  kernel's model, no longer in this repository — has no browser counterpart
  and no gate.
- **Execution records.** Principle 6 says CPU execution, scheduling, external
  input, storage commits, and receipts are one system. Network recording,
  offline replay, and per-connection receipt classification are implemented
  and gated. Execution Record V1 now binds those receipts to the runtime and
  workload identities, explicit inputs, policy, before/after checkpoints,
  output/result, instruction count, and trace artifact/root in one canonical
  digest-checked record. See `docs/EXECUTION_RECORD_V1.md`; changing any record
  field or bound artifact makes `tools/execution_record.py verify` fail. V1 is
  deliberately integrity/replay evidence, not an attestation of who ran it.

### Deferred on purpose

- **Multi-worker execution.** The single-worker deterministic model is the
  baseline, and multi-worker may not be attempted until it is provably
  correct.
- ~~**Worker cancellation leaving storage consistent.**~~ Closed by the
  digest-checked dual-generation protocol and real Worker termination gate
  described in M4.

## Product Principles

1. **Correctness before translation speed.** Start with an interpreter. Add
   hot-block translation only after workload semantics are stable.
2. **Workloads are the acceptance tests.** Instruction and syscall counts are
   diagnostics, not completion criteria.
3. **No silent compatibility lies.** An unsupported syscall or instruction
   must return a defined error or trap; it must never report fake success.
4. **Keep the runtime portable.** Linux semantics must not depend directly on
   native page tables, privileged registers, hardware drivers, or raw user
   pointers.
5. **Browser authority is explicit.** Storage, network, clipboard, files, and
   credentials enter through capability-checked host adapters.
6. **Determinism is end-to-end.** CPU execution, scheduling, external input,
   storage commits, and receipts are one system.
7. **Do not require a remote compute backend.** Guest CPU execution and kernel
   state remain in the browser. A network gateway may translate browser-safe
   transports when raw sockets are unavailable.

## Current Baseline

The repository holds one stack, and this roadmap measures it. `crates/` is
`x64-engine` (interpreter, decoder, guest memory), `linux-compat` (ELF,
syscalls, processes, VFS, signals, futex, sockets, epoll, pseudoterminals),
and `webtos-web` + `web/` (the wasm module and its browser host). It compiles
to `wasm32-unknown-unknown` and executes unmodified Linux x86-64 binaries in
Chromium, Firefox, and WebKit.

It used to hold two. The original bare-metal TOS kernel — agent scheduler,
capabilities, mailboxes, energy accounting, keyspaces, checkpoints, receipts,
and a Wasm contract engine — has been removed; it was a separate crate the
browser pivot left behind and nothing on the browser path depended on it.
Where those concepts belong now is an open question rather than pending
integration work in this tree.

| Component | Where it stands |
|-----------|-----------------|
| x86-64 execution | Interpreter runs guest instructions in wasm; hot blocks now translate to WebAssembly and dispatch in the run loop (milestone 8) |
| ELF64 loading | Static and dynamic (musl and glibc loaders) into sparse guest memory |
| Linux compatibility | Processes, VFS, memory, signals, futex, sockets, poll/epoll, pseudoterminals — all portable, no native x86-64 dependency |
| Browser host | Workers, terminal, OPFS persistence, relayed networking, and streamed image delivery, gated in three engines |
| Resource control | Memory, CPU, storage, network bytes, and the event log all have enforced ceilings; over-budget returns an errno |
| Execution records | Deterministic replay and recorded traces exist; nothing produces a record a third party could check |

The central component, the x86-64 execution engine, exists and the Linux
runtime on top of it works in a browser. What does not exist is any way for
someone outside the tab to verify what ran in it.

## Target Architecture

webTOS is split into three primary layers with narrow contracts:

```text
Linux x86-64 workload
          |
          v
+---------------------------+
| x64-engine                |
| CPU, decoder, interpreter |
| guest memory, block cache |
+-------------+-------------+
              | CpuExit
              v
+---------------------------+
| linux-compat              |
| ELF, syscalls, processes  |
| VFS, VMAs, futex, epoll   |
+-------------+-------------+
              | HostPlatform
              v
+---------------------------+
| browser-host              |
| workers, terminal, OPFS   |
| network broker, snapshots |
+---------------------------+
```

### `x64-engine`

Responsibilities:

- x86-64 long-mode CPU state: general registers, `RIP`, `RFLAGS`, segment
  bases, floating-point, and vector state
- instruction prefixes, REX, ModR/M, SIB, immediates, and effective addresses
- interpreter-first execution with precise traps and restartable instruction
  boundaries
- sparse 64-bit guest virtual memory over bounded browser allocations
- executable-page tracking and block invalidation for self-modifying code
- atomic operations and deterministic thread handoff
- structured exits such as `Syscall`, `PageFault`, `IllegalInstruction`,
  `Breakpoint`, `Yield`, and `Halt`
- hot-block translation to WebAssembly, landed after the correctness gates (dispatched in the run loop, native and browser; region compilation of register and host self-loops, the 128-bit move/widen/logic quartet, and the inline softmmu fast path that took memory loops from ~4.6x to ~30x — both register and memory loops now match at ~30x)

The engine does not implement Linux policy, files, sockets, or agent
capabilities.

### `linux-compat`

Responsibilities:

- ELF64 and interpreter loading, initial stack, `argv`, `envp`, and auxiliary
  vector construction
- Linux x86-64 syscall ABI and return conventions
- processes, thread groups, signals, TLS, futexes, and scheduling semantics
- VMAs, `brk`, `mmap`, file-backed mappings, and copy-on-write policy
- file descriptors, VFS, pipes, eventfd, timerfd, poll, and epoll
- socket semantics and translation to the host network interface
- deterministic time, randomness, ordering, and external-input recording

This layer must use interfaces such as `GuestMemory`, `VirtualAddressSpace`,
`TaskRuntime`, `Clock`, `Entropy`, `Storage`, and `Network`, not
`crate::arch::x86_64` directly.

### `browser-host`

Responsibilities:

- worker lifecycle, scheduling wakeups, cancellation, and crash isolation
- terminal input/output and resize events ✅ (`web/terminal.html`: an
  interactive shell on a pty, keystrokes and resize into the guest, rendered
  output back out)
- browser-backed packages, files, keyspaces, and checkpoints
- network mediation through browser-available transports ✅
  (`tools/webtos_gateway.mjs`: a deny-by-default WebSocket relay; the wasm
  module owns no transport and the guest has no network until the page asks)
- application images, dependency manifests, and version pinning ✅ (images
  stream in chunk by chunk and are cached in OPFS, so a reload does not
  download again; and an image can now install by a content-addressed chunk
  manifest — the manifest is the execution authority and every chunk is
  hash-verified before it enters the store, which is version pinning — with
  execution fetching only the pages it touches)
- capability prompts and credential injection
- snapshot, reload, resume, diagnostics, and performance metrics

The UI must remain a client of the browser host. It must not reach into CPU or
kernel internals.

## Stable Boundaries

The first architecture task is to define interfaces before moving large
amounts of code:

```rust
enum CpuExit {
    Syscall(SyscallFrame),
    PageFault { address: u64, access: AccessType },
    IllegalInstruction { rip: u64 },
    Breakpoint { rip: u64 },
    Yield,
    Halt,
}

trait GuestMemory {
    fn read(&self, address: u64, output: &mut [u8]) -> Result<(), MemoryError>;
    fn write(&mut self, address: u64, input: &[u8]) -> Result<(), MemoryError>;
}

trait HostPlatform {
    fn monotonic_time(&mut self) -> RecordedTime;
    fn random_bytes(&mut self, output: &mut [u8]) -> Result<(), HostError>;
    fn storage(&mut self) -> &mut dyn Storage;
    fn network(&mut self) -> &mut dyn Network;
}
```

The exact Rust API may change, but the ownership rule may not: the CPU engine
owns instruction semantics, Linux compatibility owns OS semantics, and the
browser host owns Web APIs.

## Milestone 0: Lock the Baseline 🔶

**Outcome:** native behavior and reusable fixtures are captured before the
browser refactor begins.

Work:

- Record the current native build, Linux maturity, and runtime validation
  results from a clean checkout. ✅ (a clean checkout reproduces the native
  reference build and the trace suite, and does; the pre-pivot kernel/QEMU
  validation harnesses this once named have been removed with the kernel they
  validated, so nothing here is pending on a target the interpreter replaced)
- Extract small ELF fixtures for static, PIE, dynamic, TLS, signal, futex,
  filesystem, and socket behavior. ✅ (test_data holds the in-repo fixtures,
  and the executable ones plus the reference traces are now a formal pinned
  set: `test_data/FIXTURES.sha256` records a SHA-256 per fixture and
  `tests/fixtures.rs` recomputes and compares them, so a fixture changing
  silently — a corrupted download, an accidental regen — is caught)
- Create an instruction trace format containing registers, flags, memory
  effects, traps, and syscall exits. ✅ (`linux_compat::trace`: a documented,
  versioned, line-oriented text format carrying a self-describing header, the
  syscall stream with arguments and results, delivered signals, exits and
  stops, and register/flag samples taken at exact instruction counts.
  Memory effects appear as the syscall arguments that make them observable
  rather than as a per-write log)
- Record syscall traces for the target workloads without treating trace count
  as proof of semantic completeness. ✅ (four traces in `test_data/traces/`,
  regenerated deliberately and diffed on every run; the count is not the
  claim, the contents are)
- Define browser support and performance dashboards. ✅ (browser support is
  published and verifier-gated in `docs/compatibility/`; `docs/performance/`
  now binds the same 1/4 MiB workload on x86-64 Linux and all three engines to
  the exact runtime digest, source commit, browser versions, control module,
  memory ceilings, and cross-host instruction fingerprints)
- Classify the existing `TODO-*` files as native-substrate supporting plans. ✅ (docs/plans/)

Exit gate:

- Native reference tests are reproducible. ✅ (the trace suite reproduces the
  recorded traces exactly — natively, and register for register in all three
  browser engines. The pre-pivot QEMU kernel harness is not part of this: it
  validated a bootable kernel target the browser pivot replaced, and is not
  applicable to the interpreter the project now is)
- Fixtures and expected traces are versioned. ✅ (the traces live in
  `test_data/traces/` and are diffed on every run; the fixture set itself is
  now pinned too, by `test_data/FIXTURES.sha256` and the gate in
  `tests/fixtures.rs`, which catches a fixture changing out from under a test)
- Every later milestone can run without depending on a full root filesystem. ✅

## Milestone 1: Static `hello` ✅

**Outcome:** a static x86-64 ELF prints text and exits entirely inside a
browser worker.

Work:

- Implement CPU state, basic decoder, effective-address calculation, integer
  arithmetic, branches, stack operations, loads/stores, and `SYSCALL` exit. ✅ (vendored SLEIGH core + interpreter VM)
- Implement sparse guest pages with read, write, execute, and bounds checks. ✅
- Port ELF loading and initial process stack construction to `GuestMemory`. ✅
- Support the minimal Linux path for `write`, `exit`, and `exit_group`. ✅
- Connect stdout to the browser terminal. ✅ (web/ demo terminal, and a real
  pty-backed terminal at web/terminal.html)
- Add instruction differential fixtures and malformed-ELF tests. ✅
  (malformed-ELF is done and then some: every truncation and every single-bit
  flip of a real image, which found five defects, and a load fails closed
  rather than reserving memory on the strength of a header field. The
  differential is the architectural trace suite — a stream recorded on native
  x86 and reproduced register for register in every browser engine is a
  per-sample differential between the native reference and the runtime; a
  separate fixture suite against an external emulator is not applicable, the
  external reference being what the browser pivot moved away from)

Exit gate:

- Static assembly and C `hello` binaries run in Chromium, Firefox, and WebKit
  engine test environments. ✅ (`web/test_browsers.mjs`; the three engines retire an identical instruction stream)
- Invalid instructions and memory accesses trap with useful diagnostics. ✅
- No native x86-64 instruction is executed by the host. ✅

## Milestone 2: Static BusyBox ✅

**Outcome:** a static BusyBox image provides useful shell and filesystem
operations in the browser.

Work:

- Expand integer, bit-manipulation, string, multiply/divide, and baseline
  floating-point/SIMD instruction coverage from executed traces. ✅ (SLEIGH coverage; BusyBox/glibc/musl exercise it)
- Port `brk`, anonymous `mmap`, `mprotect`, `munmap`, `read`, `write`,
  `openat`, `close`, `stat`, `getdents`, `ioctl`, and related fd behavior. ✅
- Implement browser-backed files, directories, permissions, and standard
  streams. ✅ (in-memory VFS; snapshots persist to OPFS)
- Provide `argv`, environment, current directory, and a minimal `/proc` and
  `/dev` view. ✅ (`/proc/self/exe`; fuller /proc pending)
- Support BusyBox applets first, then shell pipelines and redirection. ✅

Exit gate:

- `echo`, `cat`, `ls`, `mkdir`, `cp`, `mv`, `rm`, and `sh` smoke tests pass. ✅
- Files persist across browser reload. ✅ (a real reload in Chromium, Firefox, and WebKit restores the OPFS snapshot and reads the state back)
- Shell pipelines and exit codes behave consistently with the native fixture. ✅

## Milestone 3: Dynamic Linux Userland ✅

**Outcome:** dynamically linked PIE executables start through the system
dynamic loader.

Work:

- Complete file-backed mappings, demand paging, protection transitions, and
  executable-page invalidation. ✅ (`MAP_PRIVATE`, the initial ELF, and the
  dynamic loader now use immutable manifest-backed demand paging; interpreter,
  JIT, stale-ticket, snapshot, and three-browser gates cover the path. Review
  then closed a soundness hole the gates missed: host-side syscall copies
  bypassed the pager, so a path string inside an untouched mapping silently
  read as empty — and a second bug, empty paths resolving to the base
  directory instead of ENOENT, masked it. Host copies now fill or fault-in
  lazy pages copy_from_user-style, and an adversarial gate writev()s out of an
  untouched mapping and access()es a path living inside one)
- Support `PT_INTERP`, auxiliary vectors, TLS setup, `arch_prctl`, and FS/GS
  base behavior. ✅
- Complete instruction coverage exercised by the dynamic loader and libc. ✅ (musl and glibc loaders both run)
- Port signals, alternate signal stacks, and signal return frames to virtual
  CPU state. 🔶 (registration and real handler delivery with `rt_sigreturn` —
  SIGCHLD to a parent not in `wait4`, SIGWINCH to a terminal's foreground
  group, both gated. Dispositions are consulted rather than assumed: default
  actions run, including stopping a process group, a process can signal
  itself, `rt_sigprocmask` delivers what it just unblocked, and an interrupted
  wait returns `EINTR` unless the handler asked for a restart. Alternate
  signal stacks work: a handler installed with `SA_ONSTACK` runs on the stack
  the process registered, which is the whole point of registering one — the
  fault it exists to survive is the interrupted stack being the problem.
  `sigaltstack` reports `SS_ONSTACK` while a handler is on it, refuses to be
  changed under one, refuses a stack too small to hold a frame, and can be
  taken away again; nested delivery continues down the alternate stack rather
  than restarting at its top, which would overwrite the frame it interrupted.
  A fork inherits the registration and a new thread does not, because the
  memory it names is the registering thread's. Gated by `tests/altstack.rs`,
  which asks the only question that distinguishes a handler that got the
  stack it asked for from one that was told it did: where its own locals
  live)
- Build versioned minimal root images with explicit licenses and manifests. ✅
  (the Alpine minirootfs is pinned by SHA-256 and its installed package DB
  generates `docs/workloads/alpine-minirootfs-LICENSES.json`; every package
  carries version, upstream/source, license expression, redistribution
  decision, and obligations, and an undecided expression fails the build)

Exit gate:

- Pinned dynamically linked C and Rust fixtures run from a clean browser
  profile. ✅ (C and Rust via glibc; musl via Alpine; the musl fixture runs from a clean profile in all three engines)
- Loader, TLS, signal, and file-mapping regression suites pass. ✅
- Unsupported relocations, instructions, and syscalls fail explicitly. ✅

## Milestone 4: Threads and Process Semantics ✅

**Outcome:** multi-threaded Linux programs run deterministically.

Work:

- Port `clone`, `clone3`, thread groups, `fork`, `vfork`, `execve`, `wait4`,
  and process exit semantics onto virtual CPU contexts. ✅ (clone3 intentionally ENOSYS; libcs fall back to clone)
- Implement futex wait/wake, robust-list cleanup, clear-child-tid, atomics,
  and thread-local storage. ✅ (robust-list intentionally ENOSYS)
- Begin with deterministic cooperative scheduling inside one worker. ✅
- Add multi-worker execution only after the single-worker model is correct;
  retain deterministic ordering and recorded external events. ⬜ (deferred by design)
- Test races, cancellation, signals during waits, and process-image
  replacement. ✅ (races and `execve` were already covered; a wait interrupted
  by a signal now is too, on both kinds of wait — a pty `read` and a socket
  `recv` — each returning `EINTR` or restarting according to what the handler
  asked for, and cancellation is the interrupt character killing a foreground
  program blocked in a syscall, with the shell surviving its own converted
  interrupt)

Exit gate:

- Thread, futex, child-process, and exec fixture suites pass. ✅
- Repeated runs from the same checkpoint produce the same scheduled event
  sequence in deterministic mode. ✅ (identical output and instruction counts across runs)
- Worker cancellation cannot leave committed storage in a partial state. ✅
  (snapshots use two digest-checked generation slots; a reader validates both
  and chooses the newest complete generation, never a half-write. The browser
  gate persists a good snapshot, pauses after writing half the alternate
  slot, calls `worker.terminate()`, and proves a fresh worker selects the
  unchanged committed digest. It runs in Chromium and Firefox; the current
  Playwright WebKit port exposes no OPFS, which the UI and matrix report as an
  unavailable capability with persistence controls disabled)

## Milestone 5: Event Loop and Networking ✅

**Outcome:** interactive network clients and event-driven runtimes work in the
browser.

Work:

- Finish pipe, socketpair, eventfd, timerfd, poll, select, and epoll behavior
  against browser-host readiness events. ✅ (against the broker readiness interface)
- Implement DNS and socket mediation through an explicit network broker. ✅
  (two brokers over one boundary: host sockets natively, and a command stream
  the browser host carries out over a WebSocket relay)
- Support authenticated HTTPS from guest userland without exposing browser
  credentials to unrelated agents. ✅ (guest TLS verifies the full certificate
  chain, SAN, and validity against a guest-installed trust anchor; credentials
  are injected at runtime and scoped per agent, so one reaches only the files
  the host named and an out-of-scope program reads the placeholder rather than
  an empty value — gated natively and in Chromium, Firefox, and WebKit, and a
  real credential drives a live authenticated model call)
- Record network inputs for replay and receipt classification. ✅ (every byte
  the guest receives crosses one interface — the `NetworkBroker` trait, at
  `tcp_recv`/`udp_recv_from` — so recording is a wrapper around it and replay
  is another implementation of it. A `RecordingBroker` logs the results the
  guest consumed; a `ReplayBroker` answers from a recording with no transport
  behind it. The gate is the strongest kind here: a wget recorded against a
  live server replays against a fresh guest with no server and no broker
  bytes, and the output is identical — proven by a canary where replay serving
  the wrong bytes makes it diverge. `Recording::receipts` classifies a session
  into one receipt per connection — the peer reached, bytes each way, and how
  it ended — with a refused connection its own receipt keyed by its outcome,
  which is the case most worth seeing. Gated by `tests/netrecord.rs`)
- Define offline, denied, timeout, reconnect, and proxy-failure behavior. ✅
  (reconnect is gated by `tests/net_event.rs`; the accepted-then-failed proxy
  case now delivers `ECONNRESET` exactly once after buffered data instead of
  becoming EOF or a hang. The browser boundary separately gates policy and
  upgrade rejection as `ENETUNREACH`, upstream dial refusal as `ECONNREFUSED`,
  abnormal relay failure as `ECONNRESET`, and clean EOF as EOF)

Exit gate:

- HTTP, HTTPS, DNS, pipe, and epoll fixture suites pass. ✅ (natively, and
  HTTP over a relayed socket in Chromium, Firefox, and WebKit)
- A long-running event loop survives transient network failure and browser
  tab suspension. ✅ (both halves gated. Suspension: A browser stops scheduling a
  background tab, and this machine's clock is retired instructions plus an
  idle warp — neither moves while the host is not calling `run`, so a resumed
  guest believed no time had passed. `Machine::skip_time` and
  `wtw_skip_time_ms` are how a host says otherwise; `web/worker.js` forwards
  it. Across a three-second gap a one-millisecond periodic timer reports the
  periods it missed as a count rather than firing once for each, the
  monotonic clock has moved, a sleep the gap swallowed returns instead of
  waiting again, and the timer keeps working afterwards. Gated by
  `tests/suspend.rs`. Transient failure is gated too: a peer that reads the
  request and vanishes leaves the guest with an error rather than a wait —
  waiting forever is the failure that ends a long-running loop — and a retry
  afterwards succeeds, with the server counting arrivals so a clean failure
  cannot be one that never reached it. A refused connection is reported and
  does not stop the next one)
- Network access is denied by default without the appropriate capability. ✅
  (three layers: no broker unless the host attaches one, no relay unless the
  page names one, and no destination unless the relay's allowlist names it)

## Milestone 6: OpenFox 🔶

**Outcome:** a pinned Linux x86-64 OpenFox release completes a real agent task
inside webTOS.

Work:

- Add a versioned OpenFox workload manifest and dependency image.
- Close instruction and syscall gaps from real startup and task traces.
- Provide repository mounts, configuration persistence, terminal control,
  HTTPS, subprocesses, and tool execution.
- Add secret injection that keeps credentials outside guest disk snapshots by
  default.
- Add crash bundles containing the guest version, instruction exit, syscall
  trace tail, and webTOS build identifier without including secrets.

Exit gate:

- `openfox --version` and help complete in a clean browser profile. ✅ (the
  agent image is streamed into a clean browser profile and `openfox --help`
  runs there, in Chromium, Firefox, and WebKit)
- OpenFox performs one scripted network-backed agent task against a mounted
  test repository. ✅
- Configuration and repository changes survive reload and explicit resume. ✅ (filesystem snapshot restored into a fresh machine)
- A 60-minute interactive soak test completes without kernel corruption or
  unbounded memory growth. ✅ (1,000 rounds in 3,673 s on x86-64 Linux, green
  over the filesystem, guest physical memory, and the lifted-block table. It
  caught a cross-process physical-memory leak, and then caught tiered lifting
  retaining one stale block group per promoted address. An 80-round reading
  called that growth converging; the full hour showed it climbing to 76,057
  blocks and disproved it. Counting the engine's structures separately gave
  the real bound — one retired group per counted address, saturating at
  roughly twice the starting table — and that ceiling is the invariant now,
  checked every round rather than inferred from the shape of a curve. See
  `docs/performance.md`; `OPENFOX_SOAK_ROUNDS=1000` reruns it)

## Milestone 7: Codex and Claude Code 🔶

**Outcome:** pinned releases of both coding agents are usable for sustained,
interactive browser sessions.

Each agent receives a separate workload manifest and compatibility report.
Runtime dependencies must be discovered from the pinned release rather than
assumed from historical packaging.

**Runtime foundation (done).** This was justified by the belief that both
agents are Node.js applications and that a stock Node was therefore the
reduction. **Neither of them is.** Inspecting the binaries: Codex is Rust —
3,941 `cargo` strings, 296 `tokio`, no `v8::internal` at all, its handful of
"Node.js" mentions being text inside its own system prompt — and Claude Code
is Bun 1.4.1, which embeds JavaScriptCore rather than V8, with the
application's JavaScript in a 156 MB `.bun` section.

The work below still stands, because none of it is V8-specific: lifting
AVX-512, software SIMD helpers, and a CPUID baseline are general x86-64
coverage that Bun needs as much as Node did, and getting a dynamically linked
glibc program running is what both Node and Claude Code depend on. Only the
stated reason was wrong.

A stock `node` (v24, glibc) runs scripts to a clean exit — `node -e "console.log(...)"` executes and array/
string/`JSON`/`Math` output is correct (~90 M instructions). This required,
on top of milestones 1–6: upgrading the vendored Ghidra x86 SLEIGH spec to
lift the AVX-512 family, adding software helpers for the SIMD pcodeops Node/
V8/OpenSSL issue directly (AES-NI, `pshufb`, `psadbw`, `roundsd`/`roundss`,
all verified against native intrinsics), and advertising an SSE2 CPUID
baseline. AVX/AVX-512 *execution* semantics stay unvalidated, so CPUID keeps
userspace on the SSE paths. See `docs/workloads/node.md`.

A stock statically linked **Codex** binary (`codex-cli` 0.149.1, a 247 MB
`x86_64-unknown-linux-musl` build) runs directly on top of this: `--version`,
`--help`, and `exec --help` print correctly, and `login status` reports "Not
logged in" and exits — all from a clean profile. It needed a larger guest
physical-memory cap (its segments are ~246 MiB) and a `flock` no-op.

**A real, authenticated `exec` run now completes end to end**: with real
credentials mounted, the same binary discovers the CA store, performs the
TLS handshakes, downloads its cloud configuration, sends the prompt to the
OpenAI API, prints the model's reply, and exits 0 (2.37 B instructions).
Getting there fixed, in order: real SIGCHLD delivery with `rt_sigreturn`
(async runtimes reap children via a self-pipe handler, not `wait4`); vfork
parent suspension until the child execs or exits (posix_spawn's error
protocol); kernel-faithful edge-triggered epoll — a delivered edge re-arms
on new pipe/eventfd/socket activity, not only when observed not-ready
(two lost-wakeup deadlocks, found via a deadlock dump that now prints every
parked task, fd table, and a syscall trail); 33 SSE4.1/SSSE3 helpers plus
the 8 saturating packed add/sub ops (x86-64-v2 binaries issue them without
CPUID checks; all verified against native intrinsics); a configurable
wall-clock base (real certificate and token validity need real time); and a
configurable physical-memory cap (`GUEST_MEM_MB`). A Node-based mock of the
agent pipeline (`mock codex` against a local mock API) isolated the memory
and clock failures.

**Model-driven repository edits now work.** The same binary applies a patch
that creates a file in the workspace, runs `/bin/sh -lc` to verify it, reads
the output, and prints the model's natural-language summary before exiting 0.
This took real process groups (`setpgid`/`getpgid`/`setsid`, group-directed
`kill -pgid`), `PR_SET_PDEATHSIG`, `fcntl` record locks, datagram/seqpacket
socketpairs, a 128 KiB argv/envp string cap, true 80-bit x87 extended-
precision software floating point (the f80 type was reinterpreted as f64 and
the lifter lowered every 80-bit op to f64 — musl's printf digit loop relies
on the full 64-bit mantissa and walked off the stack without it; also
`FPREM`/`FIST` control-word rounding), `mremap`, 64 KiB-aligned mmap, three
network-ABI write-back fixes (`recvmsg` name length, `write_sockaddr_in`
socklen, per-thread `brk`/`mmap` cursors made address-space-shared), and
finally keying the translated-block cache by address space rather than
virtual address alone — an exec'd child's lifted blocks were being reused in
the parent at the same VA, surfacing as a stale value read from a stack slot
that crashed the session on the way out. What is *not* yet exercised is the
Claude Code, and wiring an agent's interactive TUI onto a pty. Pseudoterminals
themselves now work: `/dev/ptmx` allocates a master, `/dev/pts/<n>` opens the
slave, and openpty()/forkpty() move data both ways with per-pty termios and
window size, ONLCR output processing, and a controlling terminal (setsid +
TIOCSCTTY), gated by `crates/linux-compat/tests/pty.rs`. The host `git` binary (a
glibc dynamic executable) additionally runs real repository operations in
the guest — `status`, `diff`, `add`, `commit`, and `log` all work, gated by
`crates/linux-compat/tests/git.rs`.

Work:

- Support installation or prepackaged images without requiring host shell
  access. 🔶 (host Node and a static Codex binary run via `run_guest`; images
  stream into the browser and cache in OPFS, demonstrated with OpenFox; no
  signed or versioned image package yet)
- Complete PTY behavior, terminal resize, signals, subprocess trees, pipes,
  temporary files, file watching, Git operations, and authenticated HTTPS.
  🔶 (signals incl. real SIGCHLD delivery, pipes, subprocess trees incl.
  vfork semantics, temp files, and authenticated HTTPS are exercised by the
  real Codex `exec` run, which also drives model-authored file edits and
  child shell commands; the host `git` binary runs status/diff/add/commit/
  log in the guest (gated by `tests/git.rs`); pseudoterminals —
  openpty/forkpty, /dev/ptmx, /dev/pts, controlling terminal, termios, window
  size, and SIGWINCH-on-resize — work, including changing terminal mode with
  `tcsetattr(TCSAFLUSH)`, which a program running a command on a terminal of
  its own does before anything else, and a program a shell started in its own
  process group, and the real Codex TUI renders and takes input on a
  host-driven stdio pty; the input line discipline raises the interrupt,
  quit, and suspend characters as signals on the foreground group, and job
  control is real — `^C` kills the foreground program and the shell
  survives its own converted interrupt, `^Z` stops it with the stop
  reported through `wait4(WUNTRACED)`, and `fg` + SIGCONT resume it where
  it blocked (gated by `tests/pty.rs`); file watching works — inotify
  instances, watches on a file or a directory, `IN_MODIFY`, `IN_CREATE`,
  `IN_DELETE`, and the two halves of a rename paired by a cookie, readable
  through `poll` and `epoll` so a watcher blocks and wakes rather than
  spinning, with a queue ceiling that reports `IN_Q_OVERFLOW` rather than
  losing events quietly. A watch follows the inode, not the name, which is
  why renaming a watched file does not lose the watch. Gated by
  `tests/watch.rs`. All three target binaries carry inotify — Node in
  twenty-six places — so the syscalls answering `ENOSYS` was a real gap
  rather than a theoretical one)
- Mount a repository with explicit read/write capabilities. ✅ (host
  directories mount read/write via `run_guest`, and a repository with real Git
  history is now gated: `git log --oneline` in the guest walks a three-commit
  history newest-first, which is the smallest proof that a mounted repo's
  object database and refs — delivered as host files — are intact and
  traversable, not merely that the working tree is readable. `tests/git.rs`)
- Provide controlled environment variables and secret handles. ✅ (legacy
  placeholder injection remains for configuration templates; real handle
  mounts keep the value in a host-owned table and put only an empty read-only
  marker in the VFS. Snapshots and traces never receive the bytes, crash
  bundles redact defensively, and a host-assigned agent principal makes both a
  new open and an inherited descriptor return `EACCES` after crossing agents)
- Test tool execution, cancellation, interrupted network calls, context
  persistence, browser reload, and checkpoint resume. 🔶 (cancellation,
  browser reload, and checkpoint resume are gated, and an interrupted network
  call now is too — a guest blocked in `recv` takes a signal mid-flight and
  gets `EINTR`, or resumes under `SA_RESTART`. That gate needs a compiled C
  fixture, so it runs on Linux and skips on macOS. Tool execution and context
  persistence have no gate of their own beyond the Codex runs above)
- Maintain per-version instruction, syscall, and performance regression data.
  ✅ (a ledger, `test_data/regression/workloads.txt`, records for each of
  several in-repo workloads the figures that are exactly reproducible —
  instructions retired, syscalls issued, the distinct syscall numbers used,
  and the exit code — and `tests/regression.rs` recomputes and compares them
  on every run. Wall time is not in it, because it is not reproducible; these
  are, and the same ledger written on macOS passes register-for-register on
  the Linux host. A change names the workload and the figure that moved —
  `syscalls 40 -> 42`, or a distinct-syscall set that gained a number — so a
  regression between versions is visible and attributable rather than silent,
  and is regenerated deliberately with `--ignored rewrite` like the traces.
  The ledger carries the crate version it was written under, so its git
  history is the per-version record. The architectural traces remain the
  register-for-register gate for their four workloads; this is the wider,
  coarser net over more of them)

Exit gate for each agent:

- Version and help commands run from a clean browser profile. ✅ (both real
  agents. Codex: the 256 MB standalone installs by content-addressed manifest
  into a clean profile and answers `--version` and `--help` in Chromium,
  Firefox, and WebKit, demand-paging 21 MiB — 8% of the image. Claude Code:
  the dynamically linked Bun runtime, its loader, and its glibc libraries all
  travel in the same manifest, every file lazy, and its 186-million-instruction
  `--version` retires an identical count on every engine — 31 MiB resident of
  248 MiB)
- Authentication can be supplied without baking secrets into an image. ✅
  (real credentials mount at runtime from a host directory and drive an
  authenticated model call; a browser host injects them through the same
  placeholder mechanism, scoped to the files that should have them, and the
  checkpoint written to browser storage carries the placeholder — checked by
  reading the stored bytes, in all three engines)
- The agent reads a repository, edits a file, runs a command, and reports the
  result through the terminal. 🔶 (all four natively, in one session: asked to
  change a value in a file and then check it, Codex read the file, called the
  live model, applied its own patch, ran `cat` in a subprocess on a pty it
  allocated, and reported what that subprocess printed — 24,573 tokens, exit
  0. The browser-profile path remains)
- Child processes, cancellation, and terminal resize behave correctly. 🔶
  (child processes and vfork spawns work; terminal resize delivers SIGWINCH,
  and a full-screen program repaints from a browser window resize with nothing
  typed — gated in Chromium, Firefox, and WebKit. Driving the real Codex TUI
  into a browser profile found and fixed three engine gaps its SQLite WAL
  state needed — `fchown` was ENOSYS, the `fcntl` lock queries were EINVAL,
  and `MAP_SHARED` file mappings were unimplemented; all three now behave and
  are gated natively by a WAL-shaped probe, and a manifest-only terminal
  session reaches a live prompt in all three engines. The remaining blocker is
  now root-caused and is not this engine's: codex's TUI panic ("Span not
  found", tracing-subscriber fmt_layer.rs:833) is an upstream
  tracing-subscriber defect — a span field whose Debug impl emits a nested
  span during formatting clobbers the per-layer filter's thread-local state,
  so a filtered-out fmt layer is wrongly told about the span and misreads its
  own filtered view as "span not found" (tokio-rs/tracing #2448/#2704, still
  present in 0.3.23). A twenty-line program with two filtered fmt layers and a
  reentrant Debug reproduces the identical panic on bare macOS with no webTOS
  involved; codex's TUI installs exactly that shape (file/feedback/log-DB/OTEL
  layers, each per-layer filtered), and this engine's deterministic schedule
  makes codex hit the reentrant path reliably where real hardware sometimes
  misses. No clone/futex/TLS change is warranted; the interactive TUI steps
  stay env-gated (WEBTOS_TUI_GATE=1) pending a codex-side fix upstream)
- A checkpointed session resumes after browser reload with filesystem state
  intact. ✅ (the terminal page checkpoints the guest filesystem to browser
  storage on demand; after a real reload `openfox status` reports finding the
  profile written before it — the agent's own account of the restore, not the
  harness reading a file back. Gated in Chromium, Firefox, and WebKit. A
  checkpoint is the filesystem, not the running processes: there is no CPU or
  memory snapshot, so what resumes is what a program wrote to disk. Images the
  host cached are left out of a snapshot and injected again on boot, so a
  session costs 2,955 bytes rather than the 52.6 MB it did when it carried the
  agent binary as well)
- A multi-hour soak test has bounded memory, storage, and event-log growth.
  ✅ (`OPENFOX_SOAK_ROUNDS=1000` and up runs OpenFox back to back on one
  machine; an 8000-round run took 10,181 s — just under three hours — and
  passed. The filesystem does not grow between rounds, the guest's physical
  pages are flat, the block table stays under its one-retired-group-per-
  address ceiling, and the event log holds its 256-event cap while reporting
  the 2,997,247 events it turned away — without the cap that run would have
  accumulated three million events, which is the growth the gate exists to
  bound. Gated by `openfox_soak_is_bounded` in `tests/openfox.rs`; the
  compressed 25-round form runs in CI)

The milestone is complete only when both agent profiles pass independently.

## Milestone 8: Performance, Security, and Release 🔶

**Outcome:** correctness-complete workload profiles become a supportable web
runtime.

A measured baseline exists before any of this work starts — see
[`docs/performance.md`](docs/performance.md); the current versioned evidence is
in [`docs/performance/`](docs/performance/). Three findings shape the order
below: Chromium and WebKit run the interpreter within a small factor of native
speed, and the engine that does not is explained by its own wasm compiler
rather than by anything in webTOS (a few-hundred-byte control module shows the
same spread); process startup is dominated by lifting blocks rather than
executing them; and every engine grants the module the full wasm32 address
space, so the memory question is how guest pages, image bytes, and the block
cache share 4 GiB rather than how much a tab allows.

Work:

- Keep lifted blocks across processes that share an image, so a short-lived
  process does not pay to translate what has already been translated. ✅
  (content-addressed lift cache; `execve` 48.8 ms -> ~2 ms)
- Profile executed blocks. ✅ — and the result changed the item below it. A
  real agent's `--help` executes 29,347 distinct blocks, the hottest worth
  1.5%, and 84% of that cold start is lifting rather than executing. There is
  no hot path to translate; compute-bound work still has one (13 blocks cover
  99% of a megabyte of hashing).
- Lift blocks cheaply and optimize only the ones that prove hot. ✅ (94% of
  lifting was the p-code optimizer, and it buys about 12% on the few blocks
  that repeat; blocks now earn it by being re-entered. A cold agent start went
  from 5.3 s to 1.4 s, a five-stage shell pipeline from 1.06 s to 0.04 s, and
  compute was unaffected. The reference traces did not need regenerating.)
- Persist the lift cache across sessions, keyed by image content and validated
  against the specification it was lifted under. 🔶 (the validated key is
  built; the body serialization is deferred, with measured reason. Lifting is
  the largest single cost of a cold start, but tiered lifting already skips
  the optimizer — 94% of that cost — for cold code, so what remains to persist
  is the cheap decode-and-build: ~0.43s of a 1.4s cold start, and only on a
  reload of an image already seen. That residual is small and the thing it
  would persist — the engine's internal p-code, a 72-variant vendored enum —
  is coupled to representation that shifts under it, and executed under the
  wrong specification is silent wrong execution rather than a crash. So the
  piece built is the one a body serializer must sit behind and the one that
  fails silently if wrong: a spec fingerprint (`Machine::spec_fingerprint`,
  `wtw_spec_fingerprint`) that is a SHA-256 over the SLEIGH grammar, stable
  across builds of the same spec and different when a grammar file changes;
  and a cache header (`liftcache.rs`) keyed by that fingerprint and the images
  it covers by content digest, which refuses a cache from another spec, one
  that does not cover the bytes now present, and one that is truncated or
  forged. Gated by `tests/liftcache.rs`. The body is what a later session
  writes; the refusal is what keeps it from being trusted when it should not
  be)
- Translate proven hot paths to WebAssembly. ✅ mechanism, and ✅ the speedup
  ceiling that mattered — the per-access softmmu callback that held memory loops
  at 4.6x is gone, so memory-bound and compute-bound hot loops now both run
  ~30x; with the 128-bit multiply and shifts now landed too, only multi-block
  regions are left. A p-code→wasm translator (`x64-engine/src/jit.rs`) handles
  every op wasm can reproduce, gated bit-for-bit against the interpreter
  (registers, guest memory, faults, exceptions, NaN-aware floats), and the run
  loop dispatches a hot block to compiled code instead of interpreting it —
  natively via wasmi in tests, and in the browser where the WebAssembly engine
  compiles the block to native and runs it against the engine's own memory (no
  copy), guest accesses taking a softmmu callback into the real MMU. Measured
  2.76x on a compute loop in V8 per block; region compilation of hot self-loops
  — a loop's back-edge folded into one wasm function, so millions of iterations
  are one `jit_call`, not one each — then took a register loop to ~30x and, with
  fault-in-region accounting, a memory-scan (host) loop to ~4.6x. The 128-bit
  move/widen/logic quartet, added on the bail-cause histogram's evidence, took
  glibc/Node coverage from ~90 to ~94% and codex to ~98%. Then the inline softmmu
  fast path landed: a compiled load/store is checked in wasm against icicle's
  live TLB (auto-coherent — icicle flushes it on mmap/munmap/mprotect/execve) and
  resolves the guest page directly in the shared linear memory, calling the host
  only on a miss, fault, or cross-page access; that took the memory-scan loop
  from 4.6x to ~30x — matching the compute loop — as host crossings fell from
  one-per-byte to one-per-page. Verified on the x86-64 Linux host with the real
  fixtures under `WEBTOS_REQUIRE_FIXTURES=1` (no skips): the current strict
  matrix is green across every test binary, the six `fastmem` correctness
  gates among them — coherence after
  unmap, permission fault after mprotect, cross-page defer, and TLB-index
  aliasing all matched the interpreter. The 128-bit arithmetic ops then landed —
  the full u128 multiply (schoolbook mulhi over 32-bit halves, since wasm has no
  widening multiply) and the u128 shifts (two lanes with the boundary-crossing
  carry, selected on the count) — gated against the interpreter over generative
  inputs. Bounded multi-block CFGs now compile as one state-machine region too,
  with exact fuel and fault resume metadata, static side exits, trace parity,
  and the existing compiled-code budget preventing an unbounded cache)
- Add block caching, invalidation, tiering, SIMD fast paths, and syscall fast
  paths without changing architectural results. 🔶 (block caching, tiering,
  and self-modifying-code invalidation all landed — the content-addressed lift
  cache and tiered lifting. The JIT caches then had to join that invalidation:
  they were keyed by bare address and were not cleared on a code-cache flush, so
  a re-lifted block could run a stale compiled handle after self-modifying code
  or reuse another image's handle at the same address after `execve`. They are
  now keyed by block id — the one identity that names exactly one p-code body,
  which an address does not: several blocks share a start address (a REP-style
  instruction lifts to a prologue chained to a loop block at the same address),
  and a re-lift after a lazy code page-in replaces the block behind an address,
  either of which served one block's compiled code to another and, under JIT +
  demand paging, hung a real dynamically-linked agent at the loader's memcpy.
  Block ids are append-only between flushes, so a stale id is never dispatched
  again and `execve` safety falls out. Gated by a same-address rep-string
  regression test and the eviction test, both red without the fix. A
  compiled-code budget
  then bounded the last unbounded JIT resource: the backend held every compiled
  module for the life of the session, and its native code memory was outside
  every ledger. The budget caps the wasm bytes held, evicts the least recently
  used blocks over the cap (dropping the module and instance, native and in the
  browser), and lets them recompile on demand; a transient decline no longer
  caches a permanent bail, only a genuine failure to translate does. Gated by an
  eviction/recompile test and a browser wiring test. The syscall fast path is not
  pursued — agent workloads are bound by lifting and syscalls, not execution.
  SIMD is different: the bail-cause histogram found 128-bit SSE ops are ~9% of
  executed work in glibc/Node and the top of their bail histogram, so a 128-bit
  move/widen fast path is the wide-op coverage worth adding for that class; see
  the JIT item above)
- Fuzz instruction decoding, memory translation, ELF loading, syscalls, image
  parsing, snapshot restore, and browser messages. 🔶 (six of the seven
  surfaces are swept exhaustively; the seventh names a parser that does not
  exist yet. Snapshot restore and ELF loading take every
  truncation and every single-bit flip, which found two defects and five. The
  syscall surface takes every argument position of every syscall number
  against a corpus of the ways a number breaks code that trusts it — singly
  and paired, each against four page contents, 7,128,576 cases — which found
  five more, four of them wrapped arithmetic that only the `relcheck` profile
  can see. Instruction decoding takes every opcode in all four maps under
  seventeen prefix combinations — including the three vector encodings that
  redefine the map — against six ModRM addressing forms, and then the same
  corpus again truncated one to fifteen bytes short of a page the guest did
  not map, because a length calculation running out of input is where a
  decoder reads what it was not given: 365,568 sequences, no panics. Running
  those bytes is a surface of its own — the interpreter, and every address
  translation the MMU does for an operand the guest computed — so the same
  corpus runs under nine register patterns, 940,032 executions, which found
  three more defects. A differential SSE/conversion probe (`examples/sse_probe`,
  run on the x86-64 host against the native CPU as reference) then found five
  more, driving a real Bun/JSC agent binary through the engine: `rdtsc` returned
  a constant so a spin-wait never ended; `roundsd`/`roundss` dropped the imm8
  rounding mode so `Math.floor`/`ceil`/`trunc` all rounded to nearest;
  float→int used a saturating cast where x86 yields the integer indefinite, so
  JSC's not-representable check passed garbage; and `cvtpd2dq`/`cvtps2dq`
  truncated where they should round. Random 128-bit inputs hid the mode bugs
  (almost always NaN or already-integral, where every mode agrees), so the
  probe grew crafted round-mode, flag-writing, and conversion families — 164
  cases, each confirmed to go red when its fix is reverted. The host's own half
  of the boundary — every exported
  `wtw_*` function, called with pointers, lengths, handles, and budgets it
  did not earn — is swept from Node against the real module, 6,013 calls
  across 56 functions, which found thirty-two ways for a page to trap the
  module and kill its own tab. Image parsing is the one left, and there is
  nothing to fuzz: an image arrives as a stream of bytes into a file, and
  what parses it afterwards is the ELF loader or the snapshot importer, both
  already swept. A package format with a manifest to parse arrives with the
  signed-manifest item below. What does exist is the delivery protocol — a
  reservation followed by pieces — and its sequences are now gated: a piece
  for a file nobody started, more pieces than the reservation expected, two
  streams to one path, interleaved streams, a reservation too large to serve,
  and a stream aimed at a directory, which used to replace it and discard
  everything underneath. A half-delivered image reads as the bytes that
  arrived, never as the room made for the ones that did not)
- Define memory, CPU, storage, network, and event-log quotas per agent,
  budgeting guest pages, image bytes, and the block cache against one address
  space (`wtw_set_guest_memory_mb` is the guest half of that). ✅ (all five
  have ceilings, each measuring live cost rather than lifetime. CPU was the one with no other mechanism behind it: a
  workload that computes in a loop and issues no syscalls has no kernel entry
  to be interrupted at, and the instruction limit only ends a turn that the
  host's loop begins another of — so it ran forever, and nothing in the
  machine said stop. It now stops with `OutOfCpu`, and a raised allowance
  resumes it where it stopped, so a host can put the question to a person
  instead of killing the tab. The event log stops recording rather than
  stopping the workload, since losing the tail of a diagnostic is the smaller
  harm — but it writes into the trace how much it dropped, so its end never
  reads as the workload's. Storage measures live data, not lifetime
  allocation: a guest that writes a file, deletes it, and writes another is
  not refused for the second on account of the first — gated by driving a
  write/delete/write churn through the guest's own syscalls and confirming
  freed bytes are reclaimed, which goes red if the reclamation is removed)
- Add signed workload manifests, reproducible images, dependency licenses,
  security policy, and vulnerability response procedures. 🔶 (signed
  manifests and the security policy are done. A manifest names each image
  with its size and SHA-256; delivery refuses bytes that disagree, an image
  it does not name is refused as well, and the check happens before the guest
  runs the image rather than when it arrives, so a host that forgets to say a
  stream finished cannot skip it. The signature is verified by the host with
  the platform's audited verifier rather than by the module: a wrong
  signature verifier fails open, and hand-rolling an unaudited one inside a
  security boundary is worse than none. `web/test_manifest.mjs` shows the two
  halves composing — a manifest that does not verify is never installed, and
  one that does is enforced. `SECURITY.md` states the trust boundaries, the
  seven surfaces with what each sweep found, the five ceilings, and what
  would change the document. The dependency-license manifest is done:
  `LICENSES.tsv` records every normal-dependency crate and its license,
  derived from `cargo tree` rather than hand-parsed JSON, and
  `tests/licenses.rs` checks both that the manifest matches the tree and that
  every license is one an allowlist has decided the project can ship — a
  GPL-3.0 dependency is named and refused, an undecided license is refused as
  undecided rather than passed. The six vendored engine crates, which had no
  license field, now declare `MIT OR Apache-2.0` from the icicle project's own
  LICENCE files. The core browser runtime now has a reproducible, checksummed
  release-candidate artifact with an SPDX SBOM. The separate workload builder
  rejects bytes, modes, and license decisions that differ from
  `workloads/LOCK.json`, fixes manifest and archive metadata, emits a bound
  in-toto statement, and reproduces the same archives across checkout paths
  and input mtimes. Detached Ed25519 signing and verification are gated; a
  production trust root remains an explicit maintainer operation)
- Add compatibility dashboards for supported browsers and pinned workload
  versions. ✅ (`docs/compatibility/` publishes the machine-readable report
  and dashboard for the exact BusyBox, OpenFox, Codex, and Claude Code bytes.
  Chromium, Firefox, and WebKit pass 43/43 checks each and agree on all nine
  shared instruction fingerprints; CI rejects a report that drifts from the
  lock or its rendered dashboard)
- Audit credential boundaries, host messages, guest memory, and snapshot
  data. 🔶 (host messages have a sweep of their own. The other three are
  audited by `tests/leak.rs`, which asks the question the other suites do not
  — when something is released, can what it held be read back by whoever gets
  that space next? Guest memory holds: a page mapped again reads as zeros,
  and so does one mapped after the image was replaced. Snapshots did not: a
  name written over kept the node it displaced, so a file rewritten shorter
  kept the tail of what it used to say, and `rename` onto an existing name —
  the "write a temp file and move it into place" idiom an agent edits with —
  kept the version it replaced. Both are fixed. A process cannot find
  another's credential in the memory it is handed either: a holder fills four
  megabytes of mapping and four of heap with a marker, forks, and the child
  replaces its image and searches what it is given — proven to be a search
  that works by planting the marker and watching it be found. And a crash
  bundle, which is a diagnostic that leaves the machine, now redacts for real
  rather than through a `debug_assert!` that does not run in the builds that
  ship: the executable path is the one field a guest chooses, and a guest can
  put anything in a path)

Exit gate:

- Optimized and interpreter modes pass the same architectural trace suite. ✅
  (both modes now reproduce the same reference traces register for register.
  The optimized mode is the JIT: `reference_traces_reproduce_under_the_jit` in
  `tests/trace.rs` records each workload with hot blocks translated to
  WebAssembly and executed by wasmi, asserts the JIT actually dispatched, and
  holds the result byte-for-byte to the interpreter's reference — and the
  browser matrix carries the same proof against V8/SpiderMonkey/
  JavaScriptCore. Building this gate found and fixed a real defect: a
  zero-instruction block was being JIT-dispatched, advancing register state
  under an icount that never moved and colliding in the start-keyed block
  cache, which the per-block-at-natural-termination tests never exposed because
  only a mid-sample budget cut reveals it)
- Supported workload profiles meet published startup and interactive latency
  budgets. ✅ (gated on instruction counts, which is the deterministic half of
  latency: the same workload retires the same count on every host and engine
  — the browser matrix asserts exactly that, register for register against a
  recorded trace — so a budget on it is a latency contract that cannot flap,
  where a gate on wall time would fire on a loaded box and pass on a quiet one
  and differ tenfold between engines for reasons that are the engines' wasm
  compilers rather than webTOS. `tests/budget.rs` publishes a ceiling per
  workload with the count measured when it was set, so the headroom is
  visible; static startup, a /proc read, busybox startup, `ls /`, and a
  twenty-round fork/exec loop are under budget, and the gate names any that
  are over and by how much. Wall time is printed beside each, explicitly not
  gated)
- Corrupt images, snapshots, and browser messages fail closed. ✅ (all three
  by exhaustive sweep rather than by sampling. An ELF takes every truncation
  and every single-bit flip, and a load refuses rather than reserving memory
  on the strength of a header field. A snapshot takes the same treatment.
  Browser messages take every argument position of every exported function
  against a corpus of the ways a number is not what the callee assumed,
  singly and paired — `web/test_messages.mjs`, run against the built module.
  Between them they found twelve defects, of which thirty-two distinct traps
  on the message boundary were one cause)
- Release artifacts are reproducible and carry complete dependency metadata.
  ✅ for the core browser runtime. `tools/check_release_reproducible.sh` builds
  twice in separate target directories and compares the canonical tar byte for
  byte; it includes the frozen `Cargo.lock`, `LICENSES.tsv`, an artifact-specific
  SPDX SBOM, vendored-source provenance, build metadata, and payload checksums.
  The canonical builder is fixed to x86-64 Linux and records that host in its
  metadata. The current compatibility publication passes 43/43 checks in each
  browser engine against all four locked workloads. The manual workflow is
  defined with GitHub OIDC provenance and SBOM attestations but has not run,
  and no supported release has been published. Third-party workload images
  remain outside the runtime artifact; their reproducibility and detached
  signature gates are independently implemented)

## Deliberately not pursued

Not everything unbuilt is unfinished. These were considered, measured, and
decided against; they are kept here with their reasons so the decision does
not have to be rediscovered, and they are not counted as pending work.

- **Lift-cache body serialization across sessions.** The validated key is
  built — a spec fingerprint and a content-addressed cache header that refuses
  a cache from another spec or image (`liftcache.rs`, gated). Serializing the
  body — the engine's internal p-code — would save about 0.43s on a *reload*
  of an image already seen, after tiered lifting already took the other 94% of
  lifting's cost. The p-code is a 72-variant vendored enum coupled to a
  representation that shifts under it, and run under the wrong spec it is
  silent wrong execution, not a crash. The reward did not justify that surface;
  the fingerprint is what makes it safe if a later session ever does.

This can change. A much larger reload cost would justify the cache body. The
measurements that decided against it are in `docs/performance.md`, not folklore.

## Cross-Cutting Test Matrix

Every milestone expands the same matrix:

| Layer | Required evidence |
|-------|-------------------|
| CPU | instruction fixtures, register/flag traces, faults, self-modifying code |
| Memory | sparse mappings, permissions, file mappings, copy-on-write, limits |
| Linux ABI | syscall fixtures, errno behavior, signals, threads, fd lifecycle |
| Browser host | worker failure, reload, persistence, network denial, quota errors |
| Determinism | repeated trace comparison and explicit nondeterminism classification |
| Workload | cold start, core task, cancellation, persistence, soak test |
| Security | malformed inputs, capability denial, secret redaction, resource exhaustion |

No milestone may be marked complete solely because a stub returns success or a
demo reaches its first prompt.

## Performance Strategy

Performance work follows three tiers:

1. **Interpreter:** reference semantics, tracing, debugging, and complete
   workload bring-up.
2. **Cached interpreter:** decoded blocks, direct branch linking, inline guest
   memory checks, and syscall dispatch caching. Lifting is itself tiered —
   blocks are lifted cheaply and re-lifted with the p-code optimizer once
   they have been entered enough times to be worth it.
3. **Hot-block translator:** selected x86-64 blocks translated to WebAssembly,
   guarded by page versions and deoptimized on invalidation or uncommon exits.

`docs/performance/` now publishes the BusyBox native and three-engine baseline.
Wall times remain evidence rather than flaky pass/fail thresholds; deterministic
instruction budgets, correctness, bounded memory, and actionable diagnostics
remain the release gates.

## Major Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Long-tail x86-64 instructions | Target applications fail late in startup | Trace pinned workloads, add precise illegal-instruction reports, grow fixtures incrementally |
| Native architecture coupling | Linux compatibility cannot run over virtual CPU state | Introduce `GuestMemory` and platform traits before porting modules |
| Browser memory limits | Large runtimes exhaust contiguous WebAssembly memory. Measured: every engine grants ~3.9 GiB, so the limit is architectural, not per-browser | Use sparse guest pages, quotas, eviction, and measured workload images |
| Threading differences | Futex and cancellation bugs cause hangs | Single-worker deterministic baseline before multi-worker optimization |
| Browser networking restrictions | Linux socket behavior cannot map directly | Explicit network broker, clear capability model, integration fixtures |
| Dynamic code invalidation | Translated blocks execute stale instructions | Version executable pages and invalidate blocks on writes or protection changes |
| Credential leakage | Agent secrets enter snapshots or logs | Handle-based injection, redaction, snapshot exclusion, capability isolation |
| Workload release drift | A new agent release breaks compatibility | Pin supported versions and publish per-version compatibility reports |
| Misleading completion claims | Demos pass while semantics remain stubbed | Workload gates, explicit errors, trace evidence, and soak tests |

## Target Repository Boundaries

The intended source layout is:

```text
crates/
  x64-engine/       # CPU, decoder, interpreter, guest memory, block cache
  linux-compat/     # ELF and Linux userspace semantics over portable traits
  browser-host/     # Web-facing platform adapters and worker protocol
web/
  app/              # terminal and control interface
  worker/           # execution worker entry point
tests/
  x64/              # instruction and trace fixtures
  linux/            # ELF and syscall fixtures
  browser/          # persistence, lifecycle, and network tests
  workloads/        # pinned OpenFox, Codex, and Claude Code profiles
```

This is a target boundary, not permission for a one-shot rewrite. Code moves
should follow tested interface extraction and keep the native reference path
working throughout the migration.

## Definition of Done

webTOS reaches its initial product goal when a supported browser can start a
clean webTOS environment and run pinned OpenFox, Codex, and Claude Code
workloads through real coding tasks with:

- local x86-64 guest execution
- persistent repository and configuration state
- correct terminal, subprocess, signal, thread, and network behavior
- explicit capability and credential boundaries
- bounded CPU, memory, storage, and log growth
- checkpoint and reload recovery
- actionable failures for unsupported behavior
- published workload versions and compatibility evidence

Anything short of those workload gates is an intermediate engineering
milestone, not completion of the browser Linux runtime.
