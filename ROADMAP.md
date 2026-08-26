# webTOS Roadmap

## Mission

webTOS is an AI-agent-first bare-metal operating system kernel designed to run
inside the browser. Its primary product goal is:

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

**Updated 2026-08-26.** Legend: ✅ complete (gated by tests), 🔶 partial,
⬜ not started.

| Milestone | State | Completion | Evidence |
|-----------|-------|------------|----------|
| M0 Lock the baseline | 🔶 | ~40% | fixtures exist; native QEMU harnesses not re-run since the pivot; no trace format or dashboards |
| M1 Static `hello` | ✅ | ~95% | native + wasm gates green; the three-browser matrix (Chromium/Firefox/WebKit) passes and the engines agree instruction for instruction |
| M2 Static BusyBox | ✅ | ~97% | applet gates green incl. reload persistence (FS snapshots + OPFS), verified in all three browser engines |
| M3 Dynamic userland | ✅ | ~90% | musl and glibc loaders green, native + wasm; no per-package rootfs license manifest |
| M4 Threads & processes | ✅ | ~88% | green incl. determinism and adversarial COW/fd-sharing/backpressure gates; multi-worker deferred |
| M5 Event loop & networking | 🔶 | ~90% | HTTP/HTTPS (verified guest TLS)/DNS/epoll/sendmsg/denied-by-default green natively, and the browser reaches the network through a deny-by-default relay — gated in all three engines; recording, reconnect, soak pending |
| M6 OpenFox | 🔶 | ~85% | all workload gates green natively (version/help/status, scripted network task, secret injection, crash bundles, bounded soak); browser delivery of the 97 MB image is the remaining gap |
| M7 Codex & Claude Code | 🔶 | ~72% | **Both Codex modes run end to end.** Non-interactive: a real `exec` edits a file, runs a shell command, and prints the model's summary, exiting 0. Interactive: the real Codex TUI renders full-screen on a host-driven pty (capability probes, a bordered composer, `Ask Codex to do anything`), takes keystrokes, and quits cleanly on Ctrl-C. Getting here took real process groups, true 80-bit x87 software floating point, `mremap`, an argv/envp size fix, three network-ABI write-back fixes, keying the translated-block cache by address space, pseudoterminals with SIGWINCH-on-resize, and a host-driven stdio pty. The host `git` binary runs real repo ops (status/diff/add/commit/log) in the guest. The browser now has the terminal half of this: an interactive shell and a full-screen editor run on a pty in a tab in all three engines, and `/dev/tty` resolves to the controlling terminal so a shell's job control reaches the program it started. Delivering the agent images to the browser and the Claude Code profile are the remaining agent work |
| M8 Performance & release | ⬜ | ~5% | wasm opt pin and deterministic scheduling only |

Weighted by engineering effort, overall completion is **roughly 73%**.
The native test suites (54 native cases plus the 17-check wasm harness and the
23-check-per-engine browser matrix) gate every ✅ above; `crates/x64-engine` and
`crates/linux-compat` are the delivered engine and OS layers, `crates/webtos-web`
+ `web/` the current browser host.

## Product Principles

1. **Correctness before translation speed.** Start with an interpreter. Add
   hot-block translation only after workload semantics are stable.
2. **Workloads are the acceptance tests.** Instruction and syscall counts are
   diagnostics, not completion criteria.
3. **No silent compatibility lies.** An unsupported syscall or instruction
   must return a defined error or trap; it must never report fake success.
4. **Keep the kernel portable.** Linux semantics must not depend directly on
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

The repository already contains much of the operating-system half of the
design, but not the browser CPU execution half.

| Component | Current state | Browser gap |
|-----------|---------------|-------------|
| Agent kernel | Scheduler, capabilities, mailboxes, energy, events, keyspaces, checkpoints, and receipts exist | Introduce a platform-neutral kernel host boundary |
| ELF64 loading | Native x86-64 executable and dynamic ELF support exists | Load into sparse guest memory instead of native page tables |
| Linux compatibility | Substantial process, VFS, memory, signal, futex, socket, poll, and epoll implementation exists | Eight modules still depend directly on native x86-64 facilities |
| Wasm agents | Standalone engine integration and kernel host bridge exist | Add browser worker lifecycle and browser host adapters |
| x86-64 execution | Native hardware executes guest instructions | Build the x86-64 interpreter and later a hot-block translator |
| Browser host | Workers, terminal, OPFS persistence, and relayed networking exist and are gated in three engines | Large-image delivery and checkpoints remain |
| Runtime validation | Native Java, Node.js, Python, and Linux maturity harnesses exist | Add browser-native workload and recovery gates |

This means webTOS can reuse the upper execution stack, but it cannot be
compiled to WebAssembly as-is and execute Linux x86-64 programs. The central
new component is the x86-64 execution engine.

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
- optional hot-block translation to WebAssembly after correctness gates pass

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
- application images, dependency manifests, and version pinning
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
  results from a clean checkout. 🔶 (harnesses exist; not re-run since the
  browser pivot — the native kernel build itself is verified)
- Extract small ELF fixtures for static, PIE, dynamic, TLS, signal, futex,
  filesystem, and socket behavior. 🔶 (test_data + test-compiled fixtures; not versioned as a formal set)
- Create an instruction trace format containing registers, flags, memory
  effects, traps, and syscall exits. ⬜
- Record syscall traces for the target workloads without treating trace count
  as proof of semantic completeness. 🔶 (live tracing exists; no stored traces)
- Define browser support and performance dashboards. ⬜
- Classify the existing `TODO-*` files as native-substrate supporting plans. ✅ (docs/plans/)

Exit gate:

- Native reference tests are reproducible. 🔶 (kernel builds; QEMU validation harnesses not re-run since the pivot)
- Fixtures and expected traces are versioned. 🔶
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
- Add instruction differential fixtures and malformed-ELF tests. 🔶 (trap tests exist; no differential suite)

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
  executable-page invalidation. ✅ (eager private file maps; demand paging deferred by design)
- Support `PT_INTERP`, auxiliary vectors, TLS setup, `arch_prctl`, and FS/GS
  base behavior. ✅
- Complete instruction coverage exercised by the dynamic loader and libc. ✅ (musl and glibc loaders both run)
- Port signals, alternate signal stacks, and signal return frames to virtual
  CPU state. 🔶 (registration + fatal-signal semantics; no handler delivery)
- Build versioned minimal root images with explicit licenses and manifests. 🔶 (Alpine minirootfs pinned by sha256; no per-package license manifest yet)

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
- Test races, cancellation, signals during waits, and process-image replacement. 🔶 (races/exec covered; cancellation and signal-in-wait pending)

Exit gate:

- Thread, futex, child-process, and exec fixture suites pass. ✅
- Repeated runs from the same checkpoint produce the same scheduled event
  sequence in deterministic mode. ✅ (identical output and instruction counts across runs)
- Worker cancellation cannot leave committed storage in a partial state. ⬜ (browser-host work)

## Milestone 5: Event Loop and Networking 🔶

**Outcome:** interactive network clients and event-driven runtimes work in the
browser.

Work:

- Finish pipe, socketpair, eventfd, timerfd, poll, select, and epoll behavior
  against browser-host readiness events. ✅ (against the broker readiness interface)
- Implement DNS and socket mediation through an explicit network broker. ✅
  (two brokers over one boundary: host sockets natively, and a command stream
  the browser host carries out over a WebSocket relay)
- Support authenticated HTTPS from guest userland without exposing browser
  credentials to unrelated agents. 🔶 (guest TLS with full certificate-chain, SAN, and validity verification against a guest-installed trust anchor; credential injection pending)
- Record network inputs for replay and receipt classification. ⬜
- Define offline, denied, timeout, reconnect, and proxy-failure behavior. 🔶
  (denied and timeout defined, including a browser guest with no relay and a
  destination the relay refuses; reconnect and proxy pending)

Exit gate:

- HTTP, HTTPS, DNS, pipe, and epoll fixture suites pass. ✅ (natively, and
  HTTP over a relayed socket in Chromium, Firefox, and WebKit)
- A long-running event loop survives transient network failure and browser
  tab suspension. ⬜
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

- `openfox --version` and help complete in a clean browser profile. ✅ (native; browser run pending the 97 MB image delivery)
- OpenFox performs one scripted network-backed agent task against a mounted
  test repository. ✅
- Configuration and repository changes survive reload and explicit resume. ✅ (filesystem snapshot restored into a fresh machine)
- A 60-minute interactive soak test completes without kernel corruption or
  unbounded memory growth. 🔶 (bounded 25-round soak green; caught and fixed a cross-process physical-memory leak; full 60-min pending)

## Milestone 7: Codex and Claude Code 🔶

**Outcome:** pinned releases of both coding agents are usable for sustained,
interactive browser sessions.

Each agent receives a separate workload manifest and compatibility report.
Runtime dependencies must be discovered from the pinned release rather than
assumed from historical packaging.

**Runtime foundation (done).** Both agents are Node.js applications, so a
stock Node running is the reduction. A stock `node` (v24, glibc) now runs
scripts to a clean exit — `node -e "console.log(...)"` executes and array/
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
  access. 🔶 (host Node and a static Codex binary run via `run_guest`; no
  packaged, browser-delivered agent image yet)
- Complete PTY behavior, terminal resize, signals, subprocess trees, pipes,
  temporary files, file watching, Git operations, and authenticated HTTPS.
  🔶 (signals incl. real SIGCHLD delivery, pipes, subprocess trees incl.
  vfork semantics, temp files, and authenticated HTTPS are exercised by the
  real Codex `exec` run, which also drives model-authored file edits and
  child shell commands; the host `git` binary runs status/diff/add/commit/
  log in the guest (gated by `tests/git.rs`); pseudoterminals —
  openpty/forkpty, /dev/ptmx, /dev/pts, controlling terminal, termios, window
  size, and SIGWINCH-on-resize — work, including a program a shell started in
  its own process group, and the real Codex TUI renders and takes input on a
  host-driven stdio pty; file watching is not started)
- Mount a repository with explicit read/write capabilities. 🔶 (host
  directories mount read/write via `run_guest`; a repository with real Git
  history is the next target)
- Provide controlled environment variables and secret handles. 🔶 (env + M6
  secret injection exist; per-agent handles not wired)
- Test tool execution, cancellation, interrupted network calls, context
  persistence, browser reload, and checkpoint resume. ⬜
- Maintain per-version instruction, syscall, and performance regression data.
  ⬜

Exit gate for each agent:

- Version and help commands run from a clean browser profile. ⬜ (blocked on
  the agent images; the Node runtime under them runs)
- Authentication can be supplied without baking secrets into an image. 🔶
  (real credentials mount at runtime from a host directory and drive an
  authenticated model call; per-agent secret handles and the browser path
  are pending)
- The agent reads a repository, edits a file, runs a command, and reports the
  result through the terminal. 🔶 (Codex `exec` does this natively via
  `run_guest`; the browser-profile path remains)
- Child processes, cancellation, and terminal resize behave correctly. 🔶
  (child processes and vfork spawns work; terminal resize delivers SIGWINCH,
  and a full-screen program repaints from a browser window resize with nothing
  typed — gated in Chromium, Firefox, and WebKit; Codex's interactive TUI
  quits cleanly on Ctrl-C natively, not yet in a browser profile)
- A checkpointed session resumes after browser reload with filesystem state
  intact. ⬜
- A multi-hour soak test has bounded memory, storage, and event-log growth. ⬜

The milestone is complete only when both agent profiles pass independently.

## Milestone 8: Performance, Security, and Release ⬜

**Outcome:** correctness-complete workload profiles become a supportable web
runtime.

Work:

- Profile executed blocks and translate only proven hot paths to WebAssembly.
- Add block caching, invalidation, tiering, SIMD fast paths, and syscall fast
  paths without changing architectural results.
- Fuzz instruction decoding, memory translation, ELF loading, syscalls, image
  parsing, snapshot restore, and browser messages.
- Define memory, CPU, storage, network, and event-log quotas per agent.
- Add signed workload manifests, reproducible images, dependency licenses,
  security policy, and vulnerability response procedures.
- Add compatibility dashboards for supported browsers and pinned workload
  versions.
- Audit credential boundaries, host messages, guest memory, and snapshot data.

Exit gate:

- Optimized and interpreter modes pass the same architectural trace suite.
- Supported workload profiles meet published startup and interactive latency
  budgets.
- Corrupt images, snapshots, and browser messages fail closed.
- Release artifacts are reproducible and carry complete dependency metadata.

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
   memory checks, and syscall dispatch caching.
3. **Hot-block translator:** selected x86-64 blocks translated to WebAssembly,
   guarded by page versions and deoptimized on invalidation or uncommon exits.

Release performance budgets will be set after the BusyBox and dynamic ELF
baselines produce representative measurements. Until then, correctness,
bounded memory, and actionable diagnostics are the gates.

## Major Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Long-tail x86-64 instructions | Target applications fail late in startup | Trace pinned workloads, add precise illegal-instruction reports, grow fixtures incrementally |
| Native architecture coupling | Linux compatibility cannot run over virtual CPU state | Introduce `GuestMemory` and platform traits before porting modules |
| Browser memory limits | Large runtimes exhaust contiguous WebAssembly memory | Use sparse guest pages, quotas, eviction, and measured workload images |
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
  webtos-kernel/    # agents, capabilities, scheduler, state, receipts
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

## Supporting Plans

The existing plans remain useful for deep native Linux semantics, memory, and
contract work, but they are subordinate to this roadmap:

- [`TODO-linux-maturity.md`](docs/plans/TODO-linux-maturity.md)
- [`TODO-linux-runtime.md`](docs/plans/TODO-linux-runtime.md)
- [`TODO-linux-substrate-depth.md`](docs/plans/TODO-linux-substrate-depth.md)
- [`TODO-memory-subsystem.md`](docs/plans/TODO-memory-subsystem.md)
- [`TODO-professional-uptake.md`](docs/plans/TODO-professional-uptake.md)
- [`TODO-runtime-semantics.md`](docs/plans/TODO-runtime-semantics.md)
- [`TODO-proof-contract-platform.md`](docs/plans/TODO-proof-contract-platform.md)

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
