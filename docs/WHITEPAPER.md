# webTOS White Paper

**Linux Software, Delivered by the Browser**

**Version:** Draft v2.0 · 2026-08-28
**Status:** Product and vision white paper
**Companions:** [ROADMAP](../ROADMAP.md) (milestones and exit gates) ·
[Use cases](USE-CASES.md) (what the runtime is for) ·
[Performance](performance.md) (measured throughput, memory, and method)

This paper states what webTOS is, why it should exist now, where it sits
against the alternatives, why it can be defended, and what could kill it. It
makes no adoption, revenue, or price predictions. Every capability claim is
either shipped and verifiable in this repository, or explicitly labelled as
roadmap — and the section that says which is which is written to be checked.

---

## Abstract

webTOS runs unmodified Linux x86-64 binaries inside a browser tab. Not a port,
not a reimplementation in JavaScript, and not a container on someone else's
machine: the same ELF that runs on a Linux host, executing in the page, on a
software x86-64 CPU and the operating-system half of the Linux ABI, both
compiled to WebAssembly.

The workload that makes this worth doing is the coding agent. Agents ship as
pinned Linux x86-64 releases, and running one for a user currently means a
choice between two bad options: put it on your server, where you inherit the
compute bill, the customer's data, and the blast radius; or install it on the
user's machine, where there is no boundary at all. The browser is the one
runtime that is already everywhere, already sandboxed, and free to enter — and
until now it could not run a Linux binary.

The product goal is concrete and falsifiable: a supported browser starts a
clean webTOS environment and runs pinned releases of OpenFox, Codex, and
Claude Code through real coding tasks — with persistent repositories,
subprocesses, terminals, authenticated HTTPS, and recovery after a browser
reload. Anything short of that gate is an engineering milestone, not
completion.

The one-line pitch: **the link is the install, and the tab is the computer.**

---

## The Core Innovation

The core innovation is not x86 emulation in isolation. It is a
**capability-bounded Linux computer inside a browser tab**: an execution
environment substantial enough for unmodified Linux agents and tools, local
enough to keep compute and workspace state on the user's machine, and bounded
enough that software receives only the authority the host deliberately
grants.

🔸 **The program, not a port.** webTOS runs existing Linux x86-64 ELF binaries
rather than requiring a WebAssembly rebuild, a JavaScript reimplementation,
or a vendor-maintained browser edition. Compatibility therefore follows the
software users already depend on, including dynamic loaders, subprocesses,
signals, terminals, and ordinary Unix tools.

🔸 **A third deployment shape for agents.** A coding agent no longer has to run
only in an operator's cloud container or as an unbounded local installation.
It can run on the user's hardware inside the browser sandbox, opened through a
link and isolated from the host operating system.

🔸 **Useful agency with explicit authority.** The guest can perform real work,
but it begins without ambient access to the network, credentials, host files,
or external services. The browser host grants narrowly scoped capabilities,
and graph or agent behavior may rearrange granted authority but cannot create
new authority.

🔸 **Budgets and state as runtime primitives.** CPU, memory, storage, network,
and event-log limits are enforced inside the execution model; persistent
filesystem state can survive a browser reload; and content-addressed manifests
bind large, lazily delivered workloads to the bytes the host approved.

🔸 **An execution substrate for intent-native applications.** Generating an
interface is only the visible half of a dynamic application. webTOS supplies
the repository, processes, tools, state, permissions, approval boundaries, and
resource budgets behind that interface. The current Linux runtime is concrete;
Application Graphs and public composition APIs are explicitly roadmap work.

These properties are valuable as a system. An emulator without the authority
boundary is only another virtual machine; a generated interface without the
execution substrate is only generated markup; and a remote sandbox does not
provide local-by-architecture execution. webTOS combines the three into one
browser-native runtime.

---

## 1. The Argument in One Page

1. **The software worth running ships as Linux x86-64 binaries.** Coding
   agents, developer tools, and the long tail of Unix software are released
   as pinned ELF binaries. Vendors will not rebuild them for a new ABI on
   somebody else's schedule.
2. **Running that software for a user has only had two shapes, and both cost
   something.** On your server you hold the compute, the data, and the blast
   radius. On their machine there is an install, no boundary, and no way to
   say what the program may reach.
3. **The browser is the third shape, and it was unavailable.** It is the most
   widely deployed and most aggressively sandboxed runtime in existence, with
   zero install and a permission model users already understand — but it
   cannot execute an ELF.
4. **webTOS makes it able to.** A software x86-64 CPU and the OS side of the
   Linux ABI, in WebAssembly, with a browser host supplying storage, a
   terminal, and a relayed network path. No remote compute backend.
5. **What the tab adds is not just distribution — it is a boundary.** The
   guest has no network until the page asks for one, and then only to
   destinations an allowlist names. Memory, CPU, storage, and network bytes
   are bounded. Credentials are injected at runtime and scoped. Identical
   input retires an identical instruction stream in every engine, checked
   against recorded traces.
6. **The hard part is the compatibility long tail, and it is being walked.**
   BusyBox, the real `git`, a C toolchain that forks a compiler, an
   assembler, and a linker, real `vim` on a pseudoterminal, `curl` against a
   live server, a 52 MB agent binary in a tab, and both modes of a real
   coding agent — each one run rather than asserted.

---

## 2. The Workload That Made This Worth Doing

Until recently there was no program worth this much effort to run in a
browser. Now there is a category.

Coding agents — Claude Code, Codex, and open agents such as OpenFox — are run
for hours, given repository access, handed credentials, and paid for. They are
also unusually demanding tenants: pseudoterminals with job control, subprocess
trees, `git`, authenticated HTTPS, file watching, and sessions that must
survive interruption. That makes them the right forcing function. A runtime
that hosts them hosts almost anything in their class, and the failures they
expose are the failures every other Unix program would have exposed later.

They also sharpen the question of *where* software should run. An agent that
edits your repository, reads your data, and holds your credentials is exactly
the workload you least want on a multi-tenant server you cannot inspect — and
exactly the one you least want running unbounded on the machine itself. The
interesting position is neither: the user's own hardware, inside a sandbox,
under authority someone had to grant on purpose.

---

## 3. Why Now

Three curves crossed.

**The workloads became real.** See §2. Five years ago the honest answer to
"why would you run a Linux binary in a browser" was "for a demo".

**The browser became an OS-grade target.** WebAssembly is mature and
near-universal; workers give real execution contexts; OPFS gives fast,
persistent, origin-private storage; and the security model is the most
battle-tested sandbox ever deployed. Hosting a software CPU, a filesystem, and
a process model entirely inside a tab is now feasible with no server-side
execution at all.

**The trust question became a blocker.** Enterprises adopting agents hit the
same wall: the agent acts with its operator's full authority, over a network
nobody scoped, leaving a log nobody can check. "What could this program
reach, and what did it actually do?" deserves a better answer than a promise,
and the answer is easier to give when execution is bounded and reproducible
by construction rather than by policy.

---

## 4. The Product

### 4.1 What webTOS is

webTOS puts the operating-system half of Linux — scheduler, virtual memory,
virtual filesystem, processes, signals, sockets, terminals — plus a software
x86-64 CPU inside a browser tab. Unmodified Linux x86-64 binaries run against
it. The browser supplies distribution, sandboxing, storage, and transport; it
does not supply the execution model. Guest execution and runtime state stay in
the browser.

For the user, the experience is: open a link, get a Linux environment with the
tool already in it. Close the tab; reopen it; the filesystem and the session
are still there. Share the link; the recipient gets the same environment with
zero installation. Nothing touches the host machine outside the browser
sandbox.

For the program, the environment is stricter than a Linux box. It starts with
no network at all. It gets one only when the page configures a relay, and then
only to the destinations that relay was told to allow. Its memory, CPU,
storage, and network use are capped, and crossing a cap produces an errno it
already knows how to handle rather than a dead tab. Its execution is
deterministic and can be recorded and replayed.

### 4.2 The gates

Development is gated by real workloads, not instruction counts:

```text
static hello
    -> static BusyBox
    -> dynamic Linux ELF
    -> threads and event-driven networking
    -> OpenFox
    -> Codex and Claude Code
```

The final gate requires real interactive sessions: child processes, repository
access, persistent configuration, authenticated HTTPS, correct terminal
behaviour, and recovery after a browser reload — per pinned agent version,
with published compatibility evidence. A demo that reaches its first prompt
does not pass a gate.

### 4.3 What exists today

- **The engine runs in three browsers, and they agree.** A pure-Rust software
  CPU — an interpreter over a production-grade instruction decoder — compiles
  to WebAssembly and executes unmodified Linux binaries. A 39-check matrix
  runs in Chromium, Firefox, and WebKit on every change and compares
  instruction counts across them: identical input retires an identical
  instruction stream in all three, and one recorded architectural trace is
  reproduced register for register in each.
- **The Linux userland is deep.** Dynamic linking through the real musl and
  glibc loaders; copy-on-write fork, vfork, threads, futexes, and real signal
  delivery over a deterministic scheduler; process groups and job control on
  pseudoterminals; brokered networking, denied by default, with the guest
  performing its own DNS and TLS; filesystem snapshots that survive a reload.
- **Real software runs, and not only the software we chose.** BusyBox applets
  and a shell; the host `git` doing real repository operations; a C toolchain
  where a shell forks the compiler driver, which execs the compiler, the
  assembler, and the linker, and then runs the binary that came out; real
  `vim` with eleven shared libraries and an embedded Python, full-screen on a
  pseudoterminal; `curl` against a live streaming server. Details and numbers
  are in [Use cases](USE-CASES.md).
- **A real coding agent completes real work.** The stock Codex CLI runs an
  authenticated non-interactive session end to end — discovering the CA store,
  performing TLS handshakes, calling the API, editing a file, running a shell
  command through a pseudoterminal it allocated, reporting what that
  subprocess printed, and exiting cleanly. Its interactive TUI renders
  full-screen, takes keystrokes, and quits cleanly. Both on the native runner.
- **A real agent image runs in a tab.** A 52 MB Linux x86-64 agent binary
  streams into the guest filesystem and a browser cache as it downloads,
  reaches a shell prompt in about three seconds, and executes — in all three
  engines. The browser also has an interactive shell on a pseudoterminal, a
  full-screen editor that repaints when the window is resized, networking
  through a relay that refuses every destination its allowlist does not name,
  and a session that resumes after a real page reload.
- **The boundaries have been swept rather than assumed.** Every argument
  position of every syscall number against a corpus of the ways a number
  breaks code that trusts it — 7,128,576 cases, which found five defects,
  four of them wrapped arithmetic visible only under an overflow-checking
  profile. Every opcode in all four decoder maps under seventeen prefix
  combinations, then again truncated against a mapping boundary — 365,568
  sequences. Snapshot restore and ELF loading, both of which failed closed
  only after the sweep found what they did not.
- **What remains is roadmap with exit criteria written down:** carrying
  Codex's own image into the browser, sustained Claude Code work, general
  multi-block JIT regions, the remaining 128-bit arithmetic coverage, and the
  release work of milestone 8.

Weighted by engineering effort the roadmap is roughly 94% complete; the
milestone table and its evidence are in [ROADMAP](../ROADMAP.md).

Principles that govern all of it: correctness before speed (interpreter
first, translation later); no silent compatibility lies (unsupported means a
defined error, never fake success); browser authority is explicit;
determinism is end-to-end.

---

## 5. Why the Browser

The obvious objection first: *"Browsers are for documents and apps. Serious
compute belongs in the cloud."* Four answers.

**Distribution is the moat nobody prices in.** Every previous attempt to ship
a new runtime died on distribution: installers, drivers, IT approval, platform
gatekeepers. The browser is the one runtime already deployed on effectively
every machine on earth, with an update channel and a permission model users
already trust. A runtime delivered as a URL skips the entire historical
graveyard. The next big thing tends to look like a toy; a Linux shell in a tab
looks like a toy in precisely that way.

**Local-first is the right trust posture.** An agent editing your repository
and holding your credentials is the workload you want on your own machine,
inside a sandbox, under permissions someone granted deliberately — not on a
multi-tenant server you cannot inspect. Local execution also means the user's
own silicon does the work: no per-second sandbox billing, no cold starts, and
no bill that scales with your users' idle tabs.

**The sandbox is a feature, not a limitation.** webTOS does not fight the
browser's restrictions; it aligns with them. The browser enforces the outer
wall; webTOS enforces the inner order. Storage, network, and credentials cross
the boundary only through explicit host adapters — which is also why the same
runtime can enforce one policy in a tab and a different one natively, without
the guest knowing the difference.

**Snapshot and resume come naturally.** A runtime whose entire state lives in
managed memory and origin-private storage can checkpoint, survive a reload,
and resume a long session — a first-class requirement in the final gate, and a
genuinely hard property for native ad-hoc setups.

The cloud is not the enemy; it is the complement. Heavy fleets stay in
datacentres. The browser gets the person.

---

## 6. What the Runtime Enforces

A sandbox that only promises is a convention, and a convention is optional
under pressure. Four properties are structural here, and each is gated by a
test rather than by intent.

- **No ambient network.** The guest starts with no network whatsoever. It
  gets one only when the page attaches a relay, and the relay refuses every
  destination an `--allow` rule does not name — matched by address, because
  the guest resolves DNS itself and connects to an address. With no rules it
  starts and refuses everything, loudly. It logs every decision, allowed and
  refused alike.
- **Bounds that produce an errno.** Memory, CPU, storage, network bytes, and
  the event log all have ceilings. A workload that will not fit is refused at
  the request rather than dying part-way through; a guest over a limit sees an
  error it already knows how to handle. A program that computes without ever
  entering the kernel used to be outside every mechanism for stopping it —
  that gap is closed.
- **Scoped credentials.** Secrets are injected at runtime, scoped so that a
  program reaches only the files the host named, and kept out of filesystem
  snapshots. An out-of-scope program reads a placeholder rather than an empty
  value that would read as "no key configured".
- **Determinism, checked against a record.** The compatibility layer replaces
  every source of non-determinism at the syscall boundary — time, randomness,
  thread interleaving, address layout, event ordering — with deterministic
  equivalents, and external inputs are recorded for replay. That is gated
  against recorded architectural traces rather than only against another run,
  and reproduced in every browser engine.

What is deliberately *not* claimed: an execution record a third party could
check. Determinism and replay exist; nothing today produces a signed artifact
that binds an output to the code, input, and state that produced it. An
earlier version of this paper described such a system as shipped. It was a
separate bare-metal kernel, it has been removed from this repository, and the
claim went with it.

---

## 7. Architecture in Brief

Three layers, narrow contracts, one ownership rule:

```text
Linux x86-64 workload
        |
        v
x64-engine        CPU, decoder, interpreter, sparse guest memory
        | CpuExit
        v
linux-compat      ELF, syscalls, processes, VFS, VMAs, futex, epoll
        | HostPlatform
        v
browser-host      workers, terminal, persistent storage, network broker
```

The CPU engine owns instruction semantics; Linux compatibility owns OS
semantics; the browser host owns Web APIs. Performance follows a three-tier
strategy — reference interpreter, cached interpreter, then hot-block
translation to WebAssembly — with the architectural rule that optimized and
interpreted execution must pass the same trace suite.

Two things this architecture deliberately does **not** claim:

- It is not a PC emulator. webTOS is a focused Linux x86-64 userspace
  environment; there is no BIOS, no device model, no guest kernel.
- It does not claim hardware attestation. In the browser the sandbox belongs
  to the browser's trusted computing base, and webTOS's reproducibility claim
  rests on determinism and replay alone.

### 7.1 Execution model: interpreter first, JIT verified second

webTOS lifts each basic block of x86-64 into an intermediate representation,
caches it, and interprets it as the reference execution path. Hot blocks can
then translate from p-code to WebAssembly at run time: the browser compiles the
generated Wasm and runs it against the engine's shared memory. Register-only
self-loops and host-memory self-loops can become one Wasm region, while a
block that is unsupported, cold, exceptional, or debugging-sensitive remains
on the interpreter path.

**Why interpreter first.** The claim webTOS makes is that the same input
produces the same instruction stream everywhere. The translation tier is held
to the interpreter's result and to architectural traces, including faults and
fuel accounting, rather than being a second source of semantics.

**What the measurements said.** The interpreter sustains roughly half of
native throughput in the fast browser engines — about 11 M instructions per
second against 21 M — and about a tenth of that in the slowest. Profiling a
real agent's startup found no hot path worth translating; the first
optimization that paid was a content-addressed lift cache, which took `execve`
from 48.8 ms to about 2 ms, and tiered lifting, which cut a cold agent start
from 5.3 s to 1.4 s. The JIT then removed the hot-loop ceiling: self-loop
regions reach roughly 30x the interpreter in V8 for both register and
fast-path memory loops. Its remaining coverage work is cross-lane 128-bit
arithmetic and general multi-block regions.

**Where it is genuinely needed.** Not for agents, whose bottleneck is the
model and the network. For compute: a C compiler takes about twelve seconds to
build a trivial program, which is usable and not comfortable. Translation is
what closes that gap, and the numbers are in [Performance](performance.md).

---

## 8. Competitive Position

Every category below contains respectable work; none occupies the same
position.

| Approach | What it is | Where it differs |
|---|---|---|
| Cloud agent sandboxes | Server-side isolated execution, billed per instance | Remote: cold starts, per-second billing, the operator holds the data and the blast radius. A complement more than a competitor |
| Language-runtime shells in the browser | A JavaScript or toolchain runtime running in a tab | Runtime scope, not OS scope: no unmodified x86-64 binaries, so the tool is a reimplementation of the tool |
| In-browser x86 engines | Machine or userspace x86 emulation in a tab, the mature ones translating x86 to WebAssembly at run time | Proves the approach and are faster today. The mature ones are proprietary and separately licensed, which makes the engine somebody else's to fix and to price. webTOS's engine is MIT and in this repository, and it is built around a determinism claim those are not |
| Syscall-interception sandboxes | User-space Linux syscall reimplementation for containers | Server-side hardening; inherits Linux's ambient model; no browser story |
| Recompile-to-Wasm system interfaces | A portable Wasm system interface | Requires recompilation and often source. The binary you must run is the one the vendor pinned |

The defensible intersection: **unmodified Linux x86-64 software + fully local
browser execution + explicit, deny-by-default authority + determinism that is
gated rather than asserted — on an engine that is open and ours.** Each
pairwise combination exists somewhere; the four together do not.

---

## 9. Moat

**The compatibility grind.** Running real software is a long-tail war —
instruction quirks, syscall semantics, loader behaviour, PTY edge cases —
fought binary by binary, and largely serial: failures are discovered by
running real workloads, not enumerated up front. Wine and Proton demonstrate
both the size of that moat and its durability. The corpus compounds: 98 native
cases, a pinned fixture-and-trace set, a 39-check matrix per browser engine,
and workload gates that include a compiler toolchain and an hour-long soak. A
well-funded fast-follower still has to walk the same tail.

**Determinism is architectural.** End-to-end determinism — CPU, scheduling,
time, randomness, lock ordering, external input recording — cannot be
retrofitted onto a runtime built without it; it constrains every subsystem
from day one. A competitor adding replay later faces a rewrite, not a feature.

**Owning the engine.** The fastest in-browser x86 engines are proprietary and
licensed. Anyone building on one inherits somebody else's roadmap, bug
queue, and price list. webTOS's engine is MIT and in this repository, from the
instruction specification up. That is slower today and unblockable
tomorrow.

**Distribution compounds.** Every shared webTOS link is also a distribution
event for the runtime itself. Tools with zero-install sharing loops
historically out-distribute technically superior installed alternatives.

What is *not* claimed as moat: the browser APIs (available to everyone), the
interpreter technique (established), or secrecy (the code is open). The moat
is accumulated correctness and an architecture a competitor would have to
start over to match.

---

## 10. Who Needs This

Stated as segments with a concrete first user, not as a top-down market size:

- **Agent and tool vendors** — ship the thing as a link: sandboxed
  demo-to-production environments, reproducible bug reports where a failing
  session is a replayable artifact, and per-version compatibility evidence.
- **Enterprises adopting agents** — a defensible answer to "what could it
  reach": no network but the allowlist, credentials injected rather than baked
  into an image, bounded resources, and execution on the employee's own
  machine inside the security model IT already governs.
- **Anyone running untrusted code** — online judges, CTF platforms, plugin
  systems, and "run this user's script" features, where the compute is the
  submitter's own browser and an escape meets a trapped tab rather than your
  infrastructure.
- **Privacy-bound processing** — legal, medical, and financial files handled
  by the mature command-line tools that already exist for them, with no
  gateway configured and therefore nothing to leak through.
- **Education and evaluation** — a full Linux environment for anyone with a
  browser: courses, CTFs, benchmarks, and research artifacts that replay
  identically for everyone who opens them.

The wedge is deliberately narrow: **run a pinned coding agent in a tab,
well.** That single capability is independently valuable, brutally hard to
fake — hence the gates — and generalizes: an environment good enough for a
coding agent is good enough for most of the long tail.

On business model: the runtime is MIT open source and this paper makes no
revenue projections. The monetizable surfaces, when the workload gates are
passed, are the classic open-core set — enterprise deployment and compliance
tooling, managed persistence and network brokerage — each priced on value
above the free runtime, never by closing the runtime.

---

## 11. What Could Kill This

| Risk | Reality | Response |
|---|---|---|
| **Performance ceiling** | An interpreter in Wasm runs orders of magnitude below native. Some workloads will never fit | Agent workloads are I/O- and network-bound at interactive timescales, and gates are latency-budget based rather than throughput based. Compute-bound work genuinely needs the translation tier, which is roadmap milestone 8, attempted only after correctness gates and required to pass the same traces. If interactive budgets cannot be met for the pinned workloads, that gate fails visibly — by design |
| **Long-tail incompatibility** | A pinned release may fail deep in startup on one missing instruction or syscall | The entire methodology exists for this: trace pinned workloads, fail explicitly, grow fixtures. Never fake success — a wrong result is worse than a loud failure |
| **Browser platform drift** | Memory limits, storage quotas, worker semantics, and store policies differ and change | Content-addressed demand paging and quotas are regression-gated in Chromium, Firefox, and WebKit; asynchronous OPFS/network fallback avoids depending on one vendor's synchronous API |
| **Workload release drift** | New agent versions change runtime requirements | Version pinning with published per-version compatibility reports; drift becomes a documented delta, not a silent break |
| **A platform vendor ships it natively** | A browser or model vendor could ship a first-party agent sandbox | Likely partial overlap — their own agent, their own browser. A neutral substrate that runs all of them, locally, under one authority model, is a different product. Being MIT makes adoption cheaper than replication |
| **Security of the broker boundary** | The credential and network broker is the highest-value target | Deny-by-default network, scoped secret injection, snapshot exclusion of credentials, adversarial sweeps of every parser and boundary, fail-closed on corrupt input |
| **Believing our own demos** | The perennial emulation failure mode: the demo works, the semantics are stubbed | The gates forbid it: soak tests, reload recovery, an explicit-error policy, and a rule that a test which cannot fail is not evidence |

---

## 12. Milestones and How to Verify

Full details with exit criteria live in [ROADMAP](../ROADMAP.md).

| Milestone | Outcome | Status |
|---|---|---|
| M0 | Baseline locked; fixtures and traces pinned and versioned | ~93%: four reference traces reproduced natively and in three engines; `WEBTOS_REQUIRE_FIXTURES=1` makes a skip a failure |
| M1 | Static `hello` in a browser worker | Done; the engines agree instruction for instruction |
| M2 | Static BusyBox: shell, files, persistence across reload | Done, verified in all three engines |
| M3 | Dynamic Linux ELF via the real loader | Done, musl and glibc |
| M4 | Threads, fork/exec, deterministic scheduling, signals | Done, including adversarial and blocked-signal gates |
| M5 | Event loops, brokered networking, HTTPS | Done: guest TLS, deny-by-default relay in three engines, interruptible waits gated through a socket; native recording and offline replay exist, while browser-host replay integration remains open |
| M6 | OpenFox completes a real agent task | Done, including in a browser, and a 1,000-round soak bounded in memory, filesystem, and block table |
| M7 | Codex and Claude Code: sustained interactive sessions | ~90%: both Codex modes run end to end and a session that does work finishes; carrying Codex's image into a tab and the Claude Code profile remain |
| M8 | Performance tiers, sweeps, quotas, signed releases | ~89%: measured baseline, lift cache, tiered lifting, hot-block translation, regions, and resource caps landed; general multi-block regions, 128-bit arithmetic coverage, and release integration remain |

Verification is the point: the repository builds, the native suite runs 98
cases with skipping forbidden on a host that can run everything, and a
39-check matrix runs per browser engine. Every completed claim above
corresponds to tests and fixtures in-tree, and the performance claims to
harnesses that print their numbers rather than assert them. Claims and code
travel together.

---

## 13. Anticipated Questions

**"Isn't this just a slower VM?"** A VM reproduces a machine; webTOS supplies
the operating system a Linux binary expects and nothing else. What it sells is
not cycles: it is the real binary, on the user's own machine, reachable by a
link, under authority someone had to grant. On the measured side the gap is
smaller than the architecture suggests — roughly half of native throughput in
the fast engines (§7.1).

**"Is it a JIT?"** It is interpreter-first with a hot-block JIT. P-code blocks
that the translator understands become WebAssembly; self-loop regions avoid a
call per iteration, while unsupported or uncommon paths fall back to the
interpreter. §7.1 explains the trace-equivalence gate and the remaining
general-region and 128-bit coverage work.

**"Why would anyone run this locally when clouds exist?"** Data gravity (the
repository and the credentials are here), cost (the user's silicon is free and
an idle tab bills nobody), trust (a sandbox with a named allowlist beats a
remote black box), and distribution (a link, not an account).

**"Is this a crypto project?"** No. No token is required, and this paper
prices nothing. An earlier version described execution receipts feeding a
settlement layer; that code lived in a separate bare-metal kernel which has
been removed, and nothing in the runtime produces such a record today. If that
capability returns it will arrive as a milestone with an exit gate, and this
paper will say so before it says anything else.

**"Why not recompile everything to Wasm?"** Because the software that matters
ships as pinned Linux x86-64 releases, and vendors will not rebuild for a new
ABI on a new platform's schedule. Meeting binaries where they ship is the
entire lesson of Wine, Proton, and Rosetta.

**"What if a model vendor ships their own sandbox?"** They likely will — for
their own agent, on their own infrastructure. The neutral substrate that runs
all of them, locally, under one authority model, is a different product with a
different owner. Neutrality here is not a weakness; it is the specification.

**"What's genuinely hard here?"** The compatibility long tail — years of
accumulated fixtures, which is the moat — and end-to-end determinism, an
architectural property a competitor cannot retrofit. Both are grind-shaped,
which is precisely why they defend.

**"How do we know the team won't fake progress?"** The methodology makes
faking expensive: workload gates with soak tests and reload recovery, an
explicit-failure policy, a requirement that a new test be shown to fail before
it is believed, and a status section written to be checked line by line. This
paper lost a section to that rule rather than keeping a claim whose code had
been deleted.

---

## 14. Closing

The software people want to run ships as Linux binaries, and the machine they
most want to run it on is their own. Until now those two facts pointed in
opposite directions: running it locally meant an install and no boundary,
running it safely meant running it somewhere else.

webTOS is the third answer — the real binary, on the user's own machine,
inside the sandbox everybody already has, reachable by a link and bounded by
something other than a promise.

The link is the install. The tab is the computer.
