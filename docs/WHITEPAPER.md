# webTOS White Paper

**An Operating System for AI Agents, Delivered by the Browser**

**Version:** Draft v1.2 · 2026-08-27
**Status:** Product and vision white paper
**Companions:** [Yellow Paper](specs/yellowpaper.md) (engineering specification) ·
[ROADMAP](../ROADMAP.md) (milestones and exit gates) ·
[Performance](performance.md) (measured throughput, memory, and method)

This paper states what webTOS is, why it should exist now, who it competes
with, why it can be defended, and what could kill it. It makes no adoption,
revenue, or price predictions. Every capability claim is either shipped and
verifiable in this repository, or explicitly labeled as roadmap.

---

## Abstract

webTOS is an AI-agent-first operating system kernel that runs inside the
browser. It executes unmodified Linux x86-64 software — up to and including
real coding agents — locally in a browser tab, on top of a kernel where agents
are the first-class abstraction: explicit capabilities instead of ambient
authority, metered energy budgets instead of unbounded execution, auditable
mailboxes instead of ad-hoc IPC, and hash-chained, replayable execution
records instead of best-effort logs.

The product goal is concrete and falsifiable: a supported browser starts a
clean webTOS environment and runs pinned releases of OpenFox, Codex, and
Claude Code through real coding tasks — with persistent repositories,
subprocesses, terminals, authenticated HTTPS, and recovery after a browser
reload. Anything short of that gate is an engineering milestone, not
completion.

The one-line pitch: **the link is the install, and the tab is the computer.**

---

## 1. The Argument in One Page

1. **Software ate the world; agents are now eating software.** The unit of
   software is shifting from applications operated by humans to agents that
   act on their own. Agents hire, spend, produce, and transact.
2. **Agents do not have an operating system.** They run as ordinary processes
   with their operator's full authority, unmetered and unaudited, on
   machine-specific installs. Every OS abstraction they inherit — user,
   process, file, root — was designed for humans.
3. **An agent OS needs different primitives:** identity, delegated and
   bounded authority, budgets, auditable communication, and verifiable
   execution. These must be kernel primitives, not conventions bolted onto a
   framework.
4. **The browser is the distribution channel.** It is the most widely
   deployed, most aggressively sandboxed runtime in existence. Zero install,
   instant revocation, capability prompts users already understand, and
   persistent local storage. Distribution is the historical failure mode of
   new operating systems; the browser removes it.
5. **The enabling technologies just matured.** WebAssembly is fast and
   universal; browser workers, OPFS, and modern storage make a persistent
   kernel host feasible; and — decisively — coding agents became real
   economic workloads worth running.
6. **webTOS is the synthesis:** a mature, from-scratch agent kernel (native
   x86-64 reference implementation with a deterministic Linux compatibility
   layer already running OpenJDK-class workloads) being delivered through a
   software x86-64 engine into the browser, gated by real workloads at every
   milestone.

---

## 2. Software Ate the World. Agents Are Eating Software.

In 2011, "software is eating the world" was a claim about companies: every
industry would be run by software. That thesis won. The next shift is
happening inside software itself: the operator is no longer necessarily a
person.

A coding agent clones a repository, edits files, runs tests, and opens a pull
request. A procurement agent compares quotes and commits budget. A research
agent spends compute against a deadline. These are not applications waiting
for clicks; they are **economic actors** — what analysts call machine
customers — that discover work, execute it, and settle for it.

Every layer of the modern stack is being rebuilt for this shift — models,
frameworks, payment rails, identity. Except the layer at the bottom. When an
agent actually executes, it lands on an operating system designed in the
1970s for human operators:

| The OS gives agents | What agent operation actually requires |
|---|---|
| Processes and threads | Agents with budgets and parent-child delegation |
| Ambient user permissions | Explicit, delegatable, revocable capabilities |
| A shared filesystem | Isolated, provable state |
| Unmetered CPU | Metered execution that maps to cost |
| Ad-hoc pipes and sockets | Typed, auditable communication |
| Best-effort logs | Replayable, verifiable execution records |

Today the gap is papered over with containers, cloud sandboxes, and
framework-level conventions. Those are perimeter defenses around the wrong
abstraction. webTOS's position is that the agent is the correct kernel
abstraction, and the operating system should be rebuilt around it.

---

## 3. Why Now

Three curves crossed.

**The workloads became real.** Until recently there was no economically
meaningful program worth this effort. Now there is a category: coding agents
(Claude Code, Codex, and open agents such as OpenFox) that people run for
hours, give repository access, and pay for. They are also demanding tenants —
PTYs, subprocess trees, git, HTTPS, file watching — which makes them the
perfect forcing function: an OS that runs them runs almost anything in their
class.

**The browser became an OS-grade target.** WebAssembly is mature and
near-universal; workers give real parallel execution contexts; OPFS gives
fast, persistent, origin-private storage; the security model is the most
battle-tested sandbox ever deployed. It is now feasible to host a kernel,
a software CPU, and a filesystem entirely inside a tab — with no server-side
execution at all.

**The trust gap became a blocker.** Enterprises adopting agents hit the same
wall: agents act with their operator's full authority and leave no verifiable
record. "What exactly did the agent do, with what authority, at what cost?"
currently has no cryptographic answer. Verifiable, metered execution — long
argued as the missing infrastructure for machine-to-machine commerce — is
exactly what a receipt-producing deterministic kernel provides.

None of these three existed five years ago. All three exist now.

---

## 4. The Product

### 4.1 What webTOS is

webTOS puts a complete operating system — scheduler, virtual memory, virtual
filesystem, capability system, and a software x86-64 CPU — inside a browser
tab. Unmodified Linux x86-64 binaries run against it. The browser supplies
distribution, sandboxing, storage, and transport; it does not supply the OS
model. No remote compute backend is required: guest execution and kernel
state stay in the browser.

For the user, the experience is: open a link, get a Linux machine with an
agent in it. Close the tab; reopen it; the filesystem and the session are
still there. Share the link; the recipient gets the same environment with
zero installation. Nothing touches the host machine outside the browser
sandbox.

For the agent, the environment is stricter than any Linux box: it has an
identity, a capability set, an energy budget, mailboxes, and a private
keyspace. Network access is denied by default and brokered when granted.
Every instruction and syscall is metered. Execution is deterministic and
produces replayable, hash-chained records.

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

The final gate requires real interactive sessions: child processes,
repository access, persistent configuration, authenticated HTTPS, correct
terminal behavior, and recovery after a browser reload — per pinned agent
version, with published compatibility evidence. A demo that reaches its first
prompt does not pass a gate.

### 4.3 What exists today (honest status)

- **The native reference kernel is mature.** A from-scratch bare-metal x86-64
  kernel with agents, capabilities, mailboxes, energy accounting, Merkle
  state, checkpoints, execution receipts, and a deterministic Linux
  compatibility layer (100+ syscalls) that runs OpenJDK-, Node.js-, and
  CPython-class workloads under QEMU, with validation harnesses in-repo.
- **The browser x86-64 engine is running, in three engines.** A pure-Rust
  software CPU (interpreter over a production-grade instruction decoder)
  compiles to WebAssembly and executes unmodified Linux binaries. A matrix of
  27 checks runs in Chromium, Firefox and WebKit on every change, and it
  compares instruction counts across them: identical input retires an
  identical instruction stream in all three.
- **The Linux userland is deep.** Dynamic linking through the real musl and
  glibc loaders; copy-on-write fork, vfork semantics, threads, futexes, and
  real signal delivery over a deterministic cooperative scheduler; brokered
  networking (denied by default) with guest TLS; filesystem snapshots that
  persist across reload.
- **A real coding agent completes real work.** The stock, statically linked
  Codex CLI (0.149.1) runs an authenticated `exec` end to end: it discovers
  the CA store, performs TLS handshakes, calls the OpenAI API, edits a file,
  runs a shell command, prints the model's summary, and exits cleanly — 2.37
  billion instructions. Its interactive TUI renders full-screen on a
  pseudoterminal, takes keystrokes, and quits cleanly. Both natively, under
  `run_guest`.
- **A real agent image runs in a tab.** A 52 MB Linux x86-64 agent binary
  streams into the guest filesystem and a browser cache as it downloads,
  reaches a shell prompt in about three seconds, and executes — in all three
  engines. The browser also has an interactive shell on a pseudoterminal, a
  full-screen editor that repaints when the window is resized, and networking
  through a relay that refuses every destination its allowlist does not name.
- What remains is roadmap with exit criteria written down: carrying Codex
  itself into the browser (five times larger, and needing credentials that
  must not be baked into an image), per-agent secret handles, checkpoint
  resume across a reload, the long soaks, and Claude Code.

Principles that govern all of it: correctness before speed (interpreter
first, translation later); no silent compatibility lies (unsupported means a
defined error, never fake success); browser authority is explicit;
determinism is end-to-end.

---

## 5. Why the Browser

The obvious objection first: *"Browsers are for documents and apps. Serious
compute belongs in the cloud."* Four answers.

**Distribution is the moat nobody prices in.** Every previous attempt to ship
a new operating system — or even a new sandbox runtime — died on
distribution: installers, drivers, IT approval, platform gatekeepers. The
browser is the one runtime already deployed on effectively every machine on
earth, with an update channel and a permission model users already trust. A
new OS delivered as a URL skips the entire historical graveyard. The next big
thing tends to look like a toy; a Linux shell in a tab looks like a toy in
precisely that way.

**Local-first is the right trust posture for agents.** An agent editing your
repository, reading your data, and holding your credentials is exactly the
workload you want on your machine, inside a sandbox, under capability
prompts — not on a multi-tenant server you cannot inspect. Local execution
also means the user's own silicon does the work: no per-second sandbox
billing, no cold starts, functional offline.

**The sandbox is a feature, not a limitation.** webTOS does not fight the
browser's restrictions; it aligns with them. The browser enforces the outer
wall; webTOS enforces the inner order (capabilities, budgets, receipts).
Storage, network, and credentials cross the boundary only through explicit,
capability-checked adapters.

**Snapshot and resume come naturally.** A kernel whose entire state lives in
managed memory and origin-private storage can checkpoint, survive a reload,
and resume a multi-hour agent session — a first-class requirement in the
final gate, and a genuinely hard property for native ad-hoc setups.

The cloud is not the enemy; it is the complement. webTOS is the local,
personal, verifiable edge of agent execution. Heavy fleets stay in
datacenters. The two meet through the same protocol layer (§8).

---

## 6. The Kernel Primitives (Why Processes Are Not Enough)

Frameworks try to provide agent governance in userland: permission wrappers,
spend limits in YAML, audit logs in a database. Anything provided by
convention is optional under pressure — a prompt-injected agent does not
respect a convention. webTOS makes the guarantees structural:

- **Capabilities, no ambient authority.** There is no root in the agent
  model. Network, state, spawning, and inter-agent communication each require
  an explicit capability record — inspectable, delegatable, revocable. A
  parent agent can delegate only a subset of its own authority to a child.
- **Energy: metered execution as a kernel invariant.** Every instruction,
  syscall, and message has a cost. Budgets are subdivided parent-to-child,
  never created; exhaustion suspends the agent. Cost control is not a billing
  afterthought — it is the scheduler.
- **Mailboxes: auditable communication.** Bounded, typed, deterministic
  delivery. Every inter-agent interaction is an event on the record.
- **Keyspaces: provable state.** Each agent's storage is an isolated,
  Merkle-backed keyspace; state transitions produce roots that proofs can be
  checked against.
- **Deterministic execution and receipts.** The Linux compatibility layer
  replaces every source of non-determinism at the syscall boundary — time,
  randomness, thread interleaving, lock ordering, address layout, event
  ordering — with deterministic equivalents; external inputs are recorded
  for replay. An execution can therefore bind output to code, input, state,
  and event sequence in a signed receipt that a third party verifies without
  re-running and without trusting the operator.

This is the infrastructure answer to the machine-customer question: agents
that transact need execution that can be *priced* (energy), *bounded*
(capabilities and budgets), and *proven* (deterministic replay and receipts).
A generic sandbox provides none of the three; webTOS provides all three at
the kernel layer, whether or not any blockchain is attached.

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
- It does not claim hardware attestation in the browser. On the native
  reference substrate, isolation and attestation are hardware-backed
  (page tables, TPM measured boot). In the browser, the sandbox belongs to
  the browser's TCB, and webTOS's verifiability claim rests on determinism
  and replay alone. The trust argument changes shape honestly rather than
  silently.

Full specification: the [Yellow Paper](specs/yellowpaper.md).

### 7.1 Execution model: an interpreter, on purpose

The question a technical reader asks first is whether this is a JIT. It is
not, and the reason is the product rather than the schedule.

webTOS lifts each basic block of x86-64 once into an intermediate
representation, caches it, and interprets it. Blocks link directly to their
successors, so the loop stays inside the interpreter rather than returning to
a dispatcher. No native code and no WebAssembly is generated at run time.
Hot-block translation is the third tier of a written strategy — reference
interpreter, cached interpreter, translator — and it is deliberately last.

**Why last.** The claim webTOS sells is that the same input produces the same
instruction stream, reproducibly, so a third party can replay it. That is
measured today: `ls /` retires 73,280 instructions in Chromium, Firefox and
WebKit alike; the musl-loaded fixture retires 31,937 in all three. A
translation tier must reproduce those numbers bit for bit or the claim is
gone, which is why the milestone gate for it reads "optimized and interpreter
modes pass the same architectural trace suite". An engine whose goal is to run
Linux in a tab does not carry that constraint. One whose goal is verifiable
execution does, and it is cheaper to add a translator to a correct interpreter
than to retrofit determinism onto a translator.

**What it costs, measured.** Full figures and method are in
[performance.md](performance.md); the shape:

| | Sustained interpretation | Notes |
|---|---|---|
| Native | ~21 M inst/s | reference |
| Chromium / WebKit | ~11 M inst/s | about half of native |
| One engine's test build | ~1.4 M inst/s | see below |

Two findings worth stating plainly. The browser is not the bottleneck: on the
fast engines the interpreter runs within about a factor of two of native,
which is a smaller gap than the architecture suggests. And the outlier is not
a webTOS problem — a few-hundred-byte control module shows the same spread, so
that column measures a browser build that compiles WebAssembly with its
baseline compiler only. The control ships in the benchmark so the mistake is
not made twice.

**A translator is not free in a browser.** You cannot emit machine code; you
emit WebAssembly, and the browser's own compiler joins your inner loop. That
compilation is itself tiered — forcing Chromium to its baseline tier costs
2.7x — so the payoff of a translator depends on a variable nobody outside the
browser controls. Real implementations therefore batch large regions rather
than translating per block, and keep an interpreter for cold code regardless.

**Measurement changed what we did first.** The first optimization was not a
translator at all. An `execve` of an image whose blocks were already lifted
cost 48.8 ms to retire 22,272 instructions — about seventy times below the
interpreter's own sustained rate, because the block cache keyed on *which
process was looking* rather than *what the memory contained*. Keying it by
content took that to roughly 2 ms, and a shell pipeline from 1.06 s to 0.28 s.
It also exposed a live bug: two images sharing a load address shared their
lifted code, so one program ran another's. Translation work that had been
assumed necessary turned out to be a caching mistake worth twenty-fold — which
is the argument for measuring before optimizing, and for publishing the
harness rather than the conclusion.

---

## 8. Come for the Tool, Stay for the Network

webTOS is designed as the local execution edge of the TOS Network — an open
coordination and settlement layer where agents hold decentralized identities,
discover each other, negotiate bounded service terms, and settle work against
signed receipts, while providers keep custody of their hardware, models, and
data.

The sequencing follows the classic pattern: **come for the tool, stay for the
network.**

- **The tool** is single-player and immediately useful with no network
  attached: run a coding agent in a tab, locally, safely, resumably. webTOS
  is MIT-licensed and requires no token, no account, and no chain to use.
- **The network** becomes valuable when many such agents exist: an OpenFox
  instance running in a browser tab can discover paid work, execute it
  locally under capability and budget constraints, and settle — because its
  execution already produces exactly the bounded, priced, provable artifacts
  a settlement layer needs. webTOS's receipts are the supply side's evidence.

This ordering also answers the cold-start question honestly: webTOS does not
depend on the network succeeding. It is a standalone product whose adoption
makes the network possible, not a network whose adoption the product waits
for.

---

## 9. Competitive Landscape

Every row below is a respectable project; none occupies webTOS's position.

| System | What it is | Where it differs |
|---|---|---|
| **Cloud agent sandboxes** (microVM/container services) | Server-side isolated execution for agents | Remote, per-instance billing, cold starts, no local data, no user-side verifiability; trusts the operator. Complement more than competitor. |
| **WebContainers-class runtimes** | Node.js/toolchain runtime in the browser | Language-runtime scope, not an OS: no unmodified x86-64 binaries, no agent primitives, no determinism or receipts. |
| **In-browser x86 emulators** (v86-class, CheerpX-class) | Full machine or userspace x86 emulation in the browser, typically booting a Linux guest; the mature ones are publicly described as translating x86 to WebAssembly at run time | Proves in-browser x86 is viable — and shares its distribution logic. But they reproduce a *human* OS in a tab: ambient authority inside the guest, no capability model, no metering, no deterministic replay, no receipts. webTOS replaces the guest OS itself with an agent kernel, and interprets rather than translates because a translation tier has to reproduce the interpreter's instruction stream exactly (see §7.1). |
| **Syscall-interception sandboxes** (gVisor-class) | User-space Linux syscall reimplementation for containers | Server-side hardening layer; inherits Linux's non-determinism and ambient model; no browser story. |
| **WASI / recompile-the-world** | Portable Wasm system interface | Requires recompilation and often source access. Agents ship as Linux x86-64 releases; the binary you must run is the binary the vendor pinned. webTOS meets software where it ships. |
| **Agent framework governance** (permissions/limits in frameworks) | Userland conventions for agent control | Optional under pressure; not enforced beneath the agent. webTOS enforces the same intent at the kernel boundary. |

The defensible intersection: **unmodified Linux x86-64 software + fully local
browser execution + agent-first kernel primitives + verifiable deterministic
execution.** Each pairwise combination exists somewhere; no system ships all
four.

---

## 10. Moat

**The compatibility grind.** Running real software is a long-tail war —
instruction quirks, syscall semantics, loader behavior, PTY edge cases —
fought binary by binary, and largely serial: failures are discovered by
running real workloads, not enumerated up front. Wine and Proton demonstrate
both the size of that moat and its durability. webTOS starts with an unusual
head start: a native kernel whose Linux layer already carries OpenJDK-class
workloads, a versioned fixture-and-trace corpus, and per-workload validation
harnesses. The corpus compounds; a well-funded fast-follower still has to
walk the same tail.

**Determinism is architectural.** End-to-end determinism — CPU, scheduling,
time, randomness, lock ordering, external input recording — cannot be
retrofitted onto a runtime built without it; it constrains every subsystem
from day one. Competitors adding "replay" later face a rewrite, not a
feature.

**Receipts are a standard-shaped asset.** If bounded, verifiable agent
execution becomes how agent work is bought and audited, the format that
accumulated the tooling and the integrations becomes infrastructure.
Standards positions are won by shipping first and being open; webTOS is MIT
and ships its verifier with its kernel.

**Distribution compounds.** Every shared webTOS link is also a distribution
event for the runtime itself. Tools with zero-install sharing loops
historically out-distribute technically superior installed alternatives.

What is *not* claimed as moat: the browser APIs (available to everyone), the
interpreter technique (established), or secrecy (the code is open). The moat
is accumulated correctness, an architecture competitors must start over to
match, and position in an ecosystem that turns execution into settlement.

---

## 11. Who Needs This

Stated as segments with a concrete first user, not as a top-down TAM:

- **Agent developers and vendors** — ship an agent as a link: sandboxed
  demo-to-production environments, reproducible bug reports (a failing
  session is a replayable artifact), per-version compatibility evidence.
- **Enterprises adopting agents** — the audit answer: capability-scoped
  authority, credential injection without baking secrets into images, and
  signed records of what an agent actually did. Runs on the employee's
  machine inside the browser's security model IT already governs.
- **Operators of autonomous agents** (the OpenFox profile) — a $0-infra,
  always-available local runtime for agents that earn: metered cost,
  bounded authority, settlement-grade receipts.
- **Education and evaluation** — a full Linux + agent environment for
  anyone with a browser: courses, CTFs, agent benchmarks, replayable
  research artifacts.

The wedge is deliberately narrow: **run a pinned coding agent in a tab,
well.** That single capability is independently valuable, brutally hard to
fake (hence the gates), and generalizes — an environment good enough for
Claude Code is good enough for most of the agent long tail.

On business model: the kernel and runtime are MIT open source, and this
paper makes no revenue projections. The monetizable surfaces, when the
workload gates are passed, are the classic open-core set — enterprise
deployment and compliance tooling, managed persistence/network brokerage,
and participation in TOS Network settlement rails — each priced on value
delivered above the free runtime, never by closing the runtime.

---

## 12. What Could Kill This (Risks, Stated Plainly)

| Risk | Reality | Response |
|---|---|---|
| **Performance ceiling** | An interpreter in Wasm runs at single-digit-to-tens of MIPS — orders of magnitude below native. Some workloads will never fit. | Coding agents are I/O- and network-bound at interactive timescales; gates are latency-budget based, not MIPS based. Tiered execution (block caching, then hot-block Wasm translation) is roadmap Milestone 8, attempted only after correctness gates, with trace-equivalence required. If interactive budgets cannot be met for the pinned workloads, that gate fails visibly — by design. |
| **Long-tail incompatibility** | A pinned agent release may fail deep in startup on one missing instruction or syscall. | The entire methodology exists for this: trace pinned workloads, fail explicitly, grow fixtures. Never fake success — a wrong result is worse than a loud failure. |
| **Browser platform drift** | Memory limits, OPFS quotas, worker semantics, and store policies differ and change. | Sparse paging and quotas from day one; a compatibility dashboard per supported browser is part of the release definition; no dependency on any single vendor's non-standard API. |
| **Workload release drift** | New agent versions change runtime requirements. | Version pinning with published per-version compatibility reports; drift becomes a documented delta, not a silent break. |
| **A platform vendor ships it natively** | A browser or model vendor could ship a first-party agent sandbox. | Likely partial overlap (their own agent, their own browser). webTOS's position — vendor-neutral, unmodified-binary, verifiable, open — is exactly the part a first-party offering structurally does not build. Being MIT makes adoption cheaper than replication. |
| **Security of the broker boundary** | The credential and network broker is the highest-value target. | Deny-by-default network, handle-based secret injection, snapshot exclusion of credentials, fuzzing of every parser and boundary (Milestone 8), fail-closed on corrupt input. |
| **Believing our own demos** | The perennial emulation failure mode: the demo works, the semantics are stubbed. | The gates forbid it: soak tests, reload recovery, explicit-error policy, and receipts that expose what actually executed. |

---

## 13. Milestones and How to Verify

Full details with exit criteria live in [ROADMAP](../ROADMAP.md):

| Milestone | Outcome | Status |
|---|---|---|
| M0 | Native baseline locked; fixtures and traces versioned | Partial (fixtures exist; trace format pending) |
| M1 | Static `hello` in a browser worker | Done; the three-engine matrix passes and the engines agree instruction for instruction |
| M2 | Static BusyBox: shell, files, persistence across reload | Done, verified in all three engines |
| M3 | Dynamic Linux ELF via the real loader | Done (musl and glibc, native + browser) |
| M4 | Threads, fork/exec, deterministic scheduling | Done incl. determinism and adversarial gates |
| M5 | Event loops, brokered networking, HTTPS | Largely done: guest TLS natively, and the browser reaches the network through a deny-by-default relay; recording and soak pending |
| M6 | OpenFox completes a real agent task | Done natively, and the image now streams into a browser and runs there; the 60-minute soak remains |
| M7 | Codex and Claude Code: sustained interactive sessions | ~74%: both Codex modes run end to end natively, including the interactive TUI on a pseudoterminal; the browser has the terminal half. Carrying Codex's own image, per-agent secrets, and Claude Code remain |
| M8 | Performance tiers, fuzzing, quotas, signed releases | Started: a measured baseline (native, per-engine, and a control module), and the first optimization — a content-addressed lift cache worth roughly twenty-fold on process startup |

Verification is the point: the repository builds, the native suites run (58
cases), the wasm host runs, and a 27-check matrix runs in three browser
engines. Every completed claim above corresponds to tests and fixtures
in-tree, and the performance claims to harnesses that print their numbers
rather than assert them. Claims and code travel together.

---

## 14. Anticipated Questions

**"Isn't this just a slower VM?"** A VM reproduces a machine; webTOS replaces
the OS. The product is not cycles — it is bounded authority, metered cost,
deterministic replay, and receipts for agent execution, with zero-install
distribution. Slow-and-verifiable already wins whole categories (consider
what blockchains trade for auditability); here the workloads are interactive
tools whose bottleneck is the model and the network, not the CPU. On the
measured side the gap is smaller than the architecture suggests: the
interpreter sustains roughly half of native throughput in the fast browser
engines (§7.1).

**"Is it a JIT?"** No — it lifts each block once, caches it, and interprets.
Translation to WebAssembly is the last of three planned tiers, and it is last
because a translator must reproduce the interpreter's instruction stream
exactly or the replay claim is gone. §7.1 has the reasoning and the numbers,
including why the first optimization worth doing turned out not to be a
translator at all.

**"Why would anyone run agents locally when clouds exist?"** Data gravity
(the repository and credentials are here), cost (the user's silicon is free),
trust (sandbox + capabilities + receipts beat a remote black box), and
distribution (a link, not an account). The cloud keeps the fleets; the
browser gets the person.

**"Is this a crypto project?"** No token is required to use webTOS, and this
paper prices nothing. webTOS is a runtime. It is *settlement-ready* — its
receipts and energy accounting are the artifacts a settlement layer consumes
— and it plugs into the TOS Network where that is wanted. The runtime stands
alone; the network is upside.

**"Why not WASI and recompilation?"** Because the software that matters ships
as pinned Linux x86-64 releases, and vendors will not rebuild for a new ABI
on a new platform's schedule. Meeting binaries where they ship is the entire
lesson of Wine, Proton, and Rosetta.

**"What if Anthropic or OpenAI ship their own sandbox?"** They likely will —
for their own agent, on their own infrastructure. The neutral substrate that
runs *all* of them, locally, verifiably, under one capability and audit
model, is a different product with a different owner. Neutrality here is not
a weakness; it is the spec.

**"What's genuinely hard here?"** The compatibility long tail (years of
accumulated fixtures — that is the moat), and end-to-end determinism (an
architectural property competitors cannot retrofit). Both are grind-shaped,
which is precisely why they defend.

**"How do we know the team won't fake progress?"** The methodology makes
faking expensive: workload gates with soak tests and reload recovery,
explicit-failure policy, receipts binding outputs to executions, and a public
rule that no milestone closes on a stub. The honest-status section of this
paper and the `[IMPL]` markers in the Yellow Paper exist for the same reason.

---

## 15. Closing

The last platform shift put a computer in every pocket. This one puts an
economic actor in every piece of software. Those actors need what every actor
in an economy needs: identity, bounded authority, budgets, and records that
can be trusted by counterparties.

webTOS is the operating system built for them — delivered through the one
runtime everyone already has.

The link is the install. The tab is the computer. The receipt is the proof.
