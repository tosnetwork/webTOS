# webTOS Use Cases

webTOS runs unmodified Linux x86-64 programs inside a browser tab, under
authority the page grants explicitly and budgets the runtime enforces.

This document is what that supports, and it is deliberately narrow: only what
a browser runs today, each claim pointing at the gate that proves it. An
earlier version also described an agent kernel — capabilities, energy,
mailboxes, receipts, attestation — which lived in a separate bare-metal kernel
beside the browser runtime and was never wired into it. That kernel has since
been removed from the repository, so the scenarios resting on it are gone from
here too. They survive in git history; nothing below depends on them.

Every status claim is traceable: [`ROADMAP.md`](../ROADMAP.md) for milestones
and their evidence, [`performance.md`](performance.md) for numbers, and
[`README.md`](../README.md) for how to run any of it.

---

## The capability surface

| Capability | Where it is proven |
|---|---|
| Unmodified Linux x86-64 ELF, static and dynamic (musl and glibc loaders) | M1–M3, green natively and in all three engines |
| Processes, threads, futexes, signals, process groups, job control | M4; `EINTR`/`SA_RESTART` semantics gated through both a terminal and a socket |
| Pseudoterminals, full-screen TUIs, SIGWINCH on resize | M7; `vi` and the real Codex TUI both render and take keystrokes |
| Sockets, epoll, DNS and TLS performed by the guest itself | M5; the guest terminates its own TLS, so the host relays bytes, not requests |
| Network reachable only through a deny-by-default relay | `tools/webtos_gateway.mjs`; with no `--allow` rule it starts and refuses everything |
| Filesystem persistence across a real page reload | M2/M6; OPFS-backed snapshot, restored into a fresh machine |
| Deterministic execution | identical instruction counts across Chromium, Firefox, and WebKit, gated against recorded architectural traces |
| Session record and offline replay | M5; a recorded session replays with no network at all |
| Budgets on memory, storage, network bytes, CPU, and the event log | `wtw_set_*_budget_*`; over-budget returns an errno the guest already handles |
| Per-agent secret injection, kept out of disk snapshots | M5; an out-of-scope program reads a placeholder, not an empty value |
| Signed image manifests | host verifies the signature, the module enforces the content hashes and refuses an image the manifest does not name |
| Streamed image delivery | a 52 MB agent binary reaches a shell prompt in about three seconds without ever being held whole |

Throughput is roughly half of native on Chromium and WebKit (about 11 M
instructions/s against 21 M), and about a tenth of that on Firefox. A tab
grants roughly 3.9 GiB. Read [`performance.md`](performance.md) before
committing to a workload; run the harnesses on the machine you care about
rather than trusting those numbers.

---

## 1. Zero-install development environments

**Problem**: browser IDEs either ship a JavaScript reimplementation of the
tools (so the tool is not the tool), or rent a container per user (so every
idle tab costs money and every user's code runs on your infrastructure).

**What webTOS provides**: the actual binaries. The host `git` runs real
repository operations in the guest — status, diff, add, commit, log. BusyBox
provides a shell with pipelines and job control. `vi` runs full-screen on a
pseudoterminal that turns `^C` and `^Z` into signals on the foreground
process group, and `fg` resumes what `^Z` stopped.

**Worked example**: a documentation site embeds a working checkout of the
project being documented. The reader edits a file in `vi`, runs the project's
own build command, and sees it fail the same way it fails locally — because it
is the same binary reading the same bytes. Nothing was ported, and the tab is
the entire backend.

**What it costs**: compute is the reader's, not yours. What you serve is a
wasm module and an image.

---

## 2. Agents that run in the user's browser

**Problem**: an AI coding agent needs a filesystem, subprocesses, a terminal,
and network access. Giving it those on a server means the operator inherits
the blast radius; giving it those on the user's machine directly means no
boundary at all.

**What webTOS provides**: the boundary is the tab, and the authority is
explicit. The guest has no network whatsoever until the page asks for one, and
then only to destinations an `--allow` rule names. Credentials are injected at
runtime, scoped to the agent that should see them, and stay out of filesystem
snapshots. Memory, CPU, storage, and network bytes all have ceilings, and
crossing one produces an errno rather than a dead tab.

**Worked example**: OpenFox — a 52 MB static Linux agent — streams into a
clean browser profile, reaches a prompt in about three seconds, and performs a
scripted network-backed task against a mounted repository. Its configuration
and repository changes survive a reload. A 1,000-round soak ran 3,673 seconds
with the filesystem, guest physical memory, and the lifted-block table all
bounded.

**Status**: OpenFox is M6 ✅. Codex runs end to end on the native host in both
non-interactive and interactive modes, and the browser has the terminal half
of it; carrying Codex's own image into a tab is the open half of M7.

---

## 3. Client-side sandboxing of untrusted binaries

**Problem**: online judges, CTF platforms, plugin systems, and
"run this user's script" features all need to execute code nobody trusts. The
usual answer is a container fleet — cost, isolation, and abuse handling all at
once.

**What webTOS provides**: the untrusted code runs inside the submitter's own
browser, inside a wasm module, with no ambient authority. It cannot reach the
network unless a relay rule names the destination. It cannot outrun its CPU
budget, outgrow its memory cap, or fill storage. The x86-64 decoder and the
syscall argument surface have both been swept adversarially — every opcode in
all four maps under seventeen prefix combinations, and every argument position
of every syscall number against a corpus of the ways a number breaks code that
trusts it.

**Worked example**: a judge serves the problem's reference binary and the
submitted one, runs both in the tab, and compares outputs. A submission that
tries to escape meets a module whose failure mode is a trapped tab, not a
compromised host. Determinism means the same submission produces the same
instruction count on every grader's machine.

---

## 4. Local processing of data that must not leave

**Problem**: legal, medical, and financial documents are exactly the files
that cannot be uploaded, and exactly the files with mature command-line tools
for processing them.

**What webTOS provides**: those tools, unmodified, running where the file
already is. With no relay configured, there is no network to leak through —
not as a policy, but as a fact about the runtime.

**Worked example**: a clinic's intake tool runs an existing de-identification
pipeline in the browser. Records are read from the local filesystem, processed
by the same binary the compliance team already reviewed, and written back. The
audit question "could this have transmitted anything?" is answered by the
absence of a gateway, and by the relay's log if one was configured at all.

---

## 5. Reproducible teaching, demonstration, and bug reproduction

**Problem**: "works on my machine" is expensive at every scale — a course
where a third of the class cannot install the toolchain, a support ticket that
cannot be reproduced, a security demonstration that needs a VM.

**What webTOS provides**: identical input retires an identical instruction
stream in every engine, and that is gated rather than assumed —
`test_data/traces/` holds architectural traces (the syscall stream with its
arguments, delivered signals, and register and flag samples at exact
instruction counts) that the browser matrix reproduces register for register.
A session can be recorded and replayed later with no network.

**Worked example**: a bug report ships as a URL and a recorded session. Whoever
opens it gets the same instructions, the same syscall returns, and the same
failure — including the network responses, replayed from the recording rather
than re-fetched. A course assignment ships the same way, and a student's
environment cannot drift from the instructor's.

---

## 6. Distributing a command-line tool as a link

**Problem**: an internal x86-64 tool has users who cannot install it —
wrong platform, no admin rights, or not worth the support burden.

**What webTOS provides**: publish the binary and the module. The tool becomes
a URL. No port, no container, no installer, no rebuild.

**Worked example**: an infrastructure team's log analyzer is a static Go
binary. It is put behind a page. Support engineers paste a log into the tab
and get the same output the on-call engineer gets from their shell, with the
log never leaving the browser.

---

## 7. Knowing what the tab is about to run

**Problem**: a page that streams a binary into a runtime is a distribution
channel, and a distribution channel with no integrity check is a supply chain
waiting to be attacked.

**What webTOS provides**: a signed image manifest, enforced in two halves. The
host verifies the signature with the platform's audited verifier. The module
then checks that delivered bytes match what the manifest names, refuses any
image the manifest does not name, and applies the same check on the streaming
path so delivery cannot skip it (`crates/webtos-web/src/lib.rs:873`). The
module deliberately does not verify the signature itself: a hand-rolled
verifier in a security boundary fails open, which is worse than none.

**Worked example**: a team publishes an internal tool as a page. The manifest
names one image and its hash. A tampered image, a substituted image, and an
image nobody declared are all refused before the guest runs one instruction.
`node web/test_manifest.mjs` is the gate that says so — it checks both that a
manifest the verifier rejects is never installed and that one it accepts is
enforced.

---

## What it does not have

Named so that nothing here gets read as a feature.

| Idea | Reality |
|---|---|
| An agent kernel — capabilities, energy accounting, mailboxes, receipts, attestation | Removed from the repository. It was a separate bare-metal kernel and was never wired into the browser runtime |
| Multi-worker execution | Deferred. One worker today |
| Hot-block translation (JIT) | Not started. Lifting is tiered but does not compile |
| Block-level on-demand image loading | An image streams whole into the guest filesystem, which bounds how large a delivered userland can be |
| A graphics path | None. Terminals and TUIs, not framebuffers |

---

## What webTOS is not for

| Scenario | Why not |
|---|---|
| CPU-bound compute | An interpreter with no JIT: about half of native at best, a tenth of that on Firefox |
| Workloads over ~3.9 GiB | That is what a tab grants, and it is the same ceiling in all three engines |
| Graphics, GPU, games | No graphics path exists |
| Non-x86-64 binaries | One ABI, one architecture |
| Hard real-time | Deterministic ordering is not a latency guarantee |
| Distributed execution | Nothing here spans machines; the tab is the unit |
| A desktop OS | The Linux surface is what agent workloads need, not a general userland |

---

## Positioning

webTOS runs an unmodified Linux x86-64 binary in a browser tab under explicit,
deny-by-default authority: the real tool, in the user's own browser, with the
operator holding neither the compute nor the data.

Everything above is a way of using that.
