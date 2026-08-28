# webTOS Use Cases

webTOS runs unmodified Linux x86-64 programs inside a browser tab, on an
execution model that meters what they spend and can reproduce what they did.

That sentence covers two things at very different stages of completion, and
this document keeps them apart. Reading them as one thing is how the previous
version of this file came to describe daemons that were never written.

- **The browser runtime** — the x86-64 engine, the Linux compatibility layer,
  and the browser host — runs real workloads today, gated by tests in
  Chromium, Firefox, and WebKit. **Part 1** is what it supports.
- **The agent kernel** — capabilities, energy, mailboxes, keyspaces,
  receipts, policy, attestation — exists in the native bare-metal kernel and
  is *not* integrated into the browser runtime. **Part 2** is what it supports
  natively, and what each scenario still needs to reach a tab.
- **Part 3** lists what neither has, so that an idea does not get read as a
  feature a second time.

Every status claim below is traceable: [`ROADMAP.md`](../ROADMAP.md) for
milestones and their evidence, [`performance.md`](performance.md) for numbers,
[`README.md`](../README.md) for how to run any of it.

---

# Part 1 — What the browser runtime supports today

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

# Part 2 — What the native kernel supports

Everything in this part runs on the bare-metal x86-64 kernel in `src/`. None of
it is wired into the browser runtime yet — in the architecture diagram in
`README.md` it is the dashed box. Each scenario names what exists and what it
still needs, so that "webTOS could do this" and "webTOS does this" stay
distinguishable.

## What exists natively

| Subsystem | File |
|---|---|
| Agents, scheduling, energy accounting | `src/agent.rs`, `src/sched.rs`, `src/energy.rs`, `src/cost.rs` |
| Capabilities: typed, targeted, use-limited, delegated as a subset, revocable by the parent | `src/capability.rs` |
| Mailboxes | `src/mailbox.rs`, `src/large_msg.rs` |
| Keyspaces and SHA-256 Merkle state roots | `src/state.rs`, `src/merkle.rs`, `src/persist.rs` |
| Signed `ExecutionReceipt`, `ReplayBundle`, `ProofBundle` | `src/receipts.rs`, `src/proof.rs` |
| Checkpoint and replay | `src/checkpoint.rs`, `src/replay.rs` |
| eBPF-lite policy engine | `src/ebpf/`, `src/policy.rs`, `src/agents/policyd.rs` |
| TPM 2.0 measured boot and attestation (signs and verifies) | `src/attestation.rs`, `src/arch/x86_64/tpm.rs` |
| Wasm runtime with runtime classes including ProofGrade | `src/wasm/`, `third_party/wasbi` |
| `.tos` packages | `src/package.rs`, `src/agents/pkgd.rs` |
| System agents: accountd, auditd, compactd, netd, pkgd, policyd, skilld, stated | `src/agents/` |
| CLI: `tos build`, `deploy`, `replay`, `inspect`, `verify` | `sdk/tos-cli/` |

---

## 7. Verifiable agent execution

**Problem**: a client who buys an agent's output cannot check what produced
it — which code version ran, on which input, consuming what.

**What the kernel provides**: an agent exiting produces an `ExecutionReceipt`
binding `code_hash`, `package_hash`, `input_commitment`,
`output_commitment`, `initial_state_root`, `final_state_root`,
`event_log_commitment`, `trace_commitment`, `energy_used`, the tick range, and
the runtime class, signed with the node's Ed25519 key
(`src/receipts.rs:78`). A `ReplayBundle` carries what is needed to re-execute
it; a `ProofBundle` carries what is needed to check it without re-executing.

**Worked example**: a contract-review agent runs in ProofGrade mode. The
receipt says which model version processed which input, how much energy it
consumed, and what state it left. An auditor holding the receipt and the
node's public key can tell whether the provider's claims are consistent with
it.

**What this still needs**:
- **Offline signature verification in a tool.** Receipts are signed, but
  `tos verify` checks a proof's hash chain (`sdk/tos-cli/src/proof.rs`), not
  the receipt's Ed25519 signature. Until a verifier checks the signature, a
  third party is trusting the transport.
- **Browser integration.** No receipt is emitted for a browser session.

---

## 8. Metered execution

**Problem**: request-count billing overcharges cheap calls and undercharges
expensive ones, and neither side can audit the other's meter.

**What the kernel provides**: energy is deducted per instruction, per
syscall, and per message; an agent that exhausts its budget is suspended by
the scheduler rather than by a supervisor. `accountd` exposes cumulative
per-agent consumption over a mailbox, and `energy_used` is a signed field of
the receipt rather than a log line.

**Worked example**: an analytics endpoint charges by energy. A cheap lookup
and an expensive aggregation are distinguished by the meter that actually
stopped the work, and every line item on the invoice has a receipt behind it.

**What this still needs**: pre-execution cost estimation and invoice
aggregation are not implemented — an earlier draft of this document named
`quotad` and `billingd` as if they existed. Settlement is also out of scope
for the kernel: it belongs to the TOS Service layer.

---

## 9. Policy-constrained computation with an audit trail

**Problem**: regulated computation must show it followed rules, and an
operator's word is not evidence.

**What the kernel provides**: capabilities are checked, not assumed — an
agent without `SendMailbox` cannot send, and cannot acquire the ability at
runtime, because delegation can only narrow (`is_subset_of`,
`src/capability.rs:95`). A policy bundle written for the eBPF-lite engine runs
at capability check points, and `auditd` collects the grant, delegate, revoke,
renew, and deny events into a queryable log.

**Worked example**: a screening agent is given read access to one keyspace, no
network capability, and a bounded energy budget. Whether each capability check
was granted or denied is in the audit log, and the policy that decided it is
identified by hash in the receipt.

**What this still needs**:
- **Time-bounded and depth-bounded delegation.** The capability model has a
  use-count limit and parent-child revocation. It has no expiry, no
  delegation-depth limit, and no principal revocation list — an earlier draft
  described all three.
- **Encryption.** Keyspaces are isolated by capability. They are not
  encrypted; there is no encryption in the kernel at all.

---

## 10. An off-chain execution layer for TOS

**Problem**: every validator re-executing every transaction bounds what an L1
can compute.

**What the kernel provides**: a deterministic execution class, Merkle state
roots before and after, a syscall transcript commitment, and a receipt that
binds them together. The `ProofBundle` format is shaped for a proving
pipeline: verify a small artifact rather than re-run the work.

**Why this is the strategic one**: it is the seam where webTOS meets the rest
of the ecosystem. Finalized TOS chain state is the authority; webTOS is where
the work happens and where the evidence is produced.

**What this still needs**: the proving pipeline itself, and the settlement
integration. What exists is the evidence format, not the proof system.

---

## 11. Attested software supply chain

**Problem**: the gap between "this code was signed" and "this code is
running" is where supply chain attacks live.

**What exists, and this one reaches the browser**: the browser host already
enforces the second half. A signed image manifest is verified by the platform's
audited verifier on the host side; the module then checks that delivered bytes
match what the manifest names, and refuses any image the manifest does not
name — including through the streaming path, so delivery cannot skip the
check (`crates/webtos-web/src/lib.rs:873`). The module deliberately does not
verify the signature itself: a hand-rolled verifier in a security boundary
fails open, which is worse than no verifier at all.

Natively, `.tos` packages carry a manifest with declared capabilities and a
`code_hash` that `pkgd` checks against the installed bytes, and TPM measured
boot extends the chain down to the kernel image.

**What this still needs**: the `.tos` manifest carries a 64-byte signature
field, but nothing verifies it — `pkgd` checks the code hash only
(`src/package.rs:50`). A package signature that is transported but not
checked is not a signature. Note also that the CLI has no `sign` subcommand;
an earlier draft of this document documented an `atp sign` workflow that does
not exist.

---

## 12. Isolated multi-party collaboration

**Problem**: two parties want a joint result without either trusting the
other's execution environment or seeing the other's data.

**What the kernel provides**: each party's agent runs against its own
keyspace, which the other holds no capability for. They exchange results
through bounded mailboxes rather than shared memory, and each round leaves a
receipt the other party can inspect.

**Worked example**: two institutions compute aggregate statistics over their
own records and exchange only the aggregates. Neither agent can read the
other's keyspace, because neither was granted the capability, and neither can
grant itself one.

**What this still needs**: this is isolation, not confidentiality. Keyspaces
are not encrypted, so the guarantee is against the other *agent*, not against
whoever operates the node. Positioning it as a substitute for MPC or a TEE
would be wrong.

---

# Part 3 — Designed, not built

Named here so nobody reads them as features. Each was described as working in
an earlier draft of this document.

| Idea | Reality |
|---|---|
| Cross-node agent messaging | `SYS_SEND_REMOTE` is a reserved number that returns `E_INVALID_ARG` (`src/syscall.rs:1365`) |
| Node membership, failover, placement, agent migration | No such code exists. `PortableCheckpoint` exists; nothing moves it between nodes |
| Mailbox-based remote administration | No `admind` |
| Cost estimation and billing aggregation | No `quotad`, no `billingd`. `accountd` reports consumption; nothing prices it |
| An authority daemon with a revocation list | No `authd`. Revocation is a parent revoking a direct child (`src/capability.rs:200`) |
| Observability daemon and dashboards | No `observabilityd`. Measurement harnesses exist; no dashboard |
| Encrypted keyspaces | No encryption anywhere in the kernel |
| Capability expiry and delegation depth | Neither field exists |
| Multi-worker browser execution | Deferred; one worker today |
| Hot-block translation (JIT) | Not started. The interpreter is tiered but does not compile |

---

# What webTOS is not for

| Scenario | Why not |
|---|---|
| CPU-bound compute | An interpreter with no JIT: about half of native at best, a tenth of that on Firefox |
| Workloads over ~3.9 GiB | That is what a tab grants, and it is the same ceiling in all three engines |
| Graphics, GPU, games | No graphics path exists |
| Non-x86-64 binaries | One ABI, one architecture |
| Hard real-time | Deterministic ordering is not a latency guarantee |
| Distributed clusters | See Part 3. Cross-node execution is a design, not a runtime |
| A desktop OS | The Linux surface is what agent workloads need, not a general userland |

---

# Positioning

**Part 1 today**: webTOS is the only runtime that executes an unmodified
Linux x86-64 binary in a browser tab under explicit, deny-by-default
authority — the real tool, in the user's own browser, with the operator
holding neither the compute nor the data.

**Part 2, once the agent kernel reaches the browser**: webTOS becomes the
substrate that makes an outside party believe *this code really ran the way it
claims* — because the receipt says which code, on which input, at what cost,
leaving which state.

The distance between those two sentences is the roadmap.
