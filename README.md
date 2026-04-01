<p align="center">
  <strong>A provable, metered, migratable agent execution platform — built from scratch.</strong>
</p>

<p align="center">
  <a href="yellowpaper.md">Yellow Paper</a> &middot;
  <a href="#quickstart">Quickstart</a> &middot;
  <a href="#the-full-picture">Vision</a> &middot;
  <a href="LICENSE">MIT License</a>
</p>

---

## What is TOS?

TOS is an **agent-first operating system** — no processes, no filesystem, no root user. All computation is an Agent. All authority is a Capability. All execution is provable.

Modern operating systems were designed for human-operated computing. Their core abstractions — files, shells, user IDs — served that era well. TOS starts from a different premise: **what would an OS look like if its primary users were AI agents?**

| Traditional OS | TOS |
|----------------|------|
| Processes and threads | **Agents** — autonomous units with energy budgets and parent-child hierarchy |
| Files and filesystems | **Keyspaces** — per-agent key-value stores with Merkle proofs |
| Root / sudo / ACL | **Capabilities** — explicit tokens of authority, delegated parent-to-child, never created from nothing |
| System calls are open | **eBPF-lite policy filters** — every syscall can be intercepted by kernel-resident policy programs in real time |
| Logging as afterthought | **Structured event stream** — every operation produces a sequenced, replayable audit event |
| "Trust the administrator" | **Cryptographic proofs** — execution results are independently verifiable by any third party |

## The Full Picture

### Agents Are Everything

Every piece of running code is an Agent. There are three runtimes, each for a different role:

- **Native x86_64** — high-performance system services (state manager, policy engine, network broker)
- **WASM** — portable, sandboxed user agents with fuel metering and three execution grades (BestEffort, ReplayGrade, ProofGrade)
- **eBPF-lite** — kernel-resident policy programs that intercept syscalls, mailbox messages, agent spawns, and timer ticks in real time

Agents communicate through **mailboxes** (no shared memory), forming a message-driven microkernel architecture.

### Capabilities, Not Permissions

There is no superuser. Authority is a concrete Capability token — `SendMailbox(3)`, `AgentSpawn`, `PolicyLoad`, `Network`. Capabilities can only be **delegated from parent to child, and only as a subset** — never enlarged, never created from nothing. Each capability carries a cryptographic signature, verifiable even across nodes.

### Provable Execution

This is what makes TOS unique. In **ProofGrade** mode:

1. Start from a checkpoint
2. Replay under a deterministic scheduler
3. Every step produces a hash-chained event log
4. Generate an **execution proof** that any third party can independently verify

You can outsource computation to an untrusted node, then verify the result is correct — without re-executing.

### Energy Is the Universal Currency

Every Agent has an **energy budget**. Every instruction, every syscall, every message costs energy. Energy is exhausted — agent suspends. Parents transfer energy to children. This isn't a limitation — it's the foundation for **metering, billing, and economic accountability**. CPU time becomes a priced, transferable, auditable resource.

### Distributed and Migratable

Agents don't know which physical node their peers are on. Mailbox messages are automatically routed across nodes (via kernel UDP with signed capability verification). Agents can be **migrated** between nodes — checkpoint on node A, transfer state, resume on node B.

### Skills as Deployable Artifacts

Developers write WASM agents, sign them, publish to a registry. Users install skills through a standard protocol — the system validates signatures, enforces capability subsets, applies eBPF policy, and spawns the skill as a sandboxed child agent. Skills can be upgraded, rolled back, and uninstalled. If the parent dies, its skills are cascade-terminated — no orphan processes, ever.

### The Analogy

If Linux is a shared factory where anyone can walk in and use any machine, TOS is a factory where **every worker operates in their own sealed chamber** — communicating only through message slots, powered by a metered energy supply, with a guard at every door checking credentials, watched by tamper-proof cameras. And any outsider can replay the footage to verify the work was done correctly.

## Quickstart

### Prerequisites

- Rust nightly toolchain (managed automatically via `rust-toolchain.toml`)
- [NASM](https://nasm.us/) assembler
- [QEMU](https://www.qemu.org/) (`qemu-system-x86_64`)
- `objcopy` (from `binutils`)

```bash
# Ubuntu/Debian
sudo apt install nasm qemu-system-x86 binutils

# macOS
brew install nasm qemu
```

### Build & Run

```bash
git clone https://github.com/tosnetwork/tos.git
cd tos
make run
```

The default QEMU launch now uses `512M` of guest RAM. Override it with
`QEMU_MEMORY=<size>` if you need a different setting.

### Optional Linux Runtime Payloads

Base-image payloads are declared through manifest files, not hardcoded in
kernel Rust source:

- `base_image.manifest` for repo-tracked payloads
- `base_image.runtime.manifest` for host-specific runtime bundles

The build script embeds both manifests automatically when present. To
generate a host-specific runtime manifest for Python, Node.js, or OpenJDK:

```bash
python3 tools/generate_runtime_manifest.py
```

That script emits `base_image.runtime.manifest` with explicit file and tree
entries for the selected runtimes and their shared-library dependencies.

To build against an alternate runtime bundle without overwriting the repo's
default manifest, point Cargo at a different manifest file:

```bash
python3 tools/generate_runtime_manifest.py \
  --output /tmp/tos-java.manifest \
  --runtimes java \
  --java-home traced

TOS_RUNTIME_MANIFEST=/tmp/tos-java.manifest make run
```

You will see agents booting, communicating via mailboxes, and enforcing policies:

```
TOS boot ok
TOS v0.1 - AI-native Operating System
[OK] Architecture initialized
[OK] Scheduler initialized
[EVENT seq=0 tick=0 agent=0 type=SYSTEM_BOOT arg0=0 arg1=0 status=0]
[INIT] Root agent created: id=1
[INIT] Ping agent created: id=2
[INIT] Pong agent created: id=3
[ROOT] Root agent started
[PING] Ping agent started (id=2)
[PONG] Received: "ping"
[PING] Received reply: "pong"
...
```

Press `Ctrl+C` to stop.

### Other Commands

```bash
make build       # Build release binary only
make clean       # Remove build artifacts
make debug-run   # Build debug + launch QEMU with GDB stub (-s -S)
make uefi-run    # Boot via UEFI (QEMU + OVMF firmware)
make test        # Single-node test with SMP + disk + network
```

## Developer SDK

```bash
# Native agent (x86_64, #![no_std])
cd sdk/tos-sdk && cargo build --target x86_64-unknown-none

# WASM agent (wasm32)
cd sdk/tos-wasm-sdk && cargo build --target wasm32-unknown-unknown --release

# CLI tools (build, deploy, inspect, replay, verify)
cd sdk/tos-cli && cargo build --release
```

## Learn More

- **[Yellow Paper](yellowpaper.md)** — full engineering specification, syscall ABI, architecture details, and 10-stage roadmap
- **[eBPF-lite Spec](eBPF-lite-spec.md)** — policy runtime specification (instruction set, helpers, maps, attachment points)

## License

[MIT](LICENSE)
