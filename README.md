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

TOS is an **agent-first operating system kernel**. Its native model is built around Agents, Capabilities, Mailboxes, Keyspaces, energy budgets, and replayable receipts rather than ambient root authority and POSIX-first process semantics.

Modern operating systems were designed for human-operated computing. Their core abstractions — files, shells, user IDs — served that era well. TOS starts from a different premise: **what would an OS look like if its primary users were AI agents?**

This repository now contains both the native TOS model and a substantial **Linux compatibility layer** used to boot and validate stock Linux ELF workloads such as OpenJDK, Node.js, and Python.

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

TOS currently has three agent/runtime paths plus one kernel policy layer:

- **Native x86_64** — high-performance system services and native agents using the TOS syscall ABI directly
- **WASM** — portable, sandboxed user agents with fuel metering and three execution grades (BestEffort, ReplayGrade, ProofGrade)
- **Linux-compat** — stock Linux ELF programs running through the translated Linux syscall ABI
- **eBPF-lite** — kernel-resident policy programs that intercept syscalls, mailbox messages, agent spawns, and timer ticks in real time

Native and WASM agents communicate through **mailboxes**, forming the message-driven core architecture. Linux-compat adds Linux process/thread, VMA, futex, fd, and dynamic-loader semantics on top of the same kernel.

### Capabilities, Not Permissions

There is no superuser in the native TOS model. Authority is a concrete Capability record — `SendMailbox(3)`, `AgentSpawn`, `PolicyLoad`, `Network`. Capabilities can only be **delegated from parent to child, and only as a subset** — never enlarged, never created from nothing.

### Provable Execution

This is what makes TOS unique. In **ProofGrade** mode:

1. Start from a checkpoint
2. Replay under a deterministic scheduler
3. Every step produces a hash-chained event log
4. Generate an **execution proof** that any third party can independently verify

You can outsource computation to an untrusted node, then verify the result is correct — without re-executing.

### Energy Is the Universal Currency

Every Agent has an **energy budget**. Every instruction, every syscall, every message costs energy. Energy is exhausted — agent suspends. Parents transfer energy to children. This isn't a limitation — it's the foundation for **metering, billing, and economic accountability**. CPU time becomes a priced, transferable, auditable resource.

### Checkpointable Today, Distributed Later

The tree already includes **portable checkpoints** and minimal kernel UDP primitives. Broader cross-node mailbox routing and live agent migration are still roadmap work, not the default shipped execution path in the current repository.

### Skills as Deployable Artifacts

Developers can package agents as signed `.tos` artifacts and install them through the in-tree package/skill path. Signature, install, rollback, and lifecycle scaffolding exist in the repo today; the larger registry/distribution story is still evolving.

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
brew install nasm qemu binutils
export PATH="$(brew --prefix binutils)/libexec/gnubin:$PATH"
```

### Build & Run

```bash
git clone https://github.com/tosnetwork/tos.git
cd tos
make run
```

The default QEMU launch now uses `1024M` of guest RAM. Override it with
`QEMU_MEMORY=<size>` if you need a different setting.

### Optional Linux Runtime Payloads

Base-image payloads are declared through manifest files, not hardcoded in
kernel Rust source:

- `base_image.manifest` for repo-tracked payloads
- `base_image.runtime.manifest` for the default runtime profile embedded by the build
- `base_image.runtime.python.manifest` and `base_image.runtime.node.manifest` as alternate repo-tracked runtime profiles

The build script always embeds `base_image.manifest` plus either
`base_image.runtime.manifest` or the manifest pointed to by
`TOS_RUNTIME_MANIFEST`. To generate a host-specific runtime manifest for
Python, Node.js, or OpenJDK:

```bash
python3 tools/generate_runtime_manifest.py
```

That script emits `base_image.runtime.manifest` with explicit file and tree
entries for the selected runtimes and their shared-library dependencies.

To build against an alternate runtime bundle without overwriting the repo's
default profile, point Cargo at a different manifest file:

```bash
python3 tools/generate_runtime_manifest.py \
  --output /tmp/tos-java.manifest \
  --runtimes java \
  --java-home traced

TOS_RUNTIME_MANIFEST=/tmp/tos-java.manifest make run
```

The repo also ships end-to-end runtime validation harnesses for the current
Linux-compat bring-up work:

```bash
tools/java_runtime_validation.sh
tools/prepare_jtreg_assets.sh
tools/jtreg_java_base_smoke.sh
tools/phase5_runtime_validation.sh --profile java
tools/phase5_runtime_validation.sh --profile python
tools/phase5_runtime_validation.sh --profile node
tools/phase6_runtime_matrix.sh
```

For future OpenJDK `jtreg` bring-up work, the repo also includes a first-pass
TOS whitelist for the non-UI `java.base`-heavy subset. The initial guest-side
smoke currently uses `-othervm` instead of `-agentvm`, because TOS does not yet
provide the localhost socket semantics that jtreg's agent VM pool expects:

```bash
cat tools/jtreg-java-base-whitelist.txt
```

There is also a guest-side jtreg launcher path for that whitelist. Start from
the preparation script, which downloads `jtreg 7.3.1+1`, sparse-clones the
OpenJDK 11 test tree, and writes a ready-to-use
`base_image.runtime.jtreg.manifest`:

```bash
tools/prepare_jtreg_assets.sh
tools/jtreg_java_base_smoke.sh
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
make test        # Single-node smoke with disk + network
```

## Developer SDK

```bash
# Native agent (x86_64, #![no_std])
cd sdk/tos-sdk && cargo build --target x86_64-unknown-none

# WASM agent (wasm32)
cd sdk/tos-wasm-sdk && cargo build --target wasm32-unknown-unknown --release

# eBPF-lite policy tooling
cd sdk/tos-ebpf-sdk && cargo build --release

# CLI tools (build, deploy, inspect, replay, verify)
cd sdk/tos-cli && cargo build --release
```

## Learn More

- **[Yellow Paper](yellowpaper.md)** — current engineering specification, syscall ABI, architecture details, and staged roadmap
- **[Linux Compatibility Notes](LinuxCompat.md)** — Linux syscall translation model and runtime bring-up notes
- **[WASM Runtime Spec](WASM-runtime-spec.md)** — WASM execution model, RuntimeClass semantics, and host ABI
- **[eBPF-lite Spec](eBPF-lite-spec.md)** — policy runtime specification (instruction set, helpers, maps, attachment points)

## License

[MIT](LICENSE)
