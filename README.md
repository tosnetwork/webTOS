<p align="center">
  <img src="ATOS.png?v=2" alt="ATOS Logo" width="200">
</p>

<p align="center">
  <strong>An agent-native operating system built from scratch.</strong><br>
  Agents. Mailboxes. Capabilities. No legacy.
</p>

<p align="center">
  <a href="yellowpaper.md">Yellow Paper</a> &middot;
  <a href="#quickstart">Quickstart</a> &middot;
  <a href="#architecture">Architecture</a> &middot;
  <a href="LICENSE">MIT License</a>
</p>

---

## What is ATOS?

ATOS is a minimal operating system designed from first principles for AI agent execution. It is **not** a Linux distribution, not a POSIX-compatible environment, and not a desktop OS. It is a bare-metal execution substrate where agents, mailboxes, and capabilities replace processes, sockets, and ambient authority.

Modern operating systems were designed for human-operated computing. Their core abstractions — files, shells, user IDs — served that era well. ATOS starts from a different premise: **what would an OS look like if its primary users were AI agents?**

### A New Paradigm

| Traditional OS | ATOS |
|----------------|------|
| Processes and threads | **Agents** — autonomous units with energy budgets and parent-child hierarchy |
| Files and filesystems | **Keyspaces** — per-agent key-value stores with Merkle proofs |
| Root / sudo / ACL | **Capabilities** — explicit tokens of authority, delegated parent→child, never created from nothing |
| System calls are open | **eBPF-lite policy filters** — every syscall can be intercepted by kernel-resident policy programs |
| Logging as afterthought | **Structured event stream** — every operation produces a sequenced, replayable audit event |
| "Trust the administrator" | **Cryptographic proofs** — execution results are independently verifiable by any third party |

### Design Principles

- **Architecture from zero.** Not inherited from legacy human-centric systems.
- **Code from zero.** Not a fork of Linux. Not a wrapper around an existing kernel.
- **VM-first.** Runs on QEMU/x86_64 to preserve architectural purity while minimizing hardware complexity.
- **Determinism over convenience.** Predictable, replayable behavior by default.
- **Explicit authority.** Nothing is accessible without a capability. No ambient root.

### Who Uses ATOS

ATOS is not a general-purpose operating system. Its users are autonomous systems that need deterministic execution, minimal privilege, and verifiable behavior.

**AI Agent Platforms** — Run AI agents in isolated, auditable sandboxes. Agents are written in WASM or native Rust, communicate via mailboxes, and operate under capability-scoped authority. Every action is logged. Agents can be checkpointed, migrated, and replayed.

**Verifiable Computation** — Execute workloads where results must be provably correct. WASM agents run deterministically (fuel-counted). State transitions produce Merkle proofs. Checkpoints enable independent replay verification. The energy model maps directly to metered execution (gas, tokens, billing units).

**Secure Edge Devices** — Deploy on embedded hardware where the attack surface must be minimal. No shell, no root, no filesystem, no ambient authority. Each agent holds only the capabilities it was explicitly granted.

## Architecture

### Layering

```
+---------------------------------------------------+
|           Applications / External Systems         |
+---------------------------------------------------+
| ATOS-NET                                           |
| brokered network | distributed execution | replay |
+---------------------------------------------------+
| ATOS-2 Agent / Service Layer                       |
| root | stated | policyd | netd | accountd | user  |
+---------------------------------------------------+
| ATOS-1 Runtime Host                                |
| native | WASM | future managed runtimes           |
+---------------------------------------------------+
| ATOS-0 Kernel                                      |
| sched | mailbox | capability | state | audit      |
| energy | syscall | checkpoint                     |
+---------------------------------------------------+
| x86_64 Architecture + Boot                        |
| gdt | idt | paging | timer | trap | multiboot     |
+---------------------------------------------------+
|                    QEMU / Hardware                |
+---------------------------------------------------+
```

### Three Runtimes

Every piece of running code is an **Agent**. ATOS supports three execution runtimes, each optimized for a different role:

| Runtime | Use Case | Determinism | Location |
|---------|----------|-------------|----------|
| **Native x86_64** | High-performance system services (stated, policyd, netd) | Scheduling-level | Ring-3 user mode |
| **WASM** | Portable, sandboxed user agents with fuel metering | Full (instruction-counted) | Kernel-hosted interpreter |
| **eBPF-lite** | Kernel-resident policy enforcement and event filtering | Full (verified, bounded) | Kernel Ring-0 |

### Capability-Based Security

There is no superuser. Authority is expressed as **Capability tokens**:

- `SendMailbox(3)` — permission to send messages to mailbox 3
- `AgentSpawn` — permission to create child agents
- `PolicyLoad` — permission to load eBPF policy programs
- `Network` — permission to make network requests via netd

Capabilities can only be **delegated from parent to child, and only as a subset**. They are never created from nothing. Each capability carries a cryptographic signature, verifiable even across nodes.

### Verifiable Execution

This is what makes ATOS unique — **ProofGrade execution**:

1. Start from a checkpoint
2. Replay under a deterministic scheduler
3. Every step produces a hash-chained event log
4. Generate an **execution proof** that any third party can independently verify

This means you can outsource computation to an untrusted node, then verify the result is correct — without re-executing. The energy model turns CPU time into a metered, billable, auditable resource.

### Distributed by Design

Agents don't know which physical node their peers are on. Mailbox messages are automatically routed across nodes by the `routerd` system agent (over kernel UDP with signed capability verification). Agents can be **migrated** between nodes — checkpoint, serialize, transfer, resume.

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
git clone https://github.com/tos-network/atos.git
cd atos
make run
```

This builds the kernel in release mode, converts the ELF64 binary to ELF32 for Multiboot compatibility, and boots it in QEMU. You will see serial output like:

```
ATOS boot ok
ATOS v0.1 - AI-native Operating System
[OK] Architecture initialized
[OK] Scheduler initialized
[EVENT seq=0 tick=0 agent=0 type=SYSTEM_BOOT arg0=0 arg1=0 status=0]
[INIT] Idle agent created: id=0
[INIT] Root agent created: id=1
[INIT] Ping agent created: id=2
[INIT] Pong agent created: id=3
[SCHED] Context switching to first agent: id=1
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

### UEFI Boot

ATOS supports both Multiboot v1 and UEFI boot:

```bash
# Install OVMF firmware
sudo apt install ovmf

# Build and run via UEFI
make uefi-run
```

The UEFI loader (`uefi/`) is a standalone PE/COFF application that embeds the kernel ELF, sets up higher-half page tables, exits UEFI boot services, and jumps to `kernel_main`.

## Developer SDK

Build agents for ATOS using the SDK:

```bash
# Native agent (x86_64)
cd sdk/atos-sdk
cargo build --target x86_64-unknown-none

# WASM agent
cd sdk/atos-wasm-sdk
cargo build --target wasm32-unknown-unknown --release

# CLI tools
cd sdk/atos-cli
cargo build --release
./target/x86_64-unknown-linux-gnu/release/atos help
```

### CLI Commands

```bash
atos build [--target native|wasm] <dir>   # Build an agent
atos deploy <agent.wasm>                  # Validate + deploy info
atos inspect <serial-log.txt>             # Analyze event log
atos replay <disk-image.img>              # Parse checkpoint
atos verify <proof.bin>                   # Verify execution proof
```

## Roadmap

ATOS is developed across 10 stages, from bare-metal boot to a production-grade agent execution appliance.

| Stage | Focus | Status |
|-------|-------|--------|
| **1** | Kernel foundation — boot, scheduler, mailbox, capabilities, energy | ✅ Complete |
| **2** | Isolation & runtimes — ring-3, WASM interpreter, eBPF-lite, persistent state | ✅ Complete |
| **3** | Production hardening — SMP, checkpoint/replay, deterministic scheduling | ✅ Complete |
| **4** | Ecosystem — NVMe, NIC drivers, distributed execution, SDK, attestation | ⚠️ Near-complete |
| **5** | Trusted authority plane — signed capability leases, revocation, admission control | Planned |
| **6** | Durable state plane — versioned storage, snapshots, encrypted keyspaces | Planned |
| **7** | Agent package ecosystem — signed packages, registry, skilld, lifecycle management | Planned |
| **8** | Distributed execution fabric — placement, cross-node pipelines, migration | Planned |
| **9** | Verifiable execution economy — billing, settlement, proof-backed accounting | Planned |
| **10** | Appliance-grade ATOS — multi-tenant, signed upgrades, remote operations | Planned |

### The Vision: All 10 Stages Complete

When all stages are delivered, ATOS becomes a **provable, metered, migratable agent execution platform**:

- **Every computation is an Agent** with an energy budget, a capability set, and an audit trail
- **Every permission is a Capability** that flows from parent to child, never from thin air, verifiable with cryptographic signatures
- **Every execution is provable** — a third party can verify "this code, on this input, produced this output" without re-running it
- **Every resource is metered** — CPU time is energy, energy is transferable, billing is built into the protocol
- **Every agent is portable** — checkpoint on node A, migrate to node B, resume execution with full state
- **Skills are deployable artifacts** — developers build WASM agents, sign them, publish to a registry, users install them via a standard protocol with automatic capability scoping

Think of it this way: if Linux is a shared factory where anyone can walk in and use any machine, ATOS is a factory where **every worker operates in their own sealed chamber**, communicating only through message slots, powered by a metered energy supply, watched by tamper-proof cameras, and any outsider can replay the footage to verify the work.

See the [Yellow Paper](yellowpaper.md) for the full engineering specification and detailed roadmap.

## License

[MIT](LICENSE)
