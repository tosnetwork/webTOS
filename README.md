<p align="center">
  <img src="AOS.png" alt="AOS Logo" width="200">
</p>

<h1 align="center">AOS</h1>

<p align="center">
  <strong>An AI-native operating system built from scratch.</strong><br>
  Agents. Mailboxes. Capabilities. No legacy.
</p>

<p align="center">
  <a href="yellowpaper.md">Yellow Paper</a> &middot;
  <a href="#quickstart">Quickstart</a> &middot;
  <a href="#architecture">Architecture</a> &middot;
  <a href="LICENSE">MIT License</a>
</p>

---

## What is AOS?

AOS is a minimal operating system designed from first principles for AI agent execution. It is **not** a Linux distribution, not a POSIX-compatible environment, and not a desktop OS. It is a bare-metal execution substrate where agents, mailboxes, and capabilities replace processes, sockets, and ambient authority.

Modern operating systems were designed for human-operated computing. Their core abstractions — files, shells, user IDs — served that era well. AOS starts from a different premise: **what would an OS look like if its primary users were AI agents?**

### Design Principles

- **Architecture from zero.** Not inherited from legacy human-centric systems.
- **Code from zero.** Not a fork of Linux. Not a wrapper around an existing kernel.
- **VM-first.** Runs on QEMU/x86_64 to preserve architectural purity while minimizing hardware complexity.
- **Determinism over convenience.** Predictable, replayable behavior by default.
- **Explicit authority.** Nothing is accessible without a capability. No ambient root.

### Core Concepts

| Concept | Replaces | Purpose |
|---------|----------|---------|
| **Agent** | Process | Primary execution unit, uniquely identifiable, budget-limited |
| **Mailbox** | Socket/pipe | Bounded message queue for inter-agent communication |
| **Capability** | UID/permissions | Explicit token of authority, no ambient access |
| **State Object** | File | In-memory key-value keyspace, capability-scoped |
| **Energy Budget** | (none) | Per-agent execution metering, enforced by the kernel |
| **Event Log** | (afterthought) | Built-in structured audit from day one |

### Who Uses AOS

AOS is not a general-purpose operating system. Its users are autonomous systems that need deterministic execution, minimal privilege, and verifiable behavior.

**AI Agent Platforms** — Run AI agents in isolated, auditable sandboxes. Agents are written in WASM or native Rust, communicate via mailboxes, and operate under capability-scoped authority. Every action is logged. Agents can be checkpointed, migrated, and replayed. If an agent crashes, it cannot affect other agents.

**Verifiable Computation** — Execute workloads where results must be provably correct. WASM agents run deterministically (fuel-counted). State transitions produce Merkle proofs. Checkpoints enable independent replay verification. The energy model maps directly to metered execution (gas, tokens, billing units).

**Secure Edge Devices** — Deploy on embedded hardware where the attack surface must be minimal. No shell, no root, no filesystem, no ambient authority. Each agent holds only the capabilities it was explicitly granted. Agent crashes are isolated by hardware-enforced memory boundaries. Energy budgets prevent runaway execution.

**AOS is not for:** desktop users, server administration, running existing Linux/POSIX programs, or any workload that requires a traditional OS interface.

### Layering

- **AOS** = the full system architecture
- **AOS-0** = the privileged kernel substrate
- **AOS-1** = the runtime host for native, WASM, and future managed runtimes
- **AOS-2** = the agent and system-service layer
- **AOS-NET** = the brokered / distributed execution layer

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
git clone https://github.com/tos-network/aos.git
cd aos
make run
```

This builds the kernel in release mode, converts the ELF64 binary to ELF32 for Multiboot compatibility, and boots it in QEMU. You will see serial output like:

```
AOS boot ok
AOS v0.1 - AI-native Operating System
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

AOS supports both Multiboot v1 and UEFI boot:

```bash
# Install OVMF firmware
sudo apt install ovmf

# Build and run via UEFI
make uefi-run
```

The UEFI loader (`uefi/`) is a standalone PE/COFF application that embeds the kernel ELF, sets up higher-half page tables, exits UEFI boot services, and jumps to `kernel_main`. This is the same approach Linux uses with its EFI stub.

## Architecture

AOS is the umbrella system. The early kernel is AOS-0, not the whole stack.

```
+---------------------------------------------------+
|           Applications / External Systems         |
+---------------------------------------------------+
| AOS-NET                                           |
| brokered network | distributed execution | replay |
+---------------------------------------------------+
| AOS-2 Agent / Service Layer                       |
| root | stated | policyd | netd | accountd | user  |
+---------------------------------------------------+
| AOS-1 Runtime Host                                |
| native | WASM | future managed runtimes           |
+---------------------------------------------------+
| AOS-0 Kernel                                      |
| sched | mailbox | capability | state | audit      |
| energy | syscall | checkpoint                     |
+---------------------------------------------------+
| x86_64 Architecture + Boot                        |
| gdt | idt | paging | timer | trap | multiboot     |
+---------------------------------------------------+
|                    QEMU / Hardware                |
+---------------------------------------------------+
```

Stage-1 is intentionally concentrated in AOS-0. AOS-1 is a thin native execution layer at first, AOS-2 starts as built-in bootstrap/test agents, and AOS-NET arrives later in the roadmap.

### Syscall ABI

22 syscalls, following the [Yellow Paper](yellowpaper.md):

| # | Name | Description |
|---|------|-------------|
| 0 | `sys_yield` | Yield execution voluntarily |
| 1 | `sys_spawn` | Create a child agent |
| 2 | `sys_exit` | Terminate the calling agent |
| 3 | `sys_send` | Send a message to a mailbox (non-blocking) |
| 4 | `sys_recv` | Receive a message from a mailbox (blocking) |
| 5 | `sys_cap_query` | Query capability possession |
| 6 | `sys_cap_grant` | Grant a capability to a child agent |
| 7 | `sys_event_emit` | Emit a custom audit event |
| 8 | `sys_energy_get` | Query remaining energy budget |
| 9 | `sys_state_get` | Read from agent's private keyspace |
| 10 | `sys_state_put` | Write to agent's private keyspace |
| 11 | `sys_cap_revoke` | Revoke a capability from an agent |
| 12 | `sys_recv_nonblocking` | Non-blocking receive |
| 13 | `sys_send_blocking` | Blocking send (waits if mailbox full) |
| 14 | `sys_energy_grant` | Grant energy to a child agent |
| 15 | `sys_checkpoint` | Save system state to disk |
| 16 | `sys_mmap` | Allocate memory pages |
| 17 | `sys_munmap` | Deallocate memory pages |
| 18 | `sys_mailbox_create` | Create additional mailbox |
| 19 | `sys_mailbox_destroy` | Destroy a mailbox |
| 20 | `sys_replay` | Enter deterministic replay mode |
| 21 | `sys_recv_timeout` | Receive with tick-based timeout |

### Project Structure

```
aos/
  asm/                        # x86_64 assembly (NASM)
    boot.asm                  #   32→64 bit boot, 512MB identity map
    multiboot_header.asm      #   Multiboot v1 header
    switch.asm                #   Context switch + ring-3 entry
    trap_entry.asm            #   Interrupt/exception stubs
    syscall_entry.asm         #   SYSCALL/SYSRET handler
    ap_trampoline.asm         #   SMP AP bootstrap (16→64 bit)
    user_agents.asm           #   Ring-3 test agents (ping/pong)
  src/
    main.rs                   # Kernel entry point
    agent.rs                  # Agent model (context, status, priority)
    sched.rs                  # SMP-safe priority scheduler
    mailbox.rs                # Bounded ring-buffer IPC
    capability.rs             # Capability authority + signing
    energy.rs                 # Execution budgeting + cost table
    event.rs                  # Structured audit events
    state.rs                  # Per-agent key-value state
    syscall.rs                # Syscall dispatcher (22 handlers)
    trap.rs                   # Fault handler + guard page detection
    init.rs                   # System bootstrap (12 agents)
    sync.rs                   # SpinLock with RFLAGS save/restore
    wasm/                     # WASM interpreter (40+ opcodes)
    ebpf/                     # eBPF-lite policy engine + verifier
    checkpoint.rs             # Checkpoint save/load + agent migration
    replay.rs                 # Deterministic replay + diff report
    proof.rs                  # Execution proof (hash chain)
    attestation.rs            # Kernel measurement + attestation report
    merkle.rs                 # Binary Merkle tree (FNV-1a 128-bit)
    persist.rs                # Append-only state log (ATA disk)
    net.rs                    # Kernel UDP (virtio-net + e1000)
    node.rs                   # Node identity for distributed execution
    smp.rs                    # SMP bootstrap (INIT/SIPI)
    arch/x86_64/              # Architecture layer
      acpi.rs                 #   RSDP/RSDT/MADT parser
      lapic.rs                #   Local APIC + timer driver
      pci.rs                  #   PCI bus enumeration + BAR decode
      virtio_net.rs           #   Virtio-net legacy PCI driver
      e1000.rs                #   Intel e1000 NIC driver
      nvme.rs                 #   NVMe DMA I/O (admin + IO queues)
      security.rs             #   SMEP/SMAP/NX enforcement
      paging.rs  gdt.rs  idt.rs  serial.rs  timer.rs  context.rs
    agents/                   # 12 built-in agents
      root.rs                 #   Checkpoint, proof, attestation
      ping.rs  pong.rs        #   Ring-3 IPC test agents
      stated.rs               #   State persistence manager
      policyd.rs              #   eBPF policy loader
      wasm_agent.rs           #   WASM interpreter demo
      accountd.rs             #   Energy accounting
      netd.rs                 #   Network broker (auto-detect NIC)
      routerd.rs              #   Cross-node mailbox routing
      skilld.rs               #   WASM skill installer
      idle.rs  bad.rs         #   Idle loop / unauthorized test
  sdk/
    aos-sdk/                  # Native agent SDK (#![no_std])
    aos-wasm-sdk/             # WASM agent SDK (wasm32 target)
    aos-cli/                  # CLI tools (build/deploy/inspect/replay/verify)
  linker.ld                   # Linker script (kernel at 1MB)
  build.rs                    # NASM build integration
  yellowpaper.md              # Full engineering specification
```

## What Works Today

### Stage 1 — Kernel Foundation
- Boots in QEMU from Multiboot v1, 32→64 bit long mode
- GDT with TSS, IDT with PIC remapping, PIT timer at 100 Hz
- Round-robin scheduler with assembly context switching
- Mailbox IPC, capability enforcement, energy budgeting
- Structured audit log over serial

### Stage 2 — Isolation & Runtimes
- Ring 3 user-mode agents with per-agent page tables (SYSCALL/SYSRET)
- WASM interpreter (40+ opcodes, fuel metering, host function bridge)
- eBPF-lite policy engine (verifier, interpreter, attachment points)
- Persistent state on ATA disk with CRC32 crash recovery

### Stage 3 — Production Hardening
- SMP: ACPI parsing, LAPIC driver, AP bootstrap via INIT/SIPI
- Priority-aware scheduling (4 levels) with SpinLock protection
- Checkpoint/replay with Merkle state tree and deterministic scheduling
- Stack guard canaries, orphan reparenting, 64KB aligned stacks
- 12 system agents running concurrently on 2 cores

### Stage 4 — Ecosystem
- NVMe DMA I/O (admin + IO queue setup, PRP-based read/write)
- e1000 + virtio-net NIC drivers with auto-detection
- Distributed execution: cross-node mailbox routing, node discovery
- Execution proofs: hash-chain verification, standalone verifier
- Remote attestation: kernel measurement + signed reports
- CPU security: SMEP/SMAP/NX detection and enforcement
- Developer SDK: native + WASM agent crates + CLI tools

### By the Numbers

- **80+ source files** across Rust + x86_64 Assembly
- **16,000+ lines of code**, written from scratch
- **22 syscalls**, **12 agents**, **2 CPU cores**
- **0 external runtime dependencies** (no libc, no POSIX, no Linux)

## Developer SDK

Build agents for AOS using the SDK:

```bash
# Native agent (x86_64)
cd sdk/aos-sdk
cargo build --target x86_64-unknown-none

# WASM agent
cd sdk/aos-wasm-sdk
cargo build --target wasm32-unknown-unknown --release

# CLI tools
cd sdk/aos-cli
cargo build --release
./target/x86_64-unknown-linux-gnu/release/aos help
```

### CLI Commands

```bash
aos build [--target native|wasm] <dir>   # Build an agent
aos deploy <agent.wasm>                  # Validate + deploy info
aos inspect <serial-log.txt>             # Analyze event log
aos replay <disk-image.img>              # Parse checkpoint
aos verify <proof.bin>                   # Verify execution proof
```

See the [Yellow Paper](yellowpaper.md) for the full specification and roadmap.

## License

[MIT](LICENSE)
