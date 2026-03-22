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
```

## Architecture

```
+---------------------------------------------------+
|              Test Agents / Runtimes                |
|   ping agent | pong agent | idle agent             |
+---------------------------------------------------+
|              AI-native Syscall ABI                 |
| yield | spawn | exit | send | recv | cap | energy  |
+---------------------------------------------------+
|                 Kernel Core                        |
| sched | mm | trap | syscall | ipc | cap | audit    |
+---------------------------------------------------+
|                x86_64 Arch Layer                   |
| gdt | idt | paging | timer | irq | context         |
+---------------------------------------------------+
|               Boot / Loader Layer                  |
|                  (Multiboot v1)                    |
+---------------------------------------------------+
|                    QEMU VM                         |
+---------------------------------------------------+
```

### Syscall ABI

11 syscalls, following the [Yellow Paper](yellowpaper.md) section 14.2:

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

### Project Structure

```
aos/
  asm/                    # x86_64 assembly (NASM)
    boot.asm              #   32-bit → 64-bit boot transition
    multiboot_header.asm  #   Multiboot v1 header
    switch.asm            #   Context switch (callee-saved regs)
    trap_entry.asm        #   Interrupt/exception stubs
    syscall_entry.asm     #   Syscall entry (future ring-3)
  src/
    main.rs               # Kernel entry point
    agent.rs              # Agent model, types, constants
    sched.rs              # Round-robin scheduler + context switch
    mailbox.rs            # Bounded ring-buffer IPC
    capability.rs         # Capability-based authority
    energy.rs             # Execution budgeting
    event.rs              # Structured audit events
    state.rs              # In-memory key-value state
    syscall.rs            # Syscall dispatcher (11 handlers)
    trap.rs               # Fault/interrupt handler policy
    init.rs               # System bootstrap (creates agents)
    panic.rs              # Kernel panic handler
    arch/x86_64/          # Architecture layer
      gdt.rs  idt.rs  serial.rs  timer.rs  paging.rs  context.rs
    agents/               # Built-in test agents
      root.rs  ping.rs  pong.rs  idle.rs
  linker.ld               # Linker script (kernel at 1MB)
  build.rs                # NASM build integration
  yellowpaper.md          # Full engineering specification
```

## What Works Today (Stage-1)

- Boots in QEMU from Multiboot v1, transitions to 64-bit long mode
- GDT with TSS, IDT with PIC remapping, PIT timer at 100 Hz
- 4 agents running with real assembly context switching
- Mailbox IPC: ping/pong agents exchange messages continuously
- Capability enforcement: send requires `CAP_SEND_MAILBOX:<target>`
- Energy budgeting: agents are suspended when budget reaches zero
- Structured audit log: every kernel action emits a parseable event over serial
- 184,000+ events verified in a single 10-second run

## What's Next

- Preemptive scheduling via timer interrupt
- Per-agent page tables (user-mode isolation)
- Checkpoint and replay
- Capability-carrying messages
- Durable state store
- WASM runtime backend
- Network and compute brokering

See the [Yellow Paper](yellowpaper.md) for the full roadmap.

## License

[MIT](LICENSE)
