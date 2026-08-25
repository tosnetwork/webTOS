<p align="center">
  <img src="webTOS.png" alt="webTOS — Operating System for AI Agents" width="360">
</p>

<p align="center">
  <strong>An AI-agent-first bare-metal operating system kernel that runs in the browser.</strong>
</p>

<p align="center">
  <a href="#overview">Overview</a> &middot;
  <a href="#architecture">Architecture</a> &middot;
  <a href="#project-status">Status</a> &middot;
  <a href="ROADMAP.md">Roadmap</a> &middot;
  <a href="#native-development">Development</a> &middot;
  <a href="LICENSE">MIT License</a>
</p>

## Overview

webTOS is an **AI-agent-first bare-metal operating system kernel designed to
run inside the browser**. It brings the isolation, scheduling, resource
accounting, Linux compatibility, and verifiable execution model of TOS to a
portable Web runtime.

Instead of treating AI agents as ordinary processes, webTOS makes them a
first-class operating-system abstraction. Each agent has explicit authority,
private state, a metered execution budget, and auditable communication
channels.

The same kernel architecture supports three workload models:

- **Native x86-64 agents** using the TOS system-call ABI
- **Linux x86-64 ELF programs** using the Linux compatibility layer
- **WebAssembly agents** using the built-in deterministic Wasm runtime

The browser is the deployment environment, not the operating-system model.
webTOS keeps its own scheduler, virtual memory model, process and agent state,
virtual filesystem, capabilities, and execution records rather than exposing
ambient browser authority directly to workloads.

### Primary Goal

The primary goal is to run unmodified Linux x86-64 AI agent software locally
in the browser. Development is gated by real workloads rather than raw
instruction or syscall counts:

```text
static hello
    -> static BusyBox
    -> dynamic Linux ELF
    -> threads and event-driven networking
    -> OpenFox
    -> Codex and Claude Code
```

See the [webTOS Roadmap](ROADMAP.md) for architecture boundaries, milestone
exit criteria, risks, and the product definition of done.

## Why webTOS?

Most execution environments were designed around applications and human
users. webTOS starts with a different question: what should an operating
system look like when its primary users are autonomous AI agents?

| Traditional environment | webTOS |
|-------------------------|--------|
| Processes and threads | Agents with budgets and parent-child relationships |
| Ambient permissions | Explicit, delegatable capabilities |
| Shared filesystem | Isolated, Merkle-backed keyspaces |
| Unmetered execution | Instruction and system-call energy accounting |
| Ad-hoc IPC | Typed, auditable mailboxes |
| Best-effort logs | Hash-chained events and replayable receipts |
| Machine-specific deployment | Portable browser execution |

## Core Model

### Agents

An agent is the primary execution unit. It owns an execution context, energy
budget, capabilities, mailboxes, and state keyspace. Parent agents can create
children and delegate only a subset of their own authority.

### Capabilities

There is no ambient root authority in the agent model. Access to networking,
state, agent creation, and inter-agent communication is represented by
explicit capability records that can be inspected and audited.

### Mailboxes

Agents communicate through bounded mailboxes. This gives the scheduler a
deterministic and observable boundary for local services, networking, and
cross-agent workflows.

### Energy

Every instruction, system call, and message has a cost. When an agent exhausts
its energy budget it is suspended, making resource control part of the kernel
execution model rather than an external convention.

### Verifiable Execution

webTOS records structured, hash-chained events and supports deterministic
replay. Execution receipts can bind an output to the code, input, state, and
event sequence that produced it.

## Architecture

```text
Browser
  |
  +-- Terminal and control interface
  +-- Persistent storage adapter
  +-- Network adapter
  +-- Worker-based execution host
          |
          v
      webTOS kernel
          |
          +-- Agent scheduler and energy accounting
          +-- Capabilities and mailboxes
          +-- Keyspaces, events, checkpoints, and receipts
          +-- Linux x86-64 compatibility layer
          +-- WebAssembly runtime
```

For Linux workloads, webTOS provides the operating-system side of the Linux
x86-64 ABI:

```text
Linux x86-64 ELF program
          |
          v
  x86-64 execution engine
          |
       SYSCALL
          |
          v
  Linux compatibility layer
          |
          v
  webTOS kernel services
```

The compatibility layer includes ELF64 loading, virtual memory areas, dynamic
linker support, file descriptors, VFS operations, processes, threads, futexes,
signals, sockets, polling, and epoll-style event handling. Runtime validation
profiles exist for OpenJDK, Node.js, and Python workloads.

## Project Status

webTOS is being migrated from the native TOS kernel into a browser-hosted
runtime. The repository currently contains the mature native kernel and its
Linux compatibility substrate. The browser execution host and x86-64 Web
execution engine are the active integration boundary.

Available in the repository today:

- Bare-metal x86-64 kernel and QEMU development path
- Agent scheduler, capabilities, mailboxes, energy accounting, and keyspaces
- Native, Linux-compatible, and WebAssembly runtime classes
- ELF64 loader and substantial Linux x86-64 system-call compatibility
- Deterministic time, randomness, scheduling, futex, and event ordering
- Checkpoints, replay, structured events, and execution receipts
- Runtime validation tooling for Java, Node.js, and Python

Browser delivery work:

- Browser execution host and worker lifecycle
- x86-64 instruction execution in the Web runtime
- Browser-backed persistent storage and networking
- Browser terminal, image loading, snapshots, and packaging
- Workload profiles for OpenFox, Codex, and Claude Code

## Native Development

The native build remains the reference environment while the browser host is
integrated.

### Prerequisites

- Rust nightly
- NASM
- QEMU with x86-64 system emulation
- GNU binutils (`objcopy`)

On Ubuntu or Debian:

```bash
sudo apt install nasm qemu-system-x86 binutils
```

### Build and Run

```bash
git clone https://github.com/tosnetwork/webTOS.git
cd webTOS
make run
```

Other useful commands:

```bash
make build       # Build the release kernel
make debug-run   # Launch QEMU with a GDB stub
make uefi-run    # Boot with UEFI firmware
make test        # Run the native smoke suite
```

## SDKs

```bash
# Native agent SDK
cd sdk/tos-sdk && cargo build --target x86_64-unknown-none

# WebAssembly agent SDK
cd sdk/tos-wasm-sdk && cargo build --target wasm32-unknown-unknown --release

# Kernel policy SDK
cd sdk/tos-ebpf-sdk && cargo build --release

# Build, deploy, inspect, replay, and verification tools
cd sdk/tos-cli && cargo build --release
```

## Documentation

- [Documentation Index](docs/README.md) - guides, specifications, runtime
  notes, and engineering roadmaps
- [Roadmap](ROADMAP.md) - browser x86-64 architecture, workload milestones,
  acceptance gates, and release definition
- [Yellow Paper](docs/specs/yellowpaper.md) - kernel architecture and execution model
- [Linux Compatibility Notes](docs/LinuxCompat.md) - Linux ABI translation and runtime bring-up
- [WebAssembly Runtime Specification](docs/specs/WASM-runtime-spec.md) - Wasm execution and host ABI
- [Wasm Engine Integration](docs/wasm-engine-integration.md) - engine and
  kernel responsibility boundary
- [Kernel Policy Specification](docs/specs/eBPF-lite-spec.md) - policy runtime, helpers, maps, and hooks

## License

[MIT](LICENSE)
