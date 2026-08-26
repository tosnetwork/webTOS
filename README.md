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

## Browser Host

The browser host runs the same engine in a Web Worker: `crates/webtos-web`
exports a C-ABI wasm module and `web/` hosts the worker, terminal, and OPFS
persistence around it.

```bash
rustup target add wasm32-unknown-unknown
tools/fetch_busybox.sh              # BusyBox demo image (GPL-2.0, not vendored)
tools/fetch_alpine_rootfs.sh        # musl loader for the dynamic-linking checks
tools/fetch_xterm.sh                # terminal emulator for the shell demo (MIT)
bash web/build.sh                   # build the wasm module and stage the images
python3 -m http.server -d web 8080
```

Guest images are streamed rather than loaded: the worker fetches an image
itself, writing it into the guest filesystem and an OPFS cache as the bytes
arrive, so nothing ever holds a whole one. A 52 MB agent binary reaches a
shell prompt in about three seconds on the first load and one on the next,
where buffering it in the page, transferring it, and copying it into the
module would need three copies at once — which wasm32 does not have room for.
`?image=NAME` on the terminal page streams `./NAME` into `/bin/NAME`:

```bash
tools/build_openfox_fixture.sh      # needs the OpenFox source (OPENFOX_SRC)
bash web/build.sh
# then open http://localhost:8080/terminal.html?image=openfox
# and run:  openfox --help
```

Two pages: `/` runs one-shot BusyBox commands against a filesystem that
survives reload, and `/terminal.html` is an interactive BusyBox shell on a
pseudoterminal — it echoes what you type, forks and execs commands through
pipelines, runs the full-screen `vi` editor, and repaints when the window is
resized (a host resize is a SIGWINCH to the guest's foreground group). A guest
blocked on a terminal read pauses the run rather than deadlocking it; the next
keystroke resumes the same process where it stopped.

### Giving the guest a network

A tab cannot open a socket, and the guest does its own TLS and its own DNS, so
what it needs is a byte relay rather than an HTTP proxy. `tools/webtos_gateway.mjs`
is that relay, and because it is the only component that can reach the network
on the guest's behalf, it is where the policy lives:

```bash
npm install                                   # the relay needs 'ws'
node tools/webtos_gateway.mjs --allow example.com:80 --allow 1.1.1.1:53
python3 -m http.server -d web 8080
# then open http://localhost:8080/terminal.html?gateway=ws://127.0.0.1:8081
```

Nothing is reachable unless an `--allow` rule names it; with no rules the relay
starts and refuses everything. A rule is `host:port`, where the host is an IPv4
literal or a name the relay resolves — the guest does its own DNS and connects
to an address, so name rules are matched by address. The relay also requires a
page `Origin` it was told to accept (localhost by default), so a page on any
site the user happens to visit cannot drive their relay as an open proxy; that
check constrains browsers, not local programs, which is why the allowlist is
the boundary that matters. It binds to loopback, and logs every decision,
allowed and refused alike.

The guest has no network at all until the page asks for one, and the machine
itself never opens anything: guest socket operations become a command stream
the host carries out, which is why the browser and the native host can enforce
different policies over the same runtime.

Two harnesses gate it:

```bash
node web/test_node.mjs              # the wasm module under Node/V8, no browser

npm install                         # Playwright, for the browser matrix
npx playwright install              # Chromium, Firefox, and WebKit engines
node web/test_browsers.mjs          # all three engines; --engines= to narrow
```

`web/test_browsers.mjs` drives the demo page the way a user does — BusyBox
applets, a snapshot, a real page reload, a read-back of the restored
filesystem — runs the static and dynamically linked fixtures through the
worker protocol directly, drives the interactive terminal (a streamed image the guest
hashes to prove it arrived intact, a shell prompt, a pipeline, the full-screen
editor, and a resize that repaints without a keystroke), starts its own
gateway allowing exactly one destination and checks
both that the guest can fetch over a real socket and that anything else is
refused, and finally reruns the page in a profile without persistent storage
to confirm the host reports the missing capability instead of failing at the
first click. It ends by comparing per-command instruction counts across
the three engines: identical input must retire an identical instruction stream
everywhere.

Measurements, as opposed to gates, live in `web/bench.mjs` and
`crates/linux-compat/tests/bench.rs`: the same guest workloads in a browser and
natively, so the two can be read against each other. What they currently
report, and what it implies, is in [`docs/performance.md`](docs/performance.md).

The native suite pins its target in `crates/.cargo/config.toml`, so on a macOS
or ARM development machine run it against the host instead — tests whose
fixtures need an x86-64 Linux toolchain skip themselves:

```bash
cd crates && cargo test -p linux-compat --release --target aarch64-apple-darwin
```

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
