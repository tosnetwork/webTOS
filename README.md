<p align="center">
  <img src="webTOS.png" alt="webTOS" width="360">
</p>

<p align="center">
  <strong>Unmodified Linux x86-64 programs, running in a browser tab.</strong>
</p>

<p align="center">
  <a href="#overview">Overview</a> &middot;
  <a href="#architecture">Architecture</a> &middot;
  <a href="#project-status">Status</a> &middot;
  <a href="ROADMAP.md">Roadmap</a> &middot;
  <a href="#running-natively">Development</a> &middot;
  <a href="LICENSE">MIT License</a>
</p>

## Overview

webTOS runs **unmodified Linux x86-64 binaries inside a browser tab**. Not a
port, not a reimplementation in JavaScript, and not a container on someone
else's machine: the same ELF that runs on a Linux host, executing in the page.

It is a WebAssembly x86-64 execution engine with the operating-system half of
the Linux ABI on top of it — processes, threads, signals, a virtual
filesystem, sockets, and pseudoterminals — plus a browser host that supplies
storage, a terminal, and a network path.

The browser is the deployment environment, not the execution model. webTOS
owns its own scheduler, guest memory, process state, and filesystem rather
than exposing ambient browser authority to what it runs: a guest reaches the
network only through a relay the page configured, and a deployment can bound
its memory, CPU, storage, and network use with runtime-enforced budgets.

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

Running a real program in a browser usually means one of three things, and
each gives something up. Reimplementing the tool in JavaScript means it is no
longer the tool. Renting a container means the operator holds the compute and
the data. Using a proprietary browser VM means the engine is somebody else's
to license and to fix.

webTOS is the third option built differently: the real binary, in the user's
own browser, on an engine that is MIT-licensed and in this repository.

## What it gives you

### The program, not a port

An ELF built for Linux x86-64 runs as-is. BusyBox applets, the host `git`
doing real repository work, and a 52 MB agent binary all run unmodified. So
does a C toolchain: a shell forks `gcc`, which execs the compiler, the
assembler, and the linker, and then runs what came out
(`crates/linux-compat/tests/gcc.rs`). What the runtime is for is in
[`docs/USE-CASES.md`](docs/USE-CASES.md).

### Authority the page grants explicitly

A guest has no network at all until the page asks for one, and then only to
destinations an allowlist names. Credentials are injected at runtime, scoped
to the workload that should see them, and kept out of filesystem snapshots.
Guest socket operations become a command stream the host carries out, which
is why the browser and a native host can enforce different policies over the
same runtime.

### Bounds that produce an errno, not a dead tab

Memory, CPU, storage, network bytes, and the event log each have a
runtime-enforced budget a deployment can set. A workload that will not fit a
configured budget is refused at the request rather than dying part-way
through, and a guest over a limit sees an error it already knows how to
handle.

### Determinism that is gated, not claimed

The same input retires the same instruction stream in Chromium, Firefox, and
WebKit, checked against recorded architectural traces — the syscall stream
with its arguments, delivered signals, and register samples at exact
instruction counts. The runtime's native network-recording layer can replay a
recorded session without a network; browser-host recording and replay is not
yet an exported user-facing flow.

### State that survives a reload

The guest filesystem is snapshotted to OPFS and restored into a fresh
machine, so a session resumes where it stopped.

## Architecture

The current architecture, in text:

```text
Browser
  |
  +-- Terminal and control interface
  +-- Persistent storage adapter
  +-- Network adapter
  +-- Worker-based execution host
          |
          v
      webtos-web (WebAssembly module)
          |
          +-- Linux x86-64 compatibility layer
          +-- x86-64 execution engine
          +-- Scheduling, budgets, snapshots, and trace events
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
  webTOS runtime services
```

The compatibility layer includes ELF64 loading, virtual memory areas, dynamic
linker support, file descriptors, VFS operations, processes, threads, futexes,
signals, sockets, polling, and epoll-style event handling.

## Project Status

webTOS is the browser-hosted runtime: a WebAssembly x86-64 engine that runs
real Linux binaries in a tab. The native TOS kernel it grew out of has been
removed from this repository — it was a separate, bare-metal Stage-1 crate
that the browser pivot left behind, and the current project under `crates/`
does not depend on it. What remains is the runtime and its host.

Available in the repository today:

- x86-64 instruction decoding, lifting, interpretation, and hot-block
  p-code-to-WebAssembly translation (`crates/x64-engine`)
- ELF64 loading and substantial Linux x86-64 system-call compatibility, with
  processes, threads, futexes, signals, sockets, polling, and epoll
  (`crates/linux-compat`)
- Deterministic time, randomness, scheduling, and event ordering
- Checkpoints, filesystem snapshots, structured trace events, and configurable
  per-agent budgets on memory, CPU, storage, network, and the event log
- Manifest enforcement for both resident images and canonical chunked images:
  a host verifies the exact manifest bytes with platform cryptography, then
  the module enforces paths, metadata, chunk hashes, and the manifest root
- Immutable file-backed demand paging for the initial ELF, dynamic loader,
  `MAP_PRIVATE`, file reads, and syscall user-buffer copies, with verified OPFS
  chunks and an async browser fallback
- A dependency-license manifest and a security policy (`SECURITY.md`)
- The browser host: a Web Worker, terminal, OPFS persistence, and a network
  relay, gated in Chromium, Firefox, and WebKit
- A gated OpenFox workload profile, plus Node/Codex/Claude Code compatibility
  evidence; complete Codex and Claude Code browser-image profiles remain M7 work

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

The browser host supports two delivery modes. The demo's `?image=NAME` path
still streams a whole image into the guest and OPFS without creating an extra
page-side copy. The manifest path installs only metadata and content hashes;
the initial ELF, dynamic loader, `MAP_PRIVATE`, and file reads then fetch
verified 64 KiB chunks on first access from an OPFS hash cache or the network.
Snapshots retain the manifest root and immutable descriptors, not cached base
chunks. A 52 MB streamed agent binary reaches a shell prompt in about three
seconds on the first load and one on the next; the lazy path is the one meant
for the 200+ MB agent images. To use the legacy demo stream:

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

Determinism is gated against recorded baselines rather than only against
another run: `test_data/traces/` holds architectural traces — the syscall
stream with its arguments, delivered signals, and register and flag samples
taken at exact instruction counts — and the browser matrix reproduces one of
them register for register in each engine. The format is documented in
`crates/linux-compat/src/trace.rs`; regenerate after an intended change with:

```bash
cd crates && cargo test -p linux-compat --release --test trace -- --ignored rewrite
```

Measurements, as opposed to gates, live in `web/bench.mjs` and
`crates/linux-compat/tests/bench.rs`: the same guest workloads in a browser and
natively, so the two can be read against each other, plus a few-hundred-byte
control module that separates "this engine is slow" from "this engine dislikes
our runtime". What they currently report, and what it implies, is in
[`docs/performance.md`](docs/performance.md).

**Run the suite on x86-64 Linux before trusting it.** Every test whose fixture
is compiled by the host `gcc` — the pseudoterminal, signal, and glibc cases —
cannot build a static Linux binary on macOS or ARM, so it returns early and
reports success. A green suite on a Mac is not a green suite: a signal-loss
bug lived behind that gap until the suite was run somewhere it could not skip.
See *A bug that only appeared where the tests ran* in the roadmap.

The native suite pins its target in `crates/.cargo/config.toml`, so on a macOS
or ARM development machine run it against the host instead — tests whose
fixtures need an x86-64 Linux toolchain skip themselves:

```bash
cd crates && cargo test -p linux-compat --release --target aarch64-apple-darwin
```

A skip prints `SKIP:` naming the fixture and how to get it, but `cargo test`
captures that for a passing test, so add `-- --nocapture` to see what a run
actually covered. On macOS 23 cases skip: every C fixture, which is most of
the threads, processes, epoll, pty, and signal surface.

On a machine that can build and run everything, make a skip a failure so the
run cannot quietly cover less than it claims:

```bash
cd crates && WEBTOS_REQUIRE_FIXTURES=1 cargo test -p linux-compat --release
```

The x86-64 Linux host passes that way with no skips.

## Running natively

The same engine runs outside a browser, which is the faster way to iterate and
the only way to run the parts of the suite a browser cannot host. Rust nightly
is the only prerequisite; cargo runs from `crates/`, never the repository
root.

```bash
cd crates
GUEST_MOUNT="/lib/x86_64-linux-gnu:/lib/x86_64-linux-gnu,/lib64:/lib64" \
cargo run --release -p linux-compat --example run_guest -- /usr/bin/git --version
```

`SYSCALL_ERR_TRACE=1` prints every syscall that returned an error, with the
path for `openat`; `RUST_LOG=linux_compat=trace` prints all of them. On a
fault the runner reports the faulting page's permissions, which separates
"jumped into nothing" from "jumped into a page the loader left
non-executable".

On a macOS or ARM development machine, run the suite against the host — tests
whose fixtures need an x86-64 Linux toolchain skip themselves:

```bash
cd crates && cargo test -p linux-compat --release --target aarch64-apple-darwin
```

## Documentation

- [Documentation Index](docs/README.md) - guides, specifications, runtime
  notes, and engineering roadmaps
- [Roadmap](ROADMAP.md) - browser x86-64 architecture, workload milestones,
  acceptance gates, and release definition
- [Use cases](docs/USE-CASES.md) - what the runtime supports today, and what
  it deliberately does not
- [Performance and memory](docs/performance.md) - what the interpreter costs
  per browser engine, and what a tab grants it

Several documents under `docs/` describe the bare-metal kernel that has been
removed — the yellow paper, the Wasm runtime and engine-integration notes, the
policy specification, and the package manager. They are kept as history and
are not linked here, because they no longer describe anything in this tree.

## License

[MIT](LICENSE)
