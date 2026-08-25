# webTOS Documentation

This directory is the entry point for webTOS documentation. webTOS is an
AI-agent-first bare-metal operating system kernel designed to run in the
browser. The repository also retains its native x86-64 reference environment
for kernel development and compatibility validation.

## Start Here

- [Project overview](../README.md) - product direction, architecture, status,
  and native development commands
- [Product roadmap](../ROADMAP.md) - the primary webTOS plan from static
  `hello` and BusyBox through OpenFox, Codex, and Claude Code
- [Architecture](../TOS_ARCHITECTURE.md) - kernel subsystems and execution
  model inherited from the native TOS core
- [Use cases](../USE-CASES.md) - agent and contract workload scenarios

## Guides and Examples

- [Smart contract example](contract-example.md) - conceptual Wasm contract
  packaging, deployment, invocation, and receipt flow
- [Real hardware testing](../REAL_HARDWARE_TEST.md) - native x86-64 reference
  validation; this is not the browser launch path
- [Package manager](../PackageManager.md) - `.tos` package and installation
  model

## Runtime and Compatibility

- [Linux compatibility](../LinuxCompat.md) - Linux x86-64 syscall, process,
  VFS, memory, and networking translation
- [WebAssembly runtime specification](../WASM-runtime-spec.md) - Wasm
  execution classes and host ABI
- [Wasm engine integration](wasm-engine-integration.md) - boundary between
  the standalone `wasbi` engine and the webTOS kernel
- [Kernel policy runtime](../eBPF-lite-spec.md) - policy instructions,
  helpers, maps, and attachment points

## Specifications

- [Yellow Paper](../yellowpaper.md) - current detailed engineering
  specification
- [Yellow Paper v2](../yellowpaper_v2.md) - retained design snapshot; verify
  implementation claims against current source before relying on it
- [Contract and proof platform plan](../TODO-proof-contract-platform.md) -
  forward-looking contract execution and proof work

## Engineering Roadmaps

[`ROADMAP.md`](../ROADMAP.md) is the primary product roadmap. The following
files are supporting implementation plans for the native Linux substrate and
contract system; they are not descriptions of guaranteed current behavior:

- [Linux maturity](../TODO-linux-maturity.md)
- [Linux runtime](../TODO-linux-runtime.md)
- [Linux substrate depth](../TODO-linux-substrate-depth.md)
- [Memory subsystem](../TODO-memory-subsystem.md)
- [Professional uptake](../TODO-professional-uptake.md)
- [Runtime semantics](../TODO-runtime-semantics.md)

## Naming and Status Conventions

- **webTOS** is the browser-capable operating-system project and product name.
- **TOS** remains in existing kernel ABI names, Rust crate names, SDK paths,
  package formats such as `.tos`, and historical specifications until those
  interfaces are deliberately migrated.
- **Available** means the implementation exists in this repository and has a
  native reference path.
- **Browser integration** means the kernel feature exists but its Web host
  adapter or x86-64 Web execution path is still being connected.
- **Roadmap** means the document describes intended work and must not be read
  as a release guarantee.

## Documentation Maintenance

When changing behavior:

1. Update the closest implementation guide or specification.
2. Mark browser-only, native-only, and shared behavior explicitly.
3. Keep commands executable against the current repository layout.
4. Link new documents from this index.
5. Avoid presenting roadmap items as completed functionality.
