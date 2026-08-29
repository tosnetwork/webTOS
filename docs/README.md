# webTOS Documentation

This directory is the entry point for webTOS documentation. webTOS runs
unmodified Linux x86-64 binaries inside a browser tab: a WebAssembly x86-64
engine, the operating-system half of the Linux ABI on top of it, and a browser
host supplying storage, a terminal, and a relayed network path.

The documents below describe the current browser runtime. Status labels mark
whether a statement is a regression gate, a recorded run, or roadmap work;
they are not interchangeable. There is no historical section, because the
documents that described the removed bare-metal kernel were deleted with it
rather than left to be mistaken for present behaviour; `git log` has them.

## Start here

- [Project overview](../README.md) - what it is, how to run it in a browser
  and natively, and what exists today
- [White paper](WHITEPAPER.md) - product and vision paper: thesis, why now,
  competitive position, moat, risks, and anticipated questions
- [Product roadmap](../ROADMAP.md) - the plan from static `hello` and BusyBox
  through OpenFox, Codex, and Claude Code, with milestone exit gates
- [Use cases](USE-CASES.md) - what the runtime supports today, what it has
  actually been pointed at, and what it deliberately does not do

## Application architecture research

- [Intent-native applications](INTENT_NATIVE_APPLICATIONS.md) - product and
  architecture direction for dynamically composing interfaces, local Linux
  processes, agents, tools, state, capabilities, approvals, and services from
  user intent; proposed graph and SDK surfaces are explicitly separated from
  current runtime capabilities

## Measurement and workloads

- [Performance and memory](performance.md) - interpreter and hot-block JIT
  measurements natively and per browser engine, what a tab grants it, and what
  that implies for milestone 8
- [OpenFox workload profile](workloads/openfox.md) - the milestone-6 agent:
  its gates and what each one covers
- [Node.js and agent runtime notes](workloads/node.md) - Node, Codex, and
  Claude Code compatibility evidence and the remaining milestone-7 boundaries
- [Lazy image demand paging](../feasibility/lazy_chunk_fs.md) - the
  first-principles scope, invariants, implementation shape, and exit gates for
  canonical chunk manifests and immutable file-backed paging

## Status conventions

- **Gated** means a test in this repository fails when the behaviour breaks.
  Milestone claims in the roadmap name the gate.
- **Run** means it has been made to work and recorded, but nothing would catch
  a regression. The use-case document distinguishes the two explicitly.
- **Roadmap** means intended work with an exit criterion written down. It is
  not a release guarantee.
- **TOS** survives in crate names and identifiers. The bare-metal kernel that
  once carried the name has been removed from this repository.

## Maintenance

When changing behaviour:

1. Update the closest document, and say which of the three states above the
   change lands in.
2. Mark browser-only, native-only, and shared behaviour explicitly — most of
   the suite cannot run on a developer's macOS machine, and a document that
   forgets this reports coverage that did not happen.
3. Keep commands executable against the current repository layout. A command
   that cannot run is worse than no command.
4. Link new documents from this index.
5. Never present roadmap items as completed functionality.
