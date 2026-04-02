# Linux Substrate Depth Plan

This document tracks the next substrate-strengthening batch after
`TODO-professional-uptake.md`. The goal is to move TOS from a runtime-compatible
Linux substrate to a steadier and more complete Linux foundation for long-lived
OpenJDK, Python, Node.js, and future higher-depth workloads.

## Goals

- Deepen Linux process, synchronization, and signal semantics beyond the
  current smoke-tested baseline.
- Reduce the number of remaining success-path stubs in memory, timer, and
  filesystem syscalls.
- Strengthen durability, temporary-workspace, and helper-process behavior for
  longer-running runtime suites.
- Keep deterministic scheduler policy, energy accounting, and TOS-native
  runtime ownership intact.

## Status Summary

- Batch 1 (`TODO-memory-subsystem.md`): completed
- Batch 2 (`TODO-runtime-semantics.md`): completed
- Batch 3 (`TODO-professional-uptake.md`): completed
- Phase 1: in progress
- Phase 2: in progress
- Phase 3: in progress

## Phase 1: Process and Synchronization Depth

Status: in progress

Target:

- Close the remaining process-lifecycle seams that still show up under helper
  JVMs, compiler subprocesses, and long-running runtime harnesses.
- Deepen synchronization semantics so runtimes rely less on compatibility
  fallbacks.

Scope:

- Continue process-object depth for helper children, `vfork`, `clone`, and
  `wait4`.
- Replace remaining futex and modern synchronization fallbacks with real
  semantics or honest failure codes.
- Tighten helper-process cleanup, resource refund, and wait visibility.
- Preserve deterministic wake ordering.

Validation gates:

- `make java-test`
- `tools/phase6_runtime_matrix.sh`
- guest-side OpenJDK `jtreg` `java.base` smoke
- longer-running Java subtree runs no longer depend on helper-child special
  handling

Current progress:

- helper-child refund and wait visibility have already been tightened in the
  preceding runtime work,
- `futex` now has real `WAIT`, `WAKE`, `WAIT_BITSET`, `WAKE_BITSET`,
  `REQUEUE`, and `CMP_REQUEUE` paths, and
- `FUTEX_WAKE_OP` now performs deterministic update-and-wake semantics for the
  uniprocessor substrate,
- unsupported futex operations are moving away from fake success results, and
- deterministic single-CPU `rseq` registration is now available so modern
  runtimes no longer need to treat it as universally unavailable, and
- single-CPU `membarrier` query/registration paths are now available so modern
  runtimes can stop treating the substrate as a legacy kernel.

## Phase 2: VM, Timer, and Signal Depth

Status: in progress

Target:

- Close the biggest remaining semantic gaps in memory management, per-process
  timers, and user-facing signal ABI behavior.

Scope:

- Implement `mremap` and deepen `msync`/mapping-lifetime behavior.
- Replace timer stubs (`getitimer`, `setitimer`, `alarm`) with real
  deterministic process-timer semantics.
- Extend signal delivery toward fuller user ABI coverage, including richer
  handler shapes and stronger timer-signal behavior.
- Keep the current VMA/backend split and deterministic fault path.

Validation gates:

- targeted memory/timer smoke tests
- `make java-test`
- guest-side OpenJDK `jtreg` `java.base` smoke
- longer-running Java subtree runs do not regress in helper VM or signal flow

Current progress:

- deterministic process-timer semantics now back `getitimer`, `setitimer`, and
  `alarm`,
- `timerfd_create`, `timerfd_settime`, and `timerfd_gettime` now expose
  deterministic timer-backed readable file descriptors with `poll`/`epoll`
  readiness and blocking read behavior,
- `mremap` now supports shrink, in-place growth, move, and fixed move for the
  current VMA model, and
- `msync` is being upgraded from unconditional success to mapped-range
  validation plus shared file-backed writeback, and
- user-facing signal delivery now supports both classic handlers and
  `SA_SIGINFO` handler shape with a populated signal frame and `rt_sigreturn`.

## Phase 3: Filesystem, Durability, and Environment Depth

Status: in progress

Target:

- Make TOS feel closer to a steady Linux userland base under sustained runtime
  pressure and larger test surfaces.

Scope:

- Deepen keyspace-backed filesystem semantics where current behavior is still a
  runtime-shaped approximation.
- Improve durability and sync semantics beyond unconditional success paths.
- Revisit temporary workspace behavior, disk growth paths, and larger runtime
  artifact lifecycles.
- Expand the baseline userland environment expected by deeper runtime probes.
- Keep current deterministic storage and image policy.

Validation gates:

- large-file lifecycle smoke
- `make java-test`
- `tools/phase6_runtime_matrix.sh`
- guest-side OpenJDK `jtreg` subtree runs advance without repeated workspace,
  sync, or disk-capacity seams

Current progress:

- `fsync` now validates FD kind instead of reporting universal success,
- `fdatasync`, `sync`, and `syncfs` have been wired into the Linux dispatcher,
- shared file-backed `msync` now writes modified mapped pages back to mutable
  keyspace-backed files, and
- substrate-depth smoke now covers timer APIs, `mremap`, `msync`, and the
  deeper sync path in the same boot flow.

## Exit Criteria

This batch can be treated as complete once:

- the three phases above are complete,
- the main runtime validation remains green,
- TOS can sustain deeper OpenJDK subtree runs without repeatedly exposing the
  same substrate-level stubs, and
- the remaining incompatibilities are mostly breadth-of-environment issues
  rather than core substrate semantics.
