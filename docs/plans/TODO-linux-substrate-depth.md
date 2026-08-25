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
- Phase 1: completed
- Phase 2: completed
- Phase 3: completed

## Phase 1: Process and Synchronization Depth

Status: completed

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

Completion notes:

- helper-child refund, `vfork` resume, wait visibility, and longer-running
  helper-process cleanup now hold up under the current Java/Python/Node runtime
  validation flow,
- the runtime matrix remains green after these synchronization-depth changes,
  and
- deeper OpenJDK subtree runs now advance without depending on compatibility
  stubs in the main synchronization paths.

## Phase 2: VM, Timer, and Signal Depth

Status: completed

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

Completion notes:

- the targeted substrate-depth smoke now covers timer APIs, `timerfd`,
  `mremap`, `msync`, `SA_SIGINFO`, `rseq`, and `membarrier` in one boot flow,
- the Java runtime validation remains green after these VM/timer/signal
  semantics were deepened, and
- current OpenJDK subtree work no longer keeps rediscovering the same timer or
  mapping-level substrate stubs.

## Phase 3: Filesystem, Durability, and Environment Depth

Status: completed

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

Completion notes:

- large-file lifecycle smoke is green again after the syscall return-path and
  writeback fixes,
- the runtime validation matrix remains green with the deeper durability path,
  and
- remaining runtime incompatibilities are now mostly about broader userland
  coverage rather than the previously repeated sync, disk, or workspace seams.

## Exit Criteria

This batch can be treated as complete once:

- the three phases above are complete,
- the main runtime validation remains green,
- deeper OpenJDK subtree runs are no longer repeatedly blocked by the same
  synchronization, timer, mapping, or durability stubs, and
- the remaining incompatibilities are mostly breadth-of-environment issues
  rather than core substrate semantics.
