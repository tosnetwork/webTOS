# Professional Linux Substrate Uplift Plan

This document tracks the next implementation batch after
`TODO-runtime-semantics.md`. The goal of this batch is to make TOS a steadier
and more professional Linux substrate without changing TOS ownership of
deterministic policy, native runtime structure, or energy accounting.

## Goals

- Make Linux process lifecycle semantics more object-oriented and less reliant
  on synthetic per-agent compatibility state.
- Unify file-backed and anonymous memory behavior behind a cleaner mapped-object
  model with stronger on-demand paging semantics.
- Make Unix stream and helper-process behavior more robust for real runtimes,
  especially OpenJDK, Node.js, Python, and future regression suites.
- Keep TOS-specific scheduler policy, energy model, receipts, and runtime split
  intact while strengthening the Linux substrate underneath them.

## Status Summary

- Batch 1 (`TODO-memory-subsystem.md`): completed
- Batch 2 (`TODO-runtime-semantics.md`): completed
- Phase 1: pending
- Phase 2: pending
- Phase 3: pending

## Current Baseline

- Dynamic ELF loading, in-place `execve`, thread-group semantics, and runtime
  validation for Java, Python, and Node.js are all working.
- Guest-side OpenJDK `jtreg` bring-up is live and already runs a small
  `java.base` subset plus the initial full-tree `java.lang` bring-up path.
- The remaining instability is no longer caused by missing syscall coverage. It
  is mainly caused by deeper lifecycle and object-model gaps in the Linux
  substrate:
  - process and child lifetime are still managed through compatibility-layer
    state more often than through explicit process objects
  - file-backed mappings and runtime helper processes still expose lifecycle
    seams under heavier workloads
  - Unix stream and helper-child behavior is functional, but not yet as
    naturally modeled as a dedicated object layer

## Phase 1: Process Objectization

Status: pending

Target:

- Move Linux process, thread-group, child, and `vfork` lifecycle tracking away
  from ad hoc compatibility tables and toward explicit process-owned objects.
- Make `execve`, `wait4`, `exit`, `exit_group`, and helper-child behavior flow
  through one consistent lifetime model.

Expected work:

- Introduce an explicit Linux process object that owns:
  - thread-group identity
  - child membership
  - wait state / reap state
  - parent notification state
  - `vfork` coordination state
- Reduce direct dependence on synthetic per-agent lookups for:
  - child enumeration
  - thread-group leader discovery
  - reaping eligibility
  - late `execve` / `vfork` transitions
- Make helper JVM / `javac` / runtime child processes observable through the
  same process lifecycle model as ordinary Linux children.
- Keep deterministic wakeup and scheduling policy unchanged.

Validation gates:

- `java -jar /usr/lib/tos-tests/java-smoke.jar` remains green.
- `tools/phase6_runtime_matrix.sh` remains green.
- `make java-test` remains green.
- Guest-side `jtreg` Java smoke remains green.
- A full-tree `jtreg` `java.lang` run no longer needs special-case leader-reap
  fixes to preserve parent wait behavior.
- No regressions in:
  - `wait4`
  - `vfork`
  - `clone3`
  - `execve`
  - child-process smoke for Java, Python, and Node.js

## Phase 2: Mapped Object and Page-Cache Uptake

Status: pending

Target:

- Strengthen the VM substrate so file-backed runtime behavior feels like a
  first-class mapped-object system rather than a collection of compatibility
  fixes.
- Unify lazy file fault, file-backed `mmap`, runtime loader access, and memory
  lifetime cleanup behind a cleaner object model.

Expected work:

- Introduce a clearer mapped-object abstraction for:
  - file-backed executable images
  - file-backed shared-library mappings
  - anonymous mappings
  - runtime-generated temporary artifacts
- Tighten ownership and cleanup rules for:
  - mapped file pages
  - shared file-backed leaves
  - post-`execve` address-space teardown
  - helper process and compiler subprocess VM cleanup
- Reduce duplicated path-specific logic between:
  - ELF loading
  - file-backed `mmap`
  - lazy page fault fill
  - file I/O fallback paths
- Keep deterministic address selection and current VMA policy ownership.

Validation gates:

- Java, Python, and Node.js runtime smokes stay green.
- Guest-side `jtreg` `java.base` smoke list stays green.
- The initial full-tree `jtreg` `java.lang` path advances without new memory
  lifetime corruption, stale mappings, or loader regressions.
- No regressions in:
  - `mmap`
  - `munmap`
  - `mprotect`
  - `brk`
  - file-backed lazy fault fill
  - repeated helper-VM / helper-compiler launches

## Phase 3: Unix Object Uptake

Status: pending

Target:

- Make Unix stream, `socketpair`, helper-process pipes, readiness, and fd
  lifecycle semantics feel like native object behavior instead of compatibility
  shims.
- Improve runtime-facing robustness for `ProcessBuilder`, `child_process`,
  `subprocess`, and future regression harnesses.

Expected work:

- Strengthen explicit object ownership for:
  - Unix stream pairs
  - pipes
  - eventfds
  - readiness state
  - helper-child communication channels
- Reduce cross-dependence between mailbox internals and Linux fd semantics
  after an fd object has already been created.
- Tighten close, shutdown, readiness, and peer-lifetime rules.
- Make helper-child I/O paths more naturally aligned with standard Linux
  runtime expectations.

Validation gates:

- Java child-process and thread smokes remain green.
- Python child-process smoke remains green.
- Node.js child-process and thread smokes remain green.
- `tools/phase6_runtime_matrix.sh` remains green.
- Guest-side `jtreg` Java runs do not regress in helper-child control flow or
  host-process protocol handling.
- No regressions in:
  - `socketpair`
  - `pipe` / `pipe2`
  - `poll`
  - `select`
  - `epoll_wait`
  - `eventfd`
  - fd duplication / close-on-exec handling

## Exit Criteria

This batch can be treated as complete once all three phases are finished and
the following remain true at the same time:

- TOS still preserves deterministic policy, energy accounting, and its current
  runtime split.
- Java, Python, and Node.js runtime validation remains green.
- Guest-side OpenJDK `jtreg` coverage can expand beyond smoke subsets without
  repeatedly exposing the same substrate-level lifecycle seams.
- TOS is materially steadier as a Linux substrate than it was at the end of the
  runtime-semantics batch.
