# Linux Maturity Plan

This document tracks the next batch after
`TODO-linux-substrate-depth.md`. The goal is to move TOS from a
runtime-compatible and substrate-deep Linux foundation toward a steadier,
broader, and more testable Linux base for OpenJDK, Python, Node.js, and future
general-purpose workloads.

## Goals

- Expand validation from smoke coverage to broader language-runtime API suites.
- Improve userland completeness so runtime test harnesses run in a more normal
  Linux environment.
- Deepen the remaining long-tail semantics in process, fd, filesystem, network,
  signal, and synchronization behavior.
- Reduce dependence on fixed-capacity tables where they limit realistic runtime
  workloads.
- Improve observability so deeper runtime failures can be localized without
  serial-log guesswork.
- Keep deterministic scheduler policy, energy accounting, and TOS-native
  runtime ownership intact.

## Status Summary

- Batch 1 (`TODO-memory-subsystem.md`): completed
- Batch 2 (`TODO-runtime-semantics.md`): completed
- Batch 3 (`TODO-professional-uptake.md`): completed
- Batch 4 (`TODO-linux-substrate-depth.md`): completed
- Phase 1: in progress
- Phase 2: in progress
- Phase 3: in progress
- Phase 4: in progress

## Current Baseline

- Java, Python, and Node.js runtime smokes are green.
- Guest-side OpenJDK `jtreg` bring-up is live and already runs a meaningful
  `java.base` subset.
- The substrate no longer repeatedly fails on the earlier core issues around
  `execve`, helper-child lifetime, file-backed mapping, large-file lifecycle,
  or the main synchronization/timer/durability stubs.
- The remaining gaps are now mostly about breadth, long-tail Linux semantics,
  userland completeness, and scaling under larger validation surfaces.

## Phase 1: Test Surface Expansion

Status: in progress

Target:

- Move from smoke-only validation toward broader runtime API coverage that can
  expose real Linux maturity gaps.

Expected work:

- Expand OpenJDK coverage from the current smoke subset toward larger `java.base`
  areas:
  - `java.lang`
  - `java.io`
  - `java.nio.file`
  - `java.util`
  - `java.util.concurrent`
  - `java.util.zip`
  - `ProcessBuilder`
  - `Thread`
- Add a first structured CPython test subset:
  - `test_os`
  - `test_io`
  - `test_pathlib`
  - `test_subprocess`
  - `test_mmap`
  - `test_signal`
  - `test_socket`
  - `test_threading`
- Add a first structured Node.js API subset:
  - filesystem tests
  - `child_process`
  - `worker_threads`
  - timers
  - net/stream basics
- Turn current validation scripts into reusable profile-based regression suites
  instead of one-off smokes.

Validation gates:

- The runtime validation matrix remains green.
- The OpenJDK guest-side subset grows materially beyond the current `java.base`
  smoke list.
- Python and Node.js move from smoke-only validation to repeatable API-subset
  validation.

Current progress:

- A structured Python API subset validation path is live and passing:
  - `os`
  - `io`
  - `pathlib`
  - filesystem round-trip and directory iteration
  - `subprocess`
  - `mmap`
  - `signal`
  - `socket` (local loopback connect/accept/send/recv)
  - `threading`
  - queue-backed thread handoff
- A structured Node.js API subset validation path is live and passing:
  - filesystem basics
  - async filesystem and path handling
  - `child_process`
  - child stdin/env round-trip
  - `worker_threads`
  - worker message validation
  - timers
  - immediate-callback scheduling
  - stream basics
  - local loopback networking (`socket/bind/listen/connect/accept/shutdown`)
- A reusable Java runtime validation path now checks a broader core surface in
  one boot:
  - version and classpath launch
  - `java.io` / `java.nio.file` temp-path round-trip
  - jar resource and zip entry scanning
  - `ProcessBuilder`
  - `Thread`
  - `CountDownLatch`
  - queue-backed worker result collection
- Guest-side OpenJDK validation continues to expand via reusable `jtreg`
  launchers instead of one-off wrappers.
- The repo-tracked Python runtime profile now embeds the full stdlib tree
  instead of a hand-curated subset, so the default validation matrix no longer
  fails on missing modules such as `pathlib`.
- `tools/linux_maturity_validation.sh` now drives:
  - the Phase 6 runtime matrix
  - the dedicated Java runtime API validation path
  - the structured Python API subset
  - the structured Node.js API subset
  - the dedicated userland-environment validation path

## Phase 2: Userland Environment Completion

Status: in progress

Target:

- Make the guest environment feel closer to a normal Linux userland so runtime
  probes and test harnesses stop failing on missing environment breadth.

Expected work:

- Broaden the runtime image with a minimal but practical tool and environment
  set:
  - `/bin/sh`
  - `/usr/bin/env`
  - basic file and directory tools
  - minimal process-inspection tools
- Deepen `/proc`, `/dev`, `/tmp`, and `/etc` behavior where current coverage is
  still shaped around narrow runtime needs.
- Make temporary workspaces, reports, and test artifacts more stable for larger
  suites.
- Improve rootfs layout consistency so runtime discovery logic encounters a more
  standard Linux environment.

Validation gates:

- OpenJDK runtime probes no longer regularly fail on environment-breadth
  assumptions.
- Python and Node.js test subsets can run without repeated failures caused by
  missing basic userland tools or directories.
- Temporary workspace and report generation remain stable across repeated runs.

Current progress:

- A minimal practical tool set is now carried in runtime-generated manifests:
  - `/bin/sh`
  - `/usr/bin/env`
  - `mkdir`
  - `mv`
  - `rm`
  - `rmdir`
  - `ln`
  - `touch`
  - `sleep`
  - `cat`
  - `pwd`
  - `ps`
  - `uname`
- A dedicated userland environment validation path now verifies:
  - `/usr/bin/env -> /bin/sh`
  - shell-script execution from the guest runtime image
  - basic file/directory utility behavior inside `/tmp`
  - `touch` timestamp-update compatibility through `utimensat`
  - `mv` / `ln -s` / `cat` behavior over guest-managed paths
  - `uname -s` availability from the embedded tool subset
  - standard guest path layout under `/bin`, `/usr/bin`, `/tmp`, `/dev`, and
    `/proc`
  - shell-side access to `/proc/self/exe` and `/dev/null`
  - guest execution of the current tool subset used by the probe:
    `mkdir`, `rm`, `rmdir`, `ln`, `mv`, `touch`, `sleep`, `cat`, `pwd`,
    `ps`, and `uname`
- Mutable symlink support, `umask`, and `fadvise64` semantics were added to
  remove environment-breadth failures from common shell-driven tools.
- The userland-environment validation path now passes as part of the broader
  Linux maturity matrix instead of only in isolated one-off runs.
- `/proc/self/fd/<n>` now has usable `readlink` and `stat/lstat` semantics for
  descriptor introspection instead of behaving like an opaque missing path.
- A minimal repo-owned `ps` executable is now embedded into generated
  userland-focused runtime manifests, so process-inspection checks no longer
  depend on a much larger procfs surface just to confirm basic environment
  breadth.

## Phase 3: Tail Semantics for Process, FD, Filesystem, Network, and Sync

Status: in progress

Target:

- Close the remaining long-tail Linux semantics that matter once runtime test
  breadth increases.

Expected work:

- Continue process/task depth:
  - process group/session semantics
  - `setsid` / `setpgid`
  - richer zombie/reap lifecycle
  - stronger `waitid`/`waitpid` behavior
- Deepen fd and Unix-object behavior:
  - `fcntl` edge cases
  - close-on-exec interactions
  - file-locking expectations
  - fuller `shutdown`
  - broader `getsockopt` / `setsockopt`
  - deeper `AF_UNIX` behavior
- Deepen filesystem behavior:
  - `rename`
  - `link`
  - `symlink`
  - `unlink`
  - `rmdir`
  - timestamps
  - richer `statx`
  - truncate/writeback edge cases
- Deepen synchronization and signal long-tail behavior:
  - remaining futex edge operations
  - robust futex cleanup
  - timer restart behavior
  - remaining signal ABI corners
- Deepen network behavior:
  - IPv6
  - richer socket error paths
  - more complete local networking semantics
  - `sendmsg` / `recvmsg` depth where runtime tests require it

Validation gates:

- Larger OpenJDK subtree runs keep advancing without repeatedly exposing the
  same tail semantics gaps.
- Python API subsets for files, subprocesses, signals, sockets, and threads
  remain green.
- Node.js API subsets for filesystem, child processes, workers, timers, and
  networking remain green.

Current progress:

- Local loopback TCP now has a real in-kernel compatibility path for:
  - `bind`
  - `listen`
  - `connect`
  - `accept4`
  - `shutdown`
  - `sendto`
  - `recvfrom`
- Basic socket-option semantics now exist for common runtime probes:
  - `SO_REUSEADDR`
  - `SO_REUSEPORT`
  - `SO_KEEPALIVE`
  - `SO_ACCEPTCONN`
  - `SO_ERROR`
  - `SO_SNDBUF`
  - `SO_RCVBUF`
  - `TCP_NODELAY`
- Node.js networking validation now requires a real `TOS-NODE-NET-OK` marker
  instead of accepting a skip path.
- Python networking validation now requires `TOS-PY-API socket=ok` instead of
  accepting a skip path.
- Additional compatibility depth now exists for:
  - real `sendto` / `recvfrom` behavior on local loopback stream sockets
  - half-close propagation through `shutdown`
  - common socket-option probes used by higher-level runtimes
- `waitid(P_PID, ..., WEXITED | WNOWAIT)` now reports the Linux child PID
  rather than the internal agent slot id, keeping `wait4`/`waitid` child
  identity consistent for cloned helper processes.
- `utimensat` is now implemented as a validated metadata-preserving update path,
  removing a recurring `touch`/timestamp compatibility failure from shell-based
  userland workflows.
- Small regular-file append/writeback now keeps sub-`256`-byte files in inline
  storage instead of accidentally exposing segmented-storage metadata to normal
  file reads, removing a recurring Node.js filesystem compatibility failure.
- Legacy tiny files that were previously written in segmented form are now read
  back through the segmented-file path instead of returning the raw 6-byte
  storage header as file content.

## Phase 4: Dynamic Capacity and Observability

Status: in progress

Target:

- Reduce the number of workload failures caused by fixed-capacity design limits,
  and improve introspection so deeper failures are easier to localize.

Expected work:

- Revisit fixed-capacity tables that are still easy to exhaust under realistic
  runtime workloads:
  - mutable path tables
  - keyspace entry tables
  - helper-process counts
  - runtime artifact lifetimes
- Replace capacity growth by constant bumps with more stable dynamic ownership
  where practical.
- Improve runtime/debug visibility:
  - process and child state visibility
  - fd/object visibility
  - VMA visibility
  - clearer failure reporting for runtime validation
- Keep debug controls low-noise and opt-in so they do not destabilize long runs.

Validation gates:

- Larger validation runs stop failing on repeated fixed-capacity ceilings.
- Runtime failures become easier to localize without ad hoc serial tracing.
- The runtime matrix and expanded API subsets remain stable with observability
  enabled in targeted debugging runs.

Current progress:

- Validation builds now isolate `CARGO_TARGET_DIR` by runtime manifest and
  focus, so Java, Python, Node.js, and userland-environment profiles no longer
  overwrite each other's embedded runtime payloads when run in parallel.
- Repo-tracked runtime profiles are now closer to what the validation matrix
  actually boots, reducing drift between ad hoc helper manifests and the
  default committed profiles.
- The committed runtime-validation defaults now match current workload needs:
  the Node.js Phase-6 and Node API validation paths use a longer QEMU timeout
  so worker-thread validation no longer fails on stale harness timing.

## Exit Criteria

This batch can be treated as complete once:

- the four phases above are complete,
- Java, Python, and Node.js have repeatable API-subset validation beyond the
  current smoke level,
- remaining failures are mostly about unsupported breadth or future expansion
  rather than rediscovering the same core Linux substrate weaknesses, and
- TOS is materially closer to a steady, testable Linux base for long-lived
  general-purpose runtimes.
