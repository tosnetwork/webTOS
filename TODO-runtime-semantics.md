# Runtime Semantics Migration Plan

This document tracks the second migration batch after
`TODO-memory-subsystem.md`. The first batch stabilized the allocator, frame
metadata, and page-table backend. This batch focuses on Linux runtime semantics
needed to reach the yellow paper Stage-10 goal with a mature ATOS-native code
structure.

## Goals

- Keep ATOS ownership of scheduler policy, syscall routing, and deterministic
  behavior.
- Replace the current `execve` spawn-and-exit approximation with a true
  process-image replacement model.
- Deepen `clone3` / thread-group / signal semantics so OpenJDK, Node.js, and
  Python can rely on standard Linux process behavior.
- Preserve the VMA/page-table split completed in the memory subsystem work and
  build richer runtime policy on top of it.
- Reuse proven implementation ideas from `~/asterinas` and `~/moss` without
  importing their full kernel architecture.

## Status Summary

- Batch 1 (`TODO-memory-subsystem.md`): completed
- Phase 1: completed
- Phase 2: completed
- Phase 3: completed
- Phase 4: completed
- Phase 5: completed
- Phase 6: completed

## Current Baseline

- Dynamic ELF loading works with `PT_INTERP`, base-image VFS, and keyspace-backed
  shared libraries.
- The Linux compatibility layer can already boot dynamic smoke tests and the
  Java JAR smoke path.
- `clone3`, futex ordering, and deterministic scheduling are present, but some
  semantics still follow an ATOS-local approximation rather than a true Linux
  process model.
- `execve` currently replaces the process by spawning a new Linux agent and
  terminating the caller, which is sufficient for smoke tests but not for full
  runtime depth.

## Phase 1: True `execve` Process Image Replacement

Status: completed

Target:

- Replace the current spawn-and-exit implementation with in-place process image
  replacement.
- Preserve observable Linux semantics for PID/TID, thread-group identity,
  inherited file descriptors, and `FD_CLOEXEC`.

Expected work:

- Rebuild the current process image instead of creating a fresh agent ID for
  every `execve`.
- Reinitialize user VMAs, stack, auxv, and entry context on the same task
  identity.
- Close only descriptors marked `FD_CLOEXEC`.
- Reset signal dispositions and other `execve`-reset state in a deterministic
  way.
- Keep ATOS deterministic policy for address selection and runtime ordering.

Validation:

- `execve("/usr/bin/hello_dynamic", ...)` keeps the expected Linux identity.
- `java -jar ...` and `python3 -c ...` continue working after replacing the
  current process image rather than spawning a new agent.
- Child-process users (`ProcessBuilder`, `subprocess`, `child_process`) no
  longer depend on ATOS-specific replacement behavior.

Completion notes:

- `execve("/usr/bin/hello_dynamic", ...)` now preserves the same Linux agent
  identity instead of spawning a replacement agent.
- `FD_CLOEXEC` descriptors are closed during `execve`, while inherited process
  identity and cwd remain on the same agent slot.
- The current syscall frame is rewritten in-place and `CR3` is switched to the
  new image before returning to user mode, keeping `execve` semantics local to
  the current task.

Primary references:

- `~/asterinas/kernel/src/process/execve.rs`
- `~/asterinas/kernel/src/process/program_loader/elf/load_elf.rs`
- `~/asterinas/kernel/src/process/program_loader/elf/elf_file.rs`

## Phase 2: Thread Group and Shared-State Semantics

Status: completed

Target:

- Bring `clone3` behavior closer to Linux for `CLONE_VM`, `CLONE_FILES`,
  `CLONE_SIGHAND`, `CLONE_THREAD`, and exit-group semantics.
- Make shared process state explicit instead of inferring it from local ATOS
  shortcuts.

Expected work:

- Split per-thread state from per-thread-group state.
- Add explicit thread-group ownership for PID/TGID-facing behavior.
- Make `exit`, `exit_group`, `wait4`, parent reaping, and `SIGCHLD` align with
  Linux thread-group rules.
- Separate shared file tables, signal handlers, and address-space sharing so
  `CLONE_VM` does not implicitly carry unrelated semantics.
- Keep deterministic wakeup order and scheduler policy unchanged.

Validation:

- Java thread creation and shutdown remain stable under repeated runs.
- Thread-group exit matches Linux expectations for `exit_group`.
- Wait/reap behavior is correct for multi-threaded and multi-process tests.

Completion notes:

- Linux thread-group identity is now explicit through `thread_group_leader`,
  rather than being inferred from ad hoc PID/TID shortcuts.
- Shared file-table ownership is explicit through `files_owner`, so
  `CLONE_FILES` no longer piggybacks on unrelated VM or per-agent state.
- Shared signal-disposition ownership is explicit through `sighand_owner`, so
  `CLONE_SIGHAND` is tracked independently from `CLONE_VM` and
  `CLONE_FILES`.
- `wait4` now reaps Linux children at thread-group granularity rather than
  exposing individual worker threads as waitable children.
- Exit status propagation is explicit, and the parent is notified only when the
  last thread in the group exits or when `exit_group` terminates the group.

Primary references:

- `~/asterinas/kernel/src/process/execve.rs`
- `~/asterinas/kernel/src/process/clone.rs`
- `~/moss/src/process/exec.rs`

## Phase 3: Signal Model Depth

Status: completed

Target:

- Extend ATOS signal handling from “minimal runtime support” to a stable Linux
  compatibility model for common runtimes.

Expected work:

- Split per-thread pending signals from thread-group pending signals.
- Make signal masks, default actions, and delivery points explicit.
- Preserve deterministic delivery order, but align signal visibility and
  lifecycle with Linux process/thread-group rules.
- Tighten `rt_sigaction`, `rt_sigprocmask`, `tgkill`, `kill`, and
  `rt_sigreturn` interactions.
- Ensure `SIGSEGV`, `SIGCHLD`, `SIGABRT`, and common runtime signals behave
  correctly for Java, Node.js, and Python.

Validation:

- Runtime-generated crashes still produce deterministic and Linux-like signal
  outcomes.
- Child exit reliably surfaces as `SIGCHLD`.
- JVM, CPython, and Node.js signal-sensitive startup paths remain stable.

Progress notes:

- Pending signals are now split into thread-directed and thread-group-directed
  queues, instead of a single per-thread approximation.
- `kill` now routes to thread-group-directed pending state, while `tgkill`
  remains thread-directed.
- Shared signal dispositions continue to flow through `sighand_owner`, while
  signal masks remain per-thread.
- Minimal user-space signal handler delivery is now live, including a synthetic
  user signal frame, `rt_sigreturn` restore, and deterministic delivery at the
  syscall-return boundary.
- `rt_sigpending` now exposes blocked pending signals, and
  `rt_sigaction`/`rt_sigprocmask` use explicit user-memory copies instead of
  raw pointer access.
- Common user-handler flags now cover `SA_NODEFER` and `SA_RESETHAND`, which is
  enough for the current runtime startup paths and signal smoke tests.

Primary references:

- `~/asterinas/kernel/src/process/signal/`
- `~/asterinas/kernel/src/syscall/`

## Phase 4: VMA Policy Depth Above the New Backend

Status: completed

Target:

- Build richer Linux VMA semantics on top of the completed page-table backend.

Expected work:

- Tighten VMA split/merge rules and overlap handling.
- Revisit `MAP_FIXED`, `MAP_SHARED`, `MAP_PRIVATE`, `PROT_NONE`, and guard-page
  behavior.
- Make `mprotect`, `munmap`, page fault fill, and `madvise` update VMA state in
  a way that matches richer Linux workloads.
- Add debugging and validation helpers so VMA state can be reasoned about
  independently from raw PTEs.

Validation:

- File-backed runtime mappings remain stable under dynamic linker and JVM
  pressure.
- Repeated `mmap/munmap/mprotect` stress does not corrupt VMA state.
- Python, Node.js, and Java startup continue to advance.

Progress notes:

- `mmap` now rejects invalid sharing-mode combinations and non-page-aligned
  offsets instead of silently accepting Linux-invalid shapes.
- `mprotect` and `madvise` now reject unmapped holes in the target range with
  `-ENOMEM`, rather than partially succeeding across gaps.
- `mprotect(PROT_NONE -> readable/writable)` no longer materializes a fresh
  anonymous page for reserved leaves; it restores lazy fault behavior so
  file-backed mappings remain file-backed.
- Initial VMAs are now installed for both fresh Linux spawns and in-place
  `execve` image replacement, so dynamic-linker `mprotect`/RELRO transitions
  operate against real VMA metadata instead of hitting false unmapped holes.
- VMA overlap checks and explicit initial-file mappings now keep dynamic
  loaders and JVM startup on the same policy path as regular `mmap` users,
  which eliminated the earlier RELRO failures on `hello_dynamic` and
  `java -jar`.

Primary references:

- `~/moss/src/memory/mmap.rs`
- `~/moss/libkernel/src/memory/proc_vm/memory_map/mod.rs`
- `~/asterinas/kernel/src/syscall/mmap.rs`
- `~/asterinas/kernel/src/syscall/mprotect.rs`

## Phase 5: Dynamic Runtime Polish

Status: completed

Target:

- Close the remaining semantic gaps that real runtime loaders and standard
  libraries depend on after the process/thread model is corrected.

Expected work:

- Revisit `arch_prctl`, TLS setup, and loader-facing x86_64 process state.
- Improve file-backed `mmap` details relied on by dynamic linkers and shared
  libraries.
- Tighten `statx`, directory traversal, path probes, `ioctl`, and runtime-facing
  metadata behavior where current semantics are still only smoke-test-deep.
- Keep base-image VFS deterministic while making it more Linux-like.

Validation:

- `python3 -c 'print(1)'`
- `node -e 'console.log(1)'`
- `java -version`
- `java -jar /usr/lib/atos-tests/java-smoke.jar`

Phase 5 close-out:

- `java -jar /usr/lib/atos-tests/java-smoke.jar` passes with
  `base_image.runtime.manifest`.
- `python3 -c 'print(1)'` passes with
  `base_image.runtime.python.manifest`.
- `node -e 'console.log(1)'` passes with
  `base_image.runtime.node.manifest`.
- `tools/phase5_runtime_validation.sh` now selects those runtime manifests by
  profile when no override is provided, and
  `tools/phase5_runtime_matrix.sh` provides a single entry point for the Phase
  5 runtime-family validation sweep.

Primary references:

- `~/asterinas/kernel/src/syscall/arch_prctl.rs`
- `~/asterinas/kernel/src/syscall/mmap.rs`
- `~/asterinas/kernel/src/process/program_loader/elf/`

Progress notes:

- Linux initial stacks now carry a richer auxv for both static and dynamic
  programs: `AT_PHDR`, `AT_PHENT`, `AT_PHNUM`, `AT_ENTRY`, `AT_BASE` (when an
  interpreter is present), `AT_RANDOM`, `AT_SECURE`, and `AT_EXECFN`.
- The argv/envp/auxv smoke now validates `AT_ENTRY` and `AT_EXECFN`, so
  loader-facing metadata regressions are visible in the normal QEMU boot path.
- Identity and x86_64 thread-pointer syscalls now use explicit user-memory
  copies through the page-table backend instead of raw pointer writes. This
  tightened `uname`, `sysinfo`, `getcpu`, `getgroups`, `prlimit64`,
  `getrandom`, and `arch_prctl(GET_*)` behavior around invalid user pointers.
- Relative `*at` path handling is now routed through real `dirfd` resolution
  instead of being treated as a flat namespace shortcut. `openat`,
  `newfstatat`, `readlinkat`, and `statx` can now resolve paths against both
  `AT_FDCWD` and directory file descriptors.
- A dedicated `*at` path smoke now verifies relative lookup for
  `/proc/self/exe` and `/usr/bin/hello_dynamic`, so future regressions in
  `dirfd` path semantics show up in the normal boot regression log.
- `stat`, `newfstatat`, and `statx` now report more Linux-like object types for
  key runtime probe targets: `/proc/self/exe` as a symlink, `/dev/null` and
  `/dev/urandom` as character devices, directories as `S_IFDIR`, and regular
  files as `S_IFREG`.
- The `*at` path smoke now validates object type bits, not just success codes,
  which makes metadata regressions visible to the normal QEMU regression path.
- `stat`/`newfstatat`/`statx` now distinguish follow vs. nofollow behavior for
  `/proc/self/exe`: default lookups follow to the executable target, while
  `lstat` and `AT_SYMLINK_NOFOLLOW` still expose the procfs symlink metadata.
- Runtime-facing `ioctl` behavior is being tightened beyond `TCGETS`: the
  compatibility layer now exposes deterministic `FIOCLEX`, `FIONCLEX`,
  `FIONBIO`, and `FIONREAD` semantics for the file and pipe/socket shapes used
  by current smoke tests.
- Linux pipe/socket file descriptors now bypass ATOS mailbox capability checks
  after fd creation, so fd-based I/O semantics are no longer blocked by the
  native capability model once a compatibility-layer fd is already open.
- `open("/proc/self/exe")` now follows the procfs symlink target by default,
  so runtime probes that open and then `fstat` the executable fd see a regular
  file instead of a pseudo-symlink handle.
- The clone/clone3 TLS-adjacent user-memory writes (`PARENT_SETTID`,
  `CHILD_SETTID`) are being moved onto the page-table-backed user-copy path,
  and a dedicated TLS smoke is being added to cover `ARCH_SET_FS/GS`,
  `ARCH_GET_FS/GS`, `CLONE_SETTLS`, and child/parent TID writeback behavior.
- `arch_prctl(SET_FS/SET_GS)` now rejects non-user canonical TLS bases, while
  the `GET_*` paths keep using explicit page-table-backed user copies.
- The TLS/runtime probe surface is being tightened beyond `arch_prctl` itself:
  `clone3` now copies its argument block through the user-copy path, and
  `prctl(PR_SET_NAME/PR_GET_NAME)`, `get_robust_list`, `wait4`,
  `sched_getaffinity`, `getrusage`, and `capget` no longer write directly to
  raw user pointers.
- Linux initial stacks now expose a richer runtime-facing auxv: in addition to
  the existing loader entries, they now carry `AT_PLATFORM`, `AT_HWCAP`,
  `AT_HWCAP2`, and `AT_CLKTCK`.
- The file-system compatibility path is moving off raw user-pointer copies:
  key runtime syscalls such as `read`, `write`, `pread64`, `readlink`,
  `readlinkat`, `statx`, `newfstatat`, `getcwd`, `getdents64`, and key `ioctl`
  probes now use page-table-backed user copies.
- Those file-system user-copy helpers now fault in lazy user pages before
  copying, which preserves Linux-like buffered I/O behavior for runtimes such
  as the JVM instead of turning first-touch reads into false `EFAULT`s.
- The remaining fd-multiplexing and scatter/gather entry points now follow the
  same user-copy path: `poll`, `readv`, `writev`, `pipe`, `pipe2`, and
  `select` no longer read or write raw user pointers.
- Pipe and file access modes are now reflected in readiness and I/O behavior,
  so `poll`/`select` no longer treat a pipe read end as writable or a write
  end as readable just because the underlying mailbox exists.
- A dedicated mux smoke now covers `pipe`/`pipe2`, `readv`/`writev`,
  `poll`, `select`, and their `-EFAULT`/`-EINVAL` edges, making regressions in
  fd-multiplexing semantics visible in the normal QEMU regression log.
- Deterministic time syscalls are also moving onto the same page-table-backed
  user-copy path, so `clock_gettime`, `clock_getres`, `time`,
  `nanosleep`, `gettimeofday`, `getitimer`, and `setitimer` no longer rely on
  raw user-pointer writes or first-touch behavior outside the VMA fault path.
- Socket- and epoll-facing runtime probes are now on the same path too:
  `connect`, `bind`, `sendto`, `recvfrom`, `sendmsg`, `recvmsg`,
  `getsockname`, `getsockopt`, `socketpair`, and `epoll_wait` no longer depend
  on raw user-pointer reads or writes.
- `epoll_wait` now shares the same access-mode view as `poll`/`select`, and it
  no longer emits zero-event records for watched fds that are not actually
  ready.
- The mux smoke now also covers `epoll_wait` null-pointer failure, empty wait
  behavior, and readable-pipe delivery, so epoll regressions show up in the
  normal boot log instead of hiding behind the syscall suite.
- Process-facing runtime probes now use the same page-table-backed user-copy
  path: `execve` argv/envp parsing, `futex` wait-timeout reads,
  `get_robust_list`, `uname`, and `prlimit64` no longer rely on raw user
  pointers or first-touch behavior outside the Linux VMA fault path.
- The identity-path `prlimit64` implementation now validates `new_limit_ptr`
  through the same fault-in copy path used by the rest of the runtime-facing
  syscalls, closing the earlier split-brain behavior between `process.rs` and
  `identity.rs`.
- The TLS/clone smoke now exercises those process-facing edges directly:
  `get_robust_list(NULL)`, `uname(NULL)`, `prlimit64` invalid
  old/new-limit pointers, and `futex(FUTEX_WAIT)` with an invalid timeout
  pointer. It currently passes `40/40` in the standard QEMU Java-focused
  regression run.
- Signal-frame installation and restore no longer serialize user-visible
  `rt_sigreturn` state through raw struct pointer casts. The compatibility
  layer now writes and reads the synthetic user signal frame through explicit
  byte serialization plus the same page-table-backed fault-in copy path used
  by the rest of Phase 5.
- The dedicated signal smoke now goes beyond the original “handler runs once”
  coverage. It checks `sigpending(NULL) -> -EFAULT`, `sigaction` old-action
  reads, `SIGKILL` rejection, blocked-mask reporting, `SA_NODEFER`
  re-entrant delivery, and `SA_RESETHAND` disposition reset. It currently
  reaches `ATOS-SIGNAL-OK` and exits cleanly in the standard Java-focused QEMU
  regression run.
- The signal path now also carries a minimal `sigaltstack` + `SA_ONSTACK`
  implementation. Alternate signal stacks are per-thread, reset on `execve`,
  copied on clone, and queried through Linux-like `stack_t` metadata. The
  signal smoke now verifies default disabled state, minimum-size rejection,
  enable/query/disable behavior, and that an `SA_ONSTACK` handler actually
  executes on the alternate stack.
- Node.js runtime bring-up exposed two Linux semantics gaps that are now
  closed: `epoll_wait`/`epoll_pwait` no longer return a spurious `0` on
  infinite waits, and `eventfd` read/write now accept any buffer size `>= 8`
  bytes while consuming or producing exactly the leading 8-byte counter value.
- The runtime validation harness now checks Node success more strictly: it
  requires the `console.log(1)` output after launch, a clean `exit_group(0)`
  after the Node launch marker, and rejects post-launch `SIGABRT`/`status=134`
  failures that earlier looser checks could miss.
- Family-specific runtime manifests are now part of the normal workflow:
  `base_image.runtime.manifest` for Java, `base_image.runtime.python.manifest`
  for Python, and `base_image.runtime.node.manifest` for Node.js. All three
  currently pass their QEMU smoke paths without new traps or kernel panics.

## Phase 6: End-to-End Runtime Validation

Status: completed

Target:

- Convert the runtime milestones into repeatable regression targets.

Expected work:

- Add stable Java, Node.js, and Python smoke harnesses.
- Add at least one child-process smoke for each runtime family.
- Add one multi-threaded stress smoke for Java and Node.js.
- Keep logs concise enough for automated regression checks.

Validation:

- `python3 -c 'print(1)'`
- `node -e 'console.log(1)'`
- `java -version`
- `java -jar /usr/lib/atos-tests/java-smoke.jar`
- Runtime child-process and multi-threaded smoke tests pass in QEMU without new
  traps or kernel panics.

Completion notes:

- Phase 6 now passes as a repeatable matrix across Java, Python, and Node.js.
- The final Node thread blocker was resolved by giving `socketpair` / `AF_UNIX`
  fd-backed stream semantics that match Linux runtime expectations.
- The final Java thread blocker was resolved by switching Linux thread-group
  scans from `0..MAX_AGENTS` assumptions to real agent-table enumeration, which
  matches the process-table style used by Asterinas, and by raising
  `MAX_AGENTS` to a runtime-appropriate fixed capacity.

## Source References

- Asterinas process / ELF loader:
  - `~/asterinas/kernel/src/process/execve.rs`
  - `~/asterinas/kernel/src/process/program_loader/elf/load_elf.rs`
  - `~/asterinas/kernel/src/process/program_loader/elf/elf_file.rs`
- Asterinas mmap / arch-specific runtime syscalls:
  - `~/asterinas/kernel/src/syscall/mmap.rs`
  - `~/asterinas/kernel/src/syscall/mprotect.rs`
  - `~/asterinas/kernel/src/syscall/arch_prctl.rs`
- Asterinas signals:
  - `~/asterinas/kernel/src/process/signal/`
- Moss VMA / mmap model:
  - `~/moss/src/memory/mmap.rs`
  - `~/moss/libkernel/src/memory/proc_vm/memory_map/mod.rs`
