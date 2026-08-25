# linux-compat

The portable Linux x86-64 userspace layer from the
[webTOS roadmap](../../ROADMAP.md): the operating-system side of the Linux
ABI over the `x64-engine` virtual CPU. It is the browser-capable rebuild of
the native kernel's `src/linux_compat` substrate and supersedes the
milestone-1 `linux_min` environment.

## What it provides (milestone 2)

- an in-memory VFS (directories, files, symlinks, hard links, `/dev`
  devices) that the host seeds with guest images and that persists across
  guest process lifetimes
- file descriptors with Linux open-file-description semantics
  (`dup` shares offsets), `getdents64`, the `stat` family, `fcntl`, tty
  `ioctl`s
- process state: System V stack and auxv construction, `brk`, anonymous and
  private file `mmap`, `mprotect`, deterministic time and `getrandom`,
  signal registration
- the syscall surface exercised by static musl BusyBox applets; everything
  else returns `-ENOSYS` with a log line — never fake success

## What it provides (milestone 3)

- dynamically linked PIE executables started through the system dynamic
  loader (`PT_INTERP`): execution begins in the interpreter, `AT_BASE` and
  the full auxiliary vector describe the main image
- validated against the musl loader (Alpine minirootfs: dynamic BusyBox,
  applet symlinks, shell) and against the host glibc loader (C and Rust
  dynamically linked fixtures)
- `poll`/`ppoll` (nothing blocks, so readiness is immediate and truthful)
  and kernel-style self-termination for fatal signals (`abort()` exits with
  128 + signal)

## What it provides (milestone 4)

- processes and threads over a deterministic cooperative scheduler: one
  virtual CPU, every other task parked with its CPU snapshot and memory
  map; the first ready task in queue order always runs next, so repeated
  runs produce identical output and instruction counts
- `fork` with copy-on-write memory, threads (`CLONE_VM`) with a shared
  map, `execve` (image replacement with close-on-exec), `wait4` and
  zombies, pipes with blocking readers/writers, futex wait/wake,
  `sched_yield`, and clear-child-tid wakeups (`pthread_join`)
- blocking syscalls use restart semantics: the parked task re-executes
  the syscall instruction on wakeup, so no continuation state is stored
- shell pipelines and external commands work end to end (BusyBox `sh`
  spawning applets through `$PATH`, multi-stage pipelines, exit codes)

Not modeled yet: signal delivery to handlers (fatal signals terminate,
registration is recorded), process groups and sessions, and futex
timeouts (time advances only with executed instructions).

## Testing

The milestone-2 workload gates run against a pinned BusyBox binary that is
not part of the repository (GPL-2.0):

```bash
tools/fetch_busybox.sh        # milestone-2 fixture (pinned sha256)
tools/fetch_alpine_rootfs.sh  # milestone-3 fixture (musl loader + dynamic BusyBox)
cd crates
cargo test -p linux-compat    # skips gracefully when fixtures are absent
```

The glibc tests compile their fixtures with the host `gcc`/`rustc` and skip
when no compiler is available.

The same workload runs inside the wasm module via `node web/test_node.mjs`.
