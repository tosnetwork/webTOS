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

Process management (`fork`, `execve`, `wait4`, pipes) is the milestone-4
boundary and is intentionally absent: BusyBox applets run as consecutive
single processes over the persistent filesystem, and `sh` works for
builtins and redirection.

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
