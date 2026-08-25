# x64-engine

The browser-portable x86-64 user-mode execution engine from the
[webTOS roadmap](../../ROADMAP.md). It executes long-mode instructions over
sparse guest memory and reports structured exits; instruction semantics come
from the vendored icicle CPU core (`third_party/icicle`, SLEIGH-based),
driven by an interpreter-only VM loop with no JIT or native-code
dependencies, so the whole crate compiles for `wasm32-unknown-unknown`.

## Layout

- `src/vm.rs` — interpreter-only VM loop (ported from upstream `icicle-vm`;
  see `third_party/icicle/PROVENANCE.md`)
- `src/build.rs` — builds an x86-64 long-mode VM from a SLEIGH spec
  (`third_party/ghidra-x86/languages/x86.ldefs`, ~120 ms to compile)
- `src/linux_min.rs` — milestone-1 Linux environment: static ELF loading,
  System V stack/auxv setup, and the `write`/`exit`-class syscalls; every
  unsupported syscall returns `-ENOSYS` with a log line
- `src/lib.rs` — the stable `Engine`/`CpuExit`/`GuestMemory` boundary

OS semantics beyond milestone 1 (VFS, processes, threads, sockets) belong to
the webTOS `linux_compat` layer, which will replace `linux_min` behind the
same `Environment` trait.

## Building and testing

This crate lives in the `crates/` workspace, which overrides the kernel-wide
cargo configuration (custom target + `build-std`). Run cargo from `crates/`:

```bash
cd crates
cargo test -p x64-engine                              # native milestone-1 gates
cargo build -p x64-engine --target wasm32-unknown-unknown
```
