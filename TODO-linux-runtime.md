# Linux Runtime TODO / Task List

Goal: move TOS from "the syscall suite passes" to the shortest path that can genuinely start `java -version`, `node -e 'console.log(1)'`, and `python3 -c 'print(1)'`.

## Completed Tasks

- [x] 1. Startup Contract
  - Build a real Linux initial stack with `argc/argv/envp/auxv` ✓
  - Record `exe_path` per Linux agent ✓
  - Return a hard error when `PT_INTERP` is missing or the interpreter is not installed ✓
  - Provide minimal deterministic envp (LANG, HOME, PATH) ✓
  - Full auxv: AT_PHDR/AT_PHENT/AT_PHNUM/AT_PAGESZ/AT_BASE/AT_ENTRY/AT_UID/AT_EUID/AT_GID/AT_EGID/AT_RANDOM ✓

- [x] 2. Base Image / VFS / File Access Chain
  - Unify base-image path-to-key derivation ✓ (via vfs::resolve_path)
  - Make `openat` return `-ENOENT` when target doesn't exist and `O_CREAT` not set ✓
  - Make `read/pread64/fstat/newfstatat/lseek/mmap(fd)` use `entry.keyspace_id` ✓
  - Add `query_file_size()` for multi-segment file size queries ✓
  - Add `read_file_data()` helper supporting both small and multi-segment files ✓
  - Support base-image `/usr/bin/...` executables ✓
  - Read embedded base-image payloads directly from the build manifest, without copying them into `BASE_IMAGE_STORE` ✓

- [x] 3. Directory and Metadata ABI
  - Add `statx` (syscall 332) ✓
  - Add `readlinkat` (syscall 267) ✓
  - `/proc/self/exe` readlink returns real `exe_path` ✓

- [x] 4. Readable Event Semantics
  - Fix `epoll_wait` — check mailbox for EPOLLIN on pipe/socket ✓
  - Fix `poll` — check mailbox for POLLIN on pipe/socket ✓
  - Fix `select` — check mailbox for readable on pipe/socket ✓

- [x] 5. Smoke Tests (current milestone)
  - Static argc/argv/envp/auxv smoke test ✓
  - Dynamically-linked musl hello world via `PT_INTERP` ✓
  - Base-image executable install at `/usr/bin/...` ✓
  - `execve("/usr/bin/hello_dynamic", argv, envp)` smoke test ✓

- [x] 6. execve
  - Load target ELF through VFS path ✓
  - Read argv from user memory ✓
  - Read envp from user memory ✓
  - Spawn new Linux agent, terminate caller ✓

- [x] 8. getdents64 Improvements
  - Register directory manifests for base-image paths ✓
  - Return real filenames instead of synthetic key hashes ✓

- [x] 9. Runtime Payload Tooling
  - Build-time `base_image.manifest` embedding ✓
  - Optional `base_image.runtime.manifest` overlay ✓
  - Recursive `@tree` manifest entries ✓
  - Host runtime manifest generator script ✓

## Remaining Tasks

- [ ] 7. Install Base Image Content
  - Generate and curate a real `base_image.runtime.manifest`
  - Install runtime binaries under `/usr/bin`, `/usr/lib`, and `/jdk`
  - Install the shared libraries and standard-library trees needed by Python, Node.js, and OpenJDK

- [ ] 10. Runtime Smoke Tests
  - `python3 -c 'print(1)'`
  - `node -e 'console.log(1)'`
  - `java -version`

## Current Known Blockers

- Real runtime payloads are not installed yet.
  The kernel can now load dynamic ELFs and execute a base-image binary via
  `/usr/bin`, but Python / Node.js / OpenJDK are not present until we install
  their binaries, libraries, and data files into the build manifest.
- Runtime payload sizes are now limited mainly by the kernel image and guest
  RAM, not by `BASE_IMAGE_STORE`, but large trees still need curation.
- `execve` is still a spawn-and-replace approximation, not a full Linux process-image replacement.
  It is good enough for smoke tests, but not yet for complete POSIX semantics.
