# Linux Syscall Compatibility Layer — Design Document

**Status:** Design Document
**Companion to:** Yellow Paper §27.10 (Stage-12)

> This document describes how to implement a Linux syscall translation layer for ATOS, enabling unmodified Linux x86_64 ELF binaries to run on ATOS. The translation layer intercepts Linux syscalls and maps them to ATOS primitives — files become keyspace entries, sockets become netd mailbox sessions, threads become child agents, and processes become spawned agents.

---

## 1. Motivation

Porting language runtimes one-by-one (wasmi, RustPython, Ristretto) gives the best ATOS integration but only covers a few languages. A Linux syscall compatibility layer covers **everything at once**:

| Approach | Effort | Coverage |
|----------|--------|----------|
| Port each runtime individually | ~3,000 lines × N runtimes | Only ported languages |
| Linux syscall compat layer | ~8,000 lines, one-time | **Any Linux x86_64 binary** |

With the compat layer, Node.js, Python (CPython), Go, GCC, curl, and any statically-linked Linux program runs on ATOS without modification.

## 2. Architecture

```
┌──────────────────────────────────────────┐
│  Unmodified Linux ELF64 binary           │
│  (Node.js, Python, Go, curl, etc.)       │
├──────────────────────────────────────────┤
│  Linux Syscall Translation Layer         │
│  intercepts SYSCALL instruction          │
│  translates Linux ABI → ATOS primitives  │
├──────────────────────────────────────────┤
│  ATOS Kernel                             │
│  mailbox | capability | keyspace | netd  │
└──────────────────────────────────────────┘
```

### 2.1 Interception Mechanism

Linux x86_64 programs invoke syscalls via the `SYSCALL` instruction with the syscall number in `rax`. ATOS already handles `SYSCALL` via `syscall_entry.asm` → `syscall_handler()`. The compat layer adds a second dispatch path:

```rust
pub fn syscall_handler(num: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
    if agent_is_linux_compat(current_agent()) {
        linux_compat::dispatch(num, a1, a2, a3, a4, a5)
    } else {
        syscall::syscall(num, a1, a2, a3, a4, a5)  // native ATOS syscall
    }
}
```

Each agent is tagged at spawn time as either `ATOS-native` or `Linux-compat`. The tag determines which syscall ABI is used.

### 2.2 Per-Agent Virtual OS State

Each Linux-compat agent maintains a virtual POSIX state:

```rust
struct LinuxAgentState {
    fd_table: [Option<FdEntry>; MAX_FDS],   // virtual file descriptor table
    cwd: [u8; 256],                         // virtual working directory
    pid: u32,                               // virtual PID (= agent_id)
    ppid: u32,                              // virtual parent PID
    uid: u32,                               // always 1000 (non-root)
    brk_current: u64,                       // current heap break
    epoll_instances: [Option<EpollInstance>; 8],  // epoll state
    signal_handlers: [SignalAction; 32],     // signal disposition table
}
```

## 3. Syscall Translation Map

### 3.1 Phase 1: Static ELF Startup (~20 syscalls)

The minimum set to boot a statically-linked ELF binary:

| Linux syscall | # | ATOS translation |
|--------------|---|-----------------|
| `mmap` | 9 | `sys_mmap` with virtual address tracking |
| `mprotect` | 10 | No-op (ATOS manages page permissions at kernel level) |
| `munmap` | 11 | `sys_munmap` |
| `brk` | 12 | Bump allocator on mmap'd region |
| `write(1/2, ...)` | 1 | fd 1,2 → serial log |
| `read(0, ...)` | 0 | fd 0 → not supported (return 0) |
| `exit` | 60 | `sys_exit` |
| `exit_group` | 231 | `sys_exit` |
| `arch_prctl` | 158 | Set FS base via MSR (for TLS) |
| `set_tid_address` | 218 | Store address, return agent_id |
| `uname` | 63 | Return `{sysname: "ATOS", release: "0.1", machine: "x86_64"}` |
| `getpid` | 39 | Return agent_id |
| `getppid` | 110 | Return parent agent_id |
| `getuid/geteuid` | 102/107 | Return 1000 |
| `getgid/getegid` | 104/108 | Return 1000 |
| `clock_gettime` | 228 | `get_ticks() * 10_000_000` (ns) |
| `getrandom` | 318 | Kernel RDRAND |
| `sigaction/rt_sigaction` | 13 | Store handler in signal table |
| `sigprocmask` | 14 | No-op (signals simplified) |

### 3.2 Phase 2: File I/O (~40 syscalls cumulative)

| Linux syscall | # | ATOS translation |
|--------------|---|-----------------|
| `openat` | 257 | Hash path → keyspace key; allocate fd |
| `open` | 2 | Delegate to openat(AT_FDCWD, ...) |
| `close` | 3 | Free fd table entry |
| `read` | 0 | Keyspace get via fd → key mapping |
| `write` | 1 | Keyspace put via fd → key mapping; fd 1/2 → serial |
| `lseek` | 8 | Update offset in fd entry |
| `fstat` | 5 | Construct stat from keyspace metadata |
| `stat/lstat` | 4/6 | Hash path, check keyspace existence |
| `statx` | 332 | Extended stat (Node.js uses this) |
| `access/faccessat` | 21/269 | Keyspace key existence check |
| `getcwd` | 79 | Return virtual cwd |
| `chdir` | 80 | Update virtual cwd |
| `readlink` | 89 | Return EINVAL (no symlinks) |
| `unlink/unlinkat` | 87/263 | Keyspace delete |
| `mkdir/mkdirat` | 83/258 | Create keyspace prefix marker |
| `rename/renameat` | 82/264 | Keyspace key rename |
| `fcntl` | 72 | F_GETFL/F_SETFL on fd entry |
| `ioctl` | 16 | Return ENOTTY for most; TIOCGWINSZ → 80x24 |
| `dup/dup2/dup3` | 32/33/292 | Copy fd table entry |
| `pipe/pipe2` | 22/293 | Create mailbox pair → two fds |
| `pread64/pwrite64` | 17/18 | Keyspace get/put with offset |
| `writev/readv` | 20/19 | Scatter-gather on keyspace |
| `getdents64` | 217 | Keyspace prefix scan |

### 3.3 Phase 3: Network + epoll (~60 syscalls cumulative)

| Linux syscall | # | ATOS translation |
|--------------|---|-----------------|
| `socket` | 41 | Create netd session → virtual fd |
| `connect` | 42 | Send connect request to netd mailbox |
| `sendto/send` | 44 | Send data via netd session |
| `recvfrom/recv` | 45 | Recv data via netd session |
| `bind` | 49 | Register server port with netd |
| `listen` | 50 | Notify netd to accept connections |
| `accept/accept4` | 43/288 | Recv new connection from netd |
| `shutdown` | 48 | Close netd session direction |
| `setsockopt/getsockopt` | 54/55 | Store in fd entry; netd handles relevant ones |
| `getpeername/getsockname` | 52/51 | Return from netd session metadata |
| `epoll_create/create1` | 213/291 | Allocate epoll instance |
| `epoll_ctl` | 233 | Add/remove fd → mailbox watch mapping |
| `epoll_wait` | 232 | `sys_recv_timeout` on multiplexed mailbox set |
| `poll/ppoll` | 7/271 | Translate to epoll internally |
| `select/pselect6` | 23/270 | Translate to epoll internally |
| `eventfd/eventfd2` | 284/290 | Mailbox-based event signaling |

**epoll implementation strategy:**

The key challenge. ATOS mailboxes are per-agent, not per-fd. The epoll translation maps multiple virtual fds to mailbox watches:

```
epoll_ctl(ADD, socket_fd_5) → watch netd session 5's response mailbox
epoll_ctl(ADD, pipe_fd_8)   → watch pipe mailbox 8
epoll_wait(timeout=100ms)   → sys_recv_timeout on a combined watch set
                              → check all watched mailboxes in round-robin
                              → return ready fds
```

This is not zero-cost — polling multiple mailboxes is less efficient than Linux's kernel-level epoll. But it works correctly and the performance is acceptable for agent workloads.

### 3.4 Phase 4: Threads + Dynamic Linking (~80 syscalls cumulative)

| Linux syscall | # | ATOS translation |
|--------------|---|-----------------|
| `clone` (thread) | 56 | `sys_spawn` child agent with shared keyspace |
| `clone3` | 435 | Same, extended flags |
| `fork` | 57 | Checkpoint + spawn (only fork+exec pattern) |
| `vfork` | 58 | Same as fork |
| `execve` | 59 | `sys_spawn_image` |
| `wait4/waitpid` | 61 | Recv child exit event |
| `futex` | 202 | Mailbox-based wake/wait protocol |
| `sched_yield` | 24 | `sys_yield` |
| `sched_getaffinity` | 204 | Return CPU count |
| `gettid` | 186 | Return agent_id |
| `tgkill` | 234 | Send signal event to agent mailbox |
| `prctl` | 157 | PR_SET_NAME → store agent label |

**Dynamic linking support:**

Requires bundling `ld-linux-x86-64.so.2` and libc in ATOS's agent storage. The ELF loader resolves the interpreter path and loads it first. The compat layer must support `open` + `mmap` for the loader to map shared libraries.

Alternative: require static linking (`-static`). This eliminates the dynamic linker requirement entirely. Most programs can be statically compiled.

## 4. Virtual File System Layout

Linux programs expect a filesystem. ATOS provides one virtually via keyspace:

```
/proc/self/pid          → agent_id
/proc/self/status       → agent status string
/dev/null               → read returns 0, write discards
/dev/urandom            → RDRAND bytes
/dev/stdin              → fd 0 (not supported)
/dev/stdout             → fd 1 → serial log
/dev/stderr             → fd 2 → serial log
/tmp/                   → temporary keyspace (auto-cleaned)
/home/agent/            → agent's persistent keyspace
/etc/hostname           → "atos"
/etc/resolv.conf        → "nameserver 8.8.8.8" (netd resolves)
```

Paths outside these prefixes map to the agent's general keyspace via path hashing.

## 5. Implementation Strategy

### 5.1 Module Structure

```
src/
  linux_compat/
    mod.rs              # dispatch table + LinuxAgentState
    fs.rs               # file I/O syscalls (open, read, write, stat, ...)
    net.rs              # network syscalls (socket, connect, epoll, ...)
    process.rs          # process/thread (clone, fork, execve, wait, ...)
    memory.rs           # memory management (mmap, brk, mprotect)
    signal.rs           # signal handling (sigaction, kill, ...)
    misc.rs             # time, random, uname, getpid, ...
    fd_table.rs         # virtual file descriptor management
    epoll.rs            # epoll state machine
```

### 5.2 Agent Spawn with Linux Compat Flag

```rust
// New RuntimeKind variant
pub enum RuntimeKind {
    Native,       // ATOS-native syscall ABI
    Wasm,         // WASM interpreter
    LinuxCompat,  // Linux syscall translation
}

// SYS_SPAWN_IMAGE with runtime_kind = 2 → Linux compat mode
```

### 5.3 Testing Strategy

| Phase | Test | Tool |
|-------|------|------|
| 1 | Static hello world (C, Rust, Go) | musl-gcc -static |
| 1 | Busybox (static) — ls, cat, echo | Pre-built static binary |
| 2 | Python (CPython, static build) | python3 -c "print('hello')" |
| 2 | File read/write round-trip | Custom C test program |
| 3 | curl (static) — HTTP GET | curl https://example.com |
| 3 | Node.js (static) — simple HTTP server | node -e "..." |
| 4 | Multi-threaded Go program | Go static binary |
| 4 | Java (static JLink image) | java -jar app.jar |

## 6. Performance Expectations

Based on WSL1 precedent (70-75% native Linux performance):

| Category | Expected overhead | Reason |
|----------|------------------|--------|
| CPU-bound computation | ~0% | No translation needed for pure computation |
| File I/O | ~30-50% | Keyspace is in-memory, but path hashing + fd lookup adds overhead |
| Network I/O | ~50-100% | Every socket op goes through netd mailbox round-trip |
| Process creation | ~200-300% | ATOS agent spawn is heavier than Linux fork |
| epoll / event loop | ~50-100% | Mailbox polling vs kernel-level epoll |

For AI agent workloads (mostly compute + HTTP calls), overall performance should be **60-80% of native Linux**. This is acceptable for a compatibility layer.

## 7. What Linux Programs Get on ATOS

Unmodified Linux binaries automatically gain ATOS properties:

| ATOS Feature | How it applies to Linux binaries |
|-------------|--------------------------------|
| Capability isolation | Linux binary can only access resources its agent has capabilities for |
| Energy metering | Timer-tick preemption charges energy like any ATOS agent |
| eBPF policy | All translated syscalls pass through eBPF attachment points |
| Audit log | Every translated syscall produces an ATOS audit event |
| Checkpoint | Agent state (including LinuxAgentState) can be checkpointed |
| Migration | Checkpoint + transfer + resume on another node |

## 8. Limitations

| Limitation | Reason | Workaround |
|-----------|--------|-----------|
| No raw device access (`/dev/sda`) | ATOS has no block device passthrough | Use netd for network, keyspace for storage |
| No shared memory (`shmget`, `shm_open`) | ATOS agents share nothing | Use mailbox for IPC |
| No `ptrace` | Debugging requires ATOS-native tools | Use ATOS event log |
| No X11/Wayland | ATOS is headless | Not applicable for agent workloads |
| `fork()` without `exec()` is limited | Agent spawn ≠ process copy | Most programs use fork+exec pattern |
| No `/proc` filesystem (full) | Only `/proc/self/*` simulated | Sufficient for most programs |

## 9. Relationship to Stage-11

Stage-11 (native runtime ports) and Stage-12 (Linux compat) are complementary:

```
Native ports (Stage-11):     Better ATOS integration, direct mailbox/capability access
Linux compat (Stage-12):     Broader coverage, run anything, less ATOS-native

Recommended combination:
  System agents      → Native Rust (ATOS syscalls)
  AI agent runtimes  → Stage-11 ports (wasmi, RustPython, Ristretto)
  Long-tail tools    → Stage-12 Linux compat (curl, git, gcc, npm, pip, ...)
```

## 10. Implementation Phases

| Phase | Syscalls | Lines | Enables |
|-------|----------|-------|---------|
| **1: Boot** | ~20 | ~1,500 | Static hello world, busybox |
| **2: File I/O** | ~40 | ~3,000 | CPython, file-based tools |
| **3: Network** | ~60 | ~5,000 | Node.js, curl, HTTP clients |
| **4: Threads** | ~80 | ~8,000 | Multi-threaded Java, Go, full npm |

## 11. Prior Art

| System | Approach | Syscalls | Performance |
|--------|----------|----------|-------------|
| **WSL1** (Windows) | Kernel driver translates Linux → NT | ~200 | 70-75% native |
| **Darling** (macOS) | Translates Linux → Darwin/XNU | ~150 | ~60% native |
| **gVisor** (Google) | User-space kernel reimplements Linux syscalls | ~200+ | 50-90% native |
| **ATOS** (proposed) | Translates Linux → ATOS agents/mailboxes | ~80 | est. 60-80% native |
