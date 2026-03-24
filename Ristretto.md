# Ristretto JVM Integration — Porting Plan

**Status:** Design Document
**Companion to:** Yellow Paper §27, ATOS Runtime Architecture

> This document describes how to port [Ristretto](https://github.com/theseus-rs/ristretto), an embeddable JVM written in pure Rust, to run natively on ATOS. The goal is to give ATOS full Java execution capability — Java programs run unmodified, believing they are on a normal OS, while underneath everything maps to ATOS primitives (agents, mailboxes, capabilities, keyspaces).

---

## 1. Why Ristretto

Ristretto is a pure-Rust JVM with no C/C++ dependencies. It already supports conditional compilation for constrained environments via 382 `#[cfg(target_family = "wasm")]` guards that disable threading, filesystem, networking, and JIT. This makes it the ideal candidate for ATOS integration — the hard work of identifying platform boundaries is already done.

Unlike the WASM path (which disables features), the ATOS path **virtualizes** them: Java's full API surface is preserved, but the underlying implementation maps to ATOS kernel primitives.

## 2. Architecture

```
┌──────────────────────────────────────────────┐
│              Java Application                │
│         (.jar / .class bytecode)             │
├──────────────────────────────────────────────┤
│           Ristretto JVM (Rust)               │
│   classfile | classloader | vm | gc          │
├──────────────────────────────────────────────┤
│       ristretto_intrinsics                   │
│   #[cfg(target_os = "atos")]                 │
│   Java native methods → ATOS virtualization  │
├──────────────────────────────────────────────┤
│          ATOS Syscall Interface              │
│   send | recv | state_get | state_put |      │
│   spawn | exit | energy_get | mmap           │
├──────────────────────────────────────────────┤
│             ATOS Kernel                      │
│   mailbox | capability | keyspace | ebpf     │
└──────────────────────────────────────────────┘
```

The key insight: Ristretto's `ristretto_intrinsics` crate is where **all Java native methods** are implemented. It already has platform branches (`unix`, `windows`, `wasm`). We add one more: `atos`.

## 3. Virtualization Mapping

Java programs see a standard OS environment. ATOS provides it through its own primitives:

### 3.1 File System → Keyspace

| Java API | ATOS Implementation |
|----------|-------------------|
| `java.io.File` / `FileInputStream` / `FileOutputStream` | Path hashed to keyspace key; `sys_state_get` / `sys_state_put` |
| `java.io.RandomAccessFile` | Keyspace entry with offset tracking |
| `java.nio.file.Files` | Keyspace operations with path-to-key mapping |
| `java.io.tmpdir` | Temporary keyspace, auto-cleaned on agent exit |
| Directory listing | Keyspace key prefix scan |

**Path-to-key mapping:**
```
"/data/config.json"  →  keyspace key = fnv_hash("/data/config.json")
"/tmp/session.dat"   →  temporary keyspace, same hash scheme
```

Files larger than `MAX_VALUE_SIZE` (256 bytes) are split across multiple keys with a metadata entry tracking the chunk count.

### 3.2 Networking → netd Mailbox Proxy

| Java API | ATOS Implementation |
|----------|-------------------|
| `java.net.Socket` / `TcpStream` | Send connect request to netd mailbox; netd proxies the connection |
| `java.net.ServerSocket` | Not supported (agents are clients, not servers) |
| `java.net.URL.openConnection()` | HTTP request via netd mailbox protocol |
| `java.net.DatagramSocket` | UDP via netd mailbox (kernel UDP stack) |

**Protocol:**
```
Agent → sys_send(NETD_MAILBOX, { op: "connect", host, port })
Agent ← sys_recv(own_mailbox, { op: "connected", handle_id })
Agent → sys_send(NETD_MAILBOX, { op: "write", handle_id, data })
Agent ← sys_recv(own_mailbox, { op: "data", handle_id, payload })
```

All network I/O is brokered through netd, which enforces `CAP_NETWORK` capability and eBPF policy filters. The Java program sees a normal socket; ATOS sees an auditable, policy-gated message flow.

### 3.3 Threading → Child Agents

| Java API | ATOS Implementation |
|----------|-------------------|
| `new Thread(() -> ...)` | `sys_spawn` creates a child agent with the thread's entry point |
| `Thread.join()` | `sys_recv` on a completion mailbox |
| `Thread.sleep(ms)` | `sys_recv_timeout` with empty mailbox (tick-based delay) |
| `synchronized` / `Lock` | Mailbox-based mutex protocol (send/recv handshake) |
| `Thread.currentThread().getId()` | Current agent ID |
| `ExecutorService` | Pool of pre-spawned child agents accepting work via mailbox |

**Concurrency model:** Java threads become ATOS agents. Each "thread" has its own energy budget, capability set, and mailbox. `synchronized` blocks map to a lock agent that serializes access via mailbox ordering. This is heavier than native threads but provides full isolation and auditability.

### 3.4 System & Runtime

| Java API | ATOS Implementation |
|----------|-------------------|
| `System.out.println()` | `log` host function → serial output + event log |
| `System.err.println()` | Same as stdout (single serial channel) |
| `System.currentTimeMillis()` | `get_ticks() * 10` (100 Hz PIT → milliseconds) |
| `System.nanoTime()` | `get_ticks() * 10_000_000` (approximate) |
| `Math.random()` / `java.util.Random` | Kernel RDRAND/RDTSC entropy source |
| `Runtime.exit(code)` | `sys_exit(code)` |
| `Runtime.availableProcessors()` | ATOS CPU core count (from ACPI/MADT) |
| `Runtime.freeMemory()` | Agent's remaining memory quota |
| `Runtime.totalMemory()` | Agent's total memory quota |
| `System.getenv("KEY")` | Keyspace lookup with `"env/"` prefix |
| `System.getProperty("key")` | Hardcoded ATOS-specific property table |

### 3.5 Process → Agent Spawning

| Java API | ATOS Implementation |
|----------|-------------------|
| `ProcessBuilder.start()` | `sys_spawn_image` with embedded binary |
| `Process.getInputStream()` | Mailbox receive from child agent |
| `Process.waitFor()` | Block on child completion event |

### 3.6 Security

| Java API | ATOS Implementation |
|----------|-------------------|
| `SecurityManager` (deprecated) | ATOS capability model (strictly superior) |
| `AccessController` | Capability checks via `sys_cap_query` |
| `java.security.Permission` | Maps to ATOS `CapType` |

## 4. Implementation Strategy

### Phase 1: Core Runtime (native agent, no Java I/O)

**Goal:** Ristretto compiles as a native ATOS agent and can execute pure-computation Java programs (no file/network/thread).

**Changes:**
1. Add `#[cfg(target_os = "atos")]` branches to `ristretto_types` and `ristretto_vm`
2. Replace `std::collections::HashMap` → `hashbrown::HashMap` (already a dependency)
3. Replace `std::sync::Arc` → `alloc::sync::Arc`
4. Replace `std::fmt` → `core::fmt`
5. Stub out I/O traits (`Read`/`Write`) on ATOS
6. Classloader: load classes from in-memory byte buffer (JAR bytes received via mailbox)
7. Entry point: ATOS agent receives JAR bytes via mailbox → Ristretto decodes and executes

**Test:** `HelloWorld.class` that prints to System.out → appears in ATOS serial log.

### Phase 2: File System Virtualization

**Goal:** `java.io.*` and `java.nio.file.*` work via keyspace.

**Changes:**
1. Implement `atos_fs` module in `ristretto_intrinsics` behind `#[cfg(target_os = "atos")]`
2. Path-to-key mapping with FNV hash
3. Large file chunking (split across multiple keyspace entries)
4. Directory simulation via key prefix convention
5. Pre-populate keyspace with application data before agent starts

**Test:** Java program reads a config file, writes a log file → both stored in keyspace.

### Phase 3: Network Virtualization

**Goal:** `java.net.*` works via netd proxy.

**Changes:**
1. Implement `atos_net` module: socket abstraction over netd mailbox protocol
2. Connection lifecycle: open → read/write → close, all via mailbox messages
3. HTTP convenience: `URL.openConnection()` maps to netd HTTP request
4. DNS: delegate to netd (netd resolves via kernel UDP)

**Test:** Java program fetches an HTTP URL → response received via netd.

### Phase 4: Threading Virtualization

**Goal:** `java.lang.Thread` works via child agents.

**Changes:**
1. Implement `atos_thread` module: Thread → agent mapping
2. Thread.start() → `sys_spawn` with a wrapper agent that runs the Runnable
3. Thread.join() → recv on completion mailbox
4. synchronized → mailbox-based lock protocol
5. Energy budget splitting: parent's energy divided among child thread-agents

**Test:** Java program spawns 3 threads, each increments a shared counter via synchronized block.

### Phase 5: Java Standard Library Bootstrap

**Goal:** Load the real `java.base` module so standard library classes (ArrayList, HashMap, String, etc.) are available.

**Changes:**
1. Pre-load `java.base` JMOD into a read-only keyspace at boot
2. Ristretto classloader reads from this keyspace via the file virtualization layer
3. Bootstrap sequence: load `java.lang.Object` → `java.lang.Class` → `java.lang.String` → core classes

**Test:** Java program uses `ArrayList<String>`, `HashMap`, `StringBuilder` → works correctly.

## 5. Deployment Model

```
Developer workflow:
  javac MyAgent.java → MyAgent.class
  jar cf agent.jar MyAgent.class
  atos deploy agent.jar        ← CLI tool writes to Agent Storage Region

ATOS runtime:
  skilld receives install request
  → loads agent.jar from disk / mailbox
  → spawns Ristretto agent with JAR bytes
  → Ristretto decodes classes, finds main(), executes
  → Java program runs with full ATOS isolation + capability model
```

## 6. What Java Programs Get for Free on ATOS

By running on ATOS instead of Linux, Java programs automatically gain:

| Benefit | How |
|---------|-----|
| **Capability-scoped authority** | Java code can only access resources its agent holds capabilities for |
| **eBPF-lite policy filtering** | Every syscall (file read, network send, thread spawn) can be intercepted by policy |
| **Energy metering** | Every bytecode instruction costs fuel; runaway programs are suspended, not killed |
| **Structured audit log** | Every I/O operation produces a sequenced, replayable event |
| **Checkpoint & migration** | JVM state can be checkpointed, transferred to another node, and resumed |
| **Verifiable execution** | ProofGrade mode: third party can verify "this JAR produced this output" |
| **Isolation** | JVM crash cannot affect other agents; no shared memory, no ambient access |

## 7. Comparison with Existing Approaches

| Approach | Java on Linux | Java on WASM (browser) | Java on ATOS |
|----------|--------------|----------------------|-------------|
| File system | Full POSIX | None | Virtualized via keyspace |
| Networking | Full sockets | None (or fetch API) | Virtualized via netd |
| Threading | Native threads | None (single-threaded) | Virtualized via child agents |
| Security model | SecurityManager (weak) | Same-origin (browser) | Capability + eBPF (strong) |
| Metering | None | None | Energy budget per agent |
| Auditability | grep logs | Console only | Structured event stream |
| Provability | None | None | Execution proofs |
| Migration | Not possible | Not possible | Checkpoint + transfer |

## 8. Non-Goals

- **Full JDK compatibility** — AWT/Swing, JDBC, JMX, and other desktop/enterprise APIs are out of scope. The target is server-side and agent-style Java workloads.
- **JIT compilation** — ATOS Ristretto runs in interpreter mode. JIT requires native code generation, which conflicts with WASM sandboxing and ProofGrade determinism.
- **Java-to-Java threading parity** — Thread scheduling is agent-based, not OS-thread-based. Performance characteristics differ from native JVM.

## 9. Relationship to ATOS Runtimes

After Ristretto integration, ATOS has four execution runtimes:

| Runtime | Language | Use Case |
|---------|----------|----------|
| **Native x86_64** | Rust | System agents (stated, policyd, netd) |
| **WASM** | Any → WASM | Portable, deterministic user agents |
| **eBPF-lite** | eBPF bytecode | Kernel-resident policy enforcement |
| **JVM (Ristretto)** | Java / Kotlin / Scala | Java ecosystem workloads on ATOS |

The JVM runtime is not a separate kernel path — it is a native ATOS agent that happens to contain an embedded JVM interpreter. From the kernel's perspective, it is just another agent with a mailbox, capabilities, and an energy budget.
