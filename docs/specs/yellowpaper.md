# TOS Yellow Paper

**Version:** Draft v2.0
**Status:** Engineering Yellow Paper
**Language:** English
**Purpose:** Implementation reference for building TOS — a hardware-level deterministic execution VM.

> **Implementation Status:** Stages 1–10 are structurally implemented. See `[IMPL]` markers throughout this document for per-item status. Last verified: 2026-04-03.
>
> **Known gaps (verified by code audit 2026-04-03):**
> - Stage-5: `StateTransaction` (atomic multi-key commit/rollback) is NOT implemented. Only single-key put/get exists in `state.rs`.
> - Stage-6: Package signing in `atp` CLI uses FNV-1a hash, NOT Ed25519. Deploy trust is not cryptographically sound.
> - Stage-8: WASM host bindings are incomplete. Only 6 basic functions (yield, send, recv, exit, energy_get, log). Missing: `state_get`, `state_put`, `state_delete`, `contract_call`. Contracts cannot access persistent state or call other contracts through the WASM ABI.
> - See `docs/plans/TODO-proof-contract-platform.md` for the plan to close these gaps.

---

## Abstract

TOS is a **hardware-level deterministic execution virtual machine**. It runs directly on x86_64 hardware (or QEMU), providing isolated, metered, verifiable execution for smart contracts and WASM modules — without relying on any host operating system. Linux x86_64 programs (including JVM and Node.js) can also run via the deterministic Linux compatibility layer.

TOS is **not** an operating system in the traditional sense. It is a bare-metal execution substrate comparable to:

* **EVM** — but running on real hardware instead of inside a blockchain node process
* **JVM/Node.js** — but running via Linux compat layer with deterministic execution, energy metering, and cryptographic state proofs
* **A hardware security module** — but programmable, auditable, and verifiable

The core promise of TOS is:

> **Submit code and input. Get deterministic output, a state transition, an energy bill, and a cryptographic proof. The execution environment is isolated, metered, and leaves no pollution between runs.**

Contracts (agents) can be **persistently deployed** and **call each other** via mailbox IPC, forming a composable execution environment similar to on-chain smart contracts.

### Design Principles

1. **The architecture is designed from zero** — not inherited from legacy human-centric operating systems.
2. **The code is written from zero** — not modifying Linux or embedding inside an existing kernel.
3. **Deterministic execution** — same input, same code, same state → same output, always.
4. **Isolated execution** — contracts cannot interfere with each other or the host environment.
5. **Metered execution** — every operation costs energy; no unbounded computation.
6. **Verifiable execution** — every execution produces a receipt with cryptographic commitments.
7. **External connectivity** — contracts communicate with the outside world via brokered TCP.

### Terminology

* **TOS** — the full system.
* **TOS-0** — the privileged kernel substrate: boot, memory, traps, syscalls, scheduling, mailbox IPC, capability enforcement, energy accounting, audit.
* **TOS-1** — the runtime host layer: WASM engine, native runtime, deterministic Linux compatibility layer.
* **TOS-2** — the contract and system-service layer: deployed contracts, stated, policyd, netd.

---

## Table of Contents

- Abstract
- Executive Roadmap
- Part I — Foundations and Stage-1 Scope (§0–§8)
- Part II — Core Execution Specification (§9–§23)
- Part III — Stage Roadmaps (§24–§27)
- Part IV — Closing Material (§28–§31)

---

## Executive Roadmap

### Core Principle

TOS is **not** a desktop operating system, not a POSIX clone, and not a Linux replacement.

TOS is a **hardware-level deterministic execution VM** for smart contracts, verifiable computation, and metered workloads.

Its first-class concepts are:

- contracts (agents)
- mailboxes (inter-contract calls)
- capabilities (explicit authority)
- state objects (contract storage)
- energy budgeting (gas metering)
- execution receipts (verifiable output)
- checkpoints and replay (deterministic verification)
- external TCP interface (communication with the outside world)

### What TOS Replaces

| Traditional VM | TOS Equivalent | Advantage |
|---|---|---|
| EVM (Ethereum) | TOS with WASM + Linux compat | Runs on hardware, not inside a process; multi-language; richer state model |
| JVM (on Linux) | TOS with Linux compat layer | Runs unmodified OpenJDK deterministically via syscall translation |
| Docker/VM isolation | TOS per-contract page tables | Hardware-enforced isolation at the page table level, not process-level |
| Gas metering (EVM) | TOS energy budget | Unified across WASM, native, Linux-compat; tick-based preemption, no per-opcode overhead |

### The Execution Model

```text
                        TOS EXECUTION MODEL

  External System                                    External System
       │                                                  ▲
       │ TCP: submit transaction                          │ TCP: result + receipt
       ▼                                                  │
+----------------------------------------------------------------------+
|  TOS-2  Contract / Service Layer                                    |
|  deployed contracts | stated | policyd | netd                       |
|                                                                      |
|  Contract A ──mailbox──→ Contract B ──mailbox──→ Contract C          |
|       │                       │                       │              |
|       ▼                       ▼                       ▼              |
|  keyspace A              keyspace B              keyspace C          |
|  (isolated storage)      (isolated storage)      (isolated storage)  |
+-------------------------------+--------------------------------------+
                                |
                                | syscall / trap / yield
                                ▼
+----------------------------------------------------------------------+
|  TOS-1  Runtime Host                                                |
|  WASM engine | Linux compat layer | native runtime                  |
|  load → execute → meter → syscall_bridge → snapshot                 |
+-------------------------------+--------------------------------------+
                                |
                                | energy accounting + capability check
                                ▼
+----------------------------------------------------------------------+
|  TOS-0  Kernel                                                      |
|  scheduler | mailbox IPC | capability enforcement | eBPF-lite        |
|  energy meter | state + Merkle | checkpoint | audit trail            |
+-------------------------------+--------------------------------------+
                                |
                                ▼
+----------------------------------------------------------------------+
|  x86_64 + Boot + Devices                                            |
|  paging | traps | timer | virtio-blk | virtio-net | serial | QEMU   |
+----------------------------------------------------------------------+
```

### The 8 Stages at a Glance

| Stage | Title | Main Outcome |
|---|---|---|
| 1 | Minimal Kernel Prototype | TOS boots and runs core contract primitives |
| 2 | Isolation + Runtime Foundation | TOS gains ring-3 isolation, WASM, eBPF-lite, persistent state |
| 3 | Deterministic Execution Layer | Deterministic scheduling, replay, Merkle state, energy cost model |
| 4 | Hardware + External Interface | Real hardware direction, TCP external interface, SDK tooling |
| 5 | Contract Persistent State | Versioned keyspaces, atomic transactions, Merkle proofs, crash recovery |
| 6 | Contract Package Management | Deployment, addressing, inter-contract calls, upgrade/rollback, signing |
| 7 | Verifiable Execution | ExecutionReceipt, Replay/Proof Bundles, TPM attestation |
| 8 | WASM Runtime | Production WASM engine with fuel metering and selector dispatch |
| 9 | Deterministic Linux Compatibility | 104 Linux syscalls with deterministic translation (67/67 tests pass) |
| 10 | Production Runtime Depth | Dynamic linking, multi-threading, signals, file mmap for OpenJDK/Node.js |

### Stage-by-Stage Roadmap

#### Stage-1 — Minimal Kernel Prototype `[IMPL: ✅ Complete]`

**Purpose**
Prove that the minimal TOS execution substrate is alive.

**Core Capabilities**
- boot in QEMU
- enter 64-bit mode
- initialize memory
- install GDT/IDT
- handle traps
- minimal syscall path
- create and schedule agents (contracts)
- mailbox IPC
- capability checks
- energy accounting
- serial audit logs

**Success Condition**
TOS boots, creates multiple contracts, supports mailbox communication, enforces capabilities, and logs events.

#### Stage-2 — Isolation + Runtime Foundation `[IMPL: ✅ Complete]`

**Purpose**
Turn the prototype into a real execution substrate with sandboxed runtimes.

**Core Capabilities**
- ring-3 user contracts `[IMPL: ✅ create_user_agent() in init.rs]`
- per-contract page tables `[IMPL: ✅ create_address_space() in paging.rs]`
- kernel heap allocator `[IMPL: ✅ heap.rs linked-list allocator]`
- ELF loader `[IMPL: ✅ loader.rs load_elf64()]`
- WASM runtime `[IMPL: ✅ wasm/ module with wasbi engine + host bindings]`
- eBPF-lite runtime `[IMPL: ✅ ebpf/ with runtime, verifier, maps, attach]`
- persistent state store (virtio-blk) `[IMPL: ✅ persist.rs log-based store]`
- checkpoint/restore foundation `[IMPL: ✅ checkpoint.rs with disk serialization]`
- first system agents (stated, policyd) `[IMPL: ✅ agents/stated.rs, policyd.rs]`

**Success Condition**
TOS can run isolated contracts, execute WASM workloads, persist state, and restore from checkpoints.

#### Stage-3 — Deterministic Execution Layer `[IMPL: ✅ Complete]`

**Purpose**
Make execution fully deterministic, replayable, and production-oriented.

**Core Capabilities**
- deterministic fixed-tick-quota scheduler `[IMPL: ✅ deterministic.rs]`
- I/O trace recording for replay `[IMPL: ✅ checkpoint.rs record_trace()]`
- Merkleized state with proofs `[IMPL: ✅ merkle.rs + proof.rs]`
- energy cost table (syscall, timer, storage, network costs) `[IMPL: ✅ cost.rs]`
- SMP/multi-core foundations `[IMPL: ✅ smp.rs]`
- advanced eBPF-lite enforcement `[IMPL: ✅ ebpf/ attach points]`
- netd with virtio-net (brokered network) `[IMPL: ✅ agents/netd.rs + virtio_net.rs]`
- multi-mailbox support `[IMPL: ⚠️ infrastructure present, legacy 1:1 usage]`

**Success Condition**
WASM contracts execute with full determinism. Native contracts execute with scheduling-level determinism. All state transitions produce Merkle roots. Replay verification works.

#### Stage-4 — Hardware + External Interface `[IMPL: ✅ Complete]`

**Purpose**
Move beyond QEMU-only and expose TOS to external systems via TCP.

**Core Capabilities**
- UEFI boot direction for real hardware `[IMPL: ⚠️ detection + mmap parsing]`
- PCI enumeration, NVMe storage, real NIC (e1000) `[IMPL: ✅ pci.rs, nvme.rs, e1000.rs]`
- **TCP external interface**: accept transaction submissions, return results + receipts `[IMPL: ✅ tcp_interface.rs]`
- developer SDKs (Rust agent SDK, WASM SDK, eBPF-lite SDK) `[IMPL: ⚠️ atp CLI exists]`
- CLI tools (tos-build, tos-deploy, tos-replay, tos-inspect) `[IMPL: ⚠️ atp covers build/sign/verify/inspect]`
- execution proof generation (hash-chain over checkpoint + events) `[IMPL: ✅ proof.rs]`
- remote attestation foundation (TPM stub) `[IMPL: ✅ tpm.rs + attestation.rs]`
- `x86_64-unknown-tos` custom Rust target `[IMPL: ✅]`
- TOS WASM engine `[IMPL: ✅]`

**Key Addition — TCP External Interface**

This is a critical new component. TOS must expose a TCP listener that external systems use to:

1. **Submit transactions**: send contract code + input data + energy budget
2. **Deploy contracts**: install a signed contract package for persistent execution
3. **Call contracts**: invoke a deployed contract's entry point with arguments
4. **Query state**: read a contract's keyspace (Merkle-proved)
5. **Get receipts**: retrieve execution receipts and proof bundles

The TCP interface is brokered through `netd`. Contracts never touch the network directly.

```text
External Client
    │
    │ TCP connection
    ▼
netd (system agent)
    │
    │ mailbox message
    ▼
Target Contract
    │
    │ execute + meter
    ▼
Result + Receipt → netd → TCP → External Client
```

**Protocol Design (Stage-4)**:

```text
Request {
    request_id: u64,
    request_type: u8,       // DEPLOY=1, CALL=2, QUERY=3, SUBMIT=4
    contract_id: Hash256,   // target contract (zero for DEPLOY/SUBMIT)
    entry_point: [u8; 64],  // function name or method selector
    input: Vec<u8>,         // calldata
    energy_limit: u64,      // max energy for this execution
    signature: [u8; 64],    // Ed25519 signature over request
}

Response {
    request_id: u64,
    status: u8,             // SUCCESS=0, REVERT=1, OUT_OF_ENERGY=2, ERROR=3
    output: Vec<u8>,        // returndata
    energy_used: u64,
    state_root: Hash256,    // post-execution Merkle root
    receipt_hash: Hash256,  // reference to full ExecutionReceipt
}
```

**Success Condition**
TOS runs on real hardware. External systems can submit transactions, deploy contracts, call contracts, and verify execution via TCP.

#### Stage-5 — Contract Persistent State `[IMPL: ✅ Complete]`

**Purpose**
Make contract storage durable, versioned, provable, and crash-recoverable.

**Core Capabilities**
- versioned keyspaces with monotonic version counter and root history `[IMPL: ✅ state.rs]`
- transactional mutation groups (atomic multi-key updates with rollback) `[IMPL: ❌ NOT IMPLEMENTED — only single-key put/get exists; StateTransaction type does not exist]`
- Merkle proofs against current and historical state roots `[IMPL: ✅ proof.rs + merkle.rs]`
- compaction and garbage collection (bounded storage growth) `[IMPL: ✅ agents/compactd.rs]`
- crash recovery with CRC-validated append-only log `[IMPL: ✅ persist.rs]`
- state snapshots for checkpoint integration `[IMPL: ✅ checkpoint.rs]`

**Why This Matters**
Contracts are persistently deployed. They accumulate state across calls (like EVM storage). That state must be:
- **Versioned**: every call advances the state version
- **Provable**: external verifiers can check inclusion/exclusion against a state root
- **Atomic**: multi-key updates either all commit or all roll back
- **Recoverable**: crash at any point → consistent state root on recovery
- **Bounded**: compaction prevents unbounded growth

**Success Condition**
Contract state survives crashes, produces Merkle proofs, supports atomic transactions, and remains bounded through compaction.

#### Stage-6 — Contract Package Management `[IMPL: ✅ Complete]`

**Purpose**
Make contracts deployable, addressable, composable, and upgradable artifacts.

**Core Capabilities**
- **Package format** (`.tos`): manifest + code + signature (Ed25519) `[IMPL: ✅ package.rs]`
- **pkgd system agent**: manages deploy/upgrade/rollback/uninstall lifecycle `[IMPL: ✅ agents/pkgd.rs]`
- **skilld system agent**: validates contracts, enforces capability subset rules `[IMPL: ✅ agents/skilld.rs]`
- **Contract addressing**: each deployed contract has a unique content-addressed ID `[IMPL: ✅ contract.rs ContractId]`
- **Inter-contract calls**: Contract A sends mailbox message to Contract B, receives response (synchronous RPC pattern) `[IMPL: ✅ contract_call.rs]`
- **Upgrade/rollback**: checkpoint old → deploy new → migrate state → verify → terminate old `[IMPL: ⚠️ checkpoint exists, upgrade flow is stub]`
- **Signature verification**: deployment requires valid publisher signature `[IMPL: ❌ atp signs with FNV-1a hash, NOT Ed25519 — not cryptographically sound; must be replaced before production use]`
- **atp CLI tool**: build, sign, deploy, inspect, list, upgrade, rollback, verify `[IMPL: ✅ tools/atp/]`

**Inter-Contract Call Model**

```text
Contract A                    Contract B
    │                              │
    ├── sys_send(B.mailbox, ──────→│
    │   method + args)             │
    │                              ├── execute method
    │                              │
    │←──── sys_recv(A.mailbox) ────┤
    │   (result)                   │
    │                              │
    ▼                              ▼
energy deducted              energy deducted
from A's budget              from A's budget (caller pays)
```

Key properties:
- **Caller pays**: energy for the callee's execution is deducted from the caller's budget (like EVM)
- **Capability-gated**: caller must hold CAP_SEND_MAILBOX for callee's mailbox
- **Audited**: every inter-contract call emits audit events
- **Deterministic**: mailbox delivery order is deterministic within a transaction
- **No reentrancy by default**: a contract is blocked while waiting for a response (can be opted into with async patterns)

**Success Condition**
A developer can build, sign, deploy, invoke, upgrade, and roll back contracts via the atp CLI. Inter-contract calls work with deterministic semantics. Package signatures are verified at deployment.

#### Stage-7 — Verifiable Execution `[IMPL: ✅ Complete]`

**Purpose**
Make every execution produce a portable, cryptographically verifiable receipt.

**Core Capabilities**
- **ExecutionReceipt**: canonical receipt with contract identity, runtime class, input/output commitments, state roots, energy used, and Ed25519 signature `[IMPL: ✅ receipts.rs — input/output commitments computed via SHA-256, receipt_id via SHA-256, signed with Ed25519]`
- **Replay Bundle**: checkpoint + execution transcript + I/O trace (for full re-execution verification) `[IMPL: ✅ receipts.rs ReplayBundle — auto-generated on agent exit, persisted to disk, retrievable via TCP GetReplay]`
- **Proof Bundle**: compact Merkle proofs and state commitments (for fast verification without replay) `[IMPL: ✅ receipts.rs ProofBundle — real SHA-256 Merkle sibling hashes, root recomputation verification, persisted to disk, retrievable via TCP GetProof]`
- **TPM measured boot**: prove the TOS VM is running unmodified code (TPM 2.0 CRB + PCR extend/read) `[IMPL: ✅ tpm.rs — PCR0 (kernel) + PCR1 (boot config) extended during boot]`
- **Attestation report**: signed measurement of kernel hash + boot config + policy bundle `[IMPL: ✅ attestation.rs — Ed25519 or keyed-hash, integrated into receipt flow via trace_commitment]`

**ExecutionReceipt Specification**

```text
ExecutionReceipt {
    receipt_version: u16,
    receipt_id: Hash256,

    contract_id: Hash256,       // deployed contract identity
    execution_id: Hash256,      // this specific invocation
    caller_id: Hash256,         // who initiated the call (external or contract)
    node_id: NodeId,            // which TOS instance

    runtime_class: RuntimeClass,  // ProofGradeWasm, ReplayGradeNative
    code_hash: Hash256,           // exact contract code hash

    input_commitment: Hash256,
    output_commitment: Hash256,

    initial_state_root: Hash256,
    final_state_root: Hash256,
    event_log_commitment: Hash256,

    energy_used: u64,

    tick_start: u64,
    tick_end: u64,

    signature: [u8; 64],         // Ed25519 over receipt
}
```

**Verification Model**

```text
Execution on TOS VM
        │
        ▼
ExecutionReceipt (portable artifact)
        │
        ├───────────────────┐
        ▼                   ▼
  Replay Bundle        Proof Bundle
  (full re-execution)  (compact check)
        │                   │
        ▼                   ▼
  Replay Verifier      Proof Verifier
  (deterministic run)  (Merkle + hash)
        │                   │
        └───────┬───────────┘
                ▼
    External System trusts result
```

**Success Condition**
Every contract execution produces an ExecutionReceipt. External verifiers can validate receipts via replay or compact proofs. TPM attestation proves the TOS VM is running trusted code.

#### Stage-8 — WASM Runtime `[IMPL: ✅ Complete]`

**Purpose**
Provide a production-grade WASM execution engine as the primary contract runtime.

**WASM Engine**

The self-built WASM interpreter provides:
- 100% WASM MVP spec compliance
- Built-in fuel metering (1 WASM fuel = 1 TOS energy)
- Type-safe host bindings for TOS syscalls `[IMPL: ⚠️ PARTIAL — only 6 basic functions (yield, send, recv, exit, energy_get, log). Missing: state_get, state_put, state_delete, contract_call. Contracts cannot access persistent state or call other contracts through the WASM ABI.]`
- `#![no_std]` — runs as native TOS agent
- Deterministic execution (ideal for verifiable computation)
- 64 KB chunked code loading from keyspace
- Per-request selector-based export dispatch
- Differentiated error status (SUCCESS / REVERT / OUT_OF_ENERGY / ERROR)

Any language that compiles to WASM runs on TOS: Rust, C, C++, Go, Zig, AssemblyScript, Python (via wasm target), Java (via TeaVM/CheerpJ), Kotlin, Swift, C#, and others.

**Success Condition**
Any WASM module runs on TOS with full spec compliance, energy metering, and deterministic execution. Contract call dispatch routes to the correct export function via SHA-256 selector matching.

`[IMPL: ⚠️ WASM execution and fuel metering work. Selector dispatch works. But WASM contracts cannot do real blockchain work because state access and inter-contract call host functions are not yet exposed. See docs/plans/TODO-proof-contract-platform.md Phase 1.]`

#### Stage-9 — Deterministic Linux Compatibility Layer `[IMPL: ✅ Complete — 104 syscalls, 67/67 tests pass in QEMU]`

**Purpose**
Run any unmodified Linux x86_64 program on TOS with **deterministic execution guarantees**. This is the key differentiator: unlike traditional Linux compatibility layers that inherit Linux's non-determinism, TOS replaces every source of non-determinism at the syscall boundary with deterministic equivalents.

**Core Idea**

```text
Unmodified Linux ELF64 binary (OpenJDK, Node.js, CPython, Go, curl, etc.)
  ↓
Linux SYSCALL instruction (rax = Linux syscall number)
  ↓ intercepted by TOS syscall_entry.asm
┌────────────────────────────────────────────────────────────┐
│  Deterministic Linux Compatibility Layer                   │
│                                                            │
│  Every non-deterministic Linux syscall is replaced with    │
│  a deterministic TOS equivalent:                          │
│                                                            │
│  Time    → logical tick clock (not wall clock)             │
│  Random  → deterministic PRNG (seed = agent_id ⊕ tick)    │
│  Threads → child agents with fixed-order scheduling        │
│  Locks   → deterministic grant order (lowest agent_id)     │
│  mmap    → sequential allocation from fixed base address   │
│  epoll   → fixed-order mailbox polling                     │
│  Files   → keyspace mapping                                │
│  Network → netd proxy with I/O trace logging               │
└────────────────────────────────────────────────────────────┘
  ↓
TOS kernel (scheduler, mailbox, capability, energy, Merkle state)
```

**Why This Matters**

TOS is a deterministic execution VM. Programs compiled to WASM already run deterministically. But many important programs (OpenJDK, Node.js, CPython, Go binaries) are distributed as native Linux x86_64 ELF binaries, not WASM. This stage enables those programs to run on TOS **without modification and without sacrificing determinism**.

The key insight is that non-determinism in Linux programs comes from a small number of syscall-level sources. By controlling the syscall boundary, TOS can make any Linux program deterministic — the program cannot tell the difference, but its execution becomes fully reproducible.

**Non-Determinism Sources and Deterministic Replacements** `[IMPL: ✅ All replacements implemented in linux_compat/]`

| Linux Syscall | Non-Determinism Source | TOS Deterministic Replacement |
|--------------|----------------------|-------------------------------|
| `gettimeofday` / `clock_gettime` | Wall clock time varies | Return TOS tick count (logical clock, monotonic, reproducible) |
| `getrandom` / `read(/dev/urandom)` | True hardware randomness | Deterministic PRNG: `SHA-256(agent_id ∥ tick ∥ counter)` |
| `clone` (thread creation) | OS thread scheduling is non-deterministic | Create child agent; deterministic scheduler enforces fixed execution order |
| `futex(WAIT/WAKE)` | Lock contention resolution is non-deterministic | Grant to lowest waiting agent_id first (total order) |
| `epoll_wait` / `poll` / `select` | Event arrival order varies | Poll file descriptors in ascending numerical order, fixed round-robin |
| `mmap(NULL, ...)` | Kernel chooses address (ASLR) | Sequential allocation from fixed base `0x1_0000_0000` |
| `getpid` / `gettid` | OS-assigned process IDs | Derived deterministically from agent_id |
| `read` / `recvfrom` (network) | Data arrival timing varies | All network I/O logged to trace; replay feeds from trace |
| `nanosleep` / `clock_nanosleep` | Wake-up time imprecise | Advance logical tick by requested amount (instant, deterministic) |
| `pipe` / `eventfd` | Reader/writer scheduling | Mailbox pair with deterministic delivery order |

**Interception Mechanism** `[IMPL: ✅ RuntimeKind::LinuxCompat in Agent struct; syscall.rs routes LinuxCompat agents to linux_compat::dispatch() with eBPF exit hook]`

Each agent is tagged at spawn time with a `RuntimeKind`:

```text
RuntimeKind::Native      = 0   // TOS-native syscall ABI
RuntimeKind::Wasm        = 1   // WASM execution via interpreter
RuntimeKind::LinuxCompat = 2   // Linux syscall ABI (deterministic translation)
```

The syscall dispatcher checks the agent's runtime kind:

```rust
fn syscall_handler(num: u64, a1-a5: u64) -> i64 {
    if agent_runtime_kind(current) == LinuxCompat {
        linux_compat::dispatch(num, a1, a2, a3, a4, a5)  // Linux ABI
    } else {
        syscall::syscall(num, a1, a2, a3, a4, a5)         // TOS ABI
    }
}
```

**Per-Agent Virtual OS State** `[IMPL: ✅ LinuxAgentState with fd_table(256), cwd, brk, mmap_next, PRNG, epoll instances — state.rs]`

Each Linux-compat agent maintains a virtual POSIX state that is fully deterministic:

```text
LinuxAgentState {
    fd_table: [FdEntry; 256],        // virtual file descriptor table
    cwd: [u8; 256],                  // virtual working directory
    brk_current: u64,                // deterministic heap break
    mmap_next: u64,                  // next mmap address (sequential)
    pid: u32,                        // = agent_id (deterministic)
    uid: u32,                        // = 1000 (fixed)
    prng_state: [u8; 32],            // SHA-256 PRNG state
    prng_counter: u64,               // monotonic counter for PRNG
    epoll_instances: [EpollState; 8], // deterministic epoll
}
```

**Deterministic Thread Model** `[IMPL: ✅ clone3 creates child agent + deterministic scheduler; futex wait queue with agent_id ordering — process.rs]`

This is the hardest and most important part. OpenJDK, Node.js (libuv), and Go all create OS threads via `clone()`.

TOS maps threads to child agents with deterministic scheduling:

```text
Linux thread model (non-deterministic):
  Thread A and Thread B run in parallel
  Lock contention resolved by OS (random winner)
  → Different runs may produce different results

TOS deterministic thread model:
  Thread A → Child Agent A (agent_id = N)
  Thread B → Child Agent B (agent_id = N+1)

  Scheduling: fixed-tick-quota round-robin by agent_id
    Tick 0-9:   Agent A runs
    Tick 10-19: Agent B runs
    Tick 20-29: Agent A runs
    ...

  futex(WAKE): always wake lowest agent_id first
  → Same input always produces same thread interleaving
  → Same interleaving always produces same output
```

**Syscall Translation Map**

The following 62 syscalls were identified by tracing actual OpenJDK 11, Node.js v24, and CPython 3.10 execution with `strace -f -c`. This is the complete set required to run all three runtimes on TOS. The "Used By" column indicates which runtimes require each syscall (J = OpenJDK, N = Node.js, P = CPython).

*Phase 1 — Boot (~18 syscalls)*

| Linux # | Name | TOS Translation | Used By |
|---------|------|-----------------|---------|
| 0 | `read` | Keyspace `state_get` (files) or mailbox recv (pipes/sockets) | J N P |
| 1 | `write` | Keyspace `state_put` (files) or serial output (stdout/stderr) | J N P |
| 3 | `close` | Release fd entry | J N P |
| 9 | `mmap` | Frame allocation at deterministic sequential address (`mmap_next`) + page mapping | J N P |
| 10 | `mprotect` | Update page table flags (PTE_WRITABLE, PTE_NX) on mapped region | J N P |
| 11 | `munmap` | Frame deallocation + page table entry removal | J N P |
| 12 | `brk` | Adjust deterministic heap break pointer (`brk_current`) | J N P |
| 15 | `rt_sigreturn` | Restore pre-signal register state from stack frame | J |
| 21 | `access` | Check keyspace key existence, return 0 or -ENOENT | J N P |
| 59 | `execve` | `sys_spawn_image` — load ELF binary into new agent | J N P |
| 63 | `uname` | Return fixed struct: sysname="TOS", release="1.0", machine="x86_64" | J |
| 99 | `sysinfo` | Return fixed values: totalram from frame allocator, uptime from tick | J N P |
| 102 | `getuid` | Return fixed uid (1000) | J N P |
| 104 | `getgid` | Return fixed gid (1000) | N P |
| 107 | `geteuid` | Return fixed euid (1000) | J N P |
| 108 | `getegid` | Return fixed egid (1000) | N P |
| 158 | `arch_prctl` | Set/get FS/GS base MSR for TLS (ARCH_SET_FS, ARCH_GET_FS) | J N P |
| 302 | `prlimit64` | Return fixed resource limits (RLIMIT_NOFILE=256, RLIMIT_STACK=64KB) | J N P |

*Phase 2 — File I/O (~20 syscalls)*

| Linux # | Name | TOS Translation | Used By |
|---------|------|-----------------|---------|
| 5 | `fstat` | Return stat struct from fd metadata (size from keyspace value len) | N |
| 8 | `lseek` | Update fd offset in fd_table (SEEK_SET/CUR/END) | J P |
| 13 | `rt_sigaction` | Store signal handler + flags in per-agent signal table | J N P |
| 14 | `rt_sigprocmask` | Update blocked signal mask in agent state | J N |
| 16 | `ioctl` | TIOCGWINSZ → return fixed 80×25; FIONREAD → return pending mailbox bytes; others → -ENOTTY | N P |
| 17 | `pread64` | Keyspace `state_get` at specific offset (no fd offset advance) | J N P |
| 32 | `dup` | Duplicate fd entry in fd_table (new lowest available fd) | P |
| 72 | `fcntl` | F_GETFL/F_SETFL (track O_NONBLOCK in fd_table), F_DUPFD, F_GETFD/F_SETFD | J N P |
| 73 | `flock` | No-op success (single-agent access, no contention) | J |
| 77 | `ftruncate` | Truncate keyspace value to specified length | J |
| 79 | `getcwd` | Return agent's virtual cwd from LinuxAgentState | J N |
| 81 | `fchdir` | Update cwd to directory path referenced by fd | J |
| 83 | `mkdir` | Create keyspace key with directory marker value | J |
| 87 | `unlink` | Delete keyspace key | J |
| 89 | `readlink` | Resolve `/proc/self/exe` → agent binary path; others → keyspace lookup | J N P |
| 217 | `getdents64` | Enumerate keyspace keys matching directory prefix, return dirent structs | J P |
| 257 | `openat` | Allocate fd, resolve path relative to dirfd, map to keyspace key | J N P |
| 262 | `newfstatat` | Stat by path: return size/mode/times from keyspace metadata | J N P |

*Phase 3 — Network + epoll (~12 syscalls)*

| Linux # | Name | TOS Translation | Used By |
|---------|------|-----------------|---------|
| 28 | `madvise` | No-op success (MADV_DONTNEED clears pages; others ignored) | J N |
| 39 | `getpid` | Return agent_id (deterministic) | J N |
| 41 | `socket` | Allocate fd for netd mailbox proxy session | J |
| 42 | `connect` | Send connect request to netd via mailbox; record target in fd_table | J |
| 51 | `getsockname` | Return local address from fd_table socket metadata | N |
| 55 | `getsockopt` | Return default socket options from fd_table | N |
| 281 | `epoll_pwait` | Fixed-order polling: iterate watched fds by ascending number, check mailbox readiness | J N |
| 290 | `eventfd2` | Create mailbox pair mapped to fd; counter semantics via keyspace u64 | N |
| 291 | `epoll_create1` | Allocate epoll instance in per-agent EpollState table | N |
| 293 | `pipe2` | Create two fds backed by a mailbox pair (read end + write end) | N |
| 425 | `io_uring_setup` | Return -ENOSYS (not supported; Node.js falls back to epoll) | N |
| 426 | `io_uring_enter` | Return -ENOSYS (not supported; Node.js falls back to epoll) | N |

*Phase 4 — Threads + synchronization (~12 syscalls)*

| Linux # | Name | TOS Translation | Used By |
|---------|------|-----------------|---------|
| 24 | `sched_yield` | `sys_yield` — yield to deterministic scheduler | J |
| 98 | `getrusage` | Return energy_used as ru_utime; tick count as wall time | J |
| 125 | `capget` | Return empty capability set (no Linux capabilities) | N |
| 157 | `prctl` | PR_SET_NAME → store in agent metadata; PR_GET_NAME → retrieve; others → 0 | J N |
| 186 | `gettid` | Return agent_id (deterministic, same as getpid for main thread) | J N |
| 202 | `futex` | FUTEX_WAIT: block agent; FUTEX_WAKE: wake by ascending agent_id (deterministic) | J N P |
| 204 | `sched_getaffinity` | Return fixed mask: all CPUs up to SMP core count | J N |
| 218 | `set_tid_address` | Store clear_child_tid pointer in agent state | J N P |
| 229 | `clock_getres` | Return fixed resolution: 10ms (100 Hz tick) | J |
| 230 | `clock_nanosleep` | Advance logical tick by `ceil(requested_ns / 10_000_000)`, deterministic | J |
| 273 | `set_robust_list` | Store robust futex list pointer in agent state | J N P |
| 334 | `rseq` | Return -ENOSYS (restartable sequences not supported; glibc handles gracefully) | J N P |
| 435 | `clone3` | `sys_spawn` child agent with shared keyspace + deterministic scheduling | J N |

**Total: 62 syscalls** — verified by `strace -f -c` against OpenJDK 11, Node.js v24, and CPython 3.10. `[IMPL: ✅ 60/62 real implementations, 2 intentional -ENOSYS (io_uring only — Java doesn't use it, Node falls back to epoll)]`

**Legacy syscalls** (supported for older binaries but not observed in strace):

| Linux # | Name | TOS Translation |
|---------|------|-----------------|
| 2 | `open` | Redirect to `openat(AT_FDCWD, path, ...)` |
| 20 | `writev` | Scatter-gather write to fd (concatenate iovecs) |
| 56 | `clone` | Redirect to `clone3` path |
| 60 | `exit` | `sys_exit` |
| 96 | `gettimeofday` | Return TOS tick as seconds + microseconds |
| 228 | `clock_gettime` | Return TOS tick as timespec |
| 231 | `exit_group` | `sys_exit` for all child agents |
| 232 | `epoll_create` | Redirect to `epoll_create1(0)` |
| 233 | `epoll_ctl` | Add/remove fd from epoll watch set |

**Implementation Phases**

| Phase | New Syscalls | Cumulative | Enables | Determinism Mechanism |
|-------|-------------|-----------|---------|----------------------|
| **1: Boot** | 18 | 18 | Static hello world, busybox | mmap sequential, brk deterministic, fixed uid/gid |
| **2: File I/O** | 18 | 36 | CPython (static), file tools | fd table → keyspace, signals in agent state |
| **3: Network + epoll** | 12 | 48 | Node.js, curl, HTTP | netd proxy + I/O trace, epoll fixed-order, pipe→mailbox |
| **4: Threads + futex** | 13 | 61 | OpenJDK, Go, multi-threaded | clone3→child agent, futex→agent_id ordering |
| **Legacy** | 9 | 70 | Older binaries | Redirect to modern equivalents |

**Deterministic PRNG Specification** `[IMPL: ✅ SHA-256 chaining in identity.rs sys_getrandom()]`

Every Linux-compat agent has a built-in deterministic PRNG:

```text
seed = SHA-256(agent_id ∥ parent_id ∥ creation_tick)
state = seed

on getrandom(buf, len):
    for each 32-byte block needed:
        state = SHA-256(state ∥ counter)
        counter += 1
        copy block to buf
```

This produces output that appears random to the program but is fully reproducible given the same agent_id and creation_tick.

**I/O Trace for Network Determinism** `[IMPL: ✅ sendto/recvfrom record to NET_IO_LOG (256 entries); replay mode reads from log instead of network; TRACE_NET_SEND/RECV in checkpoint]`

Network I/O is inherently non-deterministic (data arrives at unpredictable times). TOS handles this via I/O tracing:

```text
First execution:
  socket() → fd=5
  connect(fd=5, "api.example.com:443") → netd proxy
  write(fd=5, request) → netd sends via NIC
  read(fd=5, buf) → netd receives response → log to trace

Replay:
  socket() → fd=5 (deterministic)
  connect(fd=5, ...) → same fd (deterministic)
  write(fd=5, request) → logged (deterministic)
  read(fd=5, buf) → replay from trace (deterministic, same bytes)
```

**Base Image Model for Dynamic Linking** `[IMPL: ✅ vfs.rs path→keyspace resolver; state.rs BASE_IMAGE_STORE (4096 entries) + store/load_multi_segment for files >64KB; install_base_image_file() convenience API]`

Linux programs (especially OpenJDK, Node.js, CPython) depend on dynamically linked shared libraries (`.so` files). A simple Java "Hello World" loads 13 `.so` files totaling ~26 MB at runtime:

```text
OpenJDK runtime dependency chain (verified by strace):

ld-linux-x86-64.so.2          ← dynamic linker (loaded by kernel)
├── libc.so.6                  ← C standard library (2 MB)
├── libm.so.6                  ← math library
├── libz.so.1                  ← compression (JAR decompression)
├── libstdc++.so.6             ← C++ standard library (JVM is C++)
├── libgcc_s.so.1              ← GCC runtime
├── librt.so.1                 ← POSIX realtime extensions
libjli.so                      ← JVM launcher
libjvm.so                      ← JVM core (22 MB — largest)
├── libverify.so               ← bytecode verification
├── libjava.so                 ← Java native methods
├── libjimage.so               ← module image reader
└── libzip.so                  ← ZIP/JAR handling
```

These `.so` files must be accessible through the virtual filesystem. TOS solves this with a **base image** model:

**1. Base Image Pre-Installation**

Runtime base images are deployed once to a dedicated system keyspace. Each `.so` file is stored using the chunked large-value storage (64 KB max per file, multiple files per image). The virtual filesystem maps standard Linux paths to keyspace keys:

```text
Virtual Path                              Keyspace Key
/lib/x86_64-linux-gnu/ld-linux-x86-64.so  → "base:ld-linux"
/lib/x86_64-linux-gnu/libc.so.6           → "base:libc"
/lib/x86_64-linux-gnu/libm.so.6           → "base:libm"
/lib/x86_64-linux-gnu/libz.so.1           → "base:libz"
/lib/x86_64-linux-gnu/libstdc++.so.6      → "base:libstdc++"
/lib/x86_64-linux-gnu/libgcc_s.so.1       → "base:libgcc_s"
/lib/x86_64-linux-gnu/librt.so.1          → "base:librt"
/jdk/lib/jli/libjli.so                    → "base:jdk/libjli"
/jdk/lib/server/libjvm.so                 → "base:jdk/libjvm"
/jdk/lib/libjava.so                       → "base:jdk/libjava"
/jdk/lib/libverify.so                     → "base:jdk/libverify"
/jdk/lib/libjimage.so                     → "base:jdk/libjimage"
/jdk/lib/libzip.so                        → "base:jdk/libzip"
```

**2. Dynamic Linking Flow**

When a Linux-compat agent executes, the dynamic linker loads `.so` files via the normal syscall path — no special handling needed beyond the virtual filesystem:

```text
execve("/jdk/bin/java", ...)
  ↓ kernel loads ELF, finds PT_INTERP = /lib/ld-linux-x86-64.so.2
  ↓ loads dynamic linker from keyspace "base:ld-linux"
  ↓
ld-linux resolves DT_NEEDED entries:
  openat("/lib/libc.so.6")      → keyspace "base:libc" → load_large_value()
  mmap(deterministic_addr, ...)  → map code segment with PROT_EXEC
  mprotect(...)                  → set correct permissions
  ↓ (repeat for each .so)
  ↓
All symbols resolved, jump to _start
```

The existing 62 syscalls fully cover this flow. No new syscalls are needed — `openat` resolves paths to keyspace keys, `mmap` maps code to deterministic addresses, `mprotect` sets permissions.

**3. Available Base Images**

| Image | Contents | Size | Enables |
|-------|----------|------|---------|
| `base-minimal` | ld-linux + libc + libm + libpthread | ~3 MB | Static C/C++ programs, Go, Rust |
| `base-java` | base-minimal + JDK libs (libjvm, libjava, libzip, ...) | ~26 MB | OpenJDK, Kotlin, Scala |
| `base-node` | base-minimal + libstdc++ + libuv | ~8 MB | Node.js, Deno |
| `base-python` | base-minimal + libpython3 + standard library | ~15 MB | CPython |

**4. /etc/ld.so.cache and Library Search**

The dynamic linker normally reads `/etc/ld.so.cache` to find library locations. TOS provides a deterministic version:

```text
Virtual /etc/ld.so.cache:
  Precomputed at base image installation time
  Maps library names to fixed keyspace paths
  Identical across all runs (deterministic)
  Stored at keyspace key "base:ld.so.cache"
```

If `ld.so.cache` is missing, ld-linux falls back to searching `/lib` and `/usr/lib` — both mapped to the base image keyspace.

**5. User Application Deployment**

With the base image installed, deploying a Java application is straightforward:

```text
TCP Deploy request:
  contract_id = SHA-256(Hello.jar)
  input = Hello.jar contents
  base_image = "base-java"

TOS:
  1. Store Hello.jar in agent keyspace ("app/Hello.jar")
  2. Create agent with RuntimeKind::LinuxCompat
  3. Link agent to base image keyspace (read-only access)
  4. Set entry point: /jdk/bin/java -cp /app/Hello.jar Hello
  5. Agent starts → ld-linux loads → JVM boots → Java runs
```

**6. Storage Requirements**

Each `.so` file uses chunked storage (256 bytes per chunk, up to 64 KB per large value). For files larger than 64 KB (libjvm.so is 22 MB), a multi-segment extension is used:

```text
libjvm.so (22 MB) storage:
  "base:jdk/libjvm:meta"  → { total_size: 22_000_000, segment_count: 344 }
  "base:jdk/libjvm:0"     → 64 KB segment (256 chunks)
  "base:jdk/libjvm:1"     → 64 KB segment
  ...
  "base:jdk/libjvm:343"   → final partial segment
```

This requires extending `store_large_value()` to support multi-segment files (currently limited to 64 KB). The extension is backward-compatible — files under 64 KB continue to use single-segment storage.

**Success Condition**
- OpenJDK runs Java programs on TOS with deterministic execution via the Linux compatibility layer. `[IMPL: ✅ syscall routing + base image + VFS all implemented; awaits end-to-end testing with real JDK binary]`
- Dynamic linking works: `ld-linux` loads `.so` files from keyspace-backed virtual filesystem. `[IMPL: ✅ vfs.rs resolves /lib/ paths to base image keyspace; multi-segment storage handles 22MB libjvm.so]`
- Base images are pre-installed once; user applications deploy as lightweight packages. `[IMPL: ✅ install_base_image_file() stores to BASE_IMAGE_STORE; Deploy sets up agent with app keyspace]`
- `curl https://example.com` fetches data through netd with I/O trace logging. `[IMPL: ✅ sendto proxies to netd + records TRACE_NET_SEND; recvfrom records TRACE_NET_RECV; replay reads from log]`
- A Go multi-threaded HTTP server handles concurrent requests via child agent threads with deterministic scheduling. `[IMPL: ✅ clone3 creates child agent + deterministic scheduler; futex wait queue with agent_id ordering; awaits end-to-end testing]`
- A Node.js program runs on TOS with deterministic event loop ordering. `[IMPL: ✅ epoll/poll/select all deterministic (ascending fd order); io_uring returns -ENOSYS (Node falls back to epoll)]`
- Two runs with the same input produce bit-identical execution traces and state roots. `[IMPL: ✅ all non-determinism sources replaced; network I/O recorded for replay; awaits end-to-end verification]`
- Linux-compat agents produce valid ExecutionReceipts with determinism guarantees. `[IMPL: ✅ LinuxCompat agents routed through linux_compat::dispatch(); eBPF exit hooks + receipts work on LinuxCompat path]`

#### Stage-10 — Production Runtime Depth `[IMPL: ✅ Complete]`

**Purpose**
Close the remaining gaps between the 104-syscall translation layer and actually running production Linux programs (OpenJDK, Node.js, CPython) on TOS. Stage-9 proves the syscall ABI works (67/67 tests pass); Stage-10 makes the runtime deep enough for real-world binaries.

**Core Capabilities**

1. **Dynamic Linking** `[IMPL: ✅ file-backed mmap loads .so content from keyspace; PROT_EXEC clears PTE_NX]`
   - Implement `execve` to truly load ELF binaries and start `ld-linux-x86-64.so.2`
   - `ld-linux` uses `openat` → `mmap(fd, PROT_READ|PROT_EXEC)` → symbol resolution
   - All addresses deterministic: `mmap_next` provides sequential fixed addresses
   - `.so` files served from base image keyspace via VFS path resolver
   - No new syscalls needed — uses existing `openat`, `mmap`, `mprotect`, `close`

2. **File-Backed mmap** `[IMPL: ✅ sys_mmap fd>=0 loads from keyspace via state_get or load_multi_segment; pre-loads all pages]`
   - Extend `sys_mmap` to support `fd >= 0` with `MAP_PRIVATE` + `PROT_EXEC`
   - Load file content from keyspace into mapped pages at deterministic addresses
   - Pre-load all pages on map (no lazy page fault — deterministic)
   - Required by dynamic linker to map `.so` code segments

3. **Deterministic Multi-Threading** `[IMPL: ✅ CLONE_VM shares parent cr3; FUTEX_WAIT/WAKE_BITSET + REQUEUE; agent_id ordered wake]`
   - Extend `clone3` to support `CLONE_VM` (shared address space between parent and child)
   - Currently each child agent gets its own keyspace; shared memory requires shared page tables
   - Futex: extend from simple wait/wake to full `FUTEX_WAIT_BITSET`, `FUTEX_REQUEUE`
   - All thread scheduling remains deterministic: fixed-order round-robin by agent_id
   - All futex wake ordering remains deterministic: lowest agent_id first

4. **Signal Delivery** `[IMPL: ✅ pending_signals bitmask + deliver at syscall return + SIGCHLD on child exit; lowest signal first]`
   - Implement synchronous signal delivery at deterministic points (syscall return boundaries)
   - `SIGSEGV`: JVM uses this for NullPointerException detection (deliberate NULL access → catch → throw NPE)
   - `SIGCHLD`: delivered when child agent exits (wake parent blocked in `wait4`)
   - Signal delivery modifies user stack (push signal frame) and redirects RIP to handler
   - `rt_sigreturn` restores pre-signal state from the signal frame
   - Deterministic: signals delivered only at syscall return, in order of signal number

5. **Base Image Multi-Segment Storage** `[IMPL: ✅ 131K-slot hash table + O(1) lookup; store/load_multi_segment for 22MB+ files]`
   - Extend `store_large_value` / `load_large_value` beyond 64KB limit
   - `libjvm.so` is 22MB = 344 × 64KB segments
   - Multi-segment index: metadata key stores total_size + segment_count
   - Segment keys: `base_key + 1` through `base_key + N`
   - `install_base_image_file(path, data)` handles the full flow

**Non-Goals (not needed for deterministic VM)**
- Full VFS with inodes/dentries — keyspace + VFS path resolver is sufficient
- Lazy page fault / demand paging — pre-load is simpler and deterministic
- `MAP_SHARED` between processes — not needed; each agent has its own keyspace
- POSIX signals fully — only SIGSEGV, SIGCHLD, and SIGUSR1/2 needed

**Determinism Guarantees**

All Stage-10 features maintain determinism:

| Feature | Non-Determinism Source | Deterministic Implementation |
|---------|----------------------|------------------------------|
| Dynamic linking | Library load addresses (ASLR) | `mmap_next` sequential allocation |
| Threads | OS scheduler decides order | Round-robin by agent_id, fixed tick quota |
| Futex | Wake order non-deterministic | Lowest agent_id wakes first |
| Signals | Delivery timing asynchronous | Deliver at syscall return only, ordered by signal number |
| File mmap | Page fault timing | Pre-load all pages on mmap (no lazy faulting) |

**Success Condition**
- A statically-linked OpenJDK JVM runs `Hello.class` on TOS with deterministic output.
- A dynamically-linked OpenJDK JVM loads `libjvm.so` via `ld-linux` from base image keyspace and runs `Hello.class`.
- JVM thread creation (`clone3` + shared memory) works with deterministic scheduling.
- JVM NullPointerException detection via `SIGSEGV` handler works.
- Node.js runs a simple HTTP handler with deterministic event loop.
- Two runs with identical input produce bit-identical execution traces.

### The Three Eras of TOS

#### Era I — Execution Foundation (Stage-1 to Stage-4)

TOS proves that it can execute contracts on hardware.

Focus: kernel, isolation, runtime, state, hardware, external TCP interface.

#### Era II — Production Execution (Stage-5 to Stage-8)

TOS becomes a production-grade verifiable execution platform.

Focus: durable state, contract lifecycle, verifiable execution, WASM runtime.

#### Era III — Universal Deterministic Execution (Stage-9 to Stage-10)

Any Linux program runs on TOS with deterministic guarantees.

Stage-9: syscall translation layer (104 syscalls, 67/67 tests pass).
Stage-10: runtime depth for real-world binaries (dynamic linking, threads, signals).

### One-Sentence Definition

**TOS is a bare-metal deterministic execution VM where contracts are deployed, isolated, metered, composable via mailbox calls, and every execution produces a cryptographically verifiable receipt — running directly on hardware without any host operating system. WASM contracts run with proof-grade determinism (bit-identical replay). Linux x86_64 programs, including dynamically-linked runtimes like OpenJDK and Node.js, can also run on TOS with scheduling-level deterministic guarantees through the 104-syscall Linux compatibility layer.**

---

## Part I — Foundations and Stage-1 Scope

## 0. Preface: TOS First Principles / Original Intent

TOS began from a simple premise: deterministic, metered, verifiable computation should run directly on hardware — not inside a process on a general-purpose operating system, and not limited to a single instruction set like EVM bytecode.

The original intent of TOS is:

* to provide a **hardware-level execution VM**, not a general-purpose operating system
* to make **authority explicit** through capabilities and policy, rather than ambient privilege
* to make **contract storage, energy budgeting, and auditability** first-class system concepts
* to prefer **deterministic, replayable execution** over convenience inherited from legacy APIs
* to support **multiple execution formats** (WASM, native, Linux-compat) under one unified metering and verification model
* to validate this model first in **QEMU**, then expand to real hardware

In practical terms, TOS is centered on:

* contracts (agents)
* mailboxes (inter-contract calls and external communication)
* capabilities (explicit authority)
* state objects (contract storage with Merkle proofs)
* energy budgets (gas/fuel metering)
* execution receipts (verifiable output)
* checkpoints (deterministic replay)

It is intentionally not centered on:

* files as the primary abstraction
* fork/exec as the process model
* raw sockets as the default communication model
* shell sessions as the primary operator interface
* unrestricted global authority
* POSIX compatibility

---

## 1. Motivation

### 1.1 The Problem with Software VMs

Current execution VMs (EVM, WASM runtimes) run **inside** a host operating system process. This means:

* isolation depends on the host OS process model (which was designed for human users, not deterministic execution)
* metering is approximate (wall-clock time) or requires per-opcode instrumentation (EVM gas)
* verification requires trusting the host OS, the runtime process, and the operator
* the host OS provides a massive attack surface that is irrelevant to the computation

### 1.2 The TOS Approach

TOS eliminates the host OS entirely. The execution VM **is** the operating system:

* isolation is enforced by **hardware page tables** (x86_64 ring-3 / ring-0 separation)
* metering is unified across all runtimes via **timer-tick preemption** (no per-opcode overhead)
* verification is anchored to **TPM hardware attestation** and **deterministic replay**
* the attack surface is minimal: a small kernel with no legacy compatibility burden

### 1.3 Comparison

| Property | EVM | JVM (on Linux) | TOS |
|----------|-----|----------------|------|
| Isolation | EVM sandbox | OS process | Hardware page tables |
| Metering | Per-opcode gas | None (wall-clock) | Timer-tick energy (unified) |
| Determinism | Full | No | Full (WASM) / Scheduling-level (native) |
| Verification | Consensus | None | Receipt + Replay + TPM |
| Languages | Solidity only | Java/Kotlin/Scala | WASM (any) + native + Linux binaries via compat layer |
| Storage | 256-bit slots | Filesystem | Merkle keyspaces |
| Inter-contract calls | CALL opcode | Method calls | Mailbox IPC |
| Host OS required | Yes (Linux) | Yes (Linux/Windows) | No (bare metal) |

---

## 2. Design Philosophy

### 2.1 Execution VM, not operating system

TOS is not designed to replace Linux, Windows, or macOS. It is designed as:

* a deterministic execution substrate for smart contracts
* a hardware-level VM for verifiable computation
* a metered execution environment for untrusted code
* a multi-runtime platform (WASM, native, Linux-compat)

### 2.2 Minimal kernel, rich execution model

The kernel should remain as small as possible. Only irreducible functionality belongs in the kernel:

* memory protection
* trap handling
* system call entry
* scheduling primitives
* capability enforcement
* mailbox IPC
* energy accounting
* audit trail

Higher-level services (state persistence, policy enforcement, networking, contract management) are built as system agents.

### 2.3 Determinism over convenience

TOS must prefer predictable, replayable behavior over convenience. Every source of non-determinism must be either eliminated or traced for replay.

### 2.4 Explicit authority

Nothing is accessible by default. Every meaningful action must be backed by a capability.

### 2.5 Contracts and mailboxes, not files and sockets

The primary concepts of TOS are:

* contract (agent)
* mailbox (IPC and inter-contract calls)
* capability (authority token)
* keyspace (contract storage)
* energy budget (execution metering)
* execution receipt (verifiable output)

Not:

* file path
* fork/exec
* raw socket
* ambient authority

---

## 3. Scope of Stage-1

The first implementation target of TOS is intentionally narrow.

### 3.1 Target platform

* **Architecture:** x86_64
* **Execution environment:** QEMU first
* **Boot environment:** Multiboot (v1) header, loaded directly by QEMU's `-kernel` flag.
* **CPU mode:** 64-bit long mode
* **Core assumption:** single-core initially

### 3.2 What Stage-1 must do

1. Boot in a virtual machine. `[IMPL: ✅ QEMU via Multiboot v1, ELF64→ELF32 objcopy]`
2. Enter 64-bit mode. `[IMPL: ✅ boot.asm: 32-bit → PAE → long mode transition]`
3. Initialize basic memory management. `[IMPL: ✅ bitmap frame allocator, 126 MB / 32,256 frames]`
4. Install GDT and IDT. `[IMPL: ✅ gdt.rs (7-entry GDT + TSS), idt.rs (256-entry IDT + PIC remap)]`
5. Handle traps and exceptions. `[IMPL: ✅ trap_entry.asm stubs + trap.rs policy, vectors 0-19]`
6. Provide a minimal syscall path. `[IMPL: ✅ 11 syscalls (§14.2 + §14.3), direct call in Stage-1]`
7. Create and schedule minimal contract contexts. `[IMPL: ✅ 5 agents, round-robin + preemptive via PIT 100Hz]`
8. Provide mailbox-based IPC. `[IMPL: ✅ ring-buffer mailbox, 16 slots × 256B, ping/pong verified]`
9. Enforce a minimal capability model. `[IMPL: ✅ grant/deny/subset, CAP_DENIED audit event, bad agent demo]`
10. Provide execution budgeting / energy accounting. `[IMPL: ✅ tick + syscall decrement, BUDGET_EXHAUSTED + suspend]`
11. Emit serial logs and audit events. `[IMPL: ✅ structured [EVENT ...] format over COM1 serial]`

### 3.3 What Stage-1 deliberately does not do

* no graphical user interface
* no POSIX compatibility
* no filesystem
* no USB stack
* no SMP
* no GPU support
* no network stack
* no ELF compatibility for user programs

---

## 4. System Overview

### 4.1 Layer naming

* **TOS-0** — privileged kernel substrate
* **TOS-1** — runtime host layer (WASM, native, Linux-compat)
* **TOS-2** — contract and system-service layer

### 4.2 Logical architecture

```text
+---------------------------------------------------+
|         External Systems (via TCP)                |
+---------------------------------------------------+
| TOS-2 Contract / Service Layer                    |
| deployed contracts | stated | policyd | netd      |
+---------------------------------------------------+
| TOS-1 Runtime Host                                |
| WASM engine | Linux compat layer | native          |
+---------------------------------------------------+
| TOS-0 Kernel                                      |
| sched | mailbox | capability | state | audit      |
| energy | syscall | checkpoint | Merkle            |
+---------------------------------------------------+
| x86_64 Architecture + Boot                        |
| gdt | idt | paging | timer | trap | multiboot     |
+---------------------------------------------------+
|                    QEMU / Hardware                |
+---------------------------------------------------+
```

### 4.3 Stage-1 implementation snapshot

Stage-1 realizes only a thin slice of the full stack:

* TOS-0 is the primary focus
* TOS-1 collapses to built-in native execution
* TOS-2 contains only minimal bootstrap and test contracts
* External TCP interface is deferred

### 4.4 TOS Genesis

TOS requires a trusted starting point at system bring-up:

* **authority**: the root identity and initial capability set
* **execution budget**: the initial energy pool from which contract budgets are delegated
* **bootstrap services**: system agents that must exist from the start (stated, policyd, netd)
* **policy**: the initial eBPF-lite policy bundle
* **state**: the initial keyspace configuration

In Stage-1, TOS Genesis is implicit and compiled into the boot path. Later stages may externalize this into an explicit signed genesis profile.

---

## 5. Core System Concepts

### 5.1 Contract (Agent)

A **contract** is the primary execution unit in TOS. It replaces the traditional concept of a process or a smart contract account.

```text
Contract {
    id,
    parent_id,
    status,
    runtime_kind,          // Native, WASM, LinuxCompat
    execution_context,
    runtime_state,
    mailbox_id,
    capability_set,
    energy_budget,
    memory_quota,
}
```

Required properties:

* uniquely identifiable (content-addressed for deployed contracts)
* schedulable
* interruptible (timer-tick preemption)
* message-addressable (via mailbox)
* capability-scoped
* budget-limited
* deterministic (WASM — proof-grade) or scheduling-deterministic (native, Linux-compat — replay-grade)

### 5.2 Mailbox

A **mailbox** is the primary IPC primitive and the mechanism for inter-contract calls.

```text
Mailbox {
    id,
    owner_contract,
    queue,             // ring buffer
    message_count,
    capacity,          // 16 in Stage-1
}
```

Inter-contract calls are modeled as mailbox message exchanges:
- caller sends request to callee's mailbox
- callee processes request
- callee sends response to caller's mailbox
- caller receives response

This is analogous to EVM's CALL opcode but uses message passing instead of synchronous function calls.

### 5.3 Capability

A **capability** is an explicit token of authority. There is no ambient authority.

```text
Capability {
    type,              // SEND_MAILBOX, RECV_MAILBOX, STATE_READ, STATE_WRITE, AGENT_SPAWN, EVENT_EMIT
    target,
    flags,
    use_limit,
    expiry,
}
```

### 5.4 Keyspace (Contract Storage)

A **keyspace** replaces file semantics. Each contract has a private keyspace (key-value store) analogous to EVM's contract storage.

* Keys are `u64` (Stage-1); extendable to arbitrary-length keys later
* Values are up to 256 bytes (Stage-1)
* Every write advances the keyspace version and updates the Merkle root
* Cross-contract state access requires explicit CAP_STATE_READ/WRITE capabilities

### 5.5 Energy Budget

Every contract runs under an execution budget. This is the TOS equivalent of gas:

* timer ticks decrement energy for running contracts
* syscalls have fixed energy costs
* storage operations have higher energy costs
* network operations have the highest energy costs
* budget exhaustion suspends or kills the contract
* caller pays for callee execution (like EVM)

### 5.6 Execution Receipt

Every meaningful execution produces an ExecutionReceipt containing:

* contract identity and code hash
* input/output commitments
* initial and final state roots
* energy consumed
* Ed25519 signature

### 5.7 Audit Trail

TOS emits structured events for every significant action:

* contract creation/termination
* mailbox send/receive
* capability grant/denial
* budget exhaustion
* state mutations
* inter-contract calls

---

## 6. Why TOS Must Be Written from Scratch

### 6.1 Why not use a host OS

If TOS runs inside Linux, verification depends on trusting Linux — a 30M+ line codebase. TOS eliminates this dependency by being the only software between the hardware and the contracts.

### 6.2 Why not modify an existing VM

EVM is limited to one instruction set. WASM runtimes running inside a host OS lack hardware-level isolation. TOS combines WASM execution with hardware-level isolation, built-in metering, state proofs, and deterministic execution under one unified kernel.

### 6.3 Why first run in a virtual machine

Writing from zero on real hardware would introduce major complexity too early:

* device enumeration
* storage controller differences
* interrupt controller variations
* boot firmware diversity

QEMU provides a stable, debuggable platform. Real hardware support follows in Stage-4.

---

## 7. Core System Concepts — Extended

(Reserved for detailed specifications from Part II: §9–§23. These sections carry over from v1 with terminology updated from "agent" to "contract" where appropriate.)

The following specifications from the original yellow paper remain in force:

* **§9 Programming Language Strategy** — Assembly for architecture, Rust for kernel
* **§10 Agent Model** — agent states, lifecycle, execution context (terminology: agent = contract)
* **§11 Mailbox IPC Model** — ring buffer, message structure, backpressure
* **§12 Capability Model** — types, delegation, revocation, audit
* **§13 Energy and Execution Budgeting** — provenance rules, tick-based metering, exhaustion policy
* **§14 System Call ABI** — register convention, Stage-1/2/3 syscall tables
* **§15 Scheduler Model** — round-robin, priority levels, deterministic scheduling
* **§16 Memory Model** — page tables, stack safety, guard canaries, heap allocation
* **§17 State Model** — keyspaces, capabilities, Merkle direction
* **§18 Logging and Audit** — event structure, ring buffer, serial output
* **§19 Checkpoint and Replay** — checkpoint contents, replay protocol
* **§20 Demo-Driven Validation** — message exchange, capability denial, budget exhaustion demos

---

## 8. What Was Removed from v1

The following components from yellowpaper v1 are **out of scope** for the TOS VM:

| Removed | Reason |
|---------|--------|
| **Principal model / delegation chains** (v1 Stage-5) | VM contracts don't need long-term identity hierarchies. Authority is per-call via capabilities. |
| **authd revocation service** (v1 Stage-5) | No long-lived delegation chains to revoke. |
| **Signed capability leases** (v1 Stage-5) | Capabilities are granted per-deployment, not leased with expiry. |
| **Encrypted keyspaces** (v1 Stage-6) | Contract storage is capability-gated, not encrypted. If needed, contracts encrypt their own data. |
| **Cross-node state replication** (v1 Stage-6) | TOS is a single-instance VM, not a distributed system. |
| **Distributed execution fabric** (v1 Stage-8) | routerd, membership_d, placement_d, failover_d — all removed. Single instance. |
| **billingd / quotad** (v1 Stage-9) | Billing is an external concern. TOS reports energy usage in receipts; external systems handle billing. |
| **Appliance-grade operations** (v1 Stage-10) | admind, upgraded, observabilityd, fleet management, multi-tenant, OTA — not needed for a VM. |
| **RustPython** (v1 Stage-11) | RustPython is not mature enough. Python compiles to WASM or runs via Linux compat layer. |
| **Ristretto JVM** (v1 Stage-11) | Replaced by Linux compat layer — unmodified OpenJDK runs deterministically via syscall translation. |
| **revm / EVM** (v1 Stage-11) | Removed from scope. |
| **SP1 zkVM** (v1 Stage-11) | Removed from v2 scope. Planned as a future extension: wrap wasbi WASM interpreter as SP1 guest program to produce ZK proofs alongside ExecutionReceipts. See `docs/plans/TODO-proof-contract-platform.md` Phase 4 for format compatibility notes. |

**What is kept from v1 but simplified:**

| Component | v1 Role | v2 Role |
|-----------|---------|---------|
| Capability model | Full authority plane with leases | Simple grant/revoke per deployment |
| State persistence | Durable state plane with replication | Contract storage with Merkle proofs, no replication |
| TPM / attestation | Appliance boot chain | VM integrity proof (simpler scope) |

---

## Part II — Core Execution Specification

(§9 through §23 carry over from yellowpaper v1 with the following changes:

1. "Agent" and "contract" are used interchangeably; "contract" is preferred in external-facing contexts.
2. The TCP external interface protocol (§4 Stage-4) is new.
3. Inter-contract call semantics via mailbox (§6 Stage-6) are new.
4. The ExecutionReceipt specification (§7 Stage-7) replaces the v1 Stage-9 receipt with a simplified version.
5. Removed components listed in §8 are excluded from all specifications.)

---

## Part III — Stage Roadmaps

### §24 Stage-2 Roadmap

(Carries over from v1 §24. Key additions: WASM runtime, eBPF-lite, persistent state store, system agents.)

### §25 Stage-3 Roadmap

(Carries over from v1 §25. Key additions: deterministic scheduler, Merkle state, replay, energy cost model, multi-mailbox.)

### §26 Stage-4 Roadmap

(Carries over from v1 §26 with modifications:
- Hardware support: UEFI, PCI, NVMe, e1000
- **New**: TCP external interface via netd
- **New**: Transaction submission protocol
- SDKs and CLI tools
- Removed: distributed execution, remote mailbox routing)

### §27 Stage-5 through Stage-8

(New content as specified in the Executive Roadmap above. Replaces v1 §27 entirely.)

---

## Part IV — Closing Material

## 28. Long-Term Vision

TOS evolves from a minimal kernel into a hardware-level execution VM that external systems can trust.

```text
+---------------------------------------------------+
|       External Systems (via TCP)                  |
+---------------------------------------------------+
|    Contracts (WASM / Native / Linux-compat)        |
+---------------------------------------------------+
|    TOS Runtime (scheduler, IPC, caps, metering)  |
+---------------------------------------------------+
|    TOS Kernel (mm, trap, syscall, Merkle, audit) |
+---------------------------------------------------+
|    Hardware / QEMU                                |
+---------------------------------------------------+
```

### 28.1 What TOS Is

* A hardware-level deterministic execution VM
* A bare-metal substrate for smart contracts and verifiable computation
* A multi-runtime platform (WASM, native, Linux-compat) with unified metering
* A system where every execution is isolated, metered, and produces a verifiable receipt

### 28.2 What TOS Is Not

* A desktop operating system
* A Linux replacement
* A general-purpose computing platform
* A distributed consensus system (TOS is the execution layer; consensus is external)
* A blockchain (TOS can be used by blockchains as an execution engine)

### 28.3 Relationship to Blockchain

TOS is not a blockchain. It is the **execution layer** that a blockchain (or any external system) can use:

```text
Blockchain / Coordinator
    │
    │ "Execute this contract with this input"
    ▼
TOS VM (bare metal)
    │
    │ "Here is the output, state root, energy used, and proof"
    ▼
Blockchain / Coordinator
    │
    │ Verify receipt, update consensus state
    ▼
```

TOS handles execution. The blockchain handles consensus, ordering, and finality. This separation allows TOS to be used by any consensus mechanism — not just one blockchain.

### 28.4 Integration Reference: Execute-then-Verify Model

TOS is designed to be embedded as the execution engine of a larger coordination system (e.g., a blockchain L1, an L2 rollup, or an AI-agent orchestrator). This section describes the canonical integration pattern.

#### 28.4.1 Architecture: Execute-then-Verify

```text
                   Coordinator Node A (Executor)
                           │
                           │ 1. Submit: code + input + energy_budget
                           ▼
                   ┌───────────────┐
                   │   TOS VM     │
                   │  runs program │
                   │  actual: 50K  │
                   └───────┬───────┘
                           │ 2. Returns:
                           │   output, state_root, ExecutionReceipt
                           ▼
               Coordinator settles on-chain:
                 deduct energy_budget (100K)
                 record state_root
                 publish receipt_hash
                           │
           ┌───────────────┼───────────────┐
           ▼               ▼               ▼
       Node B          Node C          Node D
     (Verifier)      (Verifier)      (Verifier)
    Does NOT re-run  Does NOT re-run  Does NOT re-run
    Verifies:        Verifies:        Verifies:
     - Ed25519 sig    - Ed25519 sig    - Ed25519 sig
     - state_root     - state_root     - state_root
     - receipt_hash   - receipt_hash   - receipt_hash
```

Only the **executor** runs an TOS VM instance. All other nodes verify the `ExecutionReceipt` cryptographically — no re-execution required.

#### 28.4.2 Energy Billing Model

The coordinator charges the caller `energy_budget` (the pre-declared maximum), not `energy_used` (the actual consumption).

```text
Caller declares:   energy_budget = 100,000
TOS executes:     energy_used   =  50,000
Coordinator deducts:               100,000  (the budget, not the actual)
```

**Rationale:**

- **Simplicity**: no dispute over actual consumption; the caller pre-commits to a ceiling.
- **No re-execution needed**: verifiers do not need to re-run the program to confirm `energy_used`; they only verify the receipt signature and state root.
- **Analogous to Ethereum gasLimit**: the caller sets a maximum; unused gas is conceptually "burned" (or in some designs, refunded — that is a coordinator policy, not an TOS concern).

The `ExecutionReceipt` records both values:

```text
ExecutionReceipt {
    ...
    energy_used:   50000,    // actual consumption (informational)
    energy_budget: 100000,   // pre-declared ceiling (billed)
    ...
}
```

The coordinator may choose to refund `energy_budget - energy_used` to the caller as a policy decision. TOS itself is agnostic — it reports both values and the coordinator decides the billing rule.

#### 28.4.3 Verification Without Re-Execution

Verifier nodes validate an execution result using only the `ExecutionReceipt`:

1. **Signature check**: verify Ed25519 signature over the receipt hash using the executor node's public key.
2. **State root check**: confirm the `final_state_root` is a valid SHA-256 Merkle root (optionally verify inclusion proofs for specific keys via the `ProofBundle`).
3. **Receipt hash check**: recompute `SHA-256(receipt fields)` and compare with `receipt_id`.

All three checks are **O(1)** — no TOS VM instance is needed on verifier nodes.

#### 28.4.4 Non-Deterministic Runtimes (JVM, CPython)

Programs running under the Linux compatibility layer (e.g., OpenJDK, Node.js, CPython) may exhibit internal non-determinism from:

- **Garbage collection timing**: GC trigger points depend on heap allocation patterns.
- **JIT compilation thresholds**: the number of interpreted invocations before JIT fires varies with thread interleaving.

TOS mitigates these at the syscall boundary (deterministic scheduling, deterministic PRNG, logical clock), but cannot eliminate non-determinism that originates entirely within the guest program's internal state machine.

**Consequence**: two runs of the same Java program with the same input may consume different `energy_used` values due to GC/JIT variance, even though both produce the **same output and same final state**.

**This is acceptable** under the execute-then-verify model because:

- The coordinator charges `energy_budget` (fixed), not `energy_used` (variable).
- Verifiers check the output and state root, not the energy consumption.
- The `runtime_class` field in the receipt is set to `ReplayGradeNative`, signaling that bit-identical replay is not guaranteed.

For programs that require **exact energy determinism**, use the WASM runtime (`ProofGradeWasm`), which provides instruction-level fuel metering with zero variance.

| Runtime | Determinism Level | Energy Variance | Receipt `runtime_class` |
|---------|------------------|-----------------|------------------------|
| WASM | Proof-grade (bit-identical) | Zero | `ProofGradeWasm` |
| Static Linux ELF | Replay-grade (scheduling-deterministic) | Near-zero | `ReplayGradeNative` |
| JVM (`-Xint -XX:+UseSerialGC`) | Replay-grade | Low (~1-5%) | `ReplayGradeNative` |
| JVM (default JIT + G1GC) | Best-effort | Variable (~5-20%) | `ReplayGradeNative` |
| Node.js / CPython | Best-effort | Variable | `ReplayGradeNative` |

#### 28.4.5 Coordinator Integration API

The coordinator communicates with TOS via the TCP external interface (Stage-4):

**Submit execution:**
```text
Request {
    request_type: Call (2),
    contract_id: SHA-256 hash of deployed contract,
    entry_point: function name or selector,
    input: calldata (up to 4096 bytes),
    energy_limit: energy_budget,
    signature: Ed25519 over request,
}
```

**Receive result:**
```text
Response {
    status: Success (0) | Revert (1) | OutOfEnergy (2) | Error (3),
    output: returndata (up to 4096 bytes),
    energy_used: actual consumption,
    state_root: post-execution SHA-256 Merkle root,
    receipt_hash: SHA-256 of full ExecutionReceipt,
}
```

**Retrieve receipt for verification:**
```text
Request { request_type: GetReceipt (5), ... }
→ Full ExecutionReceipt (360 bytes) with Ed25519 signature
```

**Retrieve proof for state verification:**
```text
Request { request_type: GetProof (6), ... }
→ ProofBundle with Merkle sibling hashes for root recomputation
```

### 28.5 Package Distribution Model

TOS is a sealed execution environment. It does **not** compile code, host registries, or download packages. All compilation and packaging happens on the developer's own machine. TOS only receives pre-built binaries, executes them, and produces receipts.

#### 28.5.1 Two Package Categories

TOS distinguishes two categories of packages with separate namespaces, distribution paths, and lifecycle rules.

**Runtime Packages** (e.g., OpenJDK, CPython, Node.js, libc):

| Aspect | Description |
|--------|-------------|
| Examples | `openjdk-21`, `python-3.12`, `node-22`, `musl-libc` |
| Built by | Runtime vendor or TOS team |
| Built where | Developer/CI machine (never inside TOS VM) |
| Size | Tens of MB to hundreds of MB |
| Installed to | Base image keyspace (shared, available to all contracts) |
| Update frequency | Low (follows upstream release cadence) |
| Registry path | `tos.im/runtimes/` |
| Review | Signed by TOS team; users verify before installing |

**Contract Packages** (e.g., token.tos, dex.tos):

| Aspect | Description |
|--------|-------------|
| Examples | `token-1.0.0.tos`, `dex-2.1.0.tos` |
| Built by | Contract developer |
| Built where | Developer's own machine (never inside TOS VM) |
| Size | Kilobytes to a few MB |
| Installed to | Contract keyspace (per-contract, isolated) |
| Update frequency | High (business iteration) |
| Registry path | `tos.im/contracts/` |
| Review | Community-published; consumers verify signature before installing |

#### 28.5.2 Distribution Architecture

```text
┌──────────────────────────────────────────────────────┐
│  tos.im Registry (external web service)             │
│                                                      │
│  /runtimes/openjdk-21.tar.gz                         │
│  /runtimes/python-3.12.tar.gz                        │
│  /runtimes/node-22.tar.gz                            │
│                                                      │
│  /contracts/token-1.0.0.tos                          │
│  /contracts/dex-2.1.0.tos                            │
├──────────────────────────────────────────────────────┤
│  Separate namespaces, separate review processes      │
└───────────┬─────────────────────────────┬────────────┘
            │                             │
     Operator downloads             Developer uploads
            │                             │
            ▼                             │
┌───────────────────────┐                 │
│  Operator's machine   │                 │
│                       │                 │
│  atp install openjdk  │←── download     │
│  atp install token    │←── download     │
│                       │                 │
│  Developer's machine  │                 │
│  1. Write contract    │                 │
│  2. Compile locally   │                 │
│  3. atp build/sign    │                 │
│  4. atp publish ──────│─────────────────→ upload
└───────────┬───────────┘
            │ TCP: Deploy / Call
            ▼
┌───────────────────────┐
│  TOS VM              │
│  (bare metal / QEMU)  │
│                       │
│  Receives binaries    │
│  Executes             │
│  Returns receipts     │
│                       │
│  Does NOT:            │
│   - compile code      │
│   - host registries   │
│   - download packages │
│   - access internet   │
└───────────────────────┘
```

#### 28.5.3 Package Lifecycle

**Runtime installation (operator-side):**

```text
1. Operator downloads runtime from tos.im (or builds from source)
2. Operator verifies signature: atp verify openjdk-21.tar.gz
3. Operator installs to TOS base image:
   → TCP Deploy with runtime files
   → TOS stores in BASE_IMAGE_KEYSPACE
   → Available to all contracts on this TOS instance
4. Upgrade: same flow, new version replaces old
```

**Contract deployment (developer-side):**

```text
1. Developer writes contract code on their own machine
2. Developer compiles: cargo build --target wasm32 (or gcc, javac, etc.)
3. Developer packages: atp build --input contract.wasm
4. Developer signs: atp sign contract.tos --key developer.key
5. Developer publishes: atp publish contract.tos --registry tos.im
6. Consumer downloads: atp install contract --from tos.im
7. Consumer verifies: atp verify contract.tos --pubkey developer.pub
8. Consumer deploys to TOS: TCP Deploy → contract registered
9. Anyone calls: TCP Call → execute → receipt
```

#### 28.5.4 What TOS Does Not Do

- TOS does **not** compile source code inside the VM
- TOS does **not** run a package registry service
- TOS does **not** download packages from the internet
- TOS does **not** mix runtime packages with contract packages
- Runtime packages and contract packages live in separate keyspaces and have separate trust models

TOS is a **sealed execution environment**: pre-built binaries go in, deterministic results and cryptographic receipts come out.

#### 28.5.5 Registry API (tos.im — External Service)

The registry at `tos.im` is an ordinary HTTP service, **not** part of the TOS kernel:

```text
GET  /api/v1/runtimes                          List available runtimes
GET  /api/v1/runtimes/{name}/{version}         Download runtime archive
PUT  /api/v1/runtimes/{name}/{version}         Upload runtime (TOS team only)

GET  /api/v1/contracts                         List published contracts
GET  /api/v1/contracts?q={query}               Search contracts
GET  /api/v1/contracts/{name}/{version}        Download .tos package
PUT  /api/v1/contracts/{name}/{version}        Publish .tos package (any developer)

GET  /api/v1/contracts/{name}/{version}/sig    Download Ed25519 signature
```

Each `.tos` package contains:
- Ed25519 signature (publisher identity)
- Code hash (SHA-256, content-addressed)
- Manifest (name, version, runtime type, energy estimate)

#### 28.5.6 Licensing

Runtime packages bundled by the TOS project or distributed via `tos.im` must comply with their upstream licenses:

| Runtime | License | Bundling Obligation |
|---------|---------|---------------------|
| OpenJDK | GPLv2 + Classpath Exception | Include license file; Classpath Exception allows proprietary applications |
| CPython | PSF License (BSD-style) | Include license file + copyright notice |
| Node.js | MIT | Include copyright notice |
| musl libc | MIT | Include copyright notice |
| glibc | LGPL | Dynamic linking (default); include library source if distributing glibc |

A `LICENSES/` directory ships with each runtime package containing the applicable license texts.

### 28.6 Closing Statement

> TOS is a bare-metal execution VM. Contracts are deployed, isolated, metered, and composable. Every execution produces a verifiable receipt. The VM runs directly on hardware — no host OS, no ambient authority. External systems submit transactions via TCP and receive cryptographic proof of what happened. Coordinator nodes execute once; all other nodes verify in O(1) without re-execution.

---

## 29. Roadmap Summary

| Stage | Title | Core Deliverable | Status |
|---|---|---|---|
| 1 | Minimal Kernel | Boot, agents, mailbox, capabilities, energy, audit | ✅ Complete |
| 2 | Isolation + Runtime | Ring-3, WASM, eBPF-lite, persistent state | ✅ Complete |
| 3 | Deterministic Execution | Deterministic scheduler, Merkle state, replay | ✅ Complete |
| 4 | Hardware + TCP Interface | Real hardware, TCP external interface, SDKs | ✅ Complete |
| 5 | Contract Storage | Versioned keyspaces, transactions, Merkle proofs, crash recovery | ⚠️ 90% — atomic multi-key StateTransaction missing |
| 6 | Package Management | Deploy, address, inter-contract calls, upgrade/rollback | ⚠️ 85% — package signing uses FNV-1a, not Ed25519 |
| 7 | Verifiable Execution | ExecutionReceipt, Replay/Proof Bundles, TPM | ✅ 95% Complete (TPM untested on real hardware) |
| 8 | WASM Runtime | Production WASM engine with fuel metering | ⚠️ 80% — WASM host bindings incomplete (no state/contract access) |
| 9 | Deterministic Linux Compat | 104 syscalls, 67/67 tests pass | ✅ Complete |
| 10 | Production Runtime Depth | Dynamic linking, threads, signals, file mmap | ✅ Complete |

**Next milestone:** Close the three critical gaps in Stages 5, 6, and 8 so that WASM contracts can access persistent state, call other contracts, and deploy with cryptographic trust. See `docs/plans/TODO-proof-contract-platform.md` for the implementation plan.

**TOS is complete when any program — whether WASM, native, or Linux-compatible — runs deterministically on bare metal, every execution produces a cryptographically verifiable receipt, and two runs with the same input produce bit-identical results.**
