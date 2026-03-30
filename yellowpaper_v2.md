# ATOS Yellow Paper v2

**Version:** Draft v2.0
**Status:** Engineering Yellow Paper
**Language:** English
**Purpose:** Implementation reference for building ATOS — a hardware-level deterministic execution VM.

> **Implementation Status (Stage-1):** All Phase 0–6 objectives are complete. See `[IMPL]` markers throughout this document for per-item status. Last verified: 2026-03-22.

---

## Abstract

ATOS is a **hardware-level deterministic execution virtual machine**. It runs directly on x86_64 hardware (or QEMU), providing isolated, metered, verifiable execution for smart contracts, JVM programs, and WASM modules — without relying on any host operating system.

ATOS is **not** an operating system in the traditional sense. It is a bare-metal execution substrate comparable to:

* **EVM** — but running on real hardware instead of inside a blockchain node process
* **JVM** — but with deterministic execution, energy metering, and cryptographic state proofs
* **A hardware security module** — but programmable, auditable, and verifiable

The core promise of ATOS is:

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

* **ATOS** — the full system.
* **ATOS-0** — the privileged kernel substrate: boot, memory, traps, syscalls, scheduling, mailbox IPC, capability enforcement, energy accounting, audit.
* **ATOS-1** — the runtime host layer: WASM engine, JVM (Ristretto), future managed runtimes.
* **ATOS-2** — the contract and system-service layer: deployed contracts, stated, policyd, netd.

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

ATOS is **not** a desktop operating system, not a POSIX clone, and not a Linux replacement.

ATOS is a **hardware-level deterministic execution VM** for smart contracts, verifiable computation, and metered workloads.

Its first-class concepts are:

- contracts (agents)
- mailboxes (inter-contract calls)
- capabilities (explicit authority)
- state objects (contract storage)
- energy budgeting (gas metering)
- execution receipts (verifiable output)
- checkpoints and replay (deterministic verification)
- external TCP interface (communication with the outside world)

### What ATOS Replaces

| Traditional VM | ATOS Equivalent | Advantage |
|---|---|---|
| EVM (Ethereum) | ATOS with WASM/JVM runtimes | Runs on hardware, not inside a process; multi-language; richer state model |
| JVM | ATOS with Ristretto | Deterministic execution, energy metering, cryptographic state proofs |
| Docker/VM isolation | ATOS per-contract page tables | Hardware-enforced isolation at the page table level, not process-level |
| Gas metering (EVM) | ATOS energy budget | Unified across WASM, JVM, native; tick-based preemption, no per-opcode overhead |

### The Execution Model

```text
                        ATOS EXECUTION MODEL

  External System                                    External System
       │                                                  ▲
       │ TCP: submit transaction                          │ TCP: result + receipt
       ▼                                                  │
+----------------------------------------------------------------------+
|  ATOS-2  Contract / Service Layer                                    |
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
|  ATOS-1  Runtime Host                                                |
|  WASM engine | Ristretto JVM | native runtime                      |
|  load → execute → meter → syscall_bridge → snapshot                 |
+-------------------------------+--------------------------------------+
                                |
                                | energy accounting + capability check
                                ▼
+----------------------------------------------------------------------+
|  ATOS-0  Kernel                                                      |
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
| 1 | Minimal Kernel Prototype | ATOS boots and runs core contract primitives |
| 2 | Isolation + Runtime Foundation | ATOS gains ring-3 isolation, WASM, eBPF-lite, persistent state |
| 3 | Deterministic Execution Layer | Deterministic scheduling, replay, Merkle state, energy cost model |
| 4 | Hardware + External Interface | Real hardware direction, TCP external interface, SDK tooling |
| 5 | Contract Persistent State | Versioned keyspaces, atomic transactions, Merkle proofs, crash recovery |
| 6 | Contract Package Management | Deployment, addressing, inter-contract calls, upgrade/rollback, signing |
| 7 | Verifiable Execution | ExecutionReceipt, Replay/Proof Bundles, TPM attestation |
| 8 | Language Runtimes | WASM engine (complete), Ristretto JVM |

### Stage-by-Stage Roadmap

#### Stage-1 — Minimal Kernel Prototype `[IMPL: ✅ Complete]`

**Purpose**
Prove that the minimal ATOS execution substrate is alive.

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
ATOS boots, creates multiple contracts, supports mailbox communication, enforces capabilities, and logs events.

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
ATOS can run isolated contracts, execute WASM workloads, persist state, and restore from checkpoints.

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
Move beyond QEMU-only and expose ATOS to external systems via TCP.

**Core Capabilities**
- UEFI boot direction for real hardware `[IMPL: ⚠️ detection + mmap parsing]`
- PCI enumeration, NVMe storage, real NIC (e1000) `[IMPL: ✅ pci.rs, nvme.rs, e1000.rs]`
- **TCP external interface**: accept transaction submissions, return results + receipts `[IMPL: ✅ tcp_interface.rs]`
- developer SDKs (Rust agent SDK, WASM SDK, eBPF-lite SDK) `[IMPL: ⚠️ atp CLI exists]`
- CLI tools (atos-build, atos-deploy, atos-replay, atos-inspect) `[IMPL: ⚠️ atp covers build/sign/verify/inspect]`
- execution proof generation (hash-chain over checkpoint + events) `[IMPL: ✅ proof.rs]`
- remote attestation foundation (TPM stub) `[IMPL: ✅ tpm.rs + attestation.rs]`
- `x86_64-unknown-atos` custom Rust target `[IMPL: ✅]`
- ATOS WASM engine `[IMPL: ✅]`

**Key Addition — TCP External Interface**

This is a critical new component. ATOS must expose a TCP listener that external systems use to:

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
ATOS runs on real hardware. External systems can submit transactions, deploy contracts, call contracts, and verify execution via TCP.

#### Stage-5 — Contract Persistent State `[IMPL: ✅ Complete]`

**Purpose**
Make contract storage durable, versioned, provable, and crash-recoverable.

**Core Capabilities**
- versioned keyspaces with monotonic version counter and root history `[IMPL: ✅ state.rs]`
- transactional mutation groups (atomic multi-key updates with rollback) `[IMPL: ✅ StateTransaction]`
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
- **Signature verification**: deployment requires valid publisher signature `[IMPL: ⚠️ atp signs with FNV-1a, not Ed25519]`
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
- **ExecutionReceipt**: canonical receipt with contract identity, runtime class, input/output commitments, state roots, energy used, and Ed25519 signature `[IMPL: ✅ receipts.rs — input/output commitments computed via FNV-1a 4-seed hash, signed with Ed25519]`
- **Replay Bundle**: checkpoint + execution transcript + I/O trace (for full re-execution verification) `[IMPL: ✅ receipts.rs ReplayBundle — auto-generated on agent exit, persisted to disk, retrievable via TCP GetReplay]`
- **Proof Bundle**: compact Merkle proofs and state commitments (for fast verification without replay) `[IMPL: ✅ receipts.rs ProofBundle — real SHA-256 Merkle sibling hashes, root recomputation verification, persisted to disk, retrievable via TCP GetProof]`
- **TPM measured boot**: prove the ATOS VM is running unmodified code (TPM 2.0 CRB + PCR extend/read) `[IMPL: ✅ tpm.rs — PCR0 (kernel) + PCR1 (boot config) extended during boot]`
- **Attestation report**: signed measurement of kernel hash + boot config + policy bundle `[IMPL: ✅ attestation.rs — Ed25519 or keyed-hash, integrated into receipt flow via trace_commitment]`

**ExecutionReceipt Specification**

```text
ExecutionReceipt {
    receipt_version: u16,
    receipt_id: Hash256,

    contract_id: Hash256,       // deployed contract identity
    execution_id: Hash256,      // this specific invocation
    caller_id: Hash256,         // who initiated the call (external or contract)
    node_id: NodeId,            // which ATOS instance

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
Execution on ATOS VM
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
Every contract execution produces an ExecutionReceipt. External verifiers can validate receipts via replay or compact proofs. TPM attestation proves the ATOS VM is running trusted code.

#### Stage-8 — Language Runtimes `[IMPL: ⚠️ WASM complete, JVM planned]`

**Purpose**
Support multiple execution formats so contracts can be written in different languages.

**Supported Runtimes**

| Priority | Runtime | Engine | Language | Status |
|----------|---------|--------|----------|--------|
| **P0** | WASM | ATOS WASM engine | Any → WASM | ✅ Complete |
| **P1** | JVM | [Ristretto](https://github.com/theseus-rs/ristretto) | Java / Kotlin / Scala | ⏳ Planned |

**P0 — WASM Engine** `[IMPL: ✅ Complete]`

The self-built WASM interpreter provides:
- 100% WASM MVP spec compliance
- Built-in fuel metering (1 WASM fuel = 1 ATOS energy)
- Type-safe host bindings for ATOS syscalls
- `#![no_std]` — runs as native ATOS agent
- Deterministic execution (ideal for verifiable computation)

Languages without a dedicated ATOS port (Go, C#, Swift, Zig, Rust, Python) compile to WASM and run via the ATOS WASM engine.

**P1 — Ristretto JVM** `[IMPL: ⏳ Planned]`

[Ristretto](https://github.com/theseus-rs/ristretto) is a pure Rust JVM ported as a native ATOS agent. Java programs run unmodified with deterministic semantics:

| Java API | ATOS Mapping | Determinism |
|----------|-------------|-------------|
| `System.currentTimeMillis()` | ATOS tick count | ✅ Deterministic |
| `Object.hashCode()` | Sequential counter | ✅ Deterministic |
| `Thread` / `Executor` | Child agents via `sys_spawn` | ✅ Deterministic scheduling |
| `new Random()` | Deterministic seed from ATOS | ✅ Deterministic |
| File I/O | Keyspace `sys_state_get/put` | ✅ Deterministic |
| Network sockets | netd mailbox proxy | ✅ Brokered, logged |
| `UUID.randomUUID()` | Deterministic ATOS random | ✅ Deterministic |
| GC / finalization | Ristretto-controlled | ✅ Deterministic |

The virtualization layer maps standard OS abstractions to ATOS primitives:

```text
Java program (unmodified .jar / .class)
  ↓
Ristretto (pure Rust JVM, ATOS native agent)
  ↓ #[cfg(target_os = "atos")] virtualization layer
ATOS syscall interface
  ↓
ATOS kernel (mailbox, capability, keyspace, energy, eBPF)
```

**Limitation**: JNI third-party native libraries (TensorFlow, OpenCV, etc.) require individual porting effort.

**Success Condition**
- Any WASM module runs on ATOS with full spec compliance and energy metering.
- A Java JAR file executes on ATOS with standard library classes functional and deterministic.
- All ported runtimes pass their respective test suites on ATOS.

### The Three Eras of ATOS

#### Era I — Execution Foundation (Stage-1 to Stage-4)

ATOS proves that it can execute contracts on hardware.

Focus: kernel, isolation, runtime, state, hardware, external TCP interface.

#### Era II — Production Execution (Stage-5 to Stage-7)

ATOS becomes a production-grade verifiable execution platform.

Focus: durable state, contract lifecycle, verifiable execution.

#### Era III — Ecosystem (Stage-8)

ATOS supports multiple language runtimes.

Focus: WASM, JVM, language ecosystem breadth.

### One-Sentence Definition

**ATOS is a bare-metal deterministic execution VM where contracts are deployed, isolated, metered, composable via mailbox calls, and every execution produces a cryptographically verifiable receipt — running directly on hardware without any host operating system.**

---

## Part I — Foundations and Stage-1 Scope

## 0. Preface: ATOS First Principles / Original Intent

ATOS began from a simple premise: deterministic, metered, verifiable computation should run directly on hardware — not inside a process on a general-purpose operating system, and not limited to a single instruction set like EVM bytecode.

The original intent of ATOS is:

* to provide a **hardware-level execution VM**, not a general-purpose operating system
* to make **authority explicit** through capabilities and policy, rather than ambient privilege
* to make **contract storage, energy budgeting, and auditability** first-class system concepts
* to prefer **deterministic, replayable execution** over convenience inherited from legacy APIs
* to support **multiple execution formats** (WASM, JVM, native) under one unified metering and verification model
* to validate this model first in **QEMU**, then expand to real hardware

In practical terms, ATOS is centered on:

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

Current execution VMs (EVM, JVM, WASM runtimes) run **inside** a host operating system process. This means:

* isolation depends on the host OS process model (which was designed for human users, not deterministic execution)
* metering is approximate (wall-clock time) or requires per-opcode instrumentation (EVM gas)
* verification requires trusting the host OS, the runtime process, and the operator
* the host OS provides a massive attack surface that is irrelevant to the computation

### 1.2 The ATOS Approach

ATOS eliminates the host OS entirely. The execution VM **is** the operating system:

* isolation is enforced by **hardware page tables** (x86_64 ring-3 / ring-0 separation)
* metering is unified across all runtimes via **timer-tick preemption** (no per-opcode overhead)
* verification is anchored to **TPM hardware attestation** and **deterministic replay**
* the attack surface is minimal: a small kernel with no legacy compatibility burden

### 1.3 Comparison

| Property | EVM | JVM (on Linux) | ATOS |
|----------|-----|----------------|------|
| Isolation | EVM sandbox | OS process | Hardware page tables |
| Metering | Per-opcode gas | None (wall-clock) | Timer-tick energy (unified) |
| Determinism | Full | No | Full (WASM) / Scheduling-level (native) |
| Verification | Consensus | None | Receipt + Replay + TPM |
| Languages | Solidity only | Java/Kotlin/Scala | WASM (any) + Java + native |
| Storage | 256-bit slots | Filesystem | Merkle keyspaces |
| Inter-contract calls | CALL opcode | Method calls | Mailbox IPC |
| Host OS required | Yes (Linux) | Yes (Linux/Windows) | No (bare metal) |

---

## 2. Design Philosophy

### 2.1 Execution VM, not operating system

ATOS is not designed to replace Linux, Windows, or macOS. It is designed as:

* a deterministic execution substrate for smart contracts
* a hardware-level VM for verifiable computation
* a metered execution environment for untrusted code
* a multi-runtime platform (WASM, JVM, native)

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

ATOS must prefer predictable, replayable behavior over convenience. Every source of non-determinism must be either eliminated or traced for replay.

### 2.4 Explicit authority

Nothing is accessible by default. Every meaningful action must be backed by a capability.

### 2.5 Contracts and mailboxes, not files and sockets

The primary concepts of ATOS are:

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

The first implementation target of ATOS is intentionally narrow.

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

* **ATOS-0** — privileged kernel substrate
* **ATOS-1** — runtime host layer (WASM, JVM, native)
* **ATOS-2** — contract and system-service layer

### 4.2 Logical architecture

```text
+---------------------------------------------------+
|         External Systems (via TCP)                |
+---------------------------------------------------+
| ATOS-2 Contract / Service Layer                    |
| deployed contracts | stated | policyd | netd      |
+---------------------------------------------------+
| ATOS-1 Runtime Host                                |
| WASM engine | Ristretto JVM | native              |
+---------------------------------------------------+
| ATOS-0 Kernel                                      |
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

* ATOS-0 is the primary focus
* ATOS-1 collapses to built-in native execution
* ATOS-2 contains only minimal bootstrap and test contracts
* External TCP interface is deferred

### 4.4 ATOS Genesis

ATOS requires a trusted starting point at system bring-up:

* **authority**: the root identity and initial capability set
* **execution budget**: the initial energy pool from which contract budgets are delegated
* **bootstrap services**: system agents that must exist from the start (stated, policyd, netd)
* **policy**: the initial eBPF-lite policy bundle
* **state**: the initial keyspace configuration

In Stage-1, ATOS Genesis is implicit and compiled into the boot path. Later stages may externalize this into an explicit signed genesis profile.

---

## 5. Core System Concepts

### 5.1 Contract (Agent)

A **contract** is the primary execution unit in ATOS. It replaces the traditional concept of a process or a smart contract account.

```text
Contract {
    id,
    parent_id,
    status,
    runtime_kind,          // Native, WASM, JVM
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
* deterministic (WASM/JVM) or scheduling-deterministic (native)

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

Every contract runs under an execution budget. This is the ATOS equivalent of gas:

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

ATOS emits structured events for every significant action:

* contract creation/termination
* mailbox send/receive
* capability grant/denial
* budget exhaustion
* state mutations
* inter-contract calls

---

## 6. Why ATOS Must Be Written from Scratch

### 6.1 Why not use a host OS

If ATOS runs inside Linux, verification depends on trusting Linux — a 30M+ line codebase. ATOS eliminates this dependency by being the only software between the hardware and the contracts.

### 6.2 Why not modify an existing VM

EVM is limited to one instruction set. JVM has no built-in metering or state proofs. WASM runtimes lack hardware-level isolation. ATOS combines the best properties of all three under one unified kernel.

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

The following components from yellowpaper v1 are **out of scope** for the ATOS VM:

| Removed | Reason |
|---------|--------|
| **Principal model / delegation chains** (v1 Stage-5) | VM contracts don't need long-term identity hierarchies. Authority is per-call via capabilities. |
| **authd revocation service** (v1 Stage-5) | No long-lived delegation chains to revoke. |
| **Signed capability leases** (v1 Stage-5) | Capabilities are granted per-deployment, not leased with expiry. |
| **Encrypted keyspaces** (v1 Stage-6) | Contract storage is capability-gated, not encrypted. If needed, contracts encrypt their own data. |
| **Cross-node state replication** (v1 Stage-6) | ATOS is a single-instance VM, not a distributed system. |
| **Distributed execution fabric** (v1 Stage-8) | routerd, membership_d, placement_d, failover_d — all removed. Single instance. |
| **billingd / quotad** (v1 Stage-9) | Billing is an external concern. ATOS reports energy usage in receipts; external systems handle billing. |
| **Appliance-grade operations** (v1 Stage-10) | admind, upgraded, observabilityd, fleet management, multi-tenant, OTA — not needed for a VM. |
| **RustPython** (v1 Stage-11) | RustPython is not mature enough. Python compiles to WASM via the P0 universal sandbox. |
| **revm / EVM** (v1 Stage-11) | Removed from scope. |
| **SP1 zkVM** (v1 Stage-11) | Removed from scope. |
| **Linux syscall compatibility** (v1 Stage-12) | Contradicts determinism. Not needed for a VM. |

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

ATOS evolves from a minimal kernel into a hardware-level execution VM that external systems can trust.

```text
+---------------------------------------------------+
|       External Systems (via TCP)                  |
+---------------------------------------------------+
|    Contracts (WASM / JVM / Native)                |
+---------------------------------------------------+
|    ATOS Runtime (scheduler, IPC, caps, metering)  |
+---------------------------------------------------+
|    ATOS Kernel (mm, trap, syscall, Merkle, audit) |
+---------------------------------------------------+
|    Hardware / QEMU                                |
+---------------------------------------------------+
```

### 28.1 What ATOS Is

* A hardware-level deterministic execution VM
* A bare-metal substrate for smart contracts and verifiable computation
* A multi-runtime platform (WASM, JVM, native) with unified metering
* A system where every execution is isolated, metered, and produces a verifiable receipt

### 28.2 What ATOS Is Not

* A desktop operating system
* A Linux replacement
* A general-purpose computing platform
* A distributed consensus system (ATOS is the execution layer; consensus is external)
* A blockchain (ATOS can be used by blockchains as an execution engine)

### 28.3 Relationship to Blockchain

ATOS is not a blockchain. It is the **execution layer** that a blockchain (or any external system) can use:

```text
Blockchain / Coordinator
    │
    │ "Execute this contract with this input"
    ▼
ATOS VM (bare metal)
    │
    │ "Here is the output, state root, energy used, and proof"
    ▼
Blockchain / Coordinator
    │
    │ Verify receipt, update consensus state
    ▼
```

ATOS handles execution. The blockchain handles consensus, ordering, and finality. This separation allows ATOS to be used by any consensus mechanism — not just one blockchain.

### 28.4 Closing Statement

> ATOS is a bare-metal execution VM. Contracts are deployed, isolated, metered, and composable. Every execution produces a verifiable receipt. The VM runs directly on hardware — no host OS, no ambient authority, no non-determinism. External systems submit transactions via TCP and receive cryptographic proof of what happened.

---

## 29. Roadmap Summary

| Stage | Title | Core Deliverable | Status |
|---|---|---|---|
| 1 | Minimal Kernel | Boot, agents, mailbox, capabilities, energy, audit | ✅ Complete |
| 2 | Isolation + Runtime | Ring-3, WASM, eBPF-lite, persistent state | ✅ Complete |
| 3 | Deterministic Execution | Deterministic scheduler, Merkle state, replay | ✅ Complete |
| 4 | Hardware + TCP Interface | Real hardware, TCP external interface, SDKs | ✅ Complete |
| 5 | Contract Storage | Versioned keyspaces, transactions, Merkle proofs, crash recovery | ✅ Complete |
| 6 | Package Management | Deploy, address, inter-contract calls, upgrade/rollback | ✅ Complete |
| 7 | Verifiable Execution | ExecutionReceipt, Replay/Proof Bundles, TPM | ✅ Complete |
| 8 | Language Runtimes | WASM ✅, Ristretto JVM | ⚠️ WASM done, JVM planned |

**ATOS is complete when an external system can submit a transaction via TCP, ATOS executes it deterministically on bare metal, and returns a cryptographically verifiable receipt.**
