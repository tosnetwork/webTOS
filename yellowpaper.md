# AOS Yellow Paper

**Version:** Draft v0.6
**Status:** Engineering Yellow Paper
**Language:** English
**Purpose:** Implementation reference for building AOS from scratch, initially targeting virtual machines and QEMU.

> **Implementation Status (Stage-1):** All Phase 0–6 objectives are complete. See `[IMPL]` markers throughout this document for per-item status. Last verified: 2026-03-22.

---

## Abstract

AOS is an AI-native minimal operating system designed from first principles for agent execution, deterministic task handling, capability-based isolation, audited state transitions, and capability-scoped resource access. It is **not** intended to be a desktop operating system or a general POSIX-compatible environment. Its primary role is to serve as a minimal execution substrate for AI agents, verifiable runtimes, blockchain-adjacent execution environments, and secure automated systems.

AOS is designed under two strict principles:

1. **The architecture must be designed from zero**, rather than inherited from legacy human-centric operating systems.
2. **The code must be written from zero**, rather than modifying Linux or embedding itself inside an existing kernel.

The first execution target is a **virtual machine environment**, especially **QEMU on x86_64**, so that architecture purity is preserved while hardware complexity is minimized.

---

## 1. Motivation

Modern operating systems were designed for human-operated computing environments. Their core abstractions center around:

* processes
* threads
* files
* sockets
* user IDs and group IDs
* shells and interactive sessions

These abstractions remain useful, but they are not ideal as the foundational model for the AI era.

AI-native systems need a different execution substrate. They require:

* deterministic or near-deterministic execution
* capability-scoped resource access
* explicit, auditable action controls
* mailbox-oriented message passing
* structured state rather than file-first semantics
* auditable execution events
* execution budgeting and energy accounting
* checkpointing and replay

AOS exists to provide these properties as primary system concepts instead of middleware layered on top of a legacy OS.

---

## 2. Design Philosophy

### 2.1 AI-native, not human-desktop-native

AOS is not designed to replace Linux, Windows, or macOS for general human use. It is designed as a substrate for:

* AI agents
* constrained runtimes
* blockchain-adjacent execution
* verifiable automation
* edge AI appliances

### 2.2 Minimal kernel, rich system model

The kernel should remain as small as possible. Only irreducible low-level functionality belongs in the kernel:

* memory protection
* trap handling
* system call entry
* scheduling primitives
* capability enforcement primitives
* mailbox IPC primitives
* timing/accounting primitives

Higher-level services should be built as structured kernel subsystems first, and later may migrate into system agents as the architecture matures.

### 2.3 Determinism over convenience

AOS must prefer predictable, replayable behavior over convenience APIs inherited from legacy systems.

### 2.4 Explicit authority

Nothing should be accessible by default. Every meaningful action must be backed by a capability or an explicit policy grant.

### 2.5 Message and state before file and socket

The primary concepts of AOS are:

* agent
* mailbox
* capability
* state object
* energy budget
* checkpoint
* event log

Not:

* file path
* fork/exec
* raw socket
* ambient authority

---

## 3. Scope of Stage-1

The first implementation target of AOS is intentionally narrow.

### 3.1 Target platform

* **Architecture:** x86_64
* **Execution environment:** QEMU first
* **Boot environment:** Multiboot (v1) header, loaded directly by QEMU's `-kernel` flag. This avoids the need for GRUB or ISO image creation in Stage-1. Multiboot2 or UEFI boot may be explored in later stages.
* **CPU mode:** 64-bit long mode
* **Core assumption:** single-core initially

### 3.2 What Stage-1 must do

1. Boot in a virtual machine. `[IMPL: ✅ QEMU via Multiboot v1, ELF64→ELF32 objcopy]`
2. Enter 64-bit mode. `[IMPL: ✅ boot.asm: 32-bit → PAE → long mode transition]`
3. Initialize basic memory management. `[IMPL: ✅ bitmap frame allocator, 126 MB / 32,256 frames]`
4. Install GDT and IDT. `[IMPL: ✅ gdt.rs (7-entry GDT + TSS), idt.rs (256-entry IDT + PIC remap)]`
5. Handle traps and exceptions. `[IMPL: ✅ trap_entry.asm stubs + trap.rs policy, vectors 0-19]`
6. Provide a minimal syscall path. `[IMPL: ✅ 11 syscalls (§14.2 + §14.3), direct call in Stage-1]`
7. Create and schedule minimal agent contexts. `[IMPL: ✅ 5 agents, round-robin + preemptive via PIT 100Hz]`
8. Provide mailbox-based IPC. `[IMPL: ✅ ring-buffer mailbox, 16 slots × 256B, ping/pong verified]`
9. Enforce a minimal capability model. `[IMPL: ✅ grant/deny/subset, CAP_DENIED audit event, bad agent demo]`
10. Provide execution budgeting / energy accounting. `[IMPL: ✅ tick + syscall decrement, BUDGET_EXHAUSTED + suspend]`
11. Emit serial logs and audit events. `[IMPL: ✅ structured [EVENT ...] format over COM1 serial]`

### 3.3 What Stage-1 deliberately does not do

* no graphical user interface
* no POSIX compatibility goal
* no full filesystem
* no USB stack
* no SMP in first iteration
* no GPU support in first iteration
* no raw network stack as a first milestone
* no ELF compatibility requirement for user programs

This is a deliberate engineering constraint. The goal is to validate the AI-native kernel model, not to rebuild a traditional operating system.

---

## 4. System Overview

The conceptual stack of AOS is as follows:

```text
+---------------------------------------------------+
|                Test Agents / Runtimes              |
|   ping agent | pong agent | idle agent             |
+---------------------------------------------------+
|              AI-native Syscall ABI                 |
| yield | spawn | exit | send | recv | cap | energy  |
+---------------------------------------------------+
|                 Kernel Core                        |
| sched | mm | trap | syscall | ipc | cap | audit    |
+---------------------------------------------------+
|                x86_64 Arch Layer                   |
| gdt | idt | paging | timer | irq | context         |
+---------------------------------------------------+
|               Boot / Loader Layer                  |
|                  (Multiboot v1)                    |
+---------------------------------------------------+
|                    QEMU VM                         |
+---------------------------------------------------+
```

AOS should be understood not as a file-centric Unix derivative, but as an **agent execution substrate**.

---

## 5. Core System Concepts

### 5.1 Agent

An **agent** is the primary execution unit in AOS. It replaces the traditional conceptual centrality of the process.

A minimal Stage-1 agent structure may be defined conceptually as:

```text
Agent {
    id,
    parent_id,
    status,
    execution_context,
    mailbox_id,
    capability_set,
    energy_budget,
    memory_quota,
}
```

* `parent_id` tracks which agent spawned this agent. This enables capability delegation chains, cascading termination, and supervisor patterns. The root system agent has `parent_id = NONE`.
* Stage-1 supports only one execution type: native x86_64 code compiled into the kernel image. A `runtime_kind` field (for WASM, custom VM, etc.) may be added in later stages when multiple runtime backends are supported.

#### Required properties

* uniquely identifiable
* schedulable
* interruptible
* message-addressable
* capability-scoped
* budget-limited

### 5.2 Mailbox

A **mailbox** is the primary IPC primitive. In Stage-1, each agent owns exactly one mailbox (1:1 binding). This is a deliberate simplification. Later stages may allow agents to own multiple mailboxes for separate control and data channels.

A mailbox is modeled as a bounded message queue, likely implemented as a ring buffer in Stage-1.

Conceptual structure:

```text
Mailbox {
    id,
    owner_agent,
    queue,
    message_count,
    capacity,
}
```

The recommended default capacity for Stage-1 is **16 messages** per mailbox. Combined with the 256-byte payload limit (§11.3), each mailbox occupies approximately 4–5 KB of kernel memory.

### 5.3 Capability

A **capability** is an explicit token of authority. There is no ambient root authority in the conceptual model.

Examples:

* permission to send to a mailbox
* permission to read or write a state object
* permission to emit events
* permission to spawn an agent

Conceptual structure:

```text
Capability {
    type,
    target,
    flags,
    use_limit,
    expiry,
}
```

`use_limit` bounds how many times this specific capability can be exercised (e.g., an agent may send at most N messages to a given mailbox). This is distinct from the agent's `energy_budget`, which bounds total execution cost. A capability with `use_limit = 0` means unlimited use (subject to energy budget). `expiry` may be tick-based or omitted in Stage-1.

### 5.4 State object

A **state object** replaces file-first semantics for internal structured execution state. State is organized into capability-scoped **keyspaces** (see §17 for details).

### 5.5 Energy budget

Every agent should run under an execution budget. This is critical for:

* safety
* fairness
* AI workload metering
* deterministic control
* future blockchain-aligned execution models

### 5.6 Event log

AOS must emit structured execution events from the beginning. Auditability is not an afterthought.

### 5.7 Checkpoint

Checkpointing may begin as a conceptual placeholder in Stage-1, but the system architecture must reserve space for it. Checkpoint and replay are core long-term features of the platform.

---

## 6. Why AOS Must Be Written from Scratch

AOS is intentionally not defined as a Linux modification project.

### 6.1 Why not modify Linux

Linux is powerful, but its core abstractions are deeply tied to historical computing assumptions:

* process hierarchy
* fork/exec model
* file descriptor unification
* raw sockets
* broad ambient authority patterns
* complex legacy compatibility layers

If AOS is implemented merely as a Linux adaptation, it risks becoming a middleware framework rather than a true operating system substrate.

### 6.2 Why first run in a virtual machine

Writing from zero on real hardware would introduce major complexity too early:

* device enumeration
* storage controller differences
* USB complexity
* graphics complexity
* multicore synchronization issues
* hardware-specific debugging pain

By targeting QEMU first, AOS gains:

* repeatable execution environment
* serial-based debugging
* better fault isolation
* easier boot and interrupt debugging
* architecture purity with lower operational complexity

Thus the chosen path is:

**architecture from zero, code from zero, first execution in a VM**.

---

## 7. Kernel Responsibilities

The kernel should remain small and focused.

### 7.1 Mandatory kernel responsibilities in Stage-1

#### 7.1.1 Boot transition and kernel entry

The system must establish a clean execution environment for the kernel. `[IMPL: ✅ boot.asm → kernel_main()]`

#### 7.1.2 Memory management primitives

The kernel must provide:

* physical memory initialization `[IMPL: ✅ paging.rs bitmap allocator]`
* page mapping primitives `[IMPL: ✅ identity-mapped 16 MB via 2 MB huge pages]`
* kernel virtual memory layout `[IMPL: ✅ linker.ld at 0x100000]`
* early heap or allocator support `[IMPL: ⚠️ frame allocator only, no heap allocator yet]`

#### 7.1.3 Trap and exception handling

The kernel must handle:

* faults `[IMPL: ✅ vectors 0-19, agent faulted + reschedule]`
* invalid instructions `[IMPL: ✅ vector 6]`
* protection violations `[IMPL: ✅ vectors 13, 14]`
* timer interrupts `[IMPL: ✅ PIT IRQ0 → vector 32, 100 Hz]`
* software interrupts or syscall entry `[IMPL: ✅ direct call in Stage-1, syscall_entry.asm ready for ring-3]`

#### 7.1.4 Scheduling

The kernel must provide a minimal scheduler capable of switching between execution contexts. `[IMPL: ✅ round-robin + preemptive, assembly context_switch (switch.asm)]`

#### 7.1.5 Mailbox IPC

The kernel must provide bounded message queues usable by agents. `[IMPL: ✅ mailbox.rs, 16-slot ring buffer, 256B max payload]`

#### 7.1.6 Capability checks

The kernel must gate syscalls through capability checks. `[IMPL: ✅ capability.rs, checked on sys_send/sys_recv/sys_spawn/sys_event_emit]`

#### 7.1.7 Energy accounting

The kernel must track execution usage per agent and enforce budget boundaries. `[IMPL: ✅ energy.rs, tick + syscall cost, suspend on exhaustion]`

#### 7.1.8 Logging and audit events

The kernel must provide serial output and structured event emission. `[IMPL: ✅ event.rs, 17 event types, serial_println! over COM1]`

### 7.2 What should not be in the Stage-1 kernel

* rich userspace loader compatibility layers
* POSIX file abstractions
* shell support as a design objective
* network stack completeness
* complex block cache logic
* high-level AI policy engines

---

## 8. Architecture Layers

### 8.1 Boot layer `[IMPL: ✅]`

Responsibilities:

* transition from firmware/bootloader into kernel entry `[IMPL: ✅ boot.asm + multiboot_header.asm]`
* establish initial page tables as needed `[IMPL: ✅ 8×2MB identity-mapped huge pages]`
* hand off memory information `[IMPL: ✅ multiboot magic + info passed to kernel_main]`
* establish clean control flow into Rust kernel logic `[IMPL: ✅ BSS zeroed, stack set, call kernel_main]`

### 8.2 x86_64 architecture layer `[IMPL: ✅]`

Responsibilities:

* GDT setup `[IMPL: ✅ gdt.rs — 7 entries + TSS with IST1]`
* IDT setup `[IMPL: ✅ idt.rs — 256 entries from trap_stub_table]`
* interrupt/trap stubs `[IMPL: ✅ trap_entry.asm — 34 stubs with uniform TrapFrame]`
* context switching (register save/restore, cr3 switch) `[IMPL: ✅ switch.asm — callee-saved + cr3]`
* timer setup (PIT or APIC timer) `[IMPL: ✅ timer.rs — PIT channel 0, 100 Hz]`
* MSR configuration (STAR, LSTAR, SFMASK for `syscall`/`sysret` support) `[IMPL: ⏳ syscall_entry.asm ready, MSR init deferred to ring-3 stage]`
* low-level register, port, and serial I/O handling `[IMPL: ✅ serial.rs — COM1 0x3F8, outb/inb helpers]`

### 8.3 Kernel core layer `[IMPL: ✅]`

Responsibilities:

* scheduler `[IMPL: ✅ sched.rs]`
* agent table `[IMPL: ✅ agent.rs]`
* mailbox subsystem `[IMPL: ✅ mailbox.rs]`
* capability subsystem `[IMPL: ✅ capability.rs]`
* event subsystem `[IMPL: ✅ event.rs]`
* energy accounting `[IMPL: ✅ energy.rs]`
* syscall dispatcher `[IMPL: ✅ syscall.rs]`

### 8.4 Test agent layer `[IMPL: ✅]`

Stage-1 should compile in a minimal set of test agents directly into the kernel image or a fixed internal image format. `[IMPL: ✅ 5 agents compiled in: idle, root, ping, pong, bad]`

This avoids early distraction from general executable loaders.

---

## 9. Programming Language Strategy

AOS should use a mixed-language implementation model.

### 9.1 Assembly responsibilities

Assembly is appropriate for:

* boot entry
* long mode transition
* GDT/IDT load sequences
* trap entry stubs
* syscall entry/exit stubs
* context switch assembly
* low-level I/O instructions

### 9.2 Rust responsibilities

Rust is recommended for the majority of kernel logic:

* memory manager
* scheduler
* mailbox implementation
* capability logic
* agent lifecycle management
* event logging structures
* syscall dispatch
* state object abstraction

### 9.3 Rationale

This combination preserves control at the architectural boundary while improving implementation safety for the bulk of the codebase.

---

## 10. Agent Model

AOS is agent-centric.

### 10.1 Agent states

A minimal set of states:

* **Created** — agent struct allocated, not yet schedulable
* **Ready** — in the run queue, waiting for CPU time
* **Running** — currently executing on the CPU
* **BlockedRecv** — waiting for a message to arrive in a mailbox
* **BlockedSend** — waiting for space in a full mailbox (reserved for future use; Stage-1 `sys_send` is non-blocking)
* **Suspended** — paused due to budget exhaustion (may be resumed if budget is replenished)
* **Exited** — terminated normally via `sys_exit`
* **Faulted** — terminated due to an unrecoverable fault (invalid instruction, protection violation, etc.)

State transitions:

```text
Created -> Ready           (kernel finishes initialization, places in run queue)
Ready -> Running           (scheduler selects this agent)
Running -> Ready           (yield, timer preemption)
Running -> BlockedRecv     (sys_recv on empty mailbox)
Running -> BlockedSend     (reserved for future blocking send; Stage-1 sys_send returns error instead)
Running -> Suspended       (energy budget exhausted)
Running -> Exited          (sys_exit called)
Running -> Faulted         (hardware fault or protection violation)
BlockedRecv -> Ready       (message arrives in target mailbox)
BlockedSend -> Ready       (space becomes available in target mailbox)
Suspended -> Ready         (budget replenished by parent or system)
```

`Exited` and `Faulted` are terminal states. The kernel reclaims all resources upon entering either.

### 10.2 Agent execution context

The execution context is the CPU state saved and restored on context switch. It contains only hardware register state:

* `rsp` — stack pointer
* `rip` — instruction pointer / entry point
* general-purpose registers (`rax`, `rbx`, `rcx`, `rdx`, `rsi`, `rdi`, `rbp`, `r8`–`r15`)
* `rflags`
* `cr3` — page table root (for memory isolation)

All other agent metadata (`energy_budget`, `mailbox_id`, `capability_set`, `memory_quota`) is stored in the Agent struct (§5.1), not in the execution context. The scheduler accesses agent metadata via the agent table, not via the saved context.

### 10.3 Root agent bootstrap

The very first agent (agent 0, the "root agent") is created by the kernel during boot, not via `sys_spawn`. The kernel grants the root agent **wildcard capabilities**: `CAP_SEND_MAILBOX:*`, `CAP_RECV_MAILBOX:*`, `CAP_AGENT_SPAWN`, `CAP_EVENT_EMIT`, `CAP_STATE_READ:*`, `CAP_STATE_WRITE:*`. Wildcard capabilities match any target id. When the root agent spawns a child and grants it `CAP_SEND_MAILBOX:3`, this is a narrowing of the root's wildcard — the child can only send to mailbox 3, not to all mailboxes.

All other agents are descendants of the root agent and can only hold capabilities that trace back to this initial grant (no-escalation principle, §12.3).

The root agent's initial energy budget and memory quota are set to the system's total available resources. As it spawns children, these resources are subdivided via the delegation rules in §12.2.

The root agent's entry point is a compiled-in initialization function that spawns the system's test agents in Stage-1.

### 10.4 Agent lifecycle

1. Parent agent calls `sys_spawn` with entry point, budget, and initial capability set.
2. Kernel creates agent, assigns unique id, records parent_id.
3. Kernel creates and binds mailbox.
4. Kernel grants initial capabilities (validated as subset of parent's capabilities).
5. Kernel assigns initial energy budget and memory quota.
6. Place in run queue.
7. Execute until yield, block, exit, budget exhaustion, or fault.
8. On budget exhaustion, the agent is suspended (see §13.3). It may be resumed if budget is replenished.
9. On termination (`sys_exit` or fault), the kernel reclaims all resources (mailbox, memory, capabilities) and moves the agent to a terminal state.
10. When a parent agent terminates, all its direct children are **cascading-terminated** (moved to `Faulted` with a "parent exited" reason). This cascades recursively to all descendants. Stage-1 implements immediate cascading termination; later stages may support reparenting to the root agent as an alternative policy.
11. Emit audit events throughout lifecycle.

---

## 11. Mailbox IPC Model

Mailbox IPC is one of the core defining traits of AOS.

### 11.1 Mailbox rules

* mailbox delivery should be explicit
* mailbox capacity should be bounded
* send failure modes must be explicit
* recv behavior should be deterministic in simple cases
* direct arbitrary shared memory should not be the default IPC model

### 11.2 Message structure

Each message in a mailbox must carry metadata for audit and replay:

```text
Message {
    sender_id,
    payload,
    len,
    tick,
}
```

`sender_id` and `tick` are set by the **kernel**, not by the caller. The `sys_send` syscall accepts only the raw payload from the caller; the kernel populates `sender_id` from the calling agent's id and `tick` from the current kernel tick counter. This prevents agents from spoofing their identity.

`sender_id` is required so the receiver can identify the origin of a message and so that audit logs can reconstruct full communication graphs. `tick` records the logical timestamp at send time for replay ordering.

### 11.3 Stage-1 implementation suggestion

Use a ring-buffer mailbox with fixed-size messages. The recommended maximum payload size for Stage-1 is **256 bytes**. This keeps the ring buffer implementation simple with fixed-slot allocation. Messages exceeding this limit must be rejected with an explicit error.

### 11.4 Future direction

In later stages, mailboxes may support:

* larger payload references
* shared immutable object references
* capability-carrying messages
* replay-friendly message logs

---

## 12. Capability Model

The capability system is central to AOS.

### 12.1 Principle

No meaningful action should succeed unless the caller holds an appropriate capability.

### 12.2 Example capability types

* `CAP_SEND_MAILBOX:<id>` — permission to send to a specific mailbox
* `CAP_RECV_MAILBOX:<id>` — permission to receive from a specific mailbox
* `CAP_EVENT_EMIT` — permission to emit audit events
* `CAP_AGENT_SPAWN` — permission to spawn child agents
* `CAP_STATE_READ:<keyspace>` — permission to read from a state keyspace
* `CAP_STATE_WRITE:<keyspace>` — permission to write to a state keyspace

Resource delegation rules for `sys_spawn`:

* **Energy**: the child's `energy_quota` is **deducted from the parent's remaining budget**. An agent cannot spawn a child with a larger energy budget than it currently holds. This prevents unbounded energy creation.
* **Memory**: the child's `mem_quota` is **deducted from the parent's remaining memory quota**. An agent cannot allocate more memory to children than its own quota allows.

Both deductions are automatic and enforced by the kernel. No separate capabilities are required for resource delegation — the spawn syscall handles it atomically.

### 12.3 Capability lifecycle

Capabilities must support:

* **Grant**: a parent agent may grant a subset of its own capabilities to a child at spawn time or via `sys_cap_grant`.
* **Revocation**: a parent agent may revoke capabilities it previously granted to a child. Revocation is immediate and does not require the child's cooperation.
* **No escalation**: an agent cannot grant capabilities it does not itself hold. This is enforced by the kernel at grant time.

Stage-1 may implement grant-at-spawn only, deferring dynamic grant and revocation to a later stage. But the data structures must anticipate the full lifecycle.

### 12.4 Implicit capabilities

To avoid circular dependencies during agent bootstrap, the following capabilities are implicitly granted by the kernel and do not need to be explicitly held:

* An agent always has `CAP_RECV_MAILBOX` for its own mailbox.
* An agent always has `CAP_STATE_READ` and `CAP_STATE_WRITE` for its own private keyspace.

These implicit capabilities cannot be revoked.

### 12.5 Enforcement

Syscalls must validate capability requirements before execution.

### 12.6 Denial behavior

On failure:

* return an explicit error
* emit an audit violation event
* do not silently degrade authority checks

---

## 13. Energy and Execution Budgeting

AI-oriented systems need execution accounting as a primary primitive.

### 13.1 Purpose

Energy budgeting exists to support:

* bounded execution
* abuse prevention
* fairness
* deterministic slicing
* future billing/meters
* future blockchain-style gas/energy semantics

### 13.2 Stage-1 strategy

Stage-1 should implement a simple per-agent decrementing budget based on:

* **timer ticks**: on each timer interrupt, the kernel decrements budget for the currently `Running` agent AND all agents in `BlockedRecv` state. Blocked agents must consume budget; otherwise an agent could block on an empty mailbox indefinitely at zero cost. In Stage-1 with a small number of agents (typically 3–5), iterating all agents per tick is trivially cheap. A blocked agent whose budget reaches zero is moved from `BlockedRecv` to `Suspended`, and `sys_recv` returns an error code when/if the agent is later resumed.
* **syscall cost**: decrement a fixed cost per syscall invocation, so that agents cannot avoid budget consumption by performing many cheap syscalls between timer ticks.

Note: precise per-instruction counting is not feasible on x86_64 without hardware performance counters and is inherently non-deterministic due to out-of-order execution. Tick-based accounting is the correct Stage-1 approach.

### 13.3 Exhaustion policy

When the budget reaches zero, the kernel must:

1. Emit a `BUDGET_EXHAUSTED` audit event.
2. Move the agent to `Suspended` state (default) or `Faulted` state (configurable at compile time).
3. Reschedule immediately.

The default policy is **suspend**, not kill. A suspended agent may be resumed if a parent agent or the system replenishes its budget. This allows for recharge patterns without losing agent state. The compile-time option to kill on exhaustion exists for environments that require hard termination (e.g., untrusted agent execution).

---

## 14. System Call ABI

The Stage-1 syscall surface should be intentionally small.

### 14.1 Register convention

On x86_64, AOS uses the `syscall` instruction with the following convention:

```text
rax = syscall number
rdi = arg0
rsi = arg1
rdx = arg2
r10 = arg3
r8  = arg4

Return:
rax = result or error code (0 = success, negative = error)
rdx = secondary return value (where applicable)

Clobbered by hardware:
rcx = destroyed (hardware saves rip here)
r11 = destroyed (hardware saves rflags here)
```

The `syscall` instruction unconditionally overwrites `rcx` and `r11`. Callers must not rely on these registers being preserved across a syscall. This convention is similar to the Linux x86_64 syscall ABI for familiarity, but the syscall numbers and semantics are entirely AOS-specific.

### 14.2 Initial syscall set `[IMPL: ✅ ALL IMPLEMENTED]`

| # | Name | Signature | Description | Status |
|---|------|-----------|-------------|--------|
| 0 | `sys_yield` | `() -> 0` | Yield execution voluntarily. The agent is moved to Ready and the scheduler runs. Always returns 0 when the agent resumes | ✅ |
| 1 | `sys_spawn` | `(entry, energy_quota, mem_quota, cap_set_ptr, cap_count) -> agent_id` | Create a new agent. `energy_quota` is deducted from caller's remaining budget. `mem_quota` sets the child's page frame limit. Capabilities must be a subset of caller's set | ✅ |
| 2 | `sys_exit` | `(status_code)` | Terminate the calling agent. Does not return | ✅ |
| 3 | `sys_send` | `(mailbox_id, ptr, len) -> error_code` | Send a message (non-blocking). Returns 0 on success, negative on failure (mailbox full, no capability, payload exceeds 256 bytes, etc.). Caller may yield and retry on mailbox-full | ✅ |
| 4 | `sys_recv` | `(mailbox_id, out_ptr, out_capacity) -> len` | Receive a message (blocking). Returns message length, or negative on error. Blocks if mailbox is empty (agent moves to BlockedRecv). Budget continues to decrement while blocked; budget exhaustion breaks the block. An agent always has implicit permission to receive from its own mailbox; receiving from another agent's mailbox requires `CAP_RECV_MAILBOX:<id>` | ✅ |
| 5 | `sys_cap_query` | `(out_ptr, out_capacity) -> count` | Return the caller's capability set | ✅ |
| 6 | `sys_cap_grant` | `(target_agent_id, cap_ptr) -> error_code` | Grant a capability to a direct child agent. Fails if caller does not hold the capability or target is not a direct child of the caller | ✅ |
| 7 | `sys_event_emit` | `(code, arg) -> error_code` | Emit an audit event | ✅ |

### 14.3 Optional early syscalls `[IMPL: ✅ ALL IMPLEMENTED]`

| # | Name | Signature | Description | Status |
|---|------|-----------|-------------|--------|
| 8 | `sys_energy_get` | `() -> remaining` | Return current remaining budget | ✅ |
| 9 | `sys_state_get` | `(key_u64, out_ptr, out_capacity) -> len` | Read a value by key from the caller's keyspace. Key is a u64 identifier | ✅ |
| 10 | `sys_state_put` | `(key_u64, value_ptr, len) -> error_code` | Write a value by key to the caller's keyspace. Key is a u64 identifier | ✅ |

### 14.4 Reserved future syscalls

The following syscalls are anticipated but not included in Stage-1:

* `sys_cap_revoke(target_agent_id, cap_ptr)` — revoke a previously granted capability from a child
* `sys_recv_nonblocking(mailbox_id, out_ptr, out_capacity)` — non-blocking receive (returns immediately if empty)
* `sys_send_blocking(mailbox_id, ptr, len)` — blocking send (waits for space)
* `sys_energy_grant(target_agent_id, amount)` — replenish a suspended child's budget

Syscall numbers 11–15 are reserved for these.

### 14.5 ABI philosophy

The syscall ABI should model the future shape of the system, even if the first implementation is minimal.

---

## 15. Scheduler Model

### 15.1 Stage-1 scheduler objective

The first scheduler does not need to be sophisticated. It needs to be correct, inspectable, and compatible with future deterministic execution goals.

### 15.2 Recommended early policy

A fixed-order or round-robin scheduler is acceptable for Stage-1.

### 15.3 Scheduling triggers

Context switching may occur on:

* explicit yield
* blocking recv (mailbox empty)
* blocking send (reserved for future; Stage-1 send is non-blocking)
* agent exit or termination
* budget exhaustion
* timer interrupt
* fault event

### 15.4 Future direction

The long-term direction is a deterministic quota-based scheduler suitable for replay and auditable execution.

---

## 16. Memory Model

### 16.1 Early boot memory

The kernel must initialize from boot-provided memory data and establish a stable kernel memory region.

### 16.2 Stage-1 memory goals

* establish physical frame allocation
* establish basic virtual mapping
* provide a kernel allocator
* provide per-agent stack allocation

### 16.3 Agent memory isolation

Each agent must execute in an isolated memory space. Without memory isolation, the capability model is meaningless — any agent could read or corrupt another agent's data by direct memory access, bypassing all capability checks.

Stage-1 implementation options:

* **Per-agent page tables**: each agent has its own page table hierarchy. The kernel switches page tables on context switch. This is the recommended approach as it provides hardware-enforced isolation.
* **Kernel-only agents**: if Stage-1 agents run in kernel mode for simplicity, isolation may be enforced by convention initially, with page-table isolation introduced when user-mode agents are added.

Memory quota enforcement: each agent's `memory_quota` limits the number of physical frames it may be allocated. Allocation requests beyond quota must fail with an explicit error.

### 16.4 Shared memory policy

Shared memory should not be the default agent communication mechanism. Mailbox delivery should remain primary.

### 16.5 Future direction

Future versions may add explicit immutable shared regions or capability-scoped shared pages.

---

## 17. State Model

### 17.1 Stage-1 state

Stage-1 uses an in-memory key-value subsystem. State is organized into **keyspaces**. Each keyspace is an isolated namespace of key-value pairs.

* Each agent is automatically assigned a private keyspace (identified by agent id) at creation.
* Additional shared keyspaces may be created by the root agent.
* Access to any keyspace requires the corresponding `CAP_STATE_READ:<keyspace>` or `CAP_STATE_WRITE:<keyspace>` capability. An agent always holds capabilities for its own private keyspace.

### 17.2 Why state objects instead of files

Structured internal state is more suitable than path-based files for AI agent workflows and deterministic execution.

### 17.3 Future state direction

Later versions may support:

* append-only event-backed state
* Merkleized state
* snapshot-aware state
* durable object store

---

## 18. Logging and Audit

Auditability must exist from the beginning.

### 18.1 Minimum audit events

* system boot
* agent creation
* agent termination (with exit status or fault reason)
* mailbox send
* mailbox receive
* capability grant
* capability denial
* budget exhaustion
* budget replenishment
* fault/exception
* syscall entry failure

### 18.2 Event structure

Conceptually:

```text
Event {
    sequence,
    tick,
    agent_id,
    event_type,
    arg0,
    arg1,
    status,
}
```

* `sequence` is a monotonically increasing counter, distinct from `tick`. It provides a total ordering of events for replay, even when multiple events share the same tick.
* `agent_id` is the agent that caused the event.
* For IPC events: `arg0` = target mailbox id, `arg1` = message length. The counterpart agent can be derived from the mailbox owner.
* For capability denial events: `arg0` = denied capability type, `arg1` = target resource id.

### 18.3 Output path

Stage-1 should emit events over serial output in a structured and parseable format.

---

## 19. Checkpoint and Replay Direction

Checkpointing may not be fully implemented in Stage-1, but the architecture should anticipate it.

Long-term checkpoint contents may include:

* execution context (all saved registers, including cr3)
* mailbox cursor state (read/write positions in ring buffers)
* energy counters (remaining budget per agent)
* state object snapshots (key-value data per keyspace)
* scheduler order state (run queue ordering, tick counter)
* event sequence counter

Replay is essential for:

* debugging
* auditing
* deterministic validation
* future distributed verification models

---

## 20. Demo-Driven Validation

The first successful version of AOS should not be judged by whether it runs a shell. It should be judged by whether the new OS model is alive.

### 20.1 Demo 1: message exchange (achievable after Phase 5) `[IMPL: ✅ VERIFIED]`

* boot system `[✅]`
* create agent_0 with `CAP_SEND_MAILBOX:1` and `CAP_RECV_MAILBOX:0` `[✅ ping agent with CAP_SEND_MAILBOX:3]`
* create agent_1 with `CAP_SEND_MAILBOX:0` and `CAP_RECV_MAILBOX:1` `[✅ pong agent with CAP_SEND_MAILBOX:2]`
* agent_0 sends a message to agent_1's mailbox `[✅ 6,566 sends verified]`
* agent_1 receives and replies to agent_0's mailbox `[✅ 6,570 receives verified]`
* serial output confirms mailbox flow with sender_id in each message `[✅ MAILBOX_SEND/RECV events with agent IDs]`

This validates:

* scheduling and context switching `[✅]`
* syscall path `[✅]`
* mailbox delivery with message metadata `[✅]`
* capability grant in the happy path `[✅]`
* agent identity model `[✅]`

### 20.2 Demo 2: capability denial (achievable after Phase 5) `[IMPL: ✅ VERIFIED]`

* agent_0 has mailbox-send capability `[✅ ping/pong agents have specific CAP_SEND_MAILBOX]`
* agent_1 lacks it `[✅ bad agent has NO send capabilities]`
* agent_1 attempts send `[✅ bad agent attempts sys_send to mailbox 1]`
* kernel denies request and emits violation event `[✅ CAP_DENIED event emitted, E_NO_CAP returned]`

This validates:

* explicit authority model `[✅]`
* syscall gating `[✅]`
* audit logging `[✅]`

### 20.3 Demo 3: budget exhaustion (achievable after Phase 6) `[IMPL: ✅ VERIFIED]`

* assign limited execution budget to an agent `[✅ ping/pong: 10,000 energy each]`
* agent runs a busy loop consuming its budget `[✅ consumed via tick decrement + syscall cost]`
* kernel detects budget reaches zero `[✅]`
* kernel emits `BUDGET_EXHAUSTED` event and moves agent to `Suspended` state `[✅ 237 events in 10s run]`
* scheduler switches to idle agent or next ready agent `[✅ root agent continues running after ping/pong suspend]`
* serial output confirms the agent is no longer running `[✅ only ROOT tick messages after exhaustion]`

This validates:

* energy accounting and tick-based decrement `[✅]`
* budget boundary enforcement `[✅]`
* suspend behavior and scheduler reaction `[✅]`
* audit event emission `[✅]`

---

## 21. Suggested Repository Layout

```text
aos0/
  Cargo.toml
  Makefile
  rust-toolchain.toml
  .cargo/
    config.toml            # target triple, linker flags, runner = qemu
  boot/
    x86_64/
      boot.asm
      multiboot_header.asm
      linker.ld
  kernel/
    src/
      main.rs
      init.rs
      panic.rs
      logger.rs
      syscall.rs
      trap.rs
      sched.rs
      agent.rs
      mailbox.rs
      capability.rs
      energy.rs
      state.rs
      event.rs
    arch/
      x86_64/
        mod.rs
        gdt.rs
        idt.rs
        paging.rs
        timer.rs
        context.rs
        serial.rs
        syscall_entry.asm
        trap_entry.asm
        switch.asm
  user/
    agents/
      root_agent.rs
      ping_agent.rs
      pong_agent.rs
      idle_agent.rs
  tools/
    run_qemu.sh
    build_image.sh
    debug_gdb.sh
  docs/
    yellowpaper.md
    abi.md
    object_model.md
    roadmap.md
```

---

## 22. Recommended Development Order

### Phase 0: boot proof `[IMPL: ✅ COMPLETE]`

Goal:

* boot in QEMU `[✅ Multiboot v1 via QEMU -kernel]`
* print `AOS boot ok` over serial `[✅ COM1 0x3F8]`

### Phase 1: architectural skeleton `[IMPL: ✅ COMPLETE]`

Goal:

* initialize GDT and IDT `[✅ gdt.rs + idt.rs]`
* install panic/fault handlers `[✅ panic.rs + trap.rs + trap_entry.asm]`
* initialize basic memory management `[✅ paging.rs bitmap frame allocator, 32,256 frames]`

### Phase 2: trap and syscall path `[IMPL: ✅ COMPLETE]`

Goal:

* syscall entry works `[✅ 11 syscalls via direct call, syscall_entry.asm ready for ring-3]`
* exception path prints diagnostics `[✅ trap_handler_common logs vector/error_code/rip/agent]`
* timer interrupt is functional `[✅ PIT 100 Hz, tick counter incrementing, preemptive schedule]`

### Phase 3: agent model `[IMPL: ✅ COMPLETE]`

Goal:

* create the idle agent — a special kernel-internal agent that runs when no other agent is Ready. It executes `hlt` in a loop and is exempt from energy budgeting. The scheduler must never remove the idle agent from the system. `[✅ agents/idle.rs, unlimited energy, not in run queue]`
* create one test agent (kernel-mode, compiled into the image) `[✅ 5 agents: idle, root, ping, pong, bad]`
* support context switching between agents `[✅ switch.asm + sched.rs, cooperative yield + preemptive timer]`

Note: Phase 3 agents run in kernel mode (ring 0) for simplicity. User-mode (ring 3) isolation with per-agent page tables is a Phase 3b or later concern. The architectural boundary exists in the design, but the first working context switch does not require a privilege transition. `[✅ Stage-1 runs in ring 0 as specified]`

### Phase 4: mailbox IPC `[IMPL: ✅ COMPLETE]`

Goal:

* bounded mailbox queue `[✅ 16-slot ring buffer, 256B max payload]`
* send/recv syscalls `[✅ sys_send (non-blocking) + sys_recv (blocking)]`
* logging for message flow `[✅ MAILBOX_SEND/MAILBOX_RECV audit events]`

### Phase 5: capability enforcement `[IMPL: ✅ COMPLETE]`

Goal:

* define capability structures `[✅ CapType enum, Capability struct with use_limit]`
* enforce checks in send/recv or spawn paths `[✅ agent_try_cap() called before send/recv/spawn/event_emit]`
* emit denial events `[✅ CAP_DENIED event with cap_type and target, verified by bad agent]`

### Phase 6: energy budgeting `[IMPL: ✅ COMPLETE]`

Goal:

* assign budget per agent `[✅ energy_budget field in Agent struct]`
* decrement via timer ticks (for running and blocked agents) and syscall cost `[✅ tick_running + tick_blocked + charge_syscall]`
* enforce zero-budget behavior: suspend agent, emit audit event, reschedule `[✅ Suspended state + BUDGET_EXHAUSTED event + schedule()]`

At the end of Phase 6, AOS Stage-1 becomes a valid AI-native minimal kernel prototype. `[✅ ALL PHASES COMPLETE — verified 2026-03-22]`

---

## 23. Non-Goals

To preserve implementation focus, the following are explicitly out of scope for the first stage:

* POSIX compatibility
* generic app ecosystem support
* desktop shell environment
* ELF loader completeness
* general networking stack completeness
* GPU runtime integration
* multiprocess compatibility with legacy binaries
* replacing Linux for server administration

---

## 24. Stage-2 Roadmap (Kernel Hardening + Runtime Foundation)

Stage-2 transforms AOS from a kernel-mode prototype into a hardened execution platform with memory isolation, sandboxed runtimes, and persistent state.

### 24.1 Objectives

* Introduce user-mode agent isolation (ring 3 + per-agent page tables)
* Add a kernel heap allocator for dynamic data structures
* Support loading agent binaries (ELF loader for native, WASM loader for sandboxed)
* Introduce WASM as the first sandboxed runtime backend
* Introduce eBPF-lite as the policy and filtering runtime
* Replace in-memory state with persistent storage via virtio-blk
* Implement basic checkpoint and replay
* Begin transition toward system agents (microkernel direction)

### 24.2 Prerequisite: Kernel Infrastructure

These must be completed before runtime or system agent work can begin.

#### 24.2.1 User-Mode Agent Isolation

Stage-1 agents run in ring 0 (kernel mode). Stage-2 must introduce hardware-enforced isolation:

* Per-agent page tables: each agent gets its own page table hierarchy. The kernel switches `cr3` on context switch. This is already anticipated by the `cr3` field in `AgentContext`.
* Ring 3 execution: agent code runs in user mode. Syscalls transition to ring 0 via the `syscall` instruction (MSR setup for STAR/LSTAR/SFMASK, already prepared in `syscall_entry.asm`).
* Kernel/user memory split: the kernel is mapped in the upper half of every agent's address space (higher-half kernel) but marked supervisor-only.
* Memory quota enforcement: `alloc_frame()` is gated by each agent's `memory_quota`. Exceeding quota returns an error.

Without memory isolation, the capability model is bypassable — any agent could read/write another agent's data via direct memory access.

#### 24.2.2 Kernel Heap Allocator

Stage-1 has only a frame allocator (4KB pages). Stage-2 requires a heap for dynamic kernel data structures (runtime metadata, variable-length messages, etc.):

* Implement a slab or bump allocator on top of the frame allocator
* Integrate with Rust's `#[global_allocator]` to enable `alloc` crate (`Vec`, `Box`, `String`)
* Heap is kernel-only; agents allocate via `memory_quota`-bounded frame allocation

#### 24.2.3 Agent Binary Loader

Stage-1 agents are compiled into the kernel image. Stage-2 must support loading agent code from external sources:

* **Native agents**: minimal ELF64 loader that maps `.text`, `.data`, `.bss` into the agent's address space and sets the entry point
* **WASM agents**: WASM binary is loaded into kernel memory and executed by the WASM runtime (§24.3.1)
* **eBPF-lite programs**: bytecode is loaded and verified before attachment (§24.3.2)
* Agent binaries may be embedded in the kernel image initially (initramfs-style), with virtio-blk loading added when persistent storage is available

### 24.3 Runtime Layer

#### 24.3.1 WASM Runtime

WASM is the primary sandboxed runtime for AOS agents. It provides portable, deterministic execution with fine-grained memory safety.

Runtime host interface:

```text
WasmRuntime {
    load(wasm_bytes) -> module_id       // parse and validate WASM module
    instantiate(module_id) -> instance  // create execution instance
    execute_slice(instance, fuel) -> result  // run with bounded fuel
    handle_syscall(instance, num, args) -> result  // bridge WASM → AOS syscalls
    snapshot(instance) -> checkpoint    // capture execution state
    restore(checkpoint) -> instance     // resume from checkpoint
}
```

Design constraints:

* **No JIT in Stage-2**: use an interpreter (e.g., a minimal stack-based WASM interpreter written in Rust). JIT compilation may be explored in Stage-3.
* **Fuel-based metering**: WASM execution is bounded by a fuel counter that maps to the agent's energy budget. Each WASM instruction consumes fuel.
* **Syscall bridging**: WASM agents invoke AOS syscalls via `call_indirect` to imported host functions. The runtime translates these to kernel syscalls.
* **Memory model**: WASM linear memory is backed by agent-allocated frames. The `memory.grow` instruction is gated by `memory_quota`.
* **Determinism**: WASM is inherently deterministic (no threads, no system clock access). This makes it ideal for checkpoint/replay.

#### 24.3.2 eBPF-lite Policy Runtime

eBPF-lite is a restricted bytecode runtime for policy enforcement, event filtering, and validation rules. It runs inside the kernel, not in user mode.

```text
EbpfProgram {
    bytecode: [u8],         // verified eBPF-lite instructions
    attachment: AttachPoint, // where this program runs
    maps: [EbpfMap],        // shared data structures
}

AttachPoint {
    SyscallEntry(syscall_num),  // filter before syscall execution
    SyscallExit(syscall_num),   // inspect after syscall execution
    MailboxSend(mailbox_id),    // filter outgoing messages
    MailboxRecv(mailbox_id),    // filter incoming messages
    AgentSpawn,                 // validate spawn parameters
    TimerTick,                  // periodic policy checks
}
```

Design constraints:

* **Verified execution**: all eBPF-lite programs must pass a static verifier before loading. The verifier ensures: no unbounded loops, no out-of-bounds memory access, termination within bounded instructions.
* **Instruction set**: a subset of Linux eBPF — 64-bit registers (r0-r10), ALU ops, conditional jumps, memory load/store, map lookups, helper calls. No direct kernel memory access.
* **Maps**: shared key-value data structures (hash map, array map) for communication between eBPF programs and the kernel or agents.
* **Helper functions**: a fixed set of kernel-provided helpers (e.g., `get_agent_id()`, `get_energy_remaining()`, `emit_event()`, `drop_message()`).
* **Return value**: programs return an action code (ALLOW, DENY, LOG, MODIFY) that the kernel enforces at the attachment point.
* **Energy cost**: eBPF-lite execution is charged against the system energy pool, not individual agents, since it runs as kernel policy.

Use cases:

* Rate-limit an agent's syscall frequency
* Block messages matching a payload pattern
* Enforce spawn policies (max children, minimum budget)
* Custom audit filtering (emit events only for specific conditions)

### 24.4 System Agents

Move higher-level services out of the kernel into privileged user-mode agents. Mailbox IPC and capability enforcement remain in-kernel — only management and policy logic migrates.

* **stated** — state persistence manager: handles durable key-value writes to virtio-blk, serves `sys_state_get`/`sys_state_put` for shared keyspaces
* **policyd** — policy engine: loads and manages eBPF-lite programs, handles dynamic policy updates
* **netd** — network broker (Stage-2 preparation, functional in Stage-3): accepts outbound network requests from agents via mailbox, performs requests on their behalf, returns responses

System agents run in ring 3 but with elevated capabilities (granted by the root agent at boot). They communicate with the kernel and other agents exclusively through mailboxes and syscalls.

### 24.5 Persistent State Store

Replace in-memory state with durable storage via virtio-blk:

* **Storage backend**: virtio-blk device driver (QEMU `-drive` flag). Simple block I/O: read/write 512-byte sectors.
* **On-disk format**: append-only log of key-value mutations. Each entry: `[sequence, keyspace_id, key_u64, len, value_bytes, checksum]`.
* **In-memory index**: the kernel maintains an in-memory hash map of current key-value pairs, rebuilt from the log on boot.
* **Snapshot**: flush the current state to a contiguous region on disk. This is the checkpoint-compatible state format.
* **Consistency**: writes are logged before acknowledgment (write-ahead). On crash recovery, replay the log to rebuild state.

### 24.6 Basic Checkpointing

Introduce execution snapshots for debugging and replay:

* **Checkpoint contents**: all agent contexts (registers, page tables), mailbox queues (read/write positions, pending messages), energy counters, state object snapshots, scheduler state (run queue, tick counter), event sequence counter.
* **Trigger**: manual (via a `sys_checkpoint` syscall from root agent) or periodic (every N ticks, configurable).
* **Storage**: serialized to virtio-blk as a single contiguous image.
* **Restore**: on boot, if a checkpoint is present, the kernel can restore all agents to the checkpointed state instead of running init.
* **Limitation**: Stage-2 checkpointing is not yet deterministic. Timer interrupt timing and I/O ordering may differ across replays. Full deterministic replay requires Stage-3.

### 24.7 Additional Syscalls (Stage-2)

| # | Name | Description |
|---|------|-------------|
| 11 | `sys_cap_revoke` | Revoke a capability from a direct child agent |
| 12 | `sys_recv_nonblocking` | Non-blocking receive (returns immediately if empty) |
| 13 | `sys_send_blocking` | Blocking send (waits for space in target mailbox) |
| 14 | `sys_energy_grant` | Replenish a suspended child's energy budget |
| 15 | `sys_checkpoint` | Trigger a checkpoint (root agent only) |
| 16 | `sys_mmap` | Map physical frames into agent's address space |
| 17 | `sys_munmap` | Unmap frames from agent's address space |

### 24.8 Suggested Development Order (Stage-2)

#### Phase 7: kernel heap + user-mode isolation

* Implement slab allocator, enable `alloc` crate
* Per-agent page tables, ring 3 execution, `syscall`/`sysret` path
* Verify: existing ping/pong demo works in ring 3

#### Phase 8: agent binary loader

* Minimal ELF64 loader for native agents
* Load agent from embedded initramfs image
* Verify: load and run a separately compiled agent binary

#### Phase 9: WASM runtime

* WASM interpreter (stack-based, no JIT)
* Fuel-based metering mapped to energy budget
* Syscall bridging (WASM host imports → AOS syscalls)
* Verify: ping/pong demo rewritten in WASM runs correctly

#### Phase 10: eBPF-lite runtime

* Bytecode format, static verifier, interpreter
* Attachment points for syscall entry and mailbox send
* Map data structures (hash map, array map)
* Verify: eBPF program blocks unauthorized sends (replaces bad_agent demo)

#### Phase 11: persistent state + checkpointing

* virtio-blk driver (read/write sectors)
* Append-only state log, in-memory index
* Checkpoint serialization and restore
* Verify: agent writes state, kernel reboots, state is preserved

#### Phase 12: system agents

* stated and policyd as ring-3 agents
* Root agent spawns system agents during init
* Verify: state operations routed through stated agent via mailbox

### 24.9 Stage-2 Success Criteria

Stage-2 is successful when:

* agents run in ring 3 with per-agent page tables
* a WASM agent and a native agent coexist and exchange messages
* an eBPF-lite program enforces a policy at a syscall attachment point
* state persists across kernel reboots via virtio-blk
* a checkpoint can be taken and restored
* at least one system agent (stated) runs as a user-mode service

---

## 25. Stage-3 Roadmap (Production-Ready Execution Layer)

Stage-3 transforms AOS into a production-capable execution substrate with deterministic replay, networking, multi-core support, and an economic model.

### 25.1 Objectives

* Achieve deterministic, replayable execution
* Support distributed and networked agents
* Introduce multi-core (SMP) scheduling
* Integrate an economic model for energy accounting
* Harden eBPF-lite into a full policy framework

### 25.2 Core Additions

#### 25.2.1 Deterministic Scheduler

Replace the round-robin scheduler with a deterministic, replay-compatible scheduler:

* **Fixed tick quotas**: each agent receives a fixed number of ticks per scheduling round. The order is deterministic given the same initial state.
* **No instruction counting**: x86_64 does not support precise per-instruction counting due to out-of-order execution and variable instruction latency. Determinism is achieved at the tick granularity, not instruction granularity.
* **I/O determinism**: external I/O (virtio-blk, network) is logged and replayed from a trace file during replay mode. The scheduler pauses agents waiting for I/O until the traced response is injected.
* **WASM advantage**: WASM agents are inherently deterministic (fuel-counted). The deterministic scheduler combined with WASM provides full replay fidelity.

#### 25.2.2 SMP / Multi-Core Support

Extend AOS to run on multiple CPU cores:

* Per-core run queues with work-stealing
* Spinlock-based synchronization for shared kernel data structures (agent table, mailbox queues, capability sets)
* Core-pinning option for deterministic execution (pin agent to core for replay)
* APIC timer per core (replaces PIT for per-core tick accounting)
* Inter-Processor Interrupts (IPI) for cross-core scheduling events

SMP is required before production deployment. Single-core is a Stage-1/2 simplification.

#### 25.2.3 Network as Brokered Capability

Agents do not access the network directly. Instead, they send requests to the **netd** system agent via mailbox:

```text
Agent → sys_send(netd_mailbox, {method: "GET", url: "...", headers: ...})
       ← sys_recv(own_mailbox, {status: 200, body: ...})
```

The netd system agent:

* Holds `CAP_NETWORK` (a new capability type, not granted to regular agents)
* Validates requests against policy (eBPF-lite filters or static rules)
* Performs the actual network I/O via a virtio-net driver
* Returns responses to the requesting agent's mailbox
* Logs all network activity as audit events

This brokered model ensures:

* No agent can perform arbitrary network access
* All network activity is auditable
* Rate limiting and filtering are enforced at the broker level

#### 25.2.4 Advanced State Model

Extend the persistent state store with verifiability:

* **Merkle tree**: each keyspace maintains a Merkle root over its key-value entries. State transitions produce a new root hash.
* **State proofs**: given a key, produce a Merkle proof that the value is (or is not) in the state tree. This enables external verification without full state access.
* **Snapshot diffing**: compare two checkpoints by comparing Merkle roots. Only changed subtrees need to be transferred or stored.
* **Rollback**: restore state to a previous Merkle root by replaying the log backwards.

#### 25.2.5 Full Checkpoint & Replay

Build on Stage-2 basic checkpointing to achieve deterministic replay:

* **Deterministic replay**: given a checkpoint and an I/O trace, reproduce the exact same sequence of events, agent states, and messages.
* **I/O trace recording**: during live execution, log all non-deterministic inputs (timer interrupt timing, virtio responses, network responses) to a trace file.
* **Replay mode**: boot from checkpoint, feed traced inputs, verify that the event log matches the original execution.
* **Execution diffing**: compare two replay runs and report divergence points.

#### 25.2.6 Energy / Economic Model

Extend per-agent energy budgets into a unified economic model:

* **Cost table**: define energy cost per operation type: syscall (1), timer tick (1), frame allocation (10), virtio-blk read (100), virtio-blk write (200), network request (500). Costs are configurable at compile time.
* **Energy transfer**: `sys_energy_grant` allows a parent to transfer energy to a child. Energy is conserved — the parent's budget decreases by the granted amount.
* **Energy accounting across runtimes**: WASM fuel consumption is mapped to AOS energy units. One WASM fuel unit = one AOS energy unit.
* **External billing interface**: the kernel exposes per-agent cumulative energy consumption via a system agent (accountd). External systems can query this for billing or token integration.

#### 25.2.7 eBPF-lite Enhancements

Extend the Stage-2 eBPF-lite runtime:

* **New attachment points**: network send/recv (at netd), state read/write, checkpoint trigger
* **Program chaining**: multiple eBPF programs on the same attachment point, executed in priority order
* **Persistent maps**: eBPF maps backed by persistent state (survives reboot)
* **Metrics helpers**: `increment_counter()`, `read_gauge()` for observability
* **Hot-reload**: replace an attached eBPF program without restarting the system

### 25.3 Stage-3 Success Criteria

Stage-3 is successful when:

* A checkpoint can be replayed deterministically with identical event output
* Agents on different cores exchange messages via mailbox
* An agent sends an HTTP request through netd and receives a response
* State transitions produce verifiable Merkle proofs
* Energy accounting is consistent across native, WASM, and eBPF-lite execution
* eBPF-lite programs enforce network-level policy at the netd broker

---

## 26. Stage-4 Roadmap (Ecosystem and Hardware)

Stage-4 expands AOS from a QEMU-only platform into a deployable system with real hardware support, distributed execution, and developer tooling.

### 26.1 Objectives

* Run on real hardware (not just QEMU)
* Support distributed agent execution across multiple nodes
* Provide developer SDK and tooling for building and deploying agents
* Establish security attestation for verifiable execution

### 26.2 Core Additions

#### 26.2.1 Hardware Support

* **PCI bus enumeration**: discover and initialize devices on a real PCI bus
* **NVMe storage driver**: replace virtio-blk with NVMe for real hardware deployment
* **Real NIC driver**: e1000 or virtio-net on real hardware
* **UEFI boot**: replace Multiboot v1 with UEFI boot path for modern hardware
* **GPU/NPU access**: brokered through a system agent (gpud), not directly accessible to agents. The broker model from netd applies here.

#### 26.2.2 Distributed Execution

* **Remote mailbox**: agents on different nodes communicate via mailbox transparently. The kernel routes messages to a network transport layer.
* **Node discovery**: a bootstrap protocol for nodes to find each other (multicast or seed node list)
* **Cross-node capability verification**: capabilities include a node ID and a cryptographic signature. The receiving node verifies the capability before accepting a remote message.
* **Agent migration**: move a checkpointed agent from one node to another. The agent resumes on the new node with its full state.

#### 26.2.3 Developer SDK

* **Agent SDK (Rust)**: a `#![no_std]` crate providing safe wrappers around AOS syscalls, mailbox send/recv helpers, state get/put, and energy queries
* **Agent SDK (WASM)**: AssemblyScript or Rust-to-WASM toolchain for writing WASM agents with AOS syscall bindings
* **eBPF-lite SDK**: a compiler from a restricted C/Rust subset to eBPF-lite bytecode, with a local verifier
* **CLI tools**: `aos-build` (compile agent), `aos-deploy` (load agent into running AOS), `aos-replay` (replay a checkpoint), `aos-inspect` (query agent state and event logs)

#### 26.2.4 Security & Attestation

* **Execution proofs**: produce a cryptographic proof that a specific event log was generated by a specific checkpoint under deterministic replay
* **Remote attestation**: a node can prove to a verifier that it is running unmodified AOS kernel code (via TPM or secure boot chain)
* **Capability signing**: capabilities include an ed25519 signature from the granting agent, enabling offline verification of authority chains

### 26.3 Stage-4 Success Criteria

Stage-4 is successful when:

* AOS boots on real x86_64 hardware (not just QEMU)
* An agent on node A sends a message to an agent on node B via remote mailbox
* A developer writes, compiles, and deploys a WASM agent using the SDK
* An execution proof can be independently verified by a third party

---

## 27. Long-Term Vision

AOS evolves from a minimal kernel into a foundational execution layer for the agent economy.

```text
+-----------------------------------------+
|         Applications / Users            |
+-----------------------------------------+
|          Agent Layer (WASM/Native)       |
+-----------------------------------------+
|    AOS Runtime (scheduler, IPC, caps)   |
+-----------------------------------------+
|    AOS Kernel (mm, trap, syscall)       |
+-----------------------------------------+
|    Hardware / Distributed Network       |
+-----------------------------------------+
```

### 27.1 What AOS Is

* An execution substrate for autonomous agents
* A deterministic, replayable computation layer
* A capability-secured runtime where every action is explicitly authorized
* A bridge between AI systems, economic systems, and verifiable computation

### 27.2 What AOS Is Not

* A desktop operating system
* A Linux replacement for server administration
* A general-purpose consumer platform

### 27.3 Closing Statement

> AOS begins as a minimal kernel. It evolves into the execution layer where autonomous systems operate, interact, and transact — with every action auditable, every resource budgeted, and every authority explicit.

---

## 28. Engineering Guidance for Implementation

This yellow paper is intended as a practical guide for implementation work.

### 28.1 Preferred implementation style

* keep subsystems small and explicit
* prefer compile-time simplicity over generic abstraction too early
* favor inspectable behavior over feature breadth
* log everything important in early versions
* keep early data structures fixed-size where possible
* avoid introducing general compatibility layers prematurely

### 28.2 Suggested first success metric `[IMPL: ✅ ALL MET]`

AOS should be considered meaningfully alive when all of the following are true:

* it boots in QEMU `[✅ Multiboot v1, boots in < 1 second]`
* it prints structured serial logs `[✅ [EVENT seq=N tick=T agent=A type=TYPE ...] format]`
* it can create at least two agents `[✅ 5 agents: idle, root, ping, pong, bad]`
* those agents can exchange mailbox messages `[✅ 6,566 sends / 6,570 receives in 10s]`
* capability denial works `[✅ bad agent denied with E_NO_CAP, CAP_DENIED event emitted]`
* budget enforcement works `[✅ 237 BUDGET_EXHAUSTED events, agents suspended at zero energy]`
* traps and panics are inspectable `[✅ vector/error_code/rip/agent logged, panic handler with location]`

When these conditions are met, AOS is no longer a toy boot project. It becomes a genuine first-stage AI-native minimal operating system. **`[✅ AOS Stage-1 is alive. Verified 2026-03-22.]`**

---

## 29. Conclusion

AOS proposes a different starting point for operating system design in the AI era.

Rather than inheriting the historical center of gravity of processes, files, sockets, and ambient authority, AOS begins with:

* agents
* mailboxes
* capabilities
* state objects
* execution budgets
* audit events
* deterministic evolution

Its implementation strategy is equally deliberate:

* design from zero
* code from zero
* first execute inside a virtual machine
* prove the model before expanding hardware ambition

This is the correct path for building a minimal AI-native OS foundation without being trapped by legacy abstractions too early.

---

## 30. One-Sentence Definition

**AOS is a from-scratch, VM-first, AI-native minimal operating system built around agents, mailboxes, capabilities, structured state, execution budgets, and auditable kernel behavior.**
