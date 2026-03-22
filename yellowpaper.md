# AOS Yellow Paper

**Version:** Draft v0.1
**Status:** Engineering Yellow Paper
**Language:** English
**Purpose:** Implementation reference for building AOS from scratch, initially targeting virtual machines and QEMU.

---

## Abstract

AOS is an AI-native minimal operating system designed from first principles for agent execution, deterministic task handling, capability-based isolation, audited state transitions, and constrained tool access. It is **not** intended to be a desktop operating system or a general POSIX-compatible environment. Its primary role is to serve as a minimal execution substrate for AI agents, verifiable runtimes, blockchain-adjacent execution environments, and secure automated systems.

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
* explicit tool invocation controls
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
* tool brokers
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
* tool endpoint
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
* **Boot environment:** UEFI or Multiboot-compatible boot path
* **CPU mode:** 64-bit long mode
* **Core assumption:** single-core initially

### 3.2 What Stage-1 must do

1. Boot in a virtual machine.
2. Enter 64-bit mode.
3. Initialize basic memory management.
4. Install GDT and IDT.
5. Handle traps and exceptions.
6. Provide a minimal syscall path.
7. Create and schedule minimal agent contexts.
8. Provide mailbox-based IPC.
9. Enforce a minimal capability model.
10. Provide execution budgeting / energy accounting.
11. Emit serial logs and audit events.

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
+----------------------------------------------+
|               Test Agents / Runtimes         |
|  ping agent | pong agent | idle agent        |
+----------------------------------------------+
|            AI-native Syscall ABI             |
| spawn | send | recv | state | cap | energy   |
+----------------------------------------------+
|               Kernel Core                    |
| sched | mm | trap | syscall | ipc | audit    |
+----------------------------------------------+
|              x86_64 Arch Layer               |
| gdt | idt | paging | timer | irq | context   |
+----------------------------------------------+
|             Boot / Loader Layer              |
+----------------------------------------------+
|                  QEMU VM                     |
+----------------------------------------------+
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
    status,
    runtime_kind,
    execution_context,
    mailbox_id,
    capability_set,
    energy_budget,
    memory_quota,
}
```

#### Required properties

* uniquely identifiable
* schedulable
* interruptible
* message-addressable
* capability-scoped
* budget-limited

### 5.2 Mailbox

A **mailbox** is the primary IPC primitive. Each agent owns or is associated with one mailbox.

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
    quota,
    expiry,
}
```

### 5.4 State object

A **state object** replaces file-first semantics for internal structured execution state.

Stage-1 may implement this as a simple in-memory key-value map. Persistent storage can be introduced later.

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

The system must establish a clean execution environment for the kernel.

#### 7.1.2 Memory management primitives

The kernel must provide:

* physical memory initialization
* page mapping primitives
* kernel virtual memory layout
* early heap or allocator support

#### 7.1.3 Trap and exception handling

The kernel must handle:

* faults
* invalid instructions
* protection violations
* timer interrupts
* software interrupts or syscall entry

#### 7.1.4 Scheduling

The kernel must provide a minimal scheduler capable of switching between execution contexts.

#### 7.1.5 Mailbox IPC

The kernel must provide bounded message queues usable by agents.

#### 7.1.6 Capability checks

The kernel must gate syscalls through capability checks.

#### 7.1.7 Energy accounting

The kernel must track execution usage per agent and enforce budget boundaries.

#### 7.1.8 Logging and audit events

The kernel must provide serial output and structured event emission.

### 7.2 What should not be in the Stage-1 kernel

* rich userspace loader compatibility layers
* POSIX file abstractions
* shell support as a design objective
* network stack completeness
* complex block cache logic
* high-level AI policy engines

---

## 8. Architecture Layers

### 8.1 Boot layer

Responsibilities:

* transition from firmware/bootloader into kernel entry
* establish initial page tables as needed
* hand off memory information
* establish clean control flow into Rust/C kernel logic

### 8.2 x86_64 architecture layer

Responsibilities:

* GDT setup
* IDT setup
* interrupt/trap stubs
* context switching
* timer setup
* low-level register and port handling

### 8.3 Kernel core layer

Responsibilities:

* scheduler
* agent table
* mailbox subsystem
* capability subsystem
* event subsystem
* energy accounting
* syscall dispatcher

### 8.4 Test agent layer

Stage-1 should compile in a minimal set of test agents directly into the kernel image or a fixed internal image format.

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

A minimal set of states may include:

* Created
* Ready
* Running
* BlockedRecv
* BlockedSend
* Suspended
* Killed
* Faulted

### 10.2 Agent execution context

Each agent requires:

* stack pointer
* instruction pointer / entry point
* saved registers
* execution budget metadata
* mailbox binding
* capability set reference

### 10.3 Agent lifecycle

1. Create agent.
2. Assign mailbox.
3. Assign capabilities.
4. Assign initial budget.
5. Place in run queue.
6. Execute until yield, block, budget exhaustion, or fault.
7. Emit audit events throughout lifecycle.

---

## 11. Mailbox IPC Model

Mailbox IPC is one of the core defining traits of AOS.

### 11.1 Mailbox rules

* mailbox delivery should be explicit
* mailbox capacity should be bounded
* send failure modes must be explicit
* recv behavior should be deterministic in simple cases
* direct arbitrary shared memory should not be the default IPC model

### 11.2 Stage-1 implementation suggestion

Use a ring-buffer mailbox with fixed-size or small bounded messages.

### 11.3 Future direction

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

* `CAP_SEND_MAILBOX:<id>`
* `CAP_RECV_MAILBOX:<id>`
* `CAP_EVENT_EMIT`
* `CAP_AGENT_SPAWN`
* `CAP_STATE_READ:<keyspace>`
* `CAP_STATE_WRITE:<keyspace>`

### 12.3 Enforcement

Syscalls must validate capability requirements before execution.

### 12.4 Denial behavior

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

Stage-1 may implement a simple per-agent decrementing budget based on:

* timer ticks
* scheduler slices
* explicit instruction window approximations

### 13.3 Exhaustion policy

When the budget reaches zero, the kernel may:

* suspend the agent
* kill the agent
* emit an event and reschedule others

The behavior should be explicit and configurable at compile time in early versions.

---

## 14. System Call ABI

The Stage-1 syscall surface should be intentionally small.

### 14.1 Initial syscall set

#### `sys_yield()`

Yield execution voluntarily.

#### `sys_spawn(entry, quota) -> agent_id`

Create a new agent with a specified entry point and initial budget.

#### `sys_send(mailbox_id, ptr, len)`

Send a message to a mailbox.

#### `sys_recv(mailbox_id, out_ptr) -> len`

Receive a message from the caller's mailbox or a specified mailbox if permitted.

#### `sys_cap_query(out_ptr)`

Return information about the current capability set.

#### `sys_event_emit(code, arg)`

Emit an audit event.

### 14.2 Optional early syscalls

#### `sys_energy_get()`

Return current remaining budget.

#### `sys_state_get(key, out_ptr)`

Read a key from an in-memory state map.

#### `sys_state_put(key, value_ptr, len)`

Write to an in-memory state map.

### 14.3 ABI philosophy

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
* blocking recv
* budget exhaustion
* timer interrupt
* fault or kill event

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

### 16.3 Shared memory policy

Shared memory should not be the default agent communication mechanism. Mailbox delivery should remain primary.

### 16.4 Future direction

Future versions may add explicit immutable shared regions or capability-scoped shared pages.

---

## 17. State Model

### 17.1 Stage-1 state

Stage-1 may use an in-memory key-value subsystem for testing.

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
* agent termination
* mailbox send
* mailbox receive
* capability denial
* budget exhaustion
* fault/exception
* syscall entry failure

### 18.2 Event structure

Conceptually:

```text
Event {
    id,
    timestamp_or_tick,
    agent_id,
    event_type,
    arg0,
    arg1,
    status,
}
```

### 18.3 Output path

Stage-1 should emit events over serial output in a structured and parseable format.

---

## 19. Checkpoint and Replay Direction

Checkpointing may not be fully implemented in Stage-1, but the architecture should anticipate it.

Long-term checkpoint contents may include:

* execution context
* mailbox cursor state
* PRNG state
* energy counters
* state object references
* scheduler order state

Replay is essential for:

* debugging
* auditing
* deterministic validation
* future distributed verification models

---

## 20. Demo-Driven Validation

The first successful version of AOS should not be judged by whether it runs a shell. It should be judged by whether the new OS model is alive.

### 20.1 Demo 1: message exchange

* boot system
* create agent_0 and agent_1
* agent_0 sends a message to agent_1
* agent_1 replies
* serial output confirms mailbox flow

This validates:

* scheduling
* syscall path
* mailbox delivery
* agent identity model

### 20.2 Demo 2: capability denial

* agent_0 has mailbox-send capability
* agent_1 lacks it
* agent_1 attempts send
* kernel denies request and emits violation event

This validates:

* explicit authority model
* syscall gating
* audit logging

### 20.3 Demo 3: budget exhaustion

* assign limited execution budget to an agent
* allow it to consume quota
* kernel suspends or kills it on exhaustion
* emit structured event

This validates:

* energy accounting
* bounded execution
* scheduler enforcement

---

## 21. Suggested Repository Layout

```text
aos0/
  boot/
    x86_64/
      boot.asm
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
    arch/
      x86_64/
        gdt.rs
        idt.rs
        paging.rs
        timer.rs
        context.rs
        syscall_entry.asm
        trap_entry.asm
        switch.asm
  user/
    agents/
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

### Phase 0: boot proof

Goal:

* boot in QEMU
* print `AOS boot ok` over serial

### Phase 1: architectural skeleton

Goal:

* initialize GDT and IDT
* install panic/fault handlers
* initialize basic memory management

### Phase 2: trap and syscall path

Goal:

* syscall entry works
* exception path prints diagnostics
* timer interrupt is functional

### Phase 3: agent model

Goal:

* create idle agent
* create one test agent
* support context switching

### Phase 4: mailbox IPC

Goal:

* bounded mailbox queue
* send/recv syscalls
* logging for message flow

### Phase 5: capability enforcement

Goal:

* define capability structures
* enforce checks in send/recv or spawn paths
* emit denial events

### Phase 6: energy budgeting

Goal:

* assign budget per agent
* decrement on scheduling slices or timer ticks
* enforce zero-budget behavior

At the end of Phase 6, AOS Stage-1 becomes a valid AI-native minimal kernel prototype.

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

## 24. Long-Term Direction

After Stage-1, the architecture may evolve toward:

* deterministic scheduling mode
* capability-carrying messages
* durable state store
* checkpoint / replay implementation
* brokered network endpoints
* brokered compute endpoints
* more advanced runtime types (WASM, JVM-lite, custom VM)
* microkernel-style system agents
* attestation and execution proof mechanisms

The long-term vision is not a Unix clone. The long-term vision is an **AI-native operating substrate**.

---

## 25. Engineering Guidance for Implementation

This yellow paper is intended as a practical guide for implementation work.

### 25.1 Preferred implementation style

* keep subsystems small and explicit
* prefer compile-time simplicity over generic abstraction too early
* favor inspectable behavior over feature breadth
* log everything important in early versions
* keep early data structures fixed-size where possible
* avoid introducing general compatibility layers prematurely

### 25.2 Suggested first success metric

AOS should be considered meaningfully alive when all of the following are true:

* it boots in QEMU
* it prints structured serial logs
* it can create at least two agents
* those agents can exchange mailbox messages
* capability denial works
* budget enforcement works
* traps and panics are inspectable

When these conditions are met, AOS is no longer a toy boot project. It becomes a genuine first-stage AI-native minimal operating system.

---

## 26. Conclusion

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

## 27. One-Sentence Definition

**AOS is a from-scratch, VM-first, AI-native minimal operating system built around agents, mailboxes, capabilities, structured state, execution budgets, and auditable kernel behavior.**
