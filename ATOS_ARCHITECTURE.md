# ATOS Architecture: Execution Engine + Settlement Layer

## What ATOS Is

ATOS is a **bare-metal verifiable execution engine** — it has the hardware control of an OS but operates under the trust model of a smart contract platform.

It is not a blockchain. It is not a traditional OS. It is a **payment-agnostic execution substrate** for autonomous agents, where authority is explicit, execution is auditable, state is durable, and computation is replayable and provable.

### One-Sentence Definition

> ATOS is a from-scratch, VM-first, AI-native minimal operating system built around agents, mailboxes, capabilities, structured state, execution budgets, and auditable kernel behavior.

---

## ATOS vs Smart Contract Platforms vs Traditional OS

| Concept | Ethereum | ATOS | Traditional OS |
|---------|----------|-----|----------------|
| Execution unit | Contract | **Agent** | Process |
| Invocation | Transaction | **Mailbox message** | Function call / socket |
| Authorization | msg.sender check | **Capability token** | UID / root |
| Fuel | Gas | **Energy** | None (or cgroup afterthought) |
| State | Storage trie | **State object + Merkle tree** | Filesystem |
| Verifiability | All-node replay | **Checkpoint + replay + proof** | None |
| Billing | gas x gasPrice | **energy x pricing_class** | None |
| Deployment | Deploy bytecode | **WASM agent + skill install** | Install binary |
| Determinism | EVM enforced | **Deterministic scheduler + WASM fuel** | Not guaranteed |
| Hardware access | None (runs on host OS) | **Direct** (bare-metal NVMe, NIC, LAPIC) | Direct |

---

## Energy Model

### Energy Is Fuel, Not Currency

Energy in ATOS behaves like rocket fuel: it is consumed by execution and cannot be recovered. It is **not** a token, not a coin, and not transferable outside the system.

### Provenance Rules

1. **Bootstrapped by the system**: at boot, the kernel grants the initial energy budget to the root agent.
2. **Transferred, not minted**: when a parent spawns a child, the child's energy is deducted from the parent's budget. Energy is subdivided, never created from nothing.
3. **Replenished only through explicit authority**: a suspended agent may only be resumed if budget is replenished by a parent or an authorized settlement adapter.
4. **Auditable at every boundary**: grant, transfer, exhaustion, and replenishment all produce audit events.

### Energy Flow

```
Root Agent (1,000,000 energy)
  |
  +-- sys_spawn(blockchain_agent, energy=500,000)
  |     Root remaining: 500,000
  |
  +-- Blockchain Agent (500,000 energy)
       |
       +-- sys_spawn(ping_agent, energy=10,000)
       |     Blockchain remaining: 490,000
       |
       +-- Ping Agent (10,000 energy)
            +-- Each syscall: -1
            +-- Each timer tick: -1
            +-- energy == 0 -> Suspended
            +-- Parent can replenish via sys_energy_grant
```

### Cost Table

| Operation | Energy Cost |
|-----------|------------|
| Syscall | 1 |
| Timer tick | 1 |
| Frame allocation | 10 |
| Disk read (per sector) | 100 |
| Disk write (per sector) | 200 |
| Network request | 500 |
| Mailbox creation | 50 |
| WASM fuel unit | 1 |

### Where Energy Lives

Energy is stored as a `u64` field (`energy_budget`) in each Agent struct, inside the kernel's in-memory `AGENT_TABLE`. It is not on disk unless a checkpoint is taken via `sys_checkpoint`.

Consumed energy is tracked in `CUMULATIVE_ENERGY[agent_id]` — a per-agent counter for accounting and billing. The `accountd` system agent exposes this via mailbox queries.

---

## Trust Model: Verifiable Execution, Not Replicated Consensus

### How Ethereum Achieves Trust

Every node executes the same transaction independently. Results are compared through consensus. Tampering is rejected by majority vote.

**Cost**: extreme redundancy (N nodes repeat the same work).

### How ATOS Achieves Trust

One node executes the workload. The node produces a signed **ExecutionReceipt** containing cryptographic commitments to the code, input, output, state transition, and energy consumed. Any third party can replay the checkpoint to verify the receipt.

**Cost**: minimal (verification only when disputed).

### Four Layers of Evidence

```
Layer 1: Execution Determinism
  WASM fuel counting + deterministic scheduler
  Same input -> guaranteed same output

Layer 2: State Proofs
  Merkle state tree -> every mutation produces a root hash
  Anyone can verify inclusion/exclusion of any key

Layer 3: Execution Receipts (Stage-9)
  ExecutionReceipt {
    code_hash, input_commitment, output_commitment,
    initial_state_root, final_state_root,
    energy_used, node_id, signature
  }

Layer 4: Optional Replay
  Checkpoint + event log -> any node can fully replay
  and verify the receipt is honest
```

### Honest Comparison

| | Ethereum | ATOS |
|--|----------|-----|
| When is verification done? | Before (all nodes compute) | After (replay on dispute) |
| Who verifies? | All full nodes | Any party with the checkpoint |
| Tampering consequence | Block rejected (consensus) | Signer held accountable (cryptographic evidence) |
| Trust assumption | Majority of nodes are honest | At least one verifier is willing to check |
| Performance cost | Extreme (N-fold redundancy) | Minimal (verify only when needed) |
| Can prevent tampering? | Yes (consensus rejects bad blocks) | No, but detects it with certainty |
| Can prevent censorship? | Partially (other nodes include tx) | No (single node can refuse to execute) |

**ATOS cannot prevent a node from refusing to execute or withholding results.** This requires a consensus layer. But ATOS can guarantee that any submitted result is verifiable.

---

## ATOS + gtos: Execution Engine + Settlement Layer

ATOS does computation. gtos (blockchain) does notarization. Each does what it is best at.

### Architecture

```
+------------------------------------------------------------------+
|                   gtos (Blockchain Layer - Notary)                |
|                                                                  |
|  ATOSNodeRegistry.tol     ATOSReceiptAnchor.tol                    |
|    - register nodes        - store receipt hashes                |
|    - attestation             - immutable audit trail             |
|    - reputation              - dispute mechanism                 |
|                                                                  |
|  ATOSEnergySettlement.tol                                         |
|    - deposit TOS/USDC/fiat -> energy credits                     |
|    - settle consumed energy from receipts                        |
|    - refund unused balance                                       |
+-------------------------------+----------------------------------+
                                |
                     Event push | Receipt submit
                                |
+-------------------------------+----------------------------------+
|                   ATOS Node (Execution Layer)                     |
|                                                                  |
|  bridge_agent: listens to gtos events, injects energy            |
|  user agents: execute workloads at bare-metal speed              |
|  produces: ExecutionReceipt + checkpoint + proof                 |
+------------------------------------------------------------------+
```

### Interaction Model

There are three phases with three different speeds:

| Phase | Where | Latency | Frequency |
|-------|-------|---------|-----------|
| **Deposit** | gtos on-chain | ~seconds | Once / occasionally |
| **Execution** | ATOS direct | **milliseconds** | Every request |
| **Settlement** | gtos on-chain | ~seconds | Batched / periodic |

The hot path (execution) never touches the chain. Only the cold paths (deposit and settlement) go on-chain.

### Detailed Flow

```
Step 1: DEPOSIT (on-chain, one-time)
  User -> gtos: ATOSEnergySettlement.deposit(nodeA) payable
  gtos records: nodeA.balance += 1,000,000 energy
  gtos emits: Deposited(nodeA, user, 1000000)

Step 2: EXECUTE (ATOS direct, milliseconds, repeated)
  User -> ATOS nodeA: "Run this inference task"
  ATOS bridge_agent: validates credential, checks energy balance
  ATOS kernel: creates Agent, executes (~10ms), charges energy
  ATOS -> User: returns result directly (no chain involved)

Step 3: SETTLE (on-chain, batched)
  ATOS nodeA -> gtos: ATOSReceiptAnchor.submitReceipt(hash, stateRoot, 48320)
  gtos -> gtos: ATOSEnergySettlement.settle(hash, nodeA, 48320)
  nodeA.balance -= 48320
```

After the initial deposit, the user interacts **directly with ATOS** for all execution. This is essential — if every AI inference call had to go through a blockchain transaction, the system would be unusable.

### Analogy

This is identical to how transit cards work:

| Transit Card | ATOS + gtos |
|-------------|------------|
| Top up card at machine (slow, once) | Deposit TOS on gtos (slow, once) |
| Tap card on bus (fast, every ride) | Call ATOS API (fast, every request) |
| Transit company reconciles with bank (daily batch) | ATOS submits receipts to gtos (periodic batch) |

---

## Payment Agnosticism

ATOS is a **payment-agnostic execution engine**. It sells compute (energy), not a specific token. What can buy energy is determined by the settlement adapter layer outside the kernel.

```
         Payment Sources
              |
   +----------+----------+
   |          |          |
   v          v          v
+--------+ +--------+ +--------+
|gtos TOS| |USDC/ETH| | Fiat   |
|on-chain| |bridge  | | Stripe |
+---+----+ +---+----+ +---+----+
    |          |          |
    v          v          v
+-------------------------------------+
|     Settlement Adapter Layer         |
|                                      |
|  Verify payment proof               |
|  Convert to energy units:           |
|    1 TOS  = 100,000 energy           |
|    1 USDC = 500,000 energy           |
|    1 USD  = 500,000 energy           |
+------------------+------------------+
                   |
                   | sys_energy_grant (unified interface)
                   v
          +------------------+
          |   ATOS Kernel     |
          |                  |
          |  Root Agent      |
          |  energy += N     |  <- kernel only sees energy
          |                  |     no concept of currency
          +------------------+
```

The kernel's `energy_grant()` function:

```rust
pub fn grant(from_id: AgentId, to_id: AgentId, amount: u64) -> Result<(), i64>
```

It does not know or care whether the energy came from TOS tokens, USDC, a credit card, or an enterprise prepayment. It only enforces:

- Does `from` have enough energy?
- Is `to` a child of `from`?
- Deduct from `from`, add to `to`
- Emit audit event

### ExecutionReceipt Billing Fields

The Stage-9 receipt design includes:

```
energy_used: u64           // how much energy was consumed
pricing_class: u32         // what pricing tier applies
payer_ref: PrincipalRef    // who paid (traces back to payment source)
```

This allows the settlement layer to reconcile: "this energy was consumed, it was paid for by this principal, through this payment channel, at this price."

---

## The Three gtos Contracts (tolang)

### ATOSNodeRegistry.tol

Registers ATOS execution nodes on-chain with their attestation hashes and public keys. Tracks reputation and allows slashing of dishonest nodes.

### ATOSReceiptAnchor.tol

Stores ATOS execution receipt hashes on-chain for immutable audit trails. Supports dispute resolution — anyone with a replay proof can challenge a receipt.

### ATOSEnergySettlement.tol

Manages energy credit deposits and consumption settlement. External payers deposit tokens, ATOS nodes draw energy, and receipts prove consumption for billing.

---

## From VM to RM: ATOS as a Hardware-Native Ethereum

### The Core Insight

Ethereum's EVM is a **Virtual Machine** — it executes deterministic, metered, capability-scoped computation, but it is trapped inside a host OS process. It cannot drive hardware, cannot schedule autonomously, and cannot execute unless triggered by an external transaction.

ATOS takes the same computational model and turns it into a **Real Machine** — an operating system that runs directly on x86_64 hardware, drives its own devices, and executes agents on its own schedule.

```
EVM: Smart contract bytecode → runs inside geth → runs inside Linux → runs on hardware
ATOS: Agent code (WASM/native) → runs on ATOS kernel → runs on hardware (direct)
```

### Structural Isomorphism

The conceptual mapping between EVM and ATOS is nearly 1:1:

| EVM (Virtual Machine) | ATOS (Real Machine) | Why It Matters |
|---|---|---|
| Smart Contract | Agent | Both are isolated execution units with explicit identity |
| Gas | Energy Budget | Both meter execution cost and prevent infinite loops |
| msg.sender + require() | Capability token | Both enforce explicit authorization on every action |
| Storage (slot-based) | State Object (keyspace) | Both provide structured, Merkle-backed persistent state |
| Transaction | Mailbox Message | Both are the unit of inter-entity communication |
| Transaction Receipt | ExecutionReceipt (Stage-9) | Both prove what happened during execution |
| Merkle Patricia Trie | Merkle State Tree | Both enable external state verification without full replay |
| EVM bytecode | WASM bytecode | Both are deterministic, fuel-metered instruction sets |
| Genesis Block | ATOS Genesis (§4.5) | Both bootstrap the initial authority, state, and budget |
| Contract deployment | Agent spawn (sys_spawn) | Both create new execution units with delegated resources |
| SELFDESTRUCT | sys_exit | Both terminate an execution unit and reclaim resources |
| DELEGATECALL | Capability delegation | Both allow controlled authority transfer |
| Block number | Kernel tick counter | Both provide a logical clock for ordering |
| Event logs (LOG0-LOG4) | Audit event log | Both emit structured, indexable execution evidence |

### What ATOS Adds Beyond EVM

The EVM model has fundamental limitations that ATOS overcomes by being a real operating system:

#### 1. Hardware Control

EVM has zero hardware access — it runs inside a process on a host OS. ATOS drives hardware directly:

- **NVMe/ATA storage**: persistent state without relying on a host filesystem
- **NIC (e1000/virtio-net)**: network access brokered through the netd system agent
- **LAPIC timer**: preemptive scheduling at 100 Hz, no external trigger needed
- **PCI bus**: device discovery and initialization at boot

#### 2. Autonomous Execution

EVM contracts are **passive** — they execute only when an external transaction arrives. Between transactions, they are inert.

ATOS agents are **active** — the kernel's timer interrupt drives preemptive scheduling. Agents can:

- Run continuously without external triggers
- Wake on timer ticks (periodic tasks, heartbeats, monitoring)
- Block on mailbox receive and resume when a message arrives
- Execute background computation across scheduling quanta

This is the difference between a **stored procedure** (EVM) and a **running process** (ATOS).

#### 3. Multiple Runtime Backends

EVM supports exactly one bytecode format (EVM opcodes). ATOS supports three:

| Runtime | Use Case | Determinism |
|---------|----------|-------------|
| **Native x86_64** | High-performance agents, system services | Partial (scheduling-level) |
| **WASM** | Portable, deterministic, proof-grade agents | Full (fuel-counted) |
| **eBPF-lite** | Kernel-resident policy enforcement | Full (verified, bounded) |

An agent platform can mix runtimes: system agents (stated, policyd, netd) run native for performance, while user agents run in WASM for deterministic replay and proof.

#### 4. Asynchronous IPC

EVM's CALL opcode is **synchronous and nested** — contract A calls contract B, which calls contract C, all within a single transaction's call stack. This creates reentrancy vulnerabilities and deep stack coupling.

ATOS uses **asynchronous mailbox messaging** — agent A sends a message to agent B's mailbox and continues (or blocks waiting for a reply). There is no shared call stack. This eliminates reentrancy by design and enables natural concurrency patterns.

#### 5. Multi-Core Parallelism

EVM is **strictly single-threaded** — one transaction executes at a time, globally ordered. This is a fundamental throughput bottleneck.

ATOS supports **SMP multi-core** scheduling — multiple agents execute in parallel on different CPU cores, with spinlock-protected shared kernel structures. Cross-core communication uses the same mailbox IPC.

#### 6. Brokered Resource Access

EVM has no concept of external resource access from within the VM. Oracles are external hacks bolted on through transactions.

ATOS has **system agents as resource brokers**:

- **netd**: network access (HTTP, UDP) gated by CAP_NETWORK capability
- **stated**: persistent state management for shared keyspaces
- **policyd**: eBPF-lite policy loading and management
- **accountd**: energy accounting queries

Every resource access is capability-checked, metered, and audit-logged — the same trust model as the core execution, extended to I/O.

### Why This Matters

The EVM proved that **metered, capability-scoped, deterministic execution with Merkle-backed state** is a powerful model for trustless computation. But it was designed as a component embedded inside a blockchain node, not as a standalone system.

ATOS takes that proven model and asks: what if the execution engine **was** the operating system? What if it could drive its own hardware, schedule its own agents, manage its own storage, and produce its own verifiable receipts — without depending on a host OS or requiring global consensus for every computation?

The result is an execution substrate that inherits the trust properties of a smart contract platform while operating at bare-metal speed with full hardware sovereignty.

```
Ethereum's path:    Hardware → Linux → geth → EVM → Smart Contract
ATOS's path:        Hardware → ATOS kernel → Agent (direct)
```

One is a VM living inside software layers. The other is the machine itself.

---

## Summary

| Question | Answer |
|----------|--------|
| Is ATOS a blockchain? | No. It does not replicate execution across nodes. |
| Is ATOS a traditional OS? | No. It enforces capability-scoped authority and energy budgets at the kernel level. |
| What is ATOS? | A bare-metal verifiable execution engine for autonomous agents. |
| How does it achieve trust? | Signed receipts + Merkle state proofs + deterministic replay. |
| How does it handle payments? | Payment-agnostic. Settlement adapters convert any currency to energy. |
| Where is the entry point? | Deposit on gtos (once), then interact directly with ATOS (milliseconds). |
| What does gtos do? | Notarization: stores receipt hashes, manages deposits, handles disputes. |
| What does ATOS do? | Execution: runs agents at bare-metal speed, produces verifiable receipts. |
