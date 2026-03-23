# AOS Architecture: Execution Engine + Settlement Layer

## What AOS Is

AOS is a **bare-metal verifiable execution engine** — it has the hardware control of an OS but operates under the trust model of a smart contract platform.

It is not a blockchain. It is not a traditional OS. It is a **payment-agnostic execution substrate** for autonomous agents, where authority is explicit, execution is auditable, state is durable, and computation is replayable and provable.

### One-Sentence Definition

> AOS is a from-scratch, VM-first, AI-native minimal operating system built around agents, mailboxes, capabilities, structured state, execution budgets, and auditable kernel behavior.

---

## AOS vs Smart Contract Platforms vs Traditional OS

| Concept | Ethereum | AOS | Traditional OS |
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

Energy in AOS behaves like rocket fuel: it is consumed by execution and cannot be recovered. It is **not** a token, not a coin, and not transferable outside the system.

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

### How AOS Achieves Trust

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

| | Ethereum | AOS |
|--|----------|-----|
| When is verification done? | Before (all nodes compute) | After (replay on dispute) |
| Who verifies? | All full nodes | Any party with the checkpoint |
| Tampering consequence | Block rejected (consensus) | Signer held accountable (cryptographic evidence) |
| Trust assumption | Majority of nodes are honest | At least one verifier is willing to check |
| Performance cost | Extreme (N-fold redundancy) | Minimal (verify only when needed) |
| Can prevent tampering? | Yes (consensus rejects bad blocks) | No, but detects it with certainty |
| Can prevent censorship? | Partially (other nodes include tx) | No (single node can refuse to execute) |

**AOS cannot prevent a node from refusing to execute or withholding results.** This requires a consensus layer. But AOS can guarantee that any submitted result is verifiable.

---

## AOS + gtos: Execution Engine + Settlement Layer

AOS does computation. gtos (blockchain) does notarization. Each does what it is best at.

### Architecture

```
+------------------------------------------------------------------+
|                   gtos (Blockchain Layer - Notary)                |
|                                                                  |
|  AOSNodeRegistry.tol     AOSReceiptAnchor.tol                    |
|    - register nodes        - store receipt hashes                |
|    - attestation             - immutable audit trail             |
|    - reputation              - dispute mechanism                 |
|                                                                  |
|  AOSEnergySettlement.tol                                         |
|    - deposit TOS/USDC/fiat -> energy credits                     |
|    - settle consumed energy from receipts                        |
|    - refund unused balance                                       |
+-------------------------------+----------------------------------+
                                |
                     Event push | Receipt submit
                                |
+-------------------------------+----------------------------------+
|                   AOS Node (Execution Layer)                     |
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
| **Execution** | AOS direct | **milliseconds** | Every request |
| **Settlement** | gtos on-chain | ~seconds | Batched / periodic |

The hot path (execution) never touches the chain. Only the cold paths (deposit and settlement) go on-chain.

### Detailed Flow

```
Step 1: DEPOSIT (on-chain, one-time)
  User -> gtos: AOSEnergySettlement.deposit(nodeA) payable
  gtos records: nodeA.balance += 1,000,000 energy
  gtos emits: Deposited(nodeA, user, 1000000)

Step 2: EXECUTE (AOS direct, milliseconds, repeated)
  User -> AOS nodeA: "Run this inference task"
  AOS bridge_agent: validates credential, checks energy balance
  AOS kernel: creates Agent, executes (~10ms), charges energy
  AOS -> User: returns result directly (no chain involved)

Step 3: SETTLE (on-chain, batched)
  AOS nodeA -> gtos: AOSReceiptAnchor.submitReceipt(hash, stateRoot, 48320)
  gtos -> gtos: AOSEnergySettlement.settle(hash, nodeA, 48320)
  nodeA.balance -= 48320
```

After the initial deposit, the user interacts **directly with AOS** for all execution. This is essential — if every AI inference call had to go through a blockchain transaction, the system would be unusable.

### Analogy

This is identical to how transit cards work:

| Transit Card | AOS + gtos |
|-------------|------------|
| Top up card at machine (slow, once) | Deposit TOS on gtos (slow, once) |
| Tap card on bus (fast, every ride) | Call AOS API (fast, every request) |
| Transit company reconciles with bank (daily batch) | AOS submits receipts to gtos (periodic batch) |

---

## Payment Agnosticism

AOS is a **payment-agnostic execution engine**. It sells compute (energy), not a specific token. What can buy energy is determined by the settlement adapter layer outside the kernel.

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
          |   AOS Kernel     |
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

### AOSNodeRegistry.tol

Registers AOS execution nodes on-chain with their attestation hashes and public keys. Tracks reputation and allows slashing of dishonest nodes.

### AOSReceiptAnchor.tol

Stores AOS execution receipt hashes on-chain for immutable audit trails. Supports dispute resolution — anyone with a replay proof can challenge a receipt.

### AOSEnergySettlement.tol

Manages energy credit deposits and consumption settlement. External payers deposit tokens, AOS nodes draw energy, and receipts prove consumption for billing.

---

## Summary

| Question | Answer |
|----------|--------|
| Is AOS a blockchain? | No. It does not replicate execution across nodes. |
| Is AOS a traditional OS? | No. It enforces capability-scoped authority and energy budgets at the kernel level. |
| What is AOS? | A bare-metal verifiable execution engine for autonomous agents. |
| How does it achieve trust? | Signed receipts + Merkle state proofs + deterministic replay. |
| How does it handle payments? | Payment-agnostic. Settlement adapters convert any currency to energy. |
| Where is the entry point? | Deposit on gtos (once), then interact directly with AOS (milliseconds). |
| What does gtos do? | Notarization: stores receipt hashes, manages deposits, handles disputes. |
| What does AOS do? | Execution: runs agents at bare-metal speed, produces verifiable receipts. |
