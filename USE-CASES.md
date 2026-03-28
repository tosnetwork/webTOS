# ATOS Use Cases

ATOS is a minimal trusted execution substrate for autonomous agents. It is not a general-purpose operating system. Its value comes from a unique combination of capabilities that no single existing platform provides together:

- Deterministic execution with cryptographic receipts
- Capability-based agent isolation
- Energy metering (execution budgets)
- Cross-node agent migration
- SHA-256 Merkle state proofs
- Ed25519 signed authority chains

This document describes the primary application scenarios where these capabilities provide real value.

---

## 1. Trusted AI Agent Execution

**Problem**: AI agents (LangChain, AutoGPT, custom models) run in opaque environments. Clients cannot verify what the agent actually did, whether it consumed the claimed resources, or whether the output is authentic.

**How ATOS solves it**:

```
User → deploys AI agent as WASM package (.tos)
ATOS → executes in ProofGrade mode (deterministic, no floats/SIMD)
     → generates ExecutionReceipt with:
       - code_hash (what ran)
       - input_commitment / output_commitment (what went in and came out)
       - initial_state_root / final_state_root (how state changed)
       - energy_used (how much compute was consumed)
       - Ed25519 signature (which node attests to the result)
Third party → verifies receipt offline without re-executing
```

**Target users**: AI SaaS providers, enterprise AI automation, AI auditing platforms.

**Key ATOS features used**: RuntimeClass (ProofGrade), ExecutionReceipt, Ed25519 signing, fuel metering.

---

## 2. Billable Compute Marketplace

**Problem**: Decentralized compute networks (Akash, Golem, Flux) lack fine-grained, verifiable billing. Providers can overcharge; requesters can dispute without evidence.

**How ATOS solves it**:

```
Compute provider → runs ATOS nodes
Requester → submits WASM workload + energy budget
ATOS → executes with fuel metering
     → produces receipt (energy_used, pricing_class, state transition proof)
Requester → verifies receipt, settles payment based on actual consumption
```

No blockchain consensus needed for billing — the receipt itself is the verifiable invoice. Cheaper than Ethereum (no global re-execution), more trustworthy than AWS Lambda (cryptographic proof of execution).

**Target users**: Decentralized compute networks, pay-per-use AI inference, edge compute billing.

**Key ATOS features used**: FuelCosts (dynamic metering), ExecutionReceipt, quotad (cost estimation), billingd (settlement).

---

## 3. Regulated Computation with Compliance Audit

**Problem**: Financial and healthcare computation must prove it followed specific rules. Current systems rely on trust in the operator, not cryptographic evidence.

**How ATOS solves it**:

```
Regulator → defines policy bundle (eBPF rules + authority roots)
Enterprise → runs regulated computation on ATOS
ATOS → enforces policy at every capability check
     → emits authority audit trail (AuthGrant/AuthDeny/AuthRevoke events)
     → generates receipt with policy_bundle_hash + policy_decision_commitment
Regulator → verifies receipt + audit trail offline
```

The receipt proves: this code ran, under this policy, with this authority, producing this state change. No need to trust the operator's word.

**Target users**: Financial institutions, healthcare data processing, government compliance systems.

**Key ATOS features used**: PolicyBundle, authd/auditd, capability leases with expiry, receipt authority_commitment.

---

## 4. Edge AI Inference Nodes

**Problem**: AI inference on edge devices (autonomous vehicles, IoT, defense) must prove the model ran correctly and was not tampered with. Edge devices cannot run full Linux + container stacks.

**How ATOS solves it**:

```
Cloud → packages AI model as signed .tos WASM package
Edge device → boots ATOS (bare metal, no Linux, ~100KB kernel)
           → ProofGrade execution + generates receipt
Cloud → verifies inference result authenticity via receipt
```

ATOS boots in milliseconds on bare metal, runs WASM with deterministic execution, and produces a cryptographic receipt — all without an OS, container runtime, or network dependency.

**Target users**: Autonomous vehicle verification, IoT secure inference, aerospace/defense.

**Key ATOS features used**: no_std bare-metal boot, wasbi (WASM engine), ProofGrade RuntimeClass, UEFI boot, small kernel footprint.

---

## 5. Multi-Party Computation Coordination

**Problem**: Multiple parties need to compute on private data and share results, but neither party trusts the other's execution environment.

**How ATOS solves it**:

```
Party A → submits agent (processes A's private data in encrypted keyspace)
Party B → submits agent (processes B's private data in encrypted keyspace)
ATOS → executes both in isolated keyspaces (capability prevents cross-access)
     → agents exchange results via mailbox (no direct memory access)
     → each party receives the other's ExecutionReceipt as evidence
     → neither party sees the other's raw data
```

Agent isolation (capability-scoped access) + encrypted keyspaces + receipts provide a lightweight multi-party computation framework without MPC protocols or TEE hardware.

**Target users**: Federated learning, cross-institutional data collaboration, privacy-preserving analytics.

**Key ATOS features used**: Capability isolation, encrypted keyspaces, mailbox IPC, ExecutionReceipt.

---

## 6. Off-Chain Execution Layer for gtos L1

**Problem**: Layer 1 blockchains cannot scale complex computation on-chain. Every validator re-executing every transaction is the bottleneck.

**How ATOS solves it**:

```
gtos L1 → submits complex computation to ATOS execution node
ATOS → ProofGrade WASM execution
     → generates ExecutionReceipt with:
       - initial_state_root (Merkle root before)
       - final_state_root (Merkle root after)
       - trace_commitment (syscall transcript hash)
gtos → verifies receipt (fast: check signature + state roots)
     → optionally generates Halo 2 ZK proof from receipt + transcript
     → on-chain: verify proof in O(1), no re-execution needed
```

This is ATOS's most strategic use case. The ExecutionReceipt format is designed to feed directly into gtos's Halo 2 proving pipeline. ATOS provides the trusted execution; gtos provides the consensus and settlement.

**Target users**: gtos / TOS Network, any L1/L2 needing verifiable off-chain execution.

**Key ATOS features used**: ProofGrade WASM (wasbi), ExecutionReceipt, SHA-256 Merkle state roots, replay transcript, ReplayBundle/ProofBundle.

---

## 7. Autonomous Agent Orchestration

**Problem**: Complex workflows require multiple agents cooperating across machines — but agents crash, machines fail, and state gets lost.

**How ATOS solves it**:

```
Orchestrator → spawns agents across ATOS nodes via routerd
Agent A (Node 1) → processes data, sends result to Agent B via cross-node mailbox
Agent B (Node 2) → receives, processes, updates state
Node 2 fails → failover_d detects via membership_d heartbeat timeout
            → restores Agent B from PortableCheckpoint on Node 3
            → Agent B resumes with full state + authority context preserved
```

Agent state, authority, and mailbox continuity survive node failures. The checkpoint includes not just data but the agent's capability set and energy budget.

**Target users**: Multi-agent AI systems, distributed workflow engines, resilient automation.

**Key ATOS features used**: PortableCheckpoint, routerd (cross-node routing), membership_d, failover_d, placement_d.

---

## What ATOS Is Not For

| Scenario | Why not |
|----------|---------|
| Desktop / server OS | No file system, no POSIX, no GUI, no shell |
| High-throughput transaction processing | Direct interpreter, not JIT — use wasmi or wasmtime |
| General container orchestration | No Docker / Kubernetes compatibility |
| Hard real-time systems | No real-time scheduling guarantees |
| Running existing Linux applications | No Linux syscall compatibility (Stage 12, future) |

---

## One-Line Positioning

**ATOS is the minimum trusted execution substrate that makes external systems believe "this code really ran the way it claims."**
