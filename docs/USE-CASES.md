# TOS Use Cases

TOS is a minimal trusted execution substrate for autonomous agents. It is not a general-purpose operating system. Its value comes from a unique combination of capabilities that no single existing platform provides together:

- Deterministic execution with cryptographic receipts
- Capability-based agent isolation
- Energy metering (execution budgets)
- Cross-node agent migration
- SHA-256 Merkle state proofs
- Ed25519 signed authority chains
- TPM 2.0 measured boot attestation

This document describes 13 application scenarios where these capabilities provide real value, each with a concrete usage example.

---

## 1. Trusted AI Agent Execution

**Problem**: AI agents (LangChain, AutoGPT, custom models) run in opaque environments. Clients cannot verify what the agent actually did, whether it consumed the claimed resources, or whether the output is authentic.

**How TOS solves it**:

```
User → deploys AI agent as WASM package (.tos)
TOS → executes in ProofGrade mode (deterministic, no floats/SIMD)
     → generates ExecutionReceipt with:
       - code_hash (what ran)
       - input_commitment / output_commitment (what went in and came out)
       - initial_state_root / final_state_root (how state changed)
       - energy_used (how much compute was consumed)
       - Ed25519 signature (which node attests to the result)
Third party → verifies receipt offline without re-executing
```

**Example**: A legal tech company deploys an AI contract review agent. The client submits a 50-page contract as input. TOS runs the agent in ProofGrade mode, producing a receipt that proves: the exact model version `code_hash=0xA3F2...` processed input `input_commitment=0x7B01...`, consumed 340,000 energy units, and produced output `output_commitment=0xE891...`. The client's auditor verifies the receipt with the verifier SDK — no need to re-run the model or trust the provider's infrastructure.

**Target users**: AI SaaS providers, enterprise AI automation, AI auditing platforms.

**Key TOS features used**: RuntimeClass (ProofGrade), ExecutionReceipt, Ed25519 signing, fuel metering.

---

## 2. Billable Compute Marketplace

**Problem**: Decentralized compute networks (Akash, Golem, Flux) lack fine-grained, verifiable billing. Providers can overcharge; requesters can dispute without evidence.

**How TOS solves it**:

```
Compute provider → runs TOS nodes
Requester → submits WASM workload + energy budget
TOS → executes with fuel metering
     → produces receipt (energy_used, pricing_class, state transition proof)
Requester → verifies receipt, settles payment based on actual consumption
```

No blockchain consensus needed for billing — the receipt itself is the verifiable invoice. Cheaper than Ethereum (no global re-execution), more trustworthy than AWS Lambda (cryptographic proof of execution).

**Example**: A machine learning team submits a feature engineering WASM module to a compute marketplace. They pre-pay 1,000,000 energy units. The TOS node executes the module, consuming 847,293 energy units. The receipt shows `energy_used=847293`, `pricing_class=2` (ProofGradeWasm). The quotad agent estimated 900,000 before execution — close to actual. The team pays only for 847,293 units. The billingd agent aggregates this into their monthly invoice, keyed by their `principal_id`.

**Target users**: Decentralized compute networks, pay-per-use AI inference, edge compute billing.

**Key TOS features used**: FuelCosts (dynamic metering), ExecutionReceipt, quotad (cost estimation), billingd (settlement).

---

## 3. Regulated Computation with Compliance Audit

**Problem**: Financial and healthcare computation must prove it followed specific rules. Current systems rely on trust in the operator, not cryptographic evidence.

**How TOS solves it**:

```
Regulator → defines policy bundle (eBPF rules + authority roots)
Enterprise → runs regulated computation on TOS
TOS → enforces policy at every capability check
     → emits authority audit trail (AuthGrant/AuthDeny/AuthRevoke events)
     → generates receipt with policy_bundle_hash + policy_decision_commitment
Regulator → verifies receipt + audit trail offline
```

The receipt proves: this code ran, under this policy, with this authority, producing this state change. No need to trust the operator's word.

**Example**: A bank runs an anti-money-laundering (AML) screening agent on TOS. The regulator provides a policy bundle that restricts the agent to: read-only access to the transaction keyspace, no network capability, 60-second execution timeout (energy limit). TOS enforces these rules — the agent cannot `sys_send` because it lacks `SendMailbox` capability. After execution, the receipt includes `policy_bundle_hash=0x9C44...` and the auditd log shows exactly which capabilities were checked and whether each was granted or denied. The regulator's compliance tool verifies the receipt against the known-good policy hash.

**Target users**: Financial institutions, healthcare data processing, government compliance systems.

**Key TOS features used**: PolicyBundle, authd/auditd, capability leases with expiry, receipt authority_commitment.

---

## 4. Edge AI Inference Nodes

**Problem**: AI inference on edge devices (autonomous vehicles, IoT, defense) must prove the model ran correctly and was not tampered with. Edge devices cannot run full Linux + container stacks.

**How TOS solves it**:

```
Cloud → packages AI model as signed .tos WASM package
Edge device → boots TOS (bare metal, no Linux, ~100KB kernel)
           → ProofGrade execution + generates receipt
Cloud → verifies inference result authenticity via receipt
```

TOS boots in milliseconds on bare metal, runs WASM with deterministic execution, and produces a cryptographic receipt — all without an OS, container runtime, or network dependency.

**Example**: An autonomous vehicle manufacturer deploys a pedestrian detection model on edge compute units inside each vehicle. The model is compiled to WASM, signed with Ed25519 (`atp build model.wasm -o detector.tos && atp sign detector.tos`), and installed via pkgd. Every inference run produces a receipt with `code_hash` matching the signed package. After an incident, the manufacturer can prove to regulators: "This exact model version ran, on an attested device (TPM PCR 0 = kernel hash), and produced this classification output at tick 47,291." The TPM measured boot chain proves the TOS kernel itself was unmodified.

**Target users**: Autonomous vehicle verification, IoT secure inference, aerospace/defense.

**Key TOS features used**: no_std bare-metal boot, wasbi (WASM engine), ProofGrade RuntimeClass, UEFI boot, TPM 2.0 measured boot, .tos signed packages.

---

## 5. Multi-Party Computation Coordination

**Problem**: Multiple parties need to compute on private data and share results, but neither party trusts the other's execution environment.

**How TOS solves it**:

```
Party A → submits agent (processes A's private data in encrypted keyspace)
Party B → submits agent (processes B's private data in encrypted keyspace)
TOS → executes both in isolated keyspaces (capability prevents cross-access)
     → agents exchange results via mailbox (no direct memory access)
     → each party receives the other's ExecutionReceipt as evidence
     → neither party sees the other's raw data
```

Agent isolation (capability-scoped access) + encrypted keyspaces + receipts provide a lightweight multi-party computation framework without MPC protocols or TEE hardware.

**Example**: Hospital A and Hospital B want to jointly train a disease prediction model without sharing patient records. Each hospital deploys an agent on TOS that computes gradient updates from their local data (stored in their encrypted keyspace). The agents exchange only aggregated gradients via mailbox — never raw patient data. Each round produces two receipts. Hospital A can verify Hospital B's receipt to confirm: the correct model code ran (`code_hash`), the state changed as expected (`final_state_root`), and the computation consumed the agreed energy budget. Neither hospital can read the other's keyspace because neither holds the `StateRead` capability for the other's keyspace.

**Target users**: Federated learning, cross-institutional data collaboration, privacy-preserving analytics.

**Key TOS features used**: Capability isolation, encrypted keyspaces, mailbox IPC, ExecutionReceipt.

---

## 6. Off-Chain Execution Layer for gtos L1

**Problem**: Layer 1 blockchains cannot scale complex computation on-chain. Every validator re-executing every transaction is the bottleneck.

**How TOS solves it**:

```
gtos L1 → submits complex computation to TOS execution node
TOS → ProofGrade WASM execution
     → generates ExecutionReceipt with:
       - initial_state_root (Merkle root before)
       - final_state_root (Merkle root after)
       - trace_commitment (syscall transcript hash)
gtos → verifies receipt (fast: check signature + state roots)
     → optionally generates Halo 2 ZK proof from receipt + transcript
     → on-chain: verify proof in O(1), no re-execution needed
```

This is TOS's most strategic use case. The ExecutionReceipt format is designed to feed directly into gtos's Halo 2 proving pipeline. TOS provides the trusted execution; gtos provides the consensus and settlement.

**Example**: A DeFi protocol on gtos needs to compute a complex portfolio rebalancing across 10,000 positions — too expensive for on-chain execution. The protocol submits the rebalancing logic as a WASM agent to an TOS execution node. TOS runs it in ProofGrade mode, recording every syscall in the transcript. The receipt shows `initial_state_root=0x1A2B...` → `final_state_root=0x5C6D...` with `energy_used=2,400,000`. The gtos node feeds the receipt + ReplayBundle into its Halo 2 prover (`tos-prover`), which generates a SNARK proof that the state transition is valid. On-chain, validators verify the 5KB proof in 2ms — no need to re-execute the 2.4M-instruction computation.

**Target users**: gtos / TOS Network, any L1/L2 needing verifiable off-chain execution.

**Key TOS features used**: ProofGrade WASM (wasbi), ExecutionReceipt, SHA-256 Merkle state roots, replay transcript, ReplayBundle/ProofBundle.

---

## 7. Autonomous Agent Orchestration

**Problem**: Complex workflows require multiple agents cooperating across machines — but agents crash, machines fail, and state gets lost.

**How TOS solves it**:

```
Orchestrator → spawns agents across TOS nodes via routerd
Agent A (Node 1) → processes data, sends result to Agent B via cross-node mailbox
Agent B (Node 2) → receives, processes, updates state
Node 2 fails → failover_d detects via membership_d heartbeat timeout
            → restores Agent B from PortableCheckpoint on Node 3
            → Agent B resumes with full state + authority context preserved
```

Agent state, authority, and mailbox continuity survive node failures. The checkpoint includes not just data but the agent's capability set and energy budget.

**Example**: A logistics company runs a multi-agent supply chain optimization system. Agent A (demand forecasting) runs on Node 1 in a US data center. Agent B (route planning) runs on Node 2 in Europe. Agent A completes its forecast and sends the result to Agent B via `SYS_SEND_REMOTE` — routerd wraps the message with a signed RoutingHeader and delivers over UDP. Midway through Agent B's computation, Node 2 crashes. The membership_d on Node 1 detects the missed heartbeat after 30 seconds. failover_d finds Agent B in its watch list, queries placement_d for the best alternate node (Node 3, in the same region, with available energy), and restores Agent B from its last PortableCheckpoint. Agent B resumes with its full keyspace state, capability set, and remaining energy budget intact.

**Target users**: Multi-agent AI systems, distributed workflow engines, resilient automation.

**Key TOS features used**: PortableCheckpoint, routerd (cross-node routing with Ed25519 verification), membership_d, failover_d, placement_d, SYS_SEND_REMOTE.

---

## 8. Zero-Trust Remote Administration

**Problem**: Traditional systems use SSH/shell for remote administration, which grants broad access and is difficult to audit. Compromised SSH keys can lead to complete system takeover.

**How TOS solves it**:

```
Operator → sends signed admin command via mailbox to admind
admind → verifies operator's principal_id + capability lease
       → checks policy bundle allows the operation
       → executes command (STATUS, AGENT_LIST, AGENT_KILL, etc.)
       → emits audit event for every admin action
       → returns result via mailbox
```

No shell, no SSH, no root login. Every admin action goes through authenticated, capability-checked, audited mailbox messages.

**Example**: A cloud operator needs to check the health of an TOS appliance and terminate a misbehaving agent. They send a `STATUS` (0x01) command to admind's mailbox using their Ed25519-signed principal credential. admind verifies the principal is active (not revoked), checks the capability lease hasn't expired, and returns system metrics: 12 agents running, 847M energy consumed, 3.2M syscalls processed. The operator then sends `AGENT_KILL` (0x03) for agent ID 7 — admind verifies the operator holds the `AgentTerminate` capability, terminates the agent, and emits an `AuthGrant` audit event. The entire interaction is recorded in auditd's log — who did what, when, under what authority.

**Target users**: Cloud operators, managed service providers, security-conscious enterprises.

**Key TOS features used**: admind (mailbox-based administration), capability leases with expiry, authd/auditd, Ed25519 principal verification, no shell access.

---

## 9. Verifiable AI Training Pipeline

**Problem**: AI model training can be tampered with — poisoned data, modified hyperparameters, or swapped model checkpoints. Downstream consumers have no way to verify the training process was legitimate.

**How TOS solves it**:

```
Training pipeline → each training step is an TOS agent
                  → each step produces a receipt with:
                    - code_hash (training code version)
                    - input_commitment (dataset hash)
                    - output_commitment (model checkpoint hash)
                    - initial_state_root → final_state_root (parameter changes)
                    - trace_commitment (full syscall transcript)
Auditor → chains the receipts to verify: correct code + correct data → correct model
```

**Example**: A pharmaceutical company trains a drug interaction prediction model. The training has 3 steps: data preprocessing, model training, and evaluation. Each step runs as a ProofGrade WASM agent on TOS. The preprocessing agent produces receipt R1 with `output_commitment=hash(cleaned_dataset)`. The training agent takes `input_commitment=hash(cleaned_dataset)` (matching R1's output) and produces receipt R2 with `output_commitment=hash(model_weights)`. The evaluation agent takes the model weights and test data, producing receipt R3 with the accuracy score in its output. An FDA auditor can chain R1→R2→R3 to verify: the correct preprocessing code ran on the declared dataset, the correct training code produced the model, and the evaluation used the same model. Any tampering breaks the hash chain.

**Target users**: Pharma/biotech model validation, AI safety auditing, ML governance platforms.

**Key TOS features used**: ProofGrade execution, ExecutionReceipt chain (input_commitment matches prior output_commitment), transcript, code_hash verification.

---

## 10. Cross-Organization Agent Delegation

**Problem**: Organizations need to grant temporary, scoped execution authority to partners — but traditional API keys are all-or-nothing and don't expire safely.

**How TOS solves it**:

```
Org A → creates capability lease for Org B:
        - scope: read Org A's public data keyspace
        - expiry: 24 hours
        - delegation_depth: 0 (B cannot re-delegate)
        - Ed25519 signed by Org A's principal
Org B → deploys agent on TOS with the leased capability
TOS → enforces expiry on every capability check
     → after 24 hours, Org B's agent loses access automatically
```

**Example**: A supply chain consortium has 5 organizations. Org A (manufacturer) grants Org B (logistics) a 48-hour read capability on its inventory keyspace, with `delegation_depth=1` so Org B can sub-delegate to its trucking partner Org C. Org B's agent reads inventory levels and sends logistics plans to Org A via mailbox. After 48 hours, `is_expired()` returns true and all of Org B's (and Org C's) access is revoked — no manual cleanup needed. If Org A discovers Org B is misbehaving, it sends a REVOKE command to authd, which immediately adds Org B's principal to the revocation list. The next time Org B's agent tries any capability-gated operation, `is_principal_revoked()` blocks it.

**Target users**: Supply chain consortiums, B2B data sharing, temporary partner access.

**Key TOS features used**: Capability leases (expiry_ticks, delegation_depth), Ed25519 signed delegation, authd revocation, automatic expiry enforcement.

---

## 11. Metered API Gateway

**Problem**: Traditional API billing is based on request counts or time — not actual computation consumed. Providers eat the cost of expensive queries; consumers overpay for cheap ones.

**How TOS solves it**:

```
API consumer → sends request to TOS-backed API endpoint
TOS → quotad estimates cost before execution
     → consumer confirms or rejects
     → execution runs with fuel metering
     → receipt shows exact energy_used
     → billingd aggregates by principal_id
     → monthly invoice reflects actual computation, not request count
```

**Example**: A data analytics API charges per computation, not per request. A simple lookup costs 500 energy units; a complex aggregation costs 50,000. Consumer submits a query — quotad returns an estimate of 12,000 energy units. Consumer approves. TOS executes and produces a receipt with `energy_used=11,847`. The consumer pays for 11,847 units. Next month, billingd produces an invoice for the consumer's `principal_id` showing: 342 requests, 2,847,291 total energy, $28.47 at $0.00001/energy. Every line item is backed by a verifiable receipt.

**Target users**: API-as-a-service platforms, metered SaaS, compute-intensive API providers.

**Key TOS features used**: quotad (pre-execution cost estimation), FuelCosts (per-instruction metering), billingd (per-principal aggregation), ExecutionReceipt.

---

## 12. Signed Software Supply Chain

**Problem**: Software supply chain attacks (SolarWinds, Log4j) exploit the gap between "code was built" and "code is running." There's no cryptographic proof that the binary running in production matches the signed source.

**How TOS solves it**:

```
Developer → atp build agent.wasm -o agent.tos
         → atp sign agent.tos (Ed25519 signature over manifest + code hash)
CI/CD    → atp verify agent.tos (checks signature + code hash)
         → submits to pkgd on TOS node
pkgd     → verifies manifest signature
         → checks code_hash matches actual binary
         → installs package
TOS     → every execution receipt includes code_hash
         → TPM measured boot proves kernel integrity
         → full chain: developer → build → sign → deploy → execute → receipt
```

**Example**: A security team deploys a threat detection agent. The developer builds `threat_detector.tos` with `atp build`, signs it with the team's Ed25519 key, and pushes to the TOS node. pkgd verifies the signature matches the team's registered principal. On every execution, the receipt includes `code_hash=0xB7F3...` which matches the signed manifest. If an attacker tries to swap the binary, the code hash won't match the signed manifest — pkgd rejects the installation. If the attacker compromises the kernel, the TPM PCR values change — remote attestation fails. The chain is: signed source → verified build → attested kernel → receipt-proven execution.

**Target users**: Security-sensitive deployments, government/military, regulated industries.

**Key TOS features used**: atp CLI (build/sign/verify), pkgd (signature verification), .tos package format, TPM 2.0 measured boot, ExecutionReceipt code_hash.

---

## 13. Disaster Recovery Orchestration

**Problem**: When infrastructure fails, restoring distributed agent workloads requires manual intervention — finding checkpoints, re-provisioning, restoring state, and re-establishing authority.

**How TOS solves it**:

```
Normal operation:
  failover_d → watches critical agents via WATCH_AGENT
  membership_d → monitors node heartbeats

Node failure detected:
  membership_d → reports NODE_DOWN to failover_d
  failover_d → for each affected agent:
    1. Queries placement_d for best alternate node
    2. Loads PortableCheckpoint (state + authority + energy)
    3. Restores agent on alternate node
    4. Emits AgentMigrate event for audit trail
```

**Example**: A financial services firm runs 50 TOS agents across 5 nodes for real-time risk calculation. Node 3 (hosting 12 agents) suffers a hardware failure. Within 30 seconds, membership_d on the remaining nodes detect the missed heartbeat. failover_d identifies the 12 affected agents from its watch table. For each agent, it queries placement_d — which selects the node with the most available energy and matching hardware class. The agents are restored from their PortableCheckpoints on Nodes 1, 2, 4, and 5, resuming with their full keyspace state, capability sets, and remaining energy budgets. The firm's monitoring dashboard (connected to observabilityd) shows the migration events in real time. Total recovery time: under 60 seconds, zero data loss, zero manual intervention.

**Target users**: Financial services, critical infrastructure, high-availability enterprise systems.

**Key TOS features used**: failover_d (automated recovery), membership_d (heartbeat monitoring), placement_d (intelligent node selection), PortableCheckpoint (full state + authority serialization), routerd (cross-node coordination).

---

## What TOS Is Not For

| Scenario | Why not |
|----------|---------|
| Desktop / server OS | No file system, no POSIX, no GUI, no shell |
| High-throughput transaction processing | Direct interpreter, not JIT — use wasmi or wasmtime |
| General container orchestration | No Docker / Kubernetes compatibility |
| Hard real-time systems | No real-time scheduling guarantees |
| Running existing Linux applications | No Linux syscall compatibility (Stage 12, future) |

---

## One-Line Positioning

**TOS is the minimum trusted execution substrate that makes external systems believe "this code really ran the way it claims."**
