# RISC-V zkVM Integration — Design Document

**Status:** Design Document
**Companion to:** Yellow Paper §27.8 (Stage-11)

> This document describes how to integrate a RISC-V zero-knowledge virtual machine into ATOS, enabling cryptographic execution proofs that can be verified in O(1) time without re-execution. This upgrades ATOS from replay-based verification (ProofGrade) to **zero-knowledge proof-based verification** — the gold standard for trustless computation.

---

## 1. Why zkVM on ATOS

ATOS already has provable execution via ProofGrade mode (hash-chain replay). But replay verification requires re-executing the entire program. A zkVM generates a **succinct proof** that can be verified in milliseconds regardless of execution length:

| | ATOS ProofGrade (current) | ATOS + zkVM (proposed) |
|---|---|---|
| Proof generation | Record event hash chain | Generate ZK-SNARK/STARK |
| Verification time | **O(n)** — must replay entire execution | **O(1)** — verify proof in milliseconds |
| Verification trust | Must trust replay environment | **Zero trust** — math guarantees correctness |
| Proof size | Proportional to execution length | **Constant** (~200-400 KB regardless of program size) |
| Privacy | Execution is visible during replay | **Optional privacy** — prove result without revealing inputs |

### What This Enables

- **Trustless computation marketplace** — outsource computation to untrusted nodes, verify the proof, pay for results
- **Ethereum L2 rollup execution** — ATOS generates validity proofs for batches of transactions (zkRollup)
- **Verifiable AI agent execution** — prove an AI agent produced a specific output without revealing the model weights
- **Cross-node verification** — node A can verify node B's execution without re-running it
- **Alignment with Ethereum 2029 roadmap** — Ethereum plans to replace EVM with RISC-V based zkVM

## 2. Why RISC-V as the zkVM ISA

The ZK proof community has converged on RISC-V as the standard instruction set for zkVMs:

| ISA | ZK proof cost per instruction | Toolchain support | Status |
|-----|------------------------------|-------------------|--------|
| EVM | **Very high** (256-bit stack, complex opcodes) | Solidity only | Being phased out |
| WASM | High (complex control flow) | Many languages | Some zkWASM projects |
| **RISC-V** | **Low** (simple, regular instruction encoding) | **GCC, LLVM, Rust, Go, C, C++** | **Industry standard for zkVM** |

RISC-V's simplicity (32 base instructions, fixed-width encoding) makes ZK circuit construction efficient. Any language with LLVM backend (Rust, C, C++, Go) compiles to RISC-V.

## 3. Engine Selection

| Project | Developer | Language | Stars | Production Use |
|---------|-----------|---------|-------|---------------|
| **[SP1](https://github.com/succinctlabs/sp1)** | Succinct | **Rust** | 5K+ | Actively deployed, fastest prover |
| [RISC Zero](https://github.com/risc0/risc0) | RISC Zero | Rust | 2K+ | Production, STARK-based |
| [Jolt](https://github.com/a16z/jolt) | a16z | Rust | 1K+ | Research, novel lookup-based approach |

**Recommended: SP1** — most active development, fastest proving times, production-deployed, pure Rust, designed for embedding.

## 4. Architecture

```
┌──────────────────────────────────────────────┐
│       Program (Rust, C, Solidity, ...)       │
│       compiled to RISC-V ELF binary          │
├──────────────────────────────────────────────┤
│          SP1 zkVM Engine (Rust)              │
│   RISC-V interpreter + ZK proof generation   │
│   precompiles: sha256, keccak, secp256k1     │
├──────────────────────────────────────────────┤
│       ATOS Host I/O Interface                │
│   stdin/stdout → mailbox send/recv           │
│   hint oracle → keyspace lookup              │
├──────────────────────────────────────────────┤
│       ATOS Native Agent Runtime              │
│   allocator (sys_mmap) | entry point         │
├──────────────────────────────────────────────┤
│              ATOS Kernel                     │
│   sched | mailbox | capability | energy      │
└──────────────────────────────────────────────┘

Proof output:
  Agent executes program → SP1 generates STARK proof
  → proof stored in keyspace or sent via mailbox
  → any party verifies proof in O(1) time
```

### 4.1 Two Execution Modes

| Mode | Speed | Proof | Use Case |
|------|-------|-------|----------|
| **Execute** | Fast (~10x native) | No proof generated | Development, testing |
| **Prove** | Slow (~1000x native) | ZK proof generated | Production verification |

The agent chooses mode at spawn time via RuntimeClass:

```
RuntimeClass::BestEffort  → Execute mode (fast, no proof)
RuntimeClass::ProofGrade  → Prove mode (slow, generates ZK proof)
```

## 5. Integration Design

### 5.1 Host I/O Mapping

SP1 programs communicate with the host via a simple read/write interface. ATOS maps this to mailbox/keyspace:

| SP1 I/O | ATOS Mapping |
|---------|-------------|
| `sp1_zkvm::io::read::<T>()` | `sys_recv` from agent's mailbox (input) |
| `sp1_zkvm::io::write::<T>()` | `sys_send` to caller's mailbox (output) |
| `sp1_zkvm::io::hint()` | `sys_state_get` from keyspace (non-deterministic hint) |
| `sp1_zkvm::io::commit()` | Append to proof's public output |

### 5.2 Proof Lifecycle

```
1. Caller agent submits program + inputs:
   caller → sys_send(zkvm_agent_mailbox, { program_elf, inputs })

2. zkVM agent executes and generates proof:
   zkvm_agent receives program
   → SP1 executes RISC-V ELF
   → program reads inputs via io::read (mapped to mailbox)
   → program writes outputs via io::write (mapped to mailbox)
   → SP1 generates STARK proof

3. zkVM agent returns proof + outputs:
   zkvm_agent → sys_send(caller_mailbox, { proof, public_outputs })

4. Anyone can verify the proof:
   verifier calls SP1::verify(proof, public_outputs) → true/false
   Verification is O(1), independent of program execution time
```

### 5.3 Energy Mapping

zkVM execution is much more expensive than native execution (~1000x for proof generation). The energy model accounts for this:

```
Execute mode:  1 energy per ~10 RISC-V instructions (similar to native)
Prove mode:    1 energy per ~1 RISC-V instruction (proof generation dominates)
```

The agent's energy budget determines how large a program can be proven. This naturally creates a market: agents with more energy can prove larger computations.

### 5.4 Precompiles

SP1 includes hardware-accelerated precompiles for crypto operations:

| Precompile | Operation | Speedup vs. software |
|-----------|-----------|---------------------|
| SHA-256 | Hash | ~100x |
| Keccak-256 | Ethereum hash | ~100x |
| secp256k1 | ECDSA verify | ~100x |
| Ed25519 | EdDSA verify | ~100x |
| BN254 | Pairing (Ethereum) | ~50x |
| BLS12-381 | Pairing (beacon chain) | ~50x |

These precompiles are critical for blockchain use cases — signature verification and hashing inside a ZK proof is otherwise prohibitively expensive.

## 6. Use Cases

### 6.1 Ethereum L2 Rollup

ATOS as a zkRollup execution engine:

```
Sequencer agent:
  collects transactions → batches them
  → submits batch to zkVM agent

zkVM agent:
  executes batch via revm (compiled to RISC-V)
  → generates proof of correct execution
  → posts proof to Ethereum L1

Ethereum L1:
  verifies proof in O(1) → accepts state transition
```

### 6.2 Verifiable AI Agent

```
AI agent on ATOS:
  receives prompt → runs inference → produces response
  entire execution inside zkVM (compiled Rust model runner)
  → generates proof: "this model, with these weights, produced this output"

Verifier:
  checks proof → confirms output is genuine
  → no need to trust the node that ran the model
```

### 6.3 Trustless Cross-Node Computation

```
Node A: "Please compute fibonacci(1000000) for me"
  → sends request to Node B

Node B (untrusted):
  runs fibonacci in zkVM → generates proof
  → sends result + proof to Node A

Node A:
  verifies proof in 200ms → trusts the result
  → no need to re-execute or trust Node B
```

## 7. Implementation Phases

### Phase 1: SP1 Integration

**Goal:** Execute a RISC-V program on ATOS and generate a ZK proof.

**Changes:**
1. Add SP1 prover as a dependency (Rust crate)
2. Create `src/zkvm/` module with SP1 host integration
3. Implement host I/O → mailbox/keyspace mapping
4. New RuntimeKind::ZkVM for agent spawning
5. Entry point: agent receives RISC-V ELF + inputs → SP1 executes → returns proof

**Test:** Prove `fibonacci(100)` on ATOS, verify proof on a separate machine.

### Phase 2: Proof Verification Agent

**Goal:** Any agent can verify proofs without running the zkVM.

**Changes:**
1. Create `verifyd` system agent that accepts proof verification requests
2. Lightweight SP1 verifier (no prover needed — verification is fast)
3. Proof stored in keyspace with content hash

**Test:** Agent A generates proof, Agent B sends proof to verifyd, verifyd confirms validity.

### Phase 3: EVM-in-zkVM

**Goal:** Run Ethereum transactions inside the zkVM to generate validity proofs (zkRollup capability).

**Changes:**
1. Compile revm to RISC-V target (`riscv32im-succinct-zkvm-elf`)
2. SP1 program: load revm → execute transaction batch → output state diff
3. Proof covers: "these N transactions, starting from state root X, produce state root Y"

**Test:** Execute a batch of 10 ERC-20 transfers, generate proof, verify on Ethereum testnet.

### Phase 4: Recursive Proofs and Aggregation

**Goal:** Aggregate multiple proofs into a single proof for scalability.

**Changes:**
1. SP1 recursive proof composition
2. Batch proof aggregation: N individual proofs → 1 aggregate proof
3. Cross-agent proof chaining: Agent A's output proof feeds into Agent B's input

**Test:** 100 independent computations → 100 proofs → 1 aggregate proof → single verification.

## 8. Relationship to Other Runtimes

| Runtime | Bytecode | Proving | Use Case |
|---------|----------|---------|----------|
| Native x86_64 | ELF64 | No | System agents |
| WASM (wasmi) | .wasm | No (replay only) | General sandbox |
| EVM (revm) | Solidity | No (replay only) | Smart contracts |
| Python (RustPython) | .py | No | AI agents |
| JVM (Ristretto) | .class | No | Enterprise |
| **RISC-V zkVM (SP1)** | **RISC-V ELF** | **ZK proof** | **Trustless computation** |

The zkVM is not a replacement for other runtimes — it is an **orthogonal capability**. Any of the above runtimes can be compiled to RISC-V and run inside the zkVM when proof generation is needed:

```
Want fast execution?     → Use native runtime (no proof)
Want replay verification? → Use ProofGrade mode (hash-chain proof)
Want ZK verification?     → Compile to RISC-V → run in zkVM (ZK proof)
```

## 9. Non-Goals

- **Replace ProofGrade mode** — zkVM is complementary, not a replacement. ProofGrade (replay) is cheaper for cases where the verifier is trusted.
- **Hardware RISC-V support** — This is about RISC-V as a software VM for proof generation, not running ATOS on RISC-V hardware.
- **Custom ZK circuit language** — We use SP1's general-purpose approach (compile any Rust to RISC-V), not a DSL like Circom.
- **Consensus mechanism** — ATOS generates proofs. How they are submitted to a blockchain (if at all) is an application-level concern.

## 10. Strategic Alignment

```
Ethereum 2029 roadmap:  EVM → RISC-V zkVM
ATOS Stage-11 P3:       EVM (revm) → current Ethereum compatibility
ATOS Stage-11 P4:       RISC-V zkVM (SP1) → future Ethereum compatibility

By supporting both, ATOS is ready for Ethereum today AND tomorrow.
```

ATOS's architecture (deterministic execution, energy metering, capability isolation, structured audit) was designed for provable computation from day one. The zkVM integration is not a bolt-on — it is the natural culmination of ATOS's design principles.
