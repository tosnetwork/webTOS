# Revm EVM Integration — Porting Plan

**Status:** Design Document
**Companion to:** Yellow Paper §27.8 (Stage-11)

> This document describes how to integrate [revm](https://github.com/bluealloy/revm), a production-grade pure Rust Ethereum Virtual Machine, into ATOS as a native agent runtime. Solidity and Vyper smart contracts run on ATOS unmodified — gas maps to energy, storage maps to keyspaces, contract calls map to mailbox messages.

---

## 1. Why EVM on ATOS

EVM and ATOS share the same design philosophy:

| EVM Principle | ATOS Equivalent | Alignment |
|--------------|----------------|-----------|
| Gas-metered execution | Energy budget per agent | **Identical** — both solve the halting problem via fuel |
| Deterministic execution | ProofGrade mode | **Identical** — same input always produces same output |
| Isolated storage per contract | Keyspace per agent | **Identical** — no shared mutable state |
| Inter-contract calls with value | Mailbox messages with energy transfer | **Direct mapping** |
| Immutable deployed bytecode | Agent binary integrity | **Compatible** |
| No ambient authority | Capability-based access | **ATOS is stricter** (capabilities vs. address-based) |

Smart contracts are the original "autonomous agents." ATOS is an agent execution platform. The fit is natural.

### What This Enables

- **Solidity/Vyper contracts** execute on ATOS with hardware isolation (Ring-3), not just software sandboxing
- **DeFi protocols** run as ATOS agents with capability-scoped authority and eBPF policy enforcement
- **Cross-chain bridges** become agent-to-agent mailbox communication
- **L2 execution** — ATOS can serve as a provable execution layer for Ethereum rollups
- **Smart contract auditing** — ProofGrade execution produces cryptographic proofs of contract behavior

## 2. Why revm

revm is the Rust Ethereum ecosystem's standard EVM implementation:

| Property | Value |
|----------|-------|
| Language | 99.6% Rust |
| `#![no_std]` | **Yes, native** — designed for embedded and WASM |
| Gas metering | Built-in, configurable per-instruction costs |
| Spec compliance | All EVM hard forks through Cancun/Prague |
| Production users | Reth, Foundry, Helios, Optimism, Base, Scroll |
| Stars / Contributors | 2.1K+ / 282 |
| License | MIT |
| Audit status | Battle-tested by L1/L2 production deployment |

## 3. Architecture

```
┌──────────────────────────────────────────────┐
│          Solidity / Vyper Source              │
│          compiled to EVM bytecode            │
├──────────────────────────────────────────────┤
│            revm Engine (no_std)              │
│   parse → execute → gas accounting           │
│   interpreter + precompiles                  │
├──────────────────────────────────────────────┤
│         ATOS Host Implementation             │
│   impl Host for AtosEvmHost                  │
│   storage → keyspace                         │
│   calls → mailbox                            │
│   logs → event subsystem                     │
├──────────────────────────────────────────────┤
│         ATOS Native Agent Runtime            │
│   allocator (sys_mmap) | entry point         │
├──────────────────────────────────────────────┤
│              ATOS Kernel                     │
│   sched | mailbox | capability | energy      │
└──────────────────────────────────────────────┘
```

From the kernel's perspective, the EVM agent is just another native agent with a mailbox and an energy budget. It happens to contain an EVM interpreter that executes Solidity bytecode.

## 4. Host Trait Implementation

revm defines a `Host` trait that provides the EVM with access to the external world. ATOS implements this trait by mapping to its own primitives:

```rust
use revm::{Host, SStoreResult, SelfDestructResult};

struct AtosEvmHost {
    agent_id: AgentId,
    keyspace: u16,
}

impl Host for AtosEvmHost {
    // Storage: SLOAD / SSTORE → keyspace
    fn sload(&mut self, address: Address, index: U256) -> (U256, bool) {
        let key = storage_key(address, index);
        match atos_sdk::state::get(self.keyspace, key) {
            Some((data, len)) => {
                let value = U256::from_le_bytes(&data[..32]);
                (value, false) // cold access
            }
            None => (U256::ZERO, false),
        }
    }

    fn sstore(&mut self, address: Address, index: U256, value: U256) -> SStoreResult {
        let key = storage_key(address, index);
        let bytes = value.to_le_bytes::<32>();
        atos_sdk::state::put(self.keyspace, key, &bytes);
        SStoreResult { .. }
    }

    // Logging: LOG0-LOG4 → ATOS event subsystem
    fn log(&mut self, log: Log) {
        atos_sdk::event::emit(
            log.topics[0].as_u64(),  // event signature as arg0
            log.data.len() as u64,   // data length as arg1
        );
    }

    // Contract call: CALL → mailbox message to target contract agent
    fn call(&mut self, inputs: &CallInputs) -> CallResult {
        let target_agent = address_to_agent_id(inputs.target_address);
        let payload = encode_call_payload(inputs);
        atos_sdk::send(target_agent, &payload);
        let response = atos_sdk::recv(self.agent_id);
        decode_call_result(&response)
    }

    // Balance: BALANCE → agent energy query
    fn balance(&mut self, address: Address) -> (U256, bool) {
        let agent = address_to_agent_id(address);
        let energy = atos_sdk::energy::query(agent);
        (U256::from(energy), false)
    }

    // Block info: BLOCKHASH, NUMBER, TIMESTAMP, etc.
    fn block_hash(&mut self, number: u64) -> B256 {
        // Derive from ATOS checkpoint hash at that block height
        B256::ZERO // simplified for Phase 1
    }

    // CREATE: deploy new contract → spawn new EVM agent
    fn create(&mut self, inputs: &CreateInputs) -> CreateResult {
        let bytecode = &inputs.init_code;
        // Spawn a new EVM agent with this bytecode
        let new_agent = atos_sdk::spawn_image(bytecode, RuntimeKind::Evm);
        CreateResult { address: agent_id_to_address(new_agent), .. }
    }
}
```

### 4.1 Storage Key Mapping

EVM storage is a 256-bit key → 256-bit value map per contract address. ATOS keyspace uses 64-bit keys and 256-byte values.

```
EVM: storage[address][slot] = value  (256-bit slot, 256-bit value)
ATOS: keyspace[key] = value          (64-bit key, 256-byte value)

Mapping: key = fnv_hash(address ++ slot)  →  64-bit keyspace key
         value = slot_value as [u8; 32]   →  stored in 256-byte keyspace value
```

For collision resistance, each contract agent has its **own keyspace** (isolated by agent_id). The slot index alone is sufficient as the key — no need to include the address.

### 4.2 Gas ↔ Energy Bridge

EVM gas costs map directly to ATOS energy:

```rust
// Configure revm with gas metering
let mut evm = Evm::builder()
    .with_gas_limit(agent_energy_budget)
    .build();

// After execution, sync remaining gas back to agent energy
let gas_used = result.gas_used();
update_agent_energy(agent_id, agent_energy_budget - gas_used);
```

The gas schedule (cost per opcode) is defined by the Ethereum specification and enforced by revm internally. ATOS does not need to define its own cost table — it uses Ethereum's.

### 4.3 Address ↔ Agent ID Mapping

EVM uses 20-byte addresses. ATOS uses 16-bit agent IDs. Mapping:

```
Agent → Address:  address = keccak256(agent_id)[0..20]
Address → Agent:  lookup table maintained by the EVM host agent

Contract deployment:
  CREATE → spawn new agent → compute address → register in lookup table
```

A dedicated **EVM registry agent** maintains the address-to-agent mapping, similar to Ethereum's account state trie but backed by ATOS keyspace.

## 5. Deployment Model

```
Developer workflow:
  solc MyContract.sol → MyContract.bin (EVM bytecode)
  atp build --runtime evm MyContract.bin → my-contract-1.0.0.tos
  atp install my-contract-1.0.0.tos

ATOS runtime:
  pkgd receives .tos package
  → detects runtime = evm
  → spawns EVM host agent with contract bytecode
  → agent registers its address in EVM registry
  → ready to receive calls via mailbox

Calling a contract:
  Any agent → sys_send(contract_mailbox, abi_encoded_call)
  Contract agent → revm executes bytecode → returns result
  Any agent ← sys_recv(own_mailbox, abi_encoded_result)
```

### 5.1 Solidity ABI Compatibility

Contract calls use standard Ethereum ABI encoding (function selector + parameters). This means existing Ethereum tooling (ethers.js, web3.py, foundry cast) can generate call payloads that ATOS EVM agents understand.

## 6. Implementation Phases

### Phase 1: Core Execution

**Goal:** A single Solidity contract executes on ATOS.

**Changes:**
1. Add `revm` dependency (default-features = false, no_std)
2. Create `src/evm/` module with `AtosEvmHost` implementing revm's `Host` trait
3. Implement SLOAD/SSTORE → keyspace mapping
4. Implement LOG → ATOS event emission
5. Gas limit set from agent energy budget
6. Entry point: agent receives EVM bytecode via mailbox → revm executes → returns result

**Test:** Deploy a simple Solidity counter contract, call `increment()`, verify storage updated in keyspace.

### Phase 2: Contract-to-Contract Calls

**Goal:** CALL/DELEGATECALL/STATICCALL between contract agents.

**Changes:**
1. Implement CALL → mailbox send/recv to target contract agent
2. Implement CREATE/CREATE2 → `sys_spawn_image` new EVM agent
3. EVM registry agent for address ↔ agent_id mapping
4. Energy (gas) forwarding on CALL (portion of caller's energy sent to callee)

**Test:** Contract A calls Contract B, B modifies its storage, A reads B's return value.

### Phase 3: Precompiles and Block Context

**Goal:** Full EVM compatibility including precompiled contracts and block metadata.

**Changes:**
1. Wire revm precompiles (ecrecover, sha256, ripemd160, modexp, bn128, blake2f)
2. Implement block context (number, timestamp, difficulty, basefee) from ATOS tick counter and checkpoint state
3. Implement COINBASE, CHAINID, SELFBALANCE from ATOS agent metadata

**Test:** Contract uses `ecrecover` to verify a signature, reads `block.timestamp`.

### Phase 4: Full Ethereum Compatibility

**Goal:** Run existing DeFi contracts (Uniswap, Aave) on ATOS.

**Changes:**
1. State snapshot and revert (ATOS checkpoint for EVM revert semantics)
2. SELFDESTRUCT → agent termination
3. Access list support (EIP-2930)
4. EIP-1559 fee logic (optional — ATOS has its own energy model)

**Test:** Deploy Uniswap V2 factory + pair contracts, execute a token swap.

## 7. Comparison: EVM on Ethereum vs. EVM on ATOS

| Aspect | Ethereum | ATOS |
|--------|----------|------|
| Execution isolation | Software sandbox (EVM) | **Hardware isolation** (Ring-3 + page tables) |
| Gas/Energy enforcement | Consensus rules | **Kernel-level timer-tick preemption + EVM gas** |
| Storage | Merkle Patricia Trie | **Keyspace with Merkle proofs** |
| Contract calls | Single-threaded within block | **Concurrent agent execution** (multi-core SMP) |
| Event logs | Bloom filter + RPC query | **Structured audit stream + ring buffer** |
| Upgradability | Proxy pattern (complex) | **atp upgrade** (atomic, rollback-safe) |
| Policy enforcement | None (all contracts equal) | **eBPF-lite filters** on every call |
| Execution proofs | Not native (requires re-execution) | **ProofGrade mode** (hash-chain proof) |

## 8. Security Model Upgrade

Running EVM on ATOS provides a strictly stronger security model than Ethereum mainnet:

| Attack | Ethereum | ATOS |
|--------|----------|------|
| Reentrancy | Possible (programmer must guard) | **Impossible** — contract calls are mailbox messages (async) |
| Gas griefing | Possible (63/64 rule) | **Mitigated** — energy budget is per-agent, not per-call |
| Storage collision | Possible (delegatecall) | **Impossible** — each agent has isolated keyspace |
| Front-running / MEV | Possible (mempool visible) | **Not applicable** — no public mempool, deterministic scheduling |
| Oracle manipulation | Possible | **Policy-gated** — eBPF filters on external data calls |

## 9. Relationship to Other Runtimes

| Runtime | Engine | Bytecode | Primary Use |
|---------|--------|----------|-------------|
| Native x86_64 | Direct | ELF64 | System agents |
| WASM | wasmi | .wasm | General-purpose sandbox |
| Python | RustPython | .py | AI/ML agents |
| JVM | Ristretto | .class/.jar | Enterprise agents |
| **EVM** | **revm** | **Solidity/Vyper bytecode** | **Smart contract agents, DeFi, L2 execution** |
| eBPF-lite | Self-built | eBPF bytecode | Kernel policy (not a user runtime) |

## 10. Non-Goals

- **Consensus mechanism** — ATOS is not a blockchain. There is no mining, staking, or block production. ATOS provides the execution layer; consensus (if needed) is an application-level concern.
- **ERC-20/ERC-721 token standards** — Tokens are just contracts. They work if the EVM works. No special kernel support needed.
- **JSON-RPC API** — Ethereum's `eth_call`, `eth_sendTransaction` interface is an application-level concern. An agent can expose this via netd if desired.
- **P2P networking** — ATOS uses its own routerd for cross-node communication, not Ethereum's devp2p.
