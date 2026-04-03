# TODO: Proof-Capable Smart Contract Platform

## Goal

Turn TOS into a proof-capable smart contract platform where a deployed contract can:

- execute inside the WASM runtime with explicit energy accounting,
- read and write persistent on-chain state,
- call other contracts through a stable kernel-mediated ABI,
- emit execution receipts that are useful to external verifiers,
- produce proof and replay artifacts that can be checked outside the node,
- upgrade through a package pipeline with verifiable integrity and controlled rollback.

This plan is focused on contract execution, state, package trust, and proof surfaces. It assumes the Linux substrate and runtime-semantic groundwork already completed in the earlier plans.

## Current Baseline

### Already strong

- Versioned persistent state exists (state.rs, 1,753 lines).
- Merkle roots and Merkle proofs exist (merkle.rs, 256 lines).
- Durable state logging and crash recovery exist with CRC32 validation (persist.rs, 1,432 lines).
- Execution receipts with SHA-256 commitments exist (receipts.rs, 807 lines).
- Proof bundles with Merkle sibling hashes exist (proof.rs, 382 lines).
- Replay bundles with checkpoint restore exist (replay.rs, 343 lines).
- Attestation with TPM 2.0 CRB support exists (attestation.rs, 413 lines).
- The WASM runtime (wasbi), fuel accounting, selector dispatch, and mailbox-driven execution loop exist (wasm_agent.rs, 569 lines).
- Contract registry, inter-contract call protocol, and package format exist.

### Main gaps

- The WASM host ABI only exposes 6 basic functions (yield, send, recv, exit, energy_get, log). Contracts cannot access persistent state or call other contracts through the host ABI.
- Atomic multi-key state transactions do not exist. Only single-key put/get is supported. Contract execution that touches multiple keys cannot roll back atomically on failure.
- Package signing uses FNV-1a hash in the atp CLI tool, not Ed25519. Deploy trust is not cryptographically sound.
- Replay and proof artifacts are not yet tied tightly enough to contract-visible state transitions and deterministic external verification.
- The contract test surface is too small for a system that aims to be verifier-friendly.

## Phase 1: Complete The Contract Host ABI

### Objective

Make WASM contracts capable of doing real work: reading/writing persistent state, calling other contracts, and knowing their own identity.

### Required work

- Add host functions for contract identity:
  - `self_id() → contract_id` — the current contract's identity
  - `caller_id() → contract_id` — who initiated this call (external caller or another contract)
  - `block_height() → u64` — current execution tick / block height
- Add host functions for contract state access:
  - `state_get(key_ptr, key_len, val_ptr, val_cap) → i32` — read a value from the contract's keyspace; returns actual length or negative error
  - `state_put(key_ptr, key_len, val_ptr, val_len) → i32` — write a value to the contract's keyspace
  - `state_delete(key_ptr, key_len) → i32` — delete a key from the contract's keyspace
- Add host functions for contract invocation:
  - `contract_call(target_id, selector, input_ptr, input_len, output_ptr, output_cap) → i32` — synchronous inter-contract call; returns output length or negative error
  - `contract_call_readonly(target_id, selector, input_ptr, input_len, output_ptr, output_cap) → i32` — read-only call; callee cannot mutate state
- Add proof-oriented state introspection:
  - `state_root() → [u8; 32]` — current contract keyspace Merkle root
- Add atomic state transaction support to the kernel:
  - `StateTransaction` type with begin/commit/rollback semantics
  - All state mutations during a contract call go through a `StateTransaction`
  - On successful return: commit all writes atomically
  - On revert/out-of-energy/error: roll back all writes
  - This is a prerequisite for Phase 2 (proof binding requires atomic transitions)
- Define stable memory ABI rules for all host calls:
  - pointer validation (must be within WASM linear memory bounds)
  - bounded copy semantics (never read/write beyond declared lengths)
  - explicit error codes (documented i32 return values)
  - deterministic energy charging per host call operation
- Ensure all host calls are reflected in receipt-relevant execution metadata (read set, write set, call trace).

### Exit criteria

- A storage contract can set, get, overwrite, and delete keys through the WASM host ABI.
- A contract can call another contract and receive a deterministic return payload.
- A contract can query its own identity and the caller's identity.
- A failed contract call rolls back all state mutations atomically.
- State access and contract-call failures return stable, documented error codes.
- Energy is charged consistently for all host ABI operations.

## Phase 2: Bind Contract State To Proof Artifacts

### Objective

Make contract-visible state transitions first-class proof material instead of side effects that happen outside the proof surface.

### Required work

- Define the contract state transition record per execution:
  - pre-state root (Merkle root before execution)
  - post-state root (Merkle root after execution)
  - read set commitment (hash of all keys read and their values)
  - write set commitment (hash of all keys written and their new values)
  - call trace commitment (hash of all inter-contract calls made)
- Extend `ExecutionReceipt` so contract executions expose:
  - contract_id
  - code_hash
  - function selector or exported entrypoint name
  - input_commitment (SHA-256 of calldata)
  - output_commitment (SHA-256 of return data)
  - pre_state_root
  - post_state_root
  - read_set_commitment
  - write_set_commitment
  - call_trace_commitment
  - energy_used
  - proof_bundle_reference
- Route all WASM host state operations through `StateTransaction` (from Phase 1).
- Add deterministic rollback behavior:
  - failed contract → all state mutations reverted
  - failed sub-call → sub-call state reverted, parent continues (or reverts depending on error handling)
  - out-of-energy → all state reverted, receipt still emitted with energy_used = budget
- Make Merkle proof export usable for per-key storage verification:
  - `state_merkle_proof(key) → MerkleProof` available via receipt/proof bundle
  - external verifier can check "key K had value V at state root R"

### Exit criteria

- A contract write changes the committed state root in a deterministic, verifiable way.
- A failed contract call does not partially commit state.
- Receipts for contract execution contain all fields listed above.
- A verifier can validate a storage Merkle proof against the recorded state root.
- The read/write set commitments in the receipt match a recomputation from the proof bundle.

## Phase 3: Make Package Deploy And Upgrade Trustworthy

### Objective

Turn package handling into a verifiable deployment path rather than a convenience wrapper around raw code installation.

### Required work

- Replace FNV-1a package signing with Ed25519:
  - atp CLI signs with Ed25519 private key
  - kernel verifies Ed25519 signature at install time
  - reject unsigned or invalid-signature packages
- Bind package identity to:
  - code_hash (SHA-256 of WASM bytecode)
  - manifest_hash (SHA-256 of manifest fields)
  - declared entrypoints (exported function selectors)
  - required capabilities
  - publisher public key
- Make deploy prefer package-driven flows over raw byte deployment:
  - reject deployment of raw WASM without a signed manifest
  - validate code_hash matches actual bytecode at install time
- Tighten upgrade semantics:
  - pre-upgrade checkpoint of contract state (full keyspace snapshot)
  - install new package version
  - run optional migration entrypoint (`_migrate` export)
  - if migration fails: rollback to checkpoint, restore old package
  - if migration succeeds: commit new state, update package registry
  - emit upgrade receipt binding: old_code_hash, new_code_hash, old_state_root, new_state_root
- Record deploy and upgrade metadata in:
  - persistent package registry (contract.rs)
  - execution receipts
  - audit trail

### Exit criteria

- An unsigned or tampered package is rejected at install time.
- A successful package install produces a stable package identity derived from code_hash + manifest_hash.
- A failed upgrade restores the previous working package and state.
- A successful upgrade emits a receipt that binds old package identity, new package identity, and resulting state root.
- atp CLI uses Ed25519 signing throughout (no FNV-1a).

## Phase 4: Strengthen Proof And Replay For External Verification

### Objective

Make proof artifacts suitable for a verifier pipeline instead of only for local structural inspection.

### Required work

- Define a verifier-facing bundle format for contract execution:
  - self-contained (no external dependencies to verify)
  - includes: contract code hash, package identity, calldata digest, return-data digest, pre/post state root, Merkle proofs for all touched keys, energy used, receipt signature
- Tighten the relationship between:
  - execution receipt (what happened)
  - proof bundle (compact cryptographic evidence)
  - replay bundle (full re-execution materials)
  - attestation payload (hardware trust anchor)
- Promote replay from structural validation toward deterministic re-checking:
  - replay bundle must include: contract WASM bytecode, calldata, pre-state snapshot (all keys the contract read), energy budget
  - a replay verifier loads these inputs, re-executes via wasbi, and compares: output, post-state root, energy used
  - any mismatch indicates tampering or non-determinism bug
- Add negative-path verification tests:
  - tampered receipt (modified field → signature check fails)
  - tampered proof bundle (modified sibling hash → Merkle root mismatch)
  - mismatched state roots (receipt says X, proof says Y → rejected)
  - truncated replay bundle (missing inputs → replay fails deterministically)

### Future extension

The receipt and proof bundle format should be designed so that a future
phase can wrap the WASM interpreter (wasbi) as an SP1 or RISC Zero guest
program and produce ZK proofs alongside replay bundles. This is not Phase 4
scope, but the format must not preclude it. Specifically:

- The public inputs of a future ZK proof would be: code_hash, calldata_digest, pre_state_root, post_state_root, energy_used
- These fields are already in the receipt; the ZK proof would attest to the same claim as the replay bundle but without requiring the verifier to re-execute
- The proof bundle format should reserve an optional `zk_proof` field (empty until ZK integration is implemented)

### Exit criteria

- A contract execution can be exported as a self-contained verifier-facing bundle.
- Tampering with receipt contents, state roots, or proof linkage is detected by the verification pipeline.
- Replay artifacts are sufficient for deterministic external re-execution that reproduces the claimed state transition.
- The bundle format has a reserved extension point for future ZK proofs.

## Phase 5: Expand The Contract Validation Surface

### Objective

Replace smoke-level validation with contract-focused regression coverage.

### Required work

- Contract storage validation suite:
  - put/get/delete
  - overwrite existing key
  - read non-existent key (returns error, not panic)
  - multi-key atomic transaction: commit on success, rollback on failure
  - state root changes after write, unchanged after read-only call
  - large value handling (values > 256 bytes)
- Contract-to-contract validation suite:
  - nested call (A calls B, B returns result to A)
  - readonly call (callee cannot write state)
  - error propagation (callee reverts → caller sees error code)
  - cycle detection or bounded failure (A calls B calls A → handled gracefully)
  - energy budget forwarding (caller specifies energy budget for callee)
  - caller/self identity correctness across call chain
- Package lifecycle validation suite:
  - install signed package → success
  - install unsigned package → rejected
  - install tampered package (code hash mismatch) → rejected
  - upgrade with migration → new state root
  - upgrade with migration failure → rollback to old state
  - downgrade / rollback → restore previous version
- Proof validation suite:
  - receipt generation for each operation type
  - proof bundle Merkle verification
  - replay bundle re-execution verification
  - tamper detection (modified receipt / proof / replay)
  - state Merkle proof for individual key verification
- Long-run stability:
  - 1000 sequential contract calls → state root consistent
  - 100 deploy/upgrade cycles → package registry consistent
  - energy accounting across nested calls → total matches sum of parts

### Exit criteria

- All validation suites pass consistently.
- No state leak between contract calls (post-test state root matches expected).
- No energy leak (total charged == sum of all host call costs + WASM fuel consumed).

## Phase 6: Publish A Verifier-Ready Contract Profile

### Objective

Define the minimum product shape that is honest, testable, and externally consumable.

### Required work

- Write a concise contract execution profile document:
  - supported WASM version (MVP, no extensions)
  - complete host function ABI reference (function signatures, error codes, energy costs)
  - receipt format specification
  - proof bundle format specification
  - replay bundle format specification
  - package format and signing specification
  - upgrade model and rollback guarantees
  - explicitly listed unsupported features
- Provide one command path for the full lifecycle:
  - `atp build <source.wasm> -o <package.tos>` — build package
  - `atp sign <package.tos> --key <key.pem>` — sign with Ed25519
  - TCP Deploy request → install package on TOS node
  - TCP Call request → execute contract function
  - TCP GetReceipt → fetch execution receipt
  - TCP GetProof → fetch proof bundle
  - TCP GetReplay → fetch replay bundle
- Provide one end-to-end example contract:
  - persistent state (counter or token balance)
  - inter-contract call (one contract calls another)
  - proof retrieval and verification walkthrough
  - step-by-step documentation from build to verification
- Provide a standalone verifier tool:
  - `tos-verify receipt <receipt.bin>` — check receipt signature
  - `tos-verify proof <proof.bin> --receipt <receipt.bin>` — check Merkle proofs against receipt state roots
  - `tos-verify replay <replay.bin>` — re-execute and compare output/state root

### Exit criteria

- A developer can deploy a contract package, execute it, and retrieve verifier-facing artifacts using the documented flow.
- The documented flow matches the implemented host ABI and package pipeline exactly.
- The example contract is covered by automated regression tests.
- The standalone verifier tool can detect tampered receipts, proofs, and replays.

## Priority Order

1. Phase 1: Complete the contract host ABI (blocking — nothing works without this)
2. Phase 2: Bind contract state to proof artifacts (core value proposition)
3. Phase 3: Make package deploy and upgrade trustworthy (production trust)
4. Phase 4: Strengthen proof and replay for external verification (verifier pipeline)
5. Phase 5: Expand the contract validation surface (quality assurance)
6. Phase 6: Publish a verifier-ready contract profile (external consumability)

## Effort Estimate

| Phase | Effort | Key dependency |
|-------|--------|----------------|
| Phase 1 | 3-4 weeks | None (can start immediately) |
| Phase 2 | 2-3 weeks | Phase 1 (needs host ABI + StateTransaction) |
| Phase 3 | 2 weeks | Phase 1 (needs working contracts to test deploy) |
| Phase 4 | 2-3 weeks | Phase 2 (needs state-bound receipts) |
| Phase 5 | 2-3 weeks | Phase 1-4 (tests all prior work) |
| Phase 6 | 1-2 weeks | Phase 1-5 (documents all prior work) |

Total: approximately 12-17 weeks for the full platform.

## Definition Of Done

TOS can reasonably claim to be a proof-capable smart contract platform when all of the following are true:

- WASM contracts can persist state and call other contracts through a stable host ABI.
- Contracts know their own identity and their caller's identity.
- All state mutations are atomic (commit on success, rollback on failure).
- Contract execution results are bound to committed state transitions via receipts.
- Deploy and upgrade flows are package-based, Ed25519-signed, and rollback-safe.
- Receipts, proof bundles, and replay bundles are coherent and externally verifiable.
- The proof bundle format reserves an extension point for future ZK proofs.
- Contract-focused regression suites pass for storage, calls, packages, and proofs.
- A standalone verifier tool can check receipts, proofs, and replays.
- There is a documented end-to-end flow that a third party can follow without relying on internal knowledge.
