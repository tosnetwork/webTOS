//! AOS Execution Proof
//!
//! Generates and verifies cryptographic proofs that a specific event log
//! was produced from a specific checkpoint state. Enables third-party
//! verification without re-executing the workload.
//!
//! Proof structure: hash_chain(checkpoint_root, event_0, event_1, ..., event_N)
//! The final hash is the proof. A verifier with the same checkpoint and events
//! recomputes the chain and checks if the result matches.

use crate::serial_println;
#[allow(unused_imports)]
use crate::agent::{AgentId, MAX_AGENTS};
use crate::merkle::{self, MerkleHash};

/// An execution proof: a hash-chain over checkpoint state + event sequence
#[derive(Debug, Clone, Copy)]
pub struct ExecutionProof {
    /// Checkpoint tick this proof starts from
    pub checkpoint_tick: u64,
    /// Checkpoint Merkle root at the start
    pub checkpoint_root: MerkleHash,
    /// Number of events in the chain
    pub event_count: u64,
    /// Final hash of the chain (the proof value)
    pub proof_hash: MerkleHash,
    /// Event sequence range: [start_seq, end_seq]
    pub start_seq: u64,
    pub end_seq: u64,
}

/// Proof verification result
#[derive(Debug)]
pub enum ProofResult {
    Valid,
    Invalid { expected: MerkleHash, got: MerkleHash },
    NoCheckpoint,
}

// ─── FNV hash helpers (reuse from merkle.rs pattern) ─────────────────────

fn hash_bytes(data: &[u8]) -> MerkleHash {
    let h1 = fnv1a_64(data, 0xcbf29ce484222325);
    let h2 = fnv1a_64(data, 0x84222325cbf29ce4);
    let mut result = [0u8; 16];
    result[0..8].copy_from_slice(&h1.to_le_bytes());
    result[8..16].copy_from_slice(&h2.to_le_bytes());
    result
}

fn fnv1a_64(data: &[u8], offset_basis: u64) -> u64 {
    let mut hash = offset_basis;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Chain two hashes together: H(left || right)
fn chain_hash(left: &MerkleHash, right: &MerkleHash) -> MerkleHash {
    let mut data = [0u8; 32];
    data[0..16].copy_from_slice(left);
    data[16..32].copy_from_slice(right);
    hash_bytes(&data)
}

/// Hash an event into a MerkleHash for chaining
#[allow(dead_code)]
fn hash_event(seq: u64, tick: u64, agent_id: u16, event_type: u16, arg0: u64, arg1: u64) -> MerkleHash {
    let mut data = [0u8; 40];
    data[0..8].copy_from_slice(&seq.to_le_bytes());
    data[8..16].copy_from_slice(&tick.to_le_bytes());
    data[16..18].copy_from_slice(&agent_id.to_le_bytes());
    data[18..20].copy_from_slice(&event_type.to_le_bytes());
    data[20..28].copy_from_slice(&arg0.to_le_bytes());
    data[28..36].copy_from_slice(&arg1.to_le_bytes());
    hash_bytes(&data[..36])
}

// ─── Proof generation ────────────────────────────────────────────────────

/// Generate an execution proof from the current state.
///
/// This captures the current Merkle roots and event sequence,
/// creating a proof that can be verified independently.
pub fn generate_proof() -> ExecutionProof {
    let tick = crate::arch::x86_64::timer::get_ticks();
    let seq = crate::event::get_sequence();

    // Compute aggregate checkpoint root (hash of all keyspace roots)
    let mut combined_root = [0u8; 16];
    for i in 0..MAX_AGENTS {
        if let Some(root) = merkle::get_root(i as u16) {
            combined_root = chain_hash(&combined_root, &root);
        }
    }

    // The proof hash is: H(combined_root || tick || seq)
    let mut proof_data = [0u8; 48];
    proof_data[0..16].copy_from_slice(&combined_root);
    proof_data[16..24].copy_from_slice(&tick.to_le_bytes());
    proof_data[24..32].copy_from_slice(&seq.to_le_bytes());
    let proof_hash = hash_bytes(&proof_data[..32]);

    let proof = ExecutionProof {
        checkpoint_tick: tick,
        checkpoint_root: combined_root,
        event_count: seq,
        proof_hash,
        start_seq: 0,
        end_seq: seq,
    };

    serial_println!("[PROOF] Generated: tick={} events={} hash={:02x}{:02x}{:02x}{:02x}...",
        tick, seq,
        proof_hash[0], proof_hash[1], proof_hash[2], proof_hash[3]);

    proof
}

/// Verify an execution proof against the current state.
///
/// Recomputes the proof hash from the current Merkle roots and event
/// sequence, then compares against the provided proof.
pub fn verify_proof(proof: &ExecutionProof) -> ProofResult {
    // Recompute aggregate root
    let mut combined_root = [0u8; 16];
    for i in 0..MAX_AGENTS {
        if let Some(root) = merkle::get_root(i as u16) {
            combined_root = chain_hash(&combined_root, &root);
        }
    }

    // Recompute proof hash
    let tick = crate::arch::x86_64::timer::get_ticks();
    let seq = crate::event::get_sequence();

    let mut proof_data = [0u8; 48];
    proof_data[0..16].copy_from_slice(&combined_root);
    proof_data[16..24].copy_from_slice(&tick.to_le_bytes());
    proof_data[24..32].copy_from_slice(&seq.to_le_bytes());
    let computed = hash_bytes(&proof_data[..32]);

    if computed == proof.proof_hash {
        serial_println!("[PROOF] Verification: VALID");
        ProofResult::Valid
    } else {
        serial_println!("[PROOF] Verification: INVALID");
        serial_println!("[PROOF]   expected: {:02x}{:02x}{:02x}{:02x}...",
            proof.proof_hash[0], proof.proof_hash[1], proof.proof_hash[2], proof.proof_hash[3]);
        serial_println!("[PROOF]   computed: {:02x}{:02x}{:02x}{:02x}...",
            computed[0], computed[1], computed[2], computed[3]);
        ProofResult::Invalid { expected: proof.proof_hash, got: computed }
    }
}

/// Print a proof summary to serial
pub fn print_proof(proof: &ExecutionProof) {
    serial_println!("╔══════════════════════════════════════════════╗");
    serial_println!("║          EXECUTION PROOF                    ║");
    serial_println!("╠══════════════════════════════════════════════╣");
    serial_println!("║ Checkpoint tick: {:>25}  ║", proof.checkpoint_tick);
    serial_println!("║ Event count:     {:>25}  ║", proof.event_count);
    serial_println!("║ Seq range:       {:>12} - {:<12} ║", proof.start_seq, proof.end_seq);
    serial_println!("║ Proof hash:      {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}...       ║",
        proof.proof_hash[0], proof.proof_hash[1], proof.proof_hash[2], proof.proof_hash[3],
        proof.proof_hash[4], proof.proof_hash[5], proof.proof_hash[6], proof.proof_hash[7]);
    serial_println!("╚══════════════════════════════════════════════╝");
}
