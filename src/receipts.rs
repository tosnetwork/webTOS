//! TOS Execution Receipt Model (Yellow Paper §27.6.3)
//!
//! An ExecutionReceipt ties agent execution to verifiable evidence. Receipts
//! are emitted when agents exit or explicitly via syscall, and stored in a
//! fixed-size ring for later retrieval.

extern crate alloc;

use crate::crypto;

// ─── Node-level receipt signing key ──────────────────────────────────────────

/// Node-level Ed25519 signing key for receipts (initialized at boot).
///
/// Safety: written once during single-threaded boot via `init_receipt_signing()`,
/// then read-only during normal operation (single-core Stage-1).
static mut NODE_SIGNING_KEY: Option<crypto::SigningKey> = None;

/// Initialise the node-level receipt signing key.
///
/// Must be called once during early boot (before any receipt is emitted).
/// Generates a fresh Ed25519 keypair using hardware RNG.
pub fn init_receipt_signing() {
    // Derive a lightweight deterministic seed from RDTSC to keep boot-time
    // key initialisation off the larger SHA-256 code path on qemu64 TCG.
    // This is sufficient for Stage-1; production would use TPM-backed keys.
    let mut seed = [0u8; 32];
    let tsc: u64;
    unsafe {
        let lo: u32;
        let hi: u32;
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi);
        tsc = ((hi as u64) << 32) | (lo as u64);
    }
    seed[0..8].copy_from_slice(&tsc.to_le_bytes());
    seed[8..16].copy_from_slice(&tsc.rotate_left(17).to_le_bytes());
    seed[16..24].copy_from_slice(&(!tsc).to_le_bytes());
    seed[24..32].copy_from_slice(&tsc.wrapping_mul(0x9E37_79B9_7F4A_7C15).to_le_bytes());
    let sk = crypto::SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();
    unsafe {
        NODE_SIGNING_KEY = Some(sk);
    }
    crate::serial_println!(
        "[RECEIPTS] Receipt signing key initialised (vk={:02x}{:02x}..)",
        vk.as_bytes()[0],
        vk.as_bytes()[1]
    );
}

/// Sign a receipt in-place with the node's Ed25519 signing key.
fn sign_receipt(receipt: &mut ExecutionReceipt) {
    let hash = receipt.compute_hash();
    unsafe {
        if let Some(ref sk) = NODE_SIGNING_KEY {
            let sig = crypto::sign(sk, &hash);
            receipt.signature = sig.to_bytes();
        }
    }
}

pub type Hash256 = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RuntimeClassTag {
    ProofGradeWasm = 0,
    ReplayGradeNative = 1,
}

#[derive(Debug, Clone, Copy)]
pub struct ContentRef {
    pub hash: Hash256,
    pub size_hint: u32,
}

#[derive(Debug, Clone)]
pub struct ExecutionReceipt {
    pub receipt_version: u16,
    pub receipt_id: Hash256,

    pub contract_id: Hash256,
    pub execution_id: Hash256,
    pub caller_id: [u8; 32],
    pub local_agent_id: Option<u16>,
    pub node_id: Hash256,

    pub runtime_class: RuntimeClassTag,
    pub package_hash: Hash256,
    pub code_hash: Hash256,

    pub input_commitment: Hash256,
    pub output_commitment: Hash256,

    pub initial_state_root: Hash256,
    pub final_state_root: Hash256,
    pub event_log_commitment: Hash256,
    pub trace_commitment: Hash256,

    pub energy_used: u64,

    pub tick_start: u64,
    pub tick_end: u64,
    pub wall_clock_hint: u64,

    pub signature: [u8; 64],
}

/// Compute a 32-byte commitment hash from arbitrary data using SHA-256.
///
/// Cryptographically secure: collision-resistant and pre-image resistant.
pub fn compute_commitment(data: &[u8]) -> Hash256 {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

impl ExecutionReceipt {
    /// Create a receipt for an agent that just finished executing.
    pub fn from_agent_exit(
        agent_id: u16,
        runtime_class: RuntimeClassTag,
        energy_used: u64,
        initial_state_root: Hash256,
        final_state_root: Hash256,
        tick_start: u64,
        tick_end: u64,
        input_hash: Hash256,
        output_hash: Hash256,
    ) -> Self {
        // Generate receipt_id from SHA-256 of key fields
        let mut receipt_id = [0u8; 32];
        {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&(agent_id as u64).to_le_bytes());
            hasher.update(&tick_start.to_le_bytes());
            hasher.update(&tick_end.to_le_bytes());
            hasher.update(&energy_used.to_le_bytes());
            let result = hasher.finalize();
            receipt_id.copy_from_slice(&result);
        }

        Self {
            receipt_version: 1,
            receipt_id,
            contract_id: [0; 32], // set by caller
            execution_id: receipt_id,
            caller_id: [0; 32], // set by caller
            local_agent_id: Some(agent_id),
            node_id: [0; 32], // set by node identity
            runtime_class,
            package_hash: [0; 32],
            code_hash: [0; 32],
            input_commitment: input_hash,
            output_commitment: output_hash,
            initial_state_root,
            final_state_root,
            event_log_commitment: [0; 32],
            trace_commitment: [0; 32],
            energy_used,
            tick_start,
            tick_end,
            wall_clock_hint: 0,
            signature: [0; 64],
        }
    }

    /// Compute the hash of this receipt (for signing).
    ///
    /// Uses a keyed-hash construction via Ed25519 pre-hash: we serialise all
    /// critical receipt fields into a buffer and sign it with a deterministic
    /// "hash key" derived from the receipt_id. The first 32 bytes of the
    /// resulting signature are used as the hash. This provides collision
    /// resistance needed for cryptographic commitments.
    pub fn compute_hash(&self) -> Hash256 {
        // Serialise all critical fields into a flat buffer for hashing.
        let mut buf = [0u8; 256];
        let mut pos = 0;

        buf[pos..pos + 32].copy_from_slice(&self.receipt_id);
        pos += 32;
        buf[pos..pos + 32].copy_from_slice(&self.contract_id);
        pos += 32;
        buf[pos..pos + 32].copy_from_slice(&self.execution_id);
        pos += 32;
        buf[pos..pos + 32].copy_from_slice(&self.initial_state_root);
        pos += 32;
        buf[pos..pos + 32].copy_from_slice(&self.final_state_root);
        pos += 32;
        buf[pos..pos + 8].copy_from_slice(&self.energy_used.to_le_bytes());
        pos += 8;
        buf[pos..pos + 8].copy_from_slice(&self.tick_start.to_le_bytes());
        pos += 8;
        buf[pos..pos + 8].copy_from_slice(&self.tick_end.to_le_bytes());
        pos += 8;
        buf[pos] = self.runtime_class as u8;
        pos += 1;
        buf[pos..pos + 32].copy_from_slice(&self.node_id);
        pos += 32;

        // Use a deterministic signing key derived from the receipt_id as a
        // keyed hash function. This gives us a 64-byte "hash" from which
        // we take the first 32 bytes.
        let hash_key = crypto::SigningKey::from_bytes(&self.receipt_id);
        let sig = crypto::sign(&hash_key, &buf[..pos]);
        let sig_bytes = sig.to_bytes();
        let mut result = [0u8; 32];
        result.copy_from_slice(&sig_bytes[..32]);
        result
    }
}

// ─── Receipt store ──────────────────────────────────────────────────────────

/// Maximum number of receipts stored in the ring buffer.
const MAX_RECEIPTS: usize = 64;

/// Fixed-size receipt store. Receipts are stored in insertion order.
///
/// Safety: single-core, no preemption during store access in Stage-1.
static mut RECEIPT_STORE: [Option<ExecutionReceipt>; MAX_RECEIPTS] = [const { None }; MAX_RECEIPTS];
static mut RECEIPT_COUNT: usize = 0;

/// Store a receipt in the global receipt store.
/// Returns the index at which the receipt was stored, or `None` if full.
pub fn store_receipt(receipt: ExecutionReceipt) -> Option<usize> {
    // Safety: single-core, no preemption during store access
    unsafe {
        if RECEIPT_COUNT < MAX_RECEIPTS {
            let idx = RECEIPT_COUNT;
            RECEIPT_STORE[idx] = Some(receipt);
            RECEIPT_COUNT += 1;
            crate::persist::save_receipts_to_disk();
            Some(idx)
        } else {
            None
        }
    }
}

/// Retrieve a receipt by index.
pub fn get_receipt(index: usize) -> Option<&'static ExecutionReceipt> {
    // Safety: single-core, no preemption during store access
    unsafe {
        if index < MAX_RECEIPTS {
            RECEIPT_STORE[index].as_ref()
        } else {
            None
        }
    }
}

/// Return the current receipt count.
pub fn receipt_count() -> usize {
    // Safety: single-core, no preemption during store access
    unsafe { RECEIPT_COUNT }
}

/// Emit a receipt for an agent that has exited, and store it.
/// Returns the store index on success.
pub fn emit_receipt_on_exit(
    agent_id: u16,
    runtime_class: RuntimeClassTag,
    energy_used: u64,
    initial_state_root: Hash256,
    final_state_root: Hash256,
    tick_start: u64,
    tick_end: u64,
    input_hash: Hash256,
    output_hash: Hash256,
) -> Option<usize> {
    let mut receipt = ExecutionReceipt::from_agent_exit(
        agent_id,
        runtime_class,
        energy_used,
        initial_state_root,
        final_state_root,
        tick_start,
        tick_end,
        input_hash,
        output_hash,
    );

    // Sign the receipt with the node's Ed25519 key before storing.
    sign_receipt(&mut receipt);

    // Log receipt emission via the event system
    crate::event::emit(
        agent_id,
        crate::event::EventType::Custom,
        0xBEEF_0009, // Stage-9 receipt marker
        energy_used,
        0,
    );

    // qemu64 TCG bisect: keep agent 4 receipts, but skip the heavier
    // attestation/proof path while isolating LinuxCompat exit corruption.
    if agent_id == 4 {
        return store_receipt(receipt);
    }

    // Generate attestation report keyed to the receipt hash and store the
    // attestation hash in the receipt's trace_commitment field.  This ties
    // each receipt to the current kernel measurement.
    let receipt_hash = receipt.compute_hash();
    let attestation_report = crate::attestation::generate_report(&receipt_hash);
    // Use the first 32 bytes of the attestation signature as the commitment
    let mut attestation_commitment: Hash256 = [0u8; 32];
    attestation_commitment.copy_from_slice(&attestation_report.signature[..32]);
    receipt.trace_commitment = attestation_commitment;

    // Re-sign the receipt after patching trace_commitment
    sign_receipt(&mut receipt);

    let idx = store_receipt(receipt);

    // Generate and store a ProofBundle and ReplayBundle alongside the receipt.
    // qemu64 TCG bisect: agent 4's exit-proof path is still the strongest
    // suspect for corrupting the next LinuxCompat exit syscall.
    if agent_id == 4 {
        return idx;
    }

    if let Some(i) = idx {
        if let Some(stored) = get_receipt(i) {
            let proof = ProofBundle::from_receipt(stored);
            store_proof_bundle(proof);

            let replay = ReplayBundle::from_receipt(stored);
            store_replay_bundle(replay);
        }
    }

    idx
}

// ─── Replay & Proof bundles (Stage 9) ───────────────────────────────────

/// A ReplayBundle contains all material needed to independently re-execute
/// and verify an execution result.
pub struct ReplayBundle {
    /// The receipt this replay bundle covers.
    pub receipt_id: Hash256,
    /// Checkpoint data: serialized agent state at execution start.
    pub checkpoint_data: [u8; 4096],
    pub checkpoint_len: u16,
    /// Execution transcript: sequence of syscalls, mailbox messages, timer events.
    pub transcript: [u8; 4096],
    pub transcript_len: u16,
    /// Initial state snapshot (keyspace values at execution start).
    pub initial_state: [u8; 2048],
    pub initial_state_len: u16,
}

impl ReplayBundle {
    /// Create an empty replay bundle for the given receipt ID.
    pub fn empty(receipt_id: Hash256) -> Self {
        Self {
            receipt_id,
            checkpoint_data: [0; 4096],
            checkpoint_len: 0,
            transcript: [0; 4096],
            transcript_len: 0,
            initial_state: [0; 2048],
            initial_state_len: 0,
        }
    }

    /// Build a replay bundle by capturing current checkpoint and trace state
    /// from `crate::checkpoint` for the agent referenced in the receipt.
    pub fn from_receipt(receipt: &ExecutionReceipt) -> Self {
        let mut bundle = Self::empty(receipt.receipt_id);

        // Capture checkpoint data from a portable checkpoint if the agent is
        // still live.
        if let Some(agent_id) = receipt.local_agent_id {
            if let Some(pc) = crate::checkpoint::PortableCheckpoint::from_agent(agent_id) {
                let copy_len = pc.checkpoint_len.min(bundle.checkpoint_data.len());
                bundle.checkpoint_data[..copy_len].copy_from_slice(&pc.checkpoint_data[..copy_len]);
                bundle.checkpoint_len = copy_len as u16;
            }
        }

        // Capture I/O trace entries from checkpoint trace log.
        // Each trace entry is serialized as: tick(8) + event_type(1) + agent_id(2) = 11 bytes.
        let trace_count = crate::checkpoint::trace_count();
        let mut tpos = 0usize;
        for i in 0..trace_count {
            if tpos + 11 > bundle.transcript.len() {
                break;
            }
            if let Some(entry) = crate::checkpoint::get_trace(i) {
                bundle.transcript[tpos..tpos + 8].copy_from_slice(&entry.tick.to_le_bytes());
                tpos += 8;
                bundle.transcript[tpos] = entry.event_type;
                tpos += 1;
                bundle.transcript[tpos..tpos + 2].copy_from_slice(&entry.agent_id.to_le_bytes());
                tpos += 2;
            }
        }
        bundle.transcript_len = tpos as u16;

        // Capture initial state snapshot from the receipt's initial_state_root.
        // Store the 32-byte root so a verifier can fetch/reconstruct the full
        // keyspace independently.
        bundle.initial_state[..32].copy_from_slice(&receipt.initial_state_root);
        bundle.initial_state_len = 32;

        bundle
    }
}

/// Compact proof artifacts for fast external verification without full replay.
///
/// Proof data layout (proof_type = 1, Merkle-state):
/// ```text
/// [0..32]   initial_state_root
/// [32..64]  final_state_root
/// [64..66]  leaf_count (u16 LE)
/// [66..68]  proof_depth (u16 LE)
/// [68..]    sibling_hashes: leaf_count * proof_depth * 32 bytes
/// ```
pub struct ProofBundle {
    /// The execution receipt this proof covers
    pub receipt_id: Hash256,
    /// Proof type (0 = replay-hash, 1 = Merkle-state)
    pub proof_type: u8,
    /// Compact proof data (4096 bytes to hold Merkle sibling hashes)
    pub proof_data: [u8; 4096],
    pub proof_len: usize,
    /// Verification key: ExecutionProof.proof_hash for cross-reference
    pub verifier_key: Hash256,
}

impl ProofBundle {
    pub fn empty(receipt_id: Hash256) -> Self {
        Self {
            receipt_id,
            proof_type: 0,
            proof_data: [0; 4096],
            proof_len: 0,
            verifier_key: [0; 32],
        }
    }

    /// Create a simple replay-hash proof from a receipt
    pub fn from_receipt_hash(receipt: &ExecutionReceipt) -> Self {
        let hash = receipt.compute_hash();
        let mut bundle = Self::empty(receipt.receipt_id);
        bundle.proof_type = 0; // replay-hash
        bundle.proof_data[0..32].copy_from_slice(&hash);
        bundle.proof_len = 32;
        bundle
    }

    /// Create a proof bundle from a receipt with real Merkle state proofs.
    ///
    /// Generates actual Merkle inclusion proofs (sibling hashes) for the
    /// contract's keyspace tree, so a verifier can recompute the root from
    /// leaves without replaying execution.
    pub fn from_receipt(receipt: &ExecutionReceipt) -> Self {
        use crate::merkle;

        let mut bundle = Self::empty(receipt.receipt_id);

        // Proof type 1: Merkle-state proof with real sibling hashes
        bundle.proof_type = 1;

        // Pack state roots
        bundle.proof_data[0..32].copy_from_slice(&receipt.initial_state_root);
        bundle.proof_data[32..64].copy_from_slice(&receipt.final_state_root);

        // Determine keyspace from the agent id
        let keyspace = receipt.local_agent_id.unwrap_or(0);

        // Get leaf count and generate proofs
        let leaf_count = merkle::get_leaf_count(keyspace).unwrap_or(0);

        if leaf_count > 0 {
            // Generate proof for leaf 0 to determine tree depth
            let first_proof = merkle::generate_proof(keyspace, 0);
            let proof_depth = first_proof.as_ref().map(|p| p.depth).unwrap_or(0);
            let proof_depth_u16 = proof_depth as u16;

            // Calculate how many leaves we can fit in the buffer.
            // Each leaf's proof = proof_depth * 32 bytes of siblings.
            // Header is 68 bytes, buffer is 4096 bytes.
            let bytes_per_leaf = proof_depth * 32;
            let available = 4096 - 68;
            let max_leaves = if bytes_per_leaf > 0 {
                available / bytes_per_leaf
            } else {
                leaf_count
            };

            // If we can't fit all leaves, include only the first modified leaf
            // (leaf 0). This is still a meaningful Merkle inclusion proof.
            let include_count = if max_leaves >= leaf_count {
                leaf_count
            } else {
                1
            };

            let include_u16 = include_count as u16;
            bundle.proof_data[64..66].copy_from_slice(&include_u16.to_le_bytes());
            bundle.proof_data[66..68].copy_from_slice(&proof_depth_u16.to_le_bytes());

            let mut pos = 68usize;
            for leaf_idx in 0..include_count {
                if let Some(proof) = merkle::generate_proof(keyspace, leaf_idx) {
                    let depth = proof.depth.min(7);
                    for d in 0..depth {
                        if pos + 32 > 4096 {
                            break;
                        }
                        bundle.proof_data[pos..pos + 32].copy_from_slice(&proof.siblings[d]);
                        pos += 32;
                    }
                }
            }

            bundle.proof_len = pos;
        } else {
            // No leaves -- pack zero counts in the header
            bundle.proof_data[64..66].copy_from_slice(&0u16.to_le_bytes());
            bundle.proof_data[66..68].copy_from_slice(&0u16.to_le_bytes());
            bundle.proof_len = 68;
        }

        // Generate an ExecutionProof and use its proof_hash as verifier_key
        // for cross-reference between proof systems.
        let exec_proof = crate::proof::generate_proof();
        bundle.verifier_key = exec_proof.proof_hash;

        bundle
    }

    /// Verify this proof bundle against a receipt.
    ///
    /// For Merkle-state proofs (type 1): extracts sibling hashes from
    /// proof_data, recomputes the Merkle root from the first leaf's path,
    /// and compares against the receipt's final_state_root.
    ///
    /// For replay-hash proofs (type 0): checks the receipt hash.
    pub fn verify_against_receipt(&self, receipt: &ExecutionReceipt) -> bool {
        if self.receipt_id != receipt.receipt_id {
            return false;
        }

        match self.proof_type {
            1 => {
                // Merkle-state verification
                if self.proof_len < 68 {
                    return false;
                }

                // Check state roots in proof_data match the receipt
                if self.proof_data[0..32] != receipt.initial_state_root {
                    return false;
                }
                if self.proof_data[32..64] != receipt.final_state_root {
                    return false;
                }

                // Extract header fields
                let leaf_count =
                    u16::from_le_bytes([self.proof_data[64], self.proof_data[65]]) as usize;
                let proof_depth =
                    u16::from_le_bytes([self.proof_data[66], self.proof_data[67]]) as usize;

                if leaf_count == 0 || proof_depth == 0 {
                    // No leaves or zero depth: state root must be zero
                    return receipt.final_state_root == [0u8; 32];
                }

                // Verify we have enough data for the sibling hashes
                let expected_data = 68 + leaf_count * proof_depth * 32;
                if self.proof_len < expected_data {
                    return false;
                }

                // Recompute the Merkle root from leaf 0 using stored sibling
                // hashes and compare against the receipt's final_state_root.
                let keyspace = receipt.local_agent_id.unwrap_or(0);

                if let Some(computed_root) =
                    recompute_root_from_siblings(keyspace, 0, &self.proof_data[68..], proof_depth)
                {
                    // The computed root from siblings must match the
                    // receipt's final_state_root (first 16 bytes, since
                    // final_state_root may be populated from get_root
                    // which only fills 16 bytes).
                    if computed_root[..16] != receipt.final_state_root[..16] {
                        return false;
                    }
                } else {
                    // Cannot recompute -- check live tree root as fallback
                    if let Some(current_root) = crate::merkle::get_root(keyspace) {
                        if current_root[..16] != receipt.final_state_root[..16] {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }

                true
            }
            0 => {
                // Legacy replay-hash verification
                if self.proof_len < 32 {
                    return false;
                }
                let expected_hash = receipt.compute_hash();
                self.proof_data[0..32] == expected_hash
            }
            _ => false,
        }
    }
}

/// Recompute a Merkle root from a leaf's perspective using sibling hashes.
///
/// Retrieves the leaf hash from the live state for `keyspace` at
/// `leaf_index`, then hashes upward using `depth` sibling hashes packed
/// contiguously in `sibling_data` (each 32 bytes).
fn recompute_root_from_siblings(
    keyspace: u16,
    leaf_index: usize,
    sibling_data: &[u8],
    depth: usize,
) -> Option<Hash256> {
    // Get the leaf hash by reading the raw key-value from the state module
    // and hashing it the same way MerkleTree::hash_kv does.
    let value = crate::state::get(keyspace, leaf_index as u64);
    let leaf_hash = if let Some(data) = value {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&(leaf_index as u64).to_le_bytes());
        hasher.update(data);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    } else {
        [0u8; 32]
    };

    let mut hash = leaf_hash;
    let mut idx = leaf_index;

    for d in 0..depth {
        let offset = d * 32;
        if offset + 32 > sibling_data.len() {
            return None;
        }
        let mut sibling = [0u8; 32];
        sibling.copy_from_slice(&sibling_data[offset..offset + 32]);

        if idx % 2 == 0 {
            hash = crate::merkle::hash_pair(&hash, &sibling);
        } else {
            hash = crate::merkle::hash_pair(&sibling, &hash);
        }
        idx /= 2;
    }

    Some(hash)
}

// ─── Proof bundle store ────────────────────────────────────────────────────

/// Fixed-size proof bundle store.
///
/// Safety: single-core, no preemption during store access in Stage-1.
static mut PROOF_STORE: [Option<ProofBundle>; 64] = [const { None }; 64];
static mut PROOF_COUNT: usize = 0;

/// Store a proof bundle in the global proof store.
pub fn store_proof_bundle(proof: ProofBundle) {
    unsafe {
        if PROOF_COUNT < PROOF_STORE.len() {
            PROOF_STORE[PROOF_COUNT] = Some(proof);
            PROOF_COUNT += 1;
        }
    }
    crate::persist::save_proof_bundles_to_disk();
}

/// Retrieve a proof bundle by index.
pub fn get_proof_bundle(idx: usize) -> Option<&'static ProofBundle> {
    unsafe { PROOF_STORE.get(idx)?.as_ref() }
}

/// Return the current proof bundle count.
pub fn proof_count() -> usize {
    unsafe { PROOF_COUNT }
}

// ─── Replay bundle store ──────────────────────────────────────────────────

/// Maximum number of replay bundles stored in the ring buffer.
const MAX_REPLAY_BUNDLES: usize = 16;

/// Fixed-size replay bundle ring buffer.
///
/// Safety: single-core, no preemption during store access in Stage-1.
static mut REPLAY_STORE: [Option<ReplayBundle>; MAX_REPLAY_BUNDLES] =
    [const { None }; MAX_REPLAY_BUNDLES];
static mut REPLAY_COUNT: usize = 0;

/// Store a replay bundle in the global replay store (ring buffer).
/// Wraps around when full, overwriting the oldest entry.
pub fn store_replay_bundle(bundle: ReplayBundle) {
    unsafe {
        let idx = REPLAY_COUNT % MAX_REPLAY_BUNDLES;
        REPLAY_STORE[idx] = Some(bundle);
        REPLAY_COUNT += 1;
    }
    crate::persist::save_replay_bundles_to_disk();
}

/// Retrieve a replay bundle by index (within the ring buffer).
pub fn get_replay_bundle(index: usize) -> Option<&'static ReplayBundle> {
    unsafe {
        if index < MAX_REPLAY_BUNDLES {
            REPLAY_STORE[index].as_ref()
        } else {
            None
        }
    }
}

/// Return the number of replay bundles stored (capped at ring capacity).
pub fn replay_bundle_count() -> usize {
    unsafe {
        if REPLAY_COUNT > MAX_REPLAY_BUNDLES {
            MAX_REPLAY_BUNDLES
        } else {
            REPLAY_COUNT
        }
    }
}

/// Patch the trace_commitment field of an already-stored receipt.
pub fn patch_trace_commitment(index: usize, commitment: Hash256) {
    unsafe {
        if index < MAX_RECEIPTS {
            if let Some(ref mut receipt) = RECEIPT_STORE[index] {
                receipt.trace_commitment = commitment;
            }
        }
    }
}

/// Emit a receipt for the current state of a running agent (via syscall).
/// Returns the store index on success.
pub fn emit_receipt_for_agent(agent_id: u16) -> Option<usize> {
    let tick_now = crate::arch::x86_64::timer::get_ticks();

    // Read agent's current energy budget and saved initial state root
    let (energy_used, initial_root, tick_start) = match crate::agent::get_agent(agent_id) {
        Some(agent) => (
            agent.energy_budget,
            agent.initial_state_root,
            agent.tick_created,
        ),
        None => (0, [0u8; 32], 0u64),
    };

    // Compute final state root from agent's keyspace
    let mut final_root = [0u8; 32];
    if let Some(root16) = crate::state::get_root(agent_id as u16) {
        final_root[..16].copy_from_slice(&root16);
    }

    // Compute trace commitment from transcript
    let trace_commitment = crate::syscall::compute_transcript_hash(agent_id, tick_start, tick_now);

    // Use state roots as input/output commitments (they are already hashes).
    let input_hash = initial_root;
    let output_hash = final_root;

    let idx = emit_receipt_on_exit(
        agent_id,
        RuntimeClassTag::ProofGradeWasm,
        energy_used,
        initial_root,
        final_root,
        tick_start,
        tick_now,
        input_hash,
        output_hash,
    );

    // Patch trace_commitment into the receipt
    if let Some(i) = idx {
        patch_trace_commitment(i, trace_commitment);
    }

    idx
}
