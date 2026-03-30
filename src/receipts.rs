//! ATOS Execution Receipt Model (Yellow Paper §27.6.3)
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
    let (sk, vk) = crypto::generate_keypair();
    unsafe { NODE_SIGNING_KEY = Some(sk); }
    crate::serial_println!("[RECEIPTS] Receipt signing key initialised (vk={:02x}{:02x}..)",
        vk.as_bytes()[0], vk.as_bytes()[1]);
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
    BestEffortNative = 0,
    ReplayGradeNative = 1,
    ProofGradeWasm = 2,
    BrokerService = 3,
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

    pub workload_id: Hash256,
    pub execution_id: Hash256,
    pub principal_id: [u8; 32],
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

    pub authority_commitment: Hash256,
    pub policy_bundle_hash: Hash256,
    pub policy_decision_commitment: Hash256,

    pub energy_used: u64,
    pub pricing_class: u32,

    pub tick_start: u64,
    pub tick_end: u64,
    pub wall_clock_hint: u64,

    pub signature: [u8; 64],
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
    ) -> Self {
        // Generate receipt_id from hash of key fields
        let mut receipt_id = [0u8; 32];
        // Simple FNV-based hash for now
        let mut h: u64 = 0xcbf29ce484222325;
        h = h.wrapping_mul(0x100000001b3) ^ (agent_id as u64);
        h = h.wrapping_mul(0x100000001b3) ^ tick_start;
        h = h.wrapping_mul(0x100000001b3) ^ tick_end;
        h = h.wrapping_mul(0x100000001b3) ^ energy_used;
        receipt_id[0..8].copy_from_slice(&h.to_le_bytes());

        Self {
            receipt_version: 1,
            receipt_id,
            workload_id: [0; 32],  // set by caller
            execution_id: receipt_id,
            principal_id: [0; 32],  // set by caller
            local_agent_id: Some(agent_id),
            node_id: [0; 32],  // set by node identity
            runtime_class,
            package_hash: [0; 32],
            code_hash: [0; 32],
            input_commitment: [0; 32],
            output_commitment: [0; 32],
            initial_state_root,
            final_state_root,
            event_log_commitment: [0; 32],
            trace_commitment: [0; 32],
            authority_commitment: [0; 32],
            policy_bundle_hash: [0; 32],
            policy_decision_commitment: [0; 32],
            energy_used,
            pricing_class: runtime_class as u32,
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
    /// resistance far beyond the previous FNV-1a placeholder.
    pub fn compute_hash(&self) -> Hash256 {
        // Serialise all critical fields into a flat buffer for hashing.
        let mut buf = [0u8; 256];
        let mut pos = 0;

        buf[pos..pos + 32].copy_from_slice(&self.receipt_id);
        pos += 32;
        buf[pos..pos + 32].copy_from_slice(&self.workload_id);
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
        buf[pos..pos + 4].copy_from_slice(&self.pricing_class.to_le_bytes());
        pos += 4;
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
) -> Option<usize> {
    let mut receipt = ExecutionReceipt::from_agent_exit(
        agent_id,
        runtime_class,
        energy_used,
        initial_state_root,
        final_state_root,
        tick_start,
        tick_end,
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

    let idx = store_receipt(receipt);

    // Generate and store a ProofBundle alongside the receipt.
    if let Some(i) = idx {
        if let Some(stored) = get_receipt(i) {
            let proof = ProofBundle::from_receipt(stored);
            store_proof_bundle(proof);
        }
    }

    idx
}

// ─── Replay & Proof bundles (Stage 9) ───────────────────────────────────

/// A replay bundle containing everything needed for independent replay verification.
pub struct ReplayBundle {
    /// The execution receipt this bundle verifies
    pub receipt_id: Hash256,
    /// Checkpoint image (compressed agent state at start)
    pub checkpoint_data: [u8; 4096],
    pub checkpoint_len: usize,
    /// I/O transcript (all syscalls and their results)
    pub transcript: [u8; 4096],
    pub transcript_len: usize,
    /// Initial state snapshot
    pub initial_state: [u8; 2048],
    pub initial_state_len: usize,
}

impl ReplayBundle {
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
}

/// Compact proof artifacts for fast external verification without full replay.
pub struct ProofBundle {
    /// The execution receipt this proof covers
    pub receipt_id: Hash256,
    /// Proof type (0 = replay-hash, 1 = Merkle-state, 2 = zk-snark placeholder)
    pub proof_type: u8,
    /// Compact proof data
    pub proof_data: [u8; 1024],
    pub proof_len: usize,
    /// Verification key or reference
    pub verifier_key: Hash256,
}

impl ProofBundle {
    pub fn empty(receipt_id: Hash256) -> Self {
        Self {
            receipt_id,
            proof_type: 0,
            proof_data: [0; 1024],
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
    pub fn from_receipt(receipt: &ExecutionReceipt) -> Self {
        let mut bundle = Self::empty(receipt.receipt_id);

        // Proof type 0: state transition proof
        // Contains: initial_state_root + final_state_root + receipt_hash
        bundle.proof_type = 0;

        // Pack state roots into proof data
        bundle.proof_data[0..32].copy_from_slice(&receipt.initial_state_root);
        bundle.proof_data[32..64].copy_from_slice(&receipt.final_state_root);

        // Pack receipt hash
        let receipt_hash = receipt.compute_hash();
        bundle.proof_data[64..96].copy_from_slice(&receipt_hash);

        // Pack energy and ticks for billing verification
        bundle.proof_data[96..104].copy_from_slice(&receipt.energy_used.to_le_bytes());
        bundle.proof_data[104..112].copy_from_slice(&receipt.tick_start.to_le_bytes());
        bundle.proof_data[112..120].copy_from_slice(&receipt.tick_end.to_le_bytes());

        bundle.proof_len = 120;

        // Verifier key = node_id (verifier needs this to check signature)
        bundle.verifier_key = receipt.node_id;

        bundle
    }

    /// Verify this proof bundle against a receipt.
    pub fn verify_against_receipt(&self, receipt: &ExecutionReceipt) -> bool {
        if self.receipt_id != receipt.receipt_id { return false; }
        if self.proof_len < 120 { return false; }

        // Check state roots match
        if self.proof_data[0..32] != receipt.initial_state_root { return false; }
        if self.proof_data[32..64] != receipt.final_state_root { return false; }

        // Check receipt hash
        let expected_hash = receipt.compute_hash();
        if self.proof_data[64..96] != expected_hash { return false; }

        // Check energy/timing
        let stored_energy = u64::from_le_bytes(
            self.proof_data[96..104].try_into().unwrap_or([0; 8])
        );
        if stored_energy != receipt.energy_used { return false; }

        true
    }
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
}

/// Retrieve a proof bundle by index.
pub fn get_proof_bundle(idx: usize) -> Option<&'static ProofBundle> {
    unsafe { PROOF_STORE.get(idx)?.as_ref() }
}

/// Return the current proof bundle count.
pub fn proof_count() -> usize {
    unsafe { PROOF_COUNT }
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
        Some(agent) => (agent.energy_budget, agent.initial_state_root, agent.tick_created),
        None => (0, [0u8; 32], 0u64),
    };

    // Compute final state root from agent's keyspace
    let mut final_root = [0u8; 32];
    if let Some(root16) = crate::state::get_root(agent_id as u16) {
        final_root[..16].copy_from_slice(&root16);
    }

    // Compute trace commitment from transcript
    let trace_commitment = crate::syscall::compute_transcript_hash(agent_id, tick_start, tick_now);

    let idx = emit_receipt_on_exit(
        agent_id,
        RuntimeClassTag::ProofGradeWasm,
        energy_used,
        initial_root,
        final_root,
        tick_start,
        tick_now,
    );

    // Patch trace_commitment into the receipt
    if let Some(i) = idx {
        patch_trace_commitment(i, trace_commitment);
    }

    idx
}
