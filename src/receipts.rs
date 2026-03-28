//! ATOS Execution Receipt Model (Yellow Paper §27.6.3)
//!
//! An ExecutionReceipt ties agent execution to verifiable evidence. Receipts
//! are emitted when agents exit or explicitly via syscall, and stored in a
//! fixed-size ring for later retrieval.

extern crate alloc;

use crate::principal::PrincipalId;

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
    pub principal_id: PrincipalId,
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
    pub fn compute_hash(&self) -> Hash256 {
        let mut h: u64 = 0xcbf29ce484222325;
        // Hash all critical fields
        for b in &self.receipt_id { h = h.wrapping_mul(0x100000001b3) ^ (*b as u64); }
        for b in &self.workload_id { h = h.wrapping_mul(0x100000001b3) ^ (*b as u64); }
        for b in &self.initial_state_root { h = h.wrapping_mul(0x100000001b3) ^ (*b as u64); }
        for b in &self.final_state_root { h = h.wrapping_mul(0x100000001b3) ^ (*b as u64); }
        h = h.wrapping_mul(0x100000001b3) ^ self.energy_used;
        h = h.wrapping_mul(0x100000001b3) ^ self.tick_start;
        h = h.wrapping_mul(0x100000001b3) ^ self.tick_end;
        let mut result = [0u8; 32];
        result[0..8].copy_from_slice(&h.to_le_bytes());
        // Second round
        h = h.wrapping_mul(0x100000001b3) ^ (self.runtime_class as u64);
        result[8..16].copy_from_slice(&h.to_le_bytes());
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
    let receipt = ExecutionReceipt::from_agent_exit(
        agent_id,
        runtime_class,
        energy_used,
        initial_state_root,
        final_state_root,
        tick_start,
        tick_end,
    );

    // Log receipt emission via the event system
    crate::event::emit(
        agent_id,
        crate::event::EventType::Custom,
        0xBEEF_0009, // Stage-9 receipt marker
        energy_used,
        0,
    );

    store_receipt(receipt)
}

/// Emit a receipt for the current state of a running agent (via syscall).
/// Returns the store index on success.
pub fn emit_receipt_for_agent(agent_id: u16) -> Option<usize> {
    let tick_now = crate::arch::x86_64::timer::get_ticks();

    // Read agent's current energy budget
    let energy_used = match crate::agent::get_agent(agent_id) {
        Some(agent) => agent.energy_budget,
        None => 0,
    };

    emit_receipt_on_exit(
        agent_id,
        RuntimeClassTag::ProofGradeWasm,
        energy_used,
        [0; 32], // initial state root placeholder
        [0; 32], // final state root placeholder
        0,       // tick_start placeholder
        tick_now,
    )
}
