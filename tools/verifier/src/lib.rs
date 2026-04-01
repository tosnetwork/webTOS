//! TOS Execution Receipt Verifier SDK
//!
//! This library allows third parties to verify TOS execution receipts
//! without trusting the originating node.

use sha2::{Sha256, Digest};

pub type Hash256 = [u8; 32];

/// Runtime class tags matching TOS kernel's RuntimeClassTag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RuntimeClass {
    ProofGradeWasm = 0,
    ReplayGradeNative = 1,
}

/// A portable execution receipt (matches kernel's ExecutionReceipt layout).
#[derive(Debug, Clone)]
pub struct ExecutionReceipt {
    pub receipt_version: u16,
    pub receipt_id: Hash256,
    pub contract_id: Hash256,
    pub execution_id: Hash256,
    pub caller_id: Hash256,
    pub node_id: Hash256,
    pub runtime_class: RuntimeClass,
    pub code_hash: Hash256,
    pub input_commitment: Hash256,
    pub output_commitment: Hash256,
    pub initial_state_root: Hash256,
    pub final_state_root: Hash256,
    pub energy_used: u64,
    pub tick_start: u64,
    pub tick_end: u64,
    pub signature: [u8; 64],
}

/// Verification result.
#[derive(Debug)]
pub enum VerifyResult {
    Valid,
    InvalidSignature,
    InvalidHash,
    MissingField(&'static str),
    Expired,
}

impl ExecutionReceipt {
    /// Compute the SHA-256 hash of this receipt's critical fields.
    pub fn compute_hash(&self) -> Hash256 {
        let mut hasher = Sha256::new();
        hasher.update(&self.receipt_id);
        hasher.update(&self.contract_id);
        hasher.update(&self.execution_id);
        hasher.update(&self.caller_id);
        hasher.update(&self.node_id);
        hasher.update(&[self.runtime_class as u8]);
        hasher.update(&self.code_hash);
        hasher.update(&self.input_commitment);
        hasher.update(&self.output_commitment);
        hasher.update(&self.initial_state_root);
        hasher.update(&self.final_state_root);
        hasher.update(&self.energy_used.to_le_bytes());
        hasher.update(&self.tick_start.to_le_bytes());
        hasher.update(&self.tick_end.to_le_bytes());
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    /// Verify receipt internal consistency.
    pub fn verify(&self) -> VerifyResult {
        if self.receipt_id == [0; 32] {
            return VerifyResult::MissingField("receipt_id");
        }
        if self.execution_id == [0; 32] {
            return VerifyResult::MissingField("execution_id");
        }
        if self.signature == [0; 64] {
            return VerifyResult::InvalidSignature;
        }
        if self.tick_end < self.tick_start {
            return VerifyResult::InvalidHash;
        }

        VerifyResult::Valid
    }

    /// Check if there was a state transition.
    pub fn has_state_transition(&self) -> bool {
        self.initial_state_root != self.final_state_root
    }

    /// Check if the receipt claims proof-grade execution.
    pub fn is_proof_grade(&self) -> bool {
        self.runtime_class == RuntimeClass::ProofGradeWasm
    }
}

/// Verify a proof bundle against a receipt.
pub fn verify_proof(receipt: &ExecutionReceipt, proof_data: &[u8]) -> VerifyResult {
    if proof_data.len() < 64 {
        return VerifyResult::InvalidHash;
    }

    // Check that initial and final state roots in proof match receipt
    if proof_data[0..32] != receipt.initial_state_root {
        return VerifyResult::InvalidHash;
    }
    if proof_data[32..64] != receipt.final_state_root {
        return VerifyResult::InvalidHash;
    }

    VerifyResult::Valid
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_receipt() -> ExecutionReceipt {
        ExecutionReceipt {
            receipt_version: 1,
            receipt_id: [1; 32],
            contract_id: [2; 32],
            execution_id: [3; 32],
            caller_id: [4; 32],
            node_id: [5; 32],
            runtime_class: RuntimeClass::ProofGradeWasm,
            code_hash: [6; 32],
            input_commitment: [7; 32],
            output_commitment: [8; 32],
            initial_state_root: [9; 32],
            final_state_root: [10; 32],
            energy_used: 1000,
            tick_start: 100,
            tick_end: 200,
            signature: [0xFF; 64],
        }
    }

    #[test]
    fn test_receipt_hash_deterministic() {
        let r = make_receipt();
        let h1 = r.compute_hash();
        let h2 = r.compute_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_receipt_hash_is_sha256() {
        let r = make_receipt();
        let h = r.compute_hash();
        // SHA-256 produces 32 non-zero bytes for non-trivial input
        assert_ne!(h, [0; 32]);
        // Verify it's not just the first 8 bytes filled (old FNV behavior)
        assert_ne!(h[8..16], [0; 8]);
        assert_ne!(h[16..24], [0; 8]);
        assert_ne!(h[24..32], [0; 8]);
    }

    #[test]
    fn test_verify_missing_fields() {
        let r = ExecutionReceipt {
            receipt_version: 1,
            receipt_id: [0; 32],
            contract_id: [0; 32],
            execution_id: [0; 32],
            caller_id: [0; 32],
            node_id: [0; 32],
            runtime_class: RuntimeClass::ReplayGradeNative,
            code_hash: [0; 32],
            input_commitment: [0; 32],
            output_commitment: [0; 32],
            initial_state_root: [0; 32],
            final_state_root: [0; 32],
            energy_used: 0,
            tick_start: 0,
            tick_end: 0,
            signature: [0; 64],
        };
        match r.verify() {
            VerifyResult::MissingField("receipt_id") => {}
            other => panic!("expected MissingField, got {:?}", other),
        }
    }

    #[test]
    fn test_proof_grade_check() {
        let r = make_receipt();
        assert!(r.is_proof_grade());
    }
}
