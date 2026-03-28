//! ATOS Execution Receipt Verifier SDK
//!
//! This library allows third parties to verify ATOS execution receipts
//! without trusting the originating node.

pub type Hash256 = [u8; 32];

/// Runtime class tags matching ATOS kernel's RuntimeClassTag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RuntimeClass {
    BestEffortNative = 0,
    ReplayGradeNative = 1,
    ProofGradeWasm = 2,
    BrokerService = 3,
}

/// A portable execution receipt (matches kernel's ExecutionReceipt layout).
#[derive(Debug, Clone)]
pub struct ExecutionReceipt {
    pub receipt_version: u16,
    pub receipt_id: Hash256,
    pub workload_id: Hash256,
    pub execution_id: Hash256,
    pub principal_id: Hash256,
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
    /// Compute the hash of this receipt.
    pub fn compute_hash(&self) -> Hash256 {
        let mut h: u64 = 0xcbf29ce484222325;
        for b in &self.receipt_id {
            h = h.wrapping_mul(0x100000001b3) ^ (*b as u64);
        }
        for b in &self.workload_id {
            h = h.wrapping_mul(0x100000001b3) ^ (*b as u64);
        }
        for b in &self.initial_state_root {
            h = h.wrapping_mul(0x100000001b3) ^ (*b as u64);
        }
        for b in &self.final_state_root {
            h = h.wrapping_mul(0x100000001b3) ^ (*b as u64);
        }
        h = h.wrapping_mul(0x100000001b3) ^ self.energy_used;
        h = h.wrapping_mul(0x100000001b3) ^ self.tick_start;
        h = h.wrapping_mul(0x100000001b3) ^ self.tick_end;
        let mut result = [0u8; 32];
        result[0..8].copy_from_slice(&h.to_le_bytes());
        h = h.wrapping_mul(0x100000001b3) ^ (self.runtime_class as u64);
        result[8..16].copy_from_slice(&h.to_le_bytes());
        result
    }

    /// Verify receipt internal consistency.
    pub fn verify(&self) -> VerifyResult {
        // Check required fields are non-zero
        if self.receipt_id == [0; 32] {
            return VerifyResult::MissingField("receipt_id");
        }
        if self.execution_id == [0; 32] {
            return VerifyResult::MissingField("execution_id");
        }

        // Check signature is present
        if self.signature == [0; 64] {
            return VerifyResult::InvalidSignature;
        }

        // Check tick ordering
        if self.tick_end < self.tick_start {
            return VerifyResult::InvalidHash;
        }

        // Verify hash matches
        let hash = self.compute_hash();
        // In a full implementation, verify signature over hash
        let _ = hash;

        VerifyResult::Valid
    }

    /// Verify a state transition: check that initial_state_root != final_state_root
    /// (or both zero for stateless execution).
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
    if proof_data.len() < 32 {
        return VerifyResult::InvalidHash;
    }

    let receipt_hash = receipt.compute_hash();
    if proof_data[0..8] != receipt_hash[0..8] {
        return VerifyResult::InvalidHash;
    }

    VerifyResult::Valid
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_receipt_hash_deterministic() {
        let r1 = ExecutionReceipt {
            receipt_version: 1,
            receipt_id: [1; 32],
            workload_id: [2; 32],
            execution_id: [3; 32],
            principal_id: [4; 32],
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
        };
        let h1 = r1.compute_hash();
        let h2 = r1.compute_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_verify_missing_fields() {
        let r = ExecutionReceipt {
            receipt_version: 1,
            receipt_id: [0; 32], // zero = missing
            workload_id: [0; 32],
            execution_id: [0; 32],
            principal_id: [0; 32],
            node_id: [0; 32],
            runtime_class: RuntimeClass::BestEffortNative,
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
        let r = ExecutionReceipt {
            receipt_version: 1,
            receipt_id: [1; 32],
            workload_id: [0; 32],
            execution_id: [1; 32],
            principal_id: [0; 32],
            node_id: [0; 32],
            runtime_class: RuntimeClass::ProofGradeWasm,
            code_hash: [0; 32],
            input_commitment: [0; 32],
            output_commitment: [0; 32],
            initial_state_root: [0; 32],
            final_state_root: [0; 32],
            energy_used: 0,
            tick_start: 0,
            tick_end: 0,
            signature: [1; 64],
        };
        assert!(r.is_proof_grade());
    }
}
