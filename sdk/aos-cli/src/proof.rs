//! Standalone execution proof verifier
//!
//! Reads an AOS execution proof file (AOSP format) and verifies
//! the hash chain integrity.

use std::fs;

const PROOF_MAGIC: &[u8; 4] = b"AOSP";
const PROOF_VERSION: u8 = 1;
const PROOF_SIZE: usize = 65;

/// AOS Execution Proof (mirrors kernel's ExecutionProof)
struct ExecutionProof {
    checkpoint_tick: u64,
    event_count: u64,
    checkpoint_root: [u8; 16],
    proof_hash: [u8; 16],
    start_seq: u64,
    end_seq: u64,
}

pub fn verify_file(path: &str) {
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[aos-verify] Failed to read {}: {}", path, e);
            std::process::exit(1);
        }
    };

    if data.len() < PROOF_SIZE {
        eprintln!("[aos-verify] File too small: {} bytes (need {})", data.len(), PROOF_SIZE);
        std::process::exit(1);
    }

    // Validate magic
    if &data[0..4] != PROOF_MAGIC {
        eprintln!("[aos-verify] Invalid magic: expected AOSP, got {:?}", &data[0..4]);
        std::process::exit(1);
    }

    // Validate version
    if data[4] != PROOF_VERSION {
        eprintln!("[aos-verify] Unsupported version: {}", data[4]);
        std::process::exit(1);
    }

    // Parse proof
    let proof = parse_proof(&data);

    println!("╔══════════════════════════════════════════════╗");
    println!("║       AOS EXECUTION PROOF VERIFICATION      ║");
    println!("╠══════════════════════════════════════════════╣");
    println!("║ File: {:38} ║", truncate(path, 38));
    println!("║ Checkpoint tick: {:27} ║", proof.checkpoint_tick);
    println!("║ Event count:     {:27} ║", proof.event_count);
    println!("║ Sequence range:  {}-{:>21} ║", proof.start_seq, proof.end_seq);
    println!("║ Root:  {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}...            ║",
        proof.checkpoint_root[0], proof.checkpoint_root[1],
        proof.checkpoint_root[2], proof.checkpoint_root[3],
        proof.checkpoint_root[4], proof.checkpoint_root[5],
        proof.checkpoint_root[6], proof.checkpoint_root[7]);
    println!("║ Hash:  {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}...            ║",
        proof.proof_hash[0], proof.proof_hash[1],
        proof.proof_hash[2], proof.proof_hash[3],
        proof.proof_hash[4], proof.proof_hash[5],
        proof.proof_hash[6], proof.proof_hash[7]);
    println!("╠══════════════════════════════════════════════╣");

    // Verify hash chain: H(root || tick || event_count) should equal proof_hash
    let recomputed = fnv1a_128_proof(&proof.checkpoint_root, proof.checkpoint_tick, proof.event_count);

    if recomputed == proof.proof_hash {
        println!("║ Status: ✓ VALID                              ║");
        println!("║ Hash chain verified successfully              ║");
    } else {
        println!("║ Status: ✗ INVALID                             ║");
        println!("║ Hash chain verification FAILED                ║");
        println!("║ Expected: {:02x}{:02x}{:02x}{:02x}...                      ║",
            recomputed[0], recomputed[1], recomputed[2], recomputed[3]);
    }
    println!("╚══════════════════════════════════════════════╝");
}

fn parse_proof(data: &[u8]) -> ExecutionProof {
    let tick = u64::from_le_bytes(data[5..13].try_into().unwrap());
    let event_count = u32::from_le_bytes(data[13..17].try_into().unwrap()) as u64;
    let mut root = [0u8; 16];
    root.copy_from_slice(&data[17..33]);
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&data[33..49]);
    let start_seq = u64::from_le_bytes(data[49..57].try_into().unwrap());
    let end_seq = u64::from_le_bytes(data[57..65].try_into().unwrap());

    ExecutionProof {
        checkpoint_tick: tick,
        event_count,
        checkpoint_root: root,
        proof_hash: hash,
        start_seq,
        end_seq,
    }
}

/// FNV-1a 128-bit hash — must match the kernel's implementation exactly
fn fnv1a_128_proof(root: &[u8; 16], tick: u64, event_count: u64) -> [u8; 16] {
    // FNV-1a 128-bit offset basis and prime (same as kernel merkle.rs)
    let mut h: u128 = 0x6c62272e07bb0142_62b821756295c58d;
    let prime: u128 = 0x0000000001000000_000000000000013B;

    // Hash root bytes
    for &b in root.iter() {
        h ^= b as u128;
        h = h.wrapping_mul(prime);
    }
    // Hash tick
    for &b in &tick.to_le_bytes() {
        h ^= b as u128;
        h = h.wrapping_mul(prime);
    }
    // Hash event_count
    for &b in &event_count.to_le_bytes() {
        h ^= b as u128;
        h = h.wrapping_mul(prime);
    }

    h.to_le_bytes()
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max { s } else { &s[..max] }
}
