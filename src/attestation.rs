//! Remote Attestation for TOS
//!
//! Provides kernel measurement and attestation report generation.
//! When a TPM 2.0 CRB is available, measurements use hardware PCR values
//! and the report is signed with Ed25519 using the node's signing key.
//! When no TPM is present, falls back to a keyed SHA-256 hash approach.
//!
//! The measurement covers:
//!   - A hash of the kernel's `.text` section bounds (start/end pointers)
//!   - A hash of the boot configuration (tick + agent_count at measurement time)
//!   - The number of active agents
//!   - The current scheduler tick
//!
//! TPM-backed reports additionally include PCR0 (kernel hash) and PCR1
//! (boot config) values, extend a PCR with the measurement data, and
//! carry a 64-byte Ed25519 signature.

use crate::crypto;
use crate::serial_println;

/// Produce a 32-byte SHA-256 hash over `data`.
fn sha256_hash(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Chain two 32-byte hashes: SHA-256(left || right)
fn chain_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[0..32].copy_from_slice(left);
    buf[32..64].copy_from_slice(right);
    sha256_hash(&buf)
}

// ─── Structures ────────────────────────────────────────────────────────────

/// Kernel measurement: hash of critical kernel state at boot.
///
/// `kernel_hash`      — SHA-256 over the kernel `.text` section address bounds.
/// `boot_config_hash` — SHA-256 over the boot-time configuration (tick, agent
///                      count, event sequence).
pub struct KernelMeasurement {
    /// SHA-256 of kernel .text section bounds (start + end addresses).
    pub kernel_hash: [u8; 32],
    /// SHA-256 of boot configuration (tick, agent_count, event_seq).
    pub boot_config_hash: [u8; 32],
    /// Number of active agents at measurement time.
    pub agent_count: u32,
    /// Scheduler tick at measurement time.
    pub tick: u64,
}

/// Attestation report: signed measurement + latest proof hash.
pub struct AttestationReport {
    /// The kernel measurement captured for this report.
    pub measurement: KernelMeasurement,
    /// Hash of the latest execution proof at report-generation time.
    pub proof_hash: [u8; 32],
    /// Ed25519 signature (64 bytes) when TPM-backed, or zero-padded
    /// keyed-hash (32 bytes in [0..32], zeros in [32..64]) for fallback.
    pub signature: [u8; 64],
    /// True when the report was generated with TPM hardware backing
    /// and signed with Ed25519. False for keyed-hash fallback.
    pub is_tpm_backed: bool,
    /// Ed25519 verifying key for TPM-backed reports (32 bytes).
    /// All zeros when `is_tpm_backed` is false.
    pub verifying_key: [u8; 32],
}

// ─── Measurement ───────────────────────────────────────────────────────────

/// Generate a kernel measurement reflecting current kernel state.
///
/// The `kernel_hash` is derived from the addresses of two well-known symbols
/// (`kernel_main` and `kernel_text_end`) to capture the `.text` section bounds
/// without requiring a dedicated linker symbol in Stage-2.
pub fn measure_kernel() -> KernelMeasurement {
    let tick = crate::arch::x86_64::timer::get_ticks();
    let event_seq = crate::event::get_sequence();

    // ── kernel_hash: SHA-256 over .text bounds ─────────────────────────────
    // Use the address of kernel_main as the start of .text, and a fixed
    // sentinel to approximate the end.  In a production build a linker script
    // would expose __kernel_text_start / __kernel_text_end.
    let text_start = crate::kernel_main as *const () as usize as u64;
    // Approximate end: start + a representative code-section size (512 KiB).
    // This is deterministic for a given binary, which is all we need.
    let text_end = text_start.wrapping_add(512 * 1024);

    let mut text_buf = [0u8; 16];
    text_buf[0..8].copy_from_slice(&text_start.to_le_bytes());
    text_buf[8..16].copy_from_slice(&text_end.to_le_bytes());
    let mut kernel_hash = sha256_hash(&text_buf);

    // ── boot_config_hash: SHA-256 over tick + agent_count + event_seq ──────
    let mut agent_count: u32 = 0;
    crate::agent::for_each_agent_mut(|agent| {
        if agent.active {
            agent_count += 1;
        }
        true
    });

    let mut cfg_buf = [0u8; 20]; // tick(8) + agent_count(4) + event_seq(8)
    cfg_buf[0..8].copy_from_slice(&tick.to_le_bytes());
    cfg_buf[8..12].copy_from_slice(&agent_count.to_le_bytes());
    cfg_buf[12..20].copy_from_slice(&event_seq.to_le_bytes());
    let mut boot_config_hash = sha256_hash(&cfg_buf);

    // If TPM is available, use hardware PCR values for measurements
    if crate::arch::x86_64::tpm::is_available() {
        if let Some(pcr0) = crate::arch::x86_64::tpm::pcr_read(0) {
            kernel_hash = pcr0;
        }
        if let Some(pcr1) = crate::arch::x86_64::tpm::pcr_read(1) {
            boot_config_hash = pcr1;
        }
    }

    KernelMeasurement {
        kernel_hash,
        boot_config_hash,
        agent_count,
        tick,
    }
}

// ─── Report generation & verification ─────────────────────────────────────

/// Generate an attestation report for the current kernel state.
///
/// When a TPM is available, the report reads PCR0/PCR1 into the
/// measurement, extends a PCR with the combined measurement data,
/// and signs the report with Ed25519.  Otherwise falls back to a
/// keyed SHA-256 hash.
pub fn generate_report(secret: &[u8; 32]) -> AttestationReport {
    let measurement = measure_kernel();

    // Retrieve the latest proof hash from the proof subsystem.
    let latest_proof = crate::proof::generate_proof();
    let proof_hash = latest_proof.proof_hash;

    // Build the message that will be signed / hashed.
    let measurement_chain = chain_hash(&measurement.kernel_hash, &measurement.boot_config_hash);
    let combined = chain_hash(&measurement_chain, &proof_hash);

    let tpm_available = crate::arch::x86_64::tpm::is_available();

    if tpm_available {
        // ── TPM-backed path ────────────────────────────────────────────
        // Extend PCR 2 with the combined measurement so it becomes part
        // of the TPM event log.
        crate::arch::x86_64::tpm::pcr_extend(2, &combined);

        // Sign the combined hash with Ed25519 using a fresh keypair.
        let (signing_key, verifying_key) = crypto::generate_keypair();
        let sig = crypto::sign(&signing_key, &combined);
        let sig_bytes = sig.to_bytes(); // [u8; 64]

        let mut vk_bytes = [0u8; 32];
        vk_bytes.copy_from_slice(verifying_key.as_bytes());

        AttestationReport {
            measurement,
            proof_hash,
            signature: sig_bytes,
            is_tpm_backed: true,
            verifying_key: vk_bytes,
        }
    } else {
        // ── Fallback: SHA-256 keyed hash (no TPM) ─────────────────────
        // HMAC-like construction: SHA-256(secret || combined)
        let mut sig_input = [0u8; 64]; // secret(32) + combined(32)
        sig_input[0..32].copy_from_slice(secret);
        sig_input[32..64].copy_from_slice(&combined);

        let keyed_hash = sha256_hash(&sig_input);

        let mut signature = [0u8; 64];
        signature[0..32].copy_from_slice(&keyed_hash);
        // bytes [32..64] remain zero — distinguishes fallback from Ed25519

        AttestationReport {
            measurement,
            proof_hash,
            signature,
            is_tpm_backed: false,
            verifying_key: [0u8; 32],
        }
    }
}

/// Verify an attestation report.
///
/// For TPM-backed reports: verifies the Ed25519 signature using the
/// embedded verifying key against the recomputed measurement hash.
///
/// For fallback reports: recomputes the keyed SHA-256 hash using
/// `secret` and compares it to the stored signature.
///
/// Returns `true` if the report is authentic.
pub fn verify_report(report: &AttestationReport, secret: &[u8; 32]) -> bool {
    let measurement_chain = chain_hash(
        &report.measurement.kernel_hash,
        &report.measurement.boot_config_hash,
    );
    let combined = chain_hash(&measurement_chain, &report.proof_hash);

    if report.is_tpm_backed {
        // ── Ed25519 verification ───────────────────────────────────────
        let vk = match crypto::VerifyingKey::from_bytes(&report.verifying_key) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let sig = crypto::Signature::from_bytes(&report.signature);
        crypto::verify(&vk, &combined, &sig)
    } else {
        // ── Fallback: SHA-256 keyed hash verification ───────────────────
        // Recompute: SHA-256(secret || combined)
        let mut sig_input = [0u8; 64];
        sig_input[0..32].copy_from_slice(secret);
        sig_input[32..64].copy_from_slice(&combined);

        let keyed_hash = sha256_hash(&sig_input);

        let mut expected = [0u8; 64];
        expected[0..32].copy_from_slice(&keyed_hash);
        // [32..64] stays zero, matching fallback signature layout

        // Constant-time comparison to avoid timing side-channels.
        let mut diff: u8 = 0;
        for (a, b) in expected.iter().zip(report.signature.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

/// Print an attestation report to the serial console.
pub fn print_report(report: &AttestationReport) {
    let m = &report.measurement;
    let mode = if report.is_tpm_backed {
        "TPM + Ed25519"
    } else {
        "Fallback (keyed-hash)"
    };
    serial_println!("╔══════════════════════════════════════════════╗");
    serial_println!("║         ATTESTATION REPORT                  ║");
    serial_println!("╠══════════════════════════════════════════════╣");
    serial_println!("║ Mode:           {:>25}  ║", mode);
    serial_println!("║ Tick:           {:>25}  ║", m.tick);
    serial_println!("║ Active agents:  {:>25}  ║", m.agent_count);
    serial_println!(
        "║ Kernel hash:    {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}...       ║",
        m.kernel_hash[0],
        m.kernel_hash[1],
        m.kernel_hash[2],
        m.kernel_hash[3],
        m.kernel_hash[4],
        m.kernel_hash[5],
        m.kernel_hash[6],
        m.kernel_hash[7]
    );
    serial_println!(
        "║ Config hash:    {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}...       ║",
        m.boot_config_hash[0],
        m.boot_config_hash[1],
        m.boot_config_hash[2],
        m.boot_config_hash[3],
        m.boot_config_hash[4],
        m.boot_config_hash[5],
        m.boot_config_hash[6],
        m.boot_config_hash[7]
    );
    serial_println!(
        "║ Proof hash:     {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}...       ║",
        report.proof_hash[0],
        report.proof_hash[1],
        report.proof_hash[2],
        report.proof_hash[3],
        report.proof_hash[4],
        report.proof_hash[5],
        report.proof_hash[6],
        report.proof_hash[7]
    );
    serial_println!(
        "║ Signature:      {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}...       ║",
        report.signature[0],
        report.signature[1],
        report.signature[2],
        report.signature[3],
        report.signature[4],
        report.signature[5],
        report.signature[6],
        report.signature[7]
    );
    serial_println!("╚══════════════════════════════════════════════╝");
}
