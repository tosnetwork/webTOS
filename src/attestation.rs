//! Remote Attestation for AOS
//!
//! Provides kernel measurement and attestation report generation.
//! In production, this would use TPM PCR values. For QEMU testing,
//! we use a software-based measurement chain.
//!
//! The measurement covers:
//!   - A hash of the kernel's `.text` section bounds (start/end pointers)
//!   - A hash of the boot configuration (tick + agent_count at measurement time)
//!   - The number of active agents
//!   - The current scheduler tick
//!
//! All hashing uses FNV-1a (consistent with the rest of the kernel).

use crate::serial_println;

// ─── FNV-1a helpers (local copy so attestation has no external hash dep) ──

fn fnv1a_64(data: &[u8], offset_basis: u64) -> u64 {
    let mut hash = offset_basis;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Produce a 16-byte (128-bit) FNV-1a hash over `data`.
fn fnv_hash_128(data: &[u8]) -> [u8; 16] {
    let h1 = fnv1a_64(data, 0xcbf29ce484222325);
    let h2 = fnv1a_64(data, 0x84222325cbf29ce4);
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&h1.to_le_bytes());
    out[8..16].copy_from_slice(&h2.to_le_bytes());
    out
}

/// Chain two 16-byte hashes: H(left || right)
fn chain_hash(left: &[u8; 16], right: &[u8; 16]) -> [u8; 16] {
    let mut buf = [0u8; 32];
    buf[0..16].copy_from_slice(left);
    buf[16..32].copy_from_slice(right);
    fnv_hash_128(&buf)
}

// ─── Structures ────────────────────────────────────────────────────────────

/// Kernel measurement: hash of critical kernel state at boot.
///
/// `kernel_hash`      — FNV-1a over the kernel `.text` section address bounds.
/// `boot_config_hash` — FNV-1a over the boot-time configuration (tick, agent
///                      count, event sequence).
pub struct KernelMeasurement {
    /// FNV-1a of kernel .text section bounds (start + end addresses).
    pub kernel_hash: [u8; 16],
    /// FNV-1a of boot configuration (tick, agent_count, event_seq).
    pub boot_config_hash: [u8; 16],
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
    pub proof_hash: [u8; 16],
    /// Keyed-hash signature over (measurement || proof_hash).
    /// Placeholder for a TPM-backed signature in production.
    pub signature: [u8; 32],
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

    // ── kernel_hash: FNV-1a over .text bounds ──────────────────────────────
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
    let kernel_hash = fnv_hash_128(&text_buf);

    // ── boot_config_hash: FNV-1a over tick + agent_count + event_seq ───────
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
    let boot_config_hash = fnv_hash_128(&cfg_buf);

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
/// The report bundles the current `KernelMeasurement` with the latest
/// execution-proof hash and a keyed FNV-1a signature over both.
pub fn generate_report(secret: &[u8; 32]) -> AttestationReport {
    let measurement = measure_kernel();

    // Retrieve the latest proof hash from the proof subsystem.
    let latest_proof = crate::proof::generate_proof();
    let proof_hash = latest_proof.proof_hash;

    // Compute signature: H( measurement_chain || proof_hash || secret )
    let measurement_chain = chain_hash(&measurement.kernel_hash, &measurement.boot_config_hash);
    let combined = chain_hash(&measurement_chain, &proof_hash);

    // Expand to 32-byte signature using two FNV-1a passes over (combined || secret).
    let mut sig_input = [0u8; 48]; // combined(16) + secret(32)
    sig_input[0..16].copy_from_slice(&combined);
    sig_input[16..48].copy_from_slice(secret);

    let h1 = fnv1a_64(&sig_input, 0xcbf29ce484222325);
    let h2 = fnv1a_64(&sig_input, 0x84222325cbf29ce4);
    let h3 = fnv1a_64(&sig_input, 0x517cc1b727220a95);
    let h4 = fnv1a_64(&sig_input, 0xa95220271bc71705);

    let mut signature = [0u8; 32];
    signature[0..8].copy_from_slice(&h1.to_le_bytes());
    signature[8..16].copy_from_slice(&h2.to_le_bytes());
    signature[16..24].copy_from_slice(&h3.to_le_bytes());
    signature[24..32].copy_from_slice(&h4.to_le_bytes());

    AttestationReport {
        measurement,
        proof_hash,
        signature,
    }
}

/// Verify an attestation report.
///
/// Recomputes the expected signature from the report's measurement and
/// proof_hash using `secret`, then compares it to the stored signature.
/// Returns `true` if the report is authentic.
pub fn verify_report(report: &AttestationReport, secret: &[u8; 32]) -> bool {
    let measurement_chain = chain_hash(
        &report.measurement.kernel_hash,
        &report.measurement.boot_config_hash,
    );
    let combined = chain_hash(&measurement_chain, &report.proof_hash);

    let mut sig_input = [0u8; 48];
    sig_input[0..16].copy_from_slice(&combined);
    sig_input[16..48].copy_from_slice(secret);

    let h1 = fnv1a_64(&sig_input, 0xcbf29ce484222325);
    let h2 = fnv1a_64(&sig_input, 0x84222325cbf29ce4);
    let h3 = fnv1a_64(&sig_input, 0x517cc1b727220a95);
    let h4 = fnv1a_64(&sig_input, 0xa95220271bc71705);

    let mut expected = [0u8; 32];
    expected[0..8].copy_from_slice(&h1.to_le_bytes());
    expected[8..16].copy_from_slice(&h2.to_le_bytes());
    expected[16..24].copy_from_slice(&h3.to_le_bytes());
    expected[24..32].copy_from_slice(&h4.to_le_bytes());

    // Constant-time comparison to avoid timing side-channels.
    let mut diff: u8 = 0;
    for (a, b) in expected.iter().zip(report.signature.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Print an attestation report to the serial console.
pub fn print_report(report: &AttestationReport) {
    let m = &report.measurement;
    serial_println!("╔══════════════════════════════════════════════╗");
    serial_println!("║         ATTESTATION REPORT                  ║");
    serial_println!("╠══════════════════════════════════════════════╣");
    serial_println!("║ Tick:           {:>25}  ║", m.tick);
    serial_println!("║ Active agents:  {:>25}  ║", m.agent_count);
    serial_println!("║ Kernel hash:    {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}...       ║",
        m.kernel_hash[0], m.kernel_hash[1], m.kernel_hash[2], m.kernel_hash[3],
        m.kernel_hash[4], m.kernel_hash[5], m.kernel_hash[6], m.kernel_hash[7]);
    serial_println!("║ Config hash:    {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}...       ║",
        m.boot_config_hash[0], m.boot_config_hash[1],
        m.boot_config_hash[2], m.boot_config_hash[3],
        m.boot_config_hash[4], m.boot_config_hash[5],
        m.boot_config_hash[6], m.boot_config_hash[7]);
    serial_println!("║ Proof hash:     {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}...       ║",
        report.proof_hash[0], report.proof_hash[1],
        report.proof_hash[2], report.proof_hash[3],
        report.proof_hash[4], report.proof_hash[5],
        report.proof_hash[6], report.proof_hash[7]);
    serial_println!("║ Signature:      {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}...       ║",
        report.signature[0], report.signature[1],
        report.signature[2], report.signature[3],
        report.signature[4], report.signature[5],
        report.signature[6], report.signature[7]);
    serial_println!("╚══════════════════════════════════════════════╝");
}
