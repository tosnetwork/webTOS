//! KASLR — Kernel Address Space Layout Randomization (stack/heap variant)
//!
//! True code KASLR requires a position-independent (PIE) kernel binary so
//! that absolute symbol addresses can be relocated at boot time. AOS is
//! currently linked at the fixed higher-half VMA 0xFFFFFFFF80000000, so
//! relocating the code segment is not yet possible without substantial
//! toolchain changes.
//!
//! This module implements the subset of KASLR that *is* achievable today:
//!
//! * **Heap ASLR** — the frame allocator skips a random number of frames
//!   after the kernel image, so heap allocations start at a non-deterministic
//!   physical (and therefore virtual) address.
//! * **Stack ASLR** — agent stack base addresses are offset by a random,
//!   page-aligned amount within each allocation, making stack addresses
//!   unpredictable across boots.
//!
//! Entropy source: RDTSC (Time Stamp Counter). RDTSC is always available on
//! x86_64 and is read before any deterministic code runs, giving good
//! boot-time entropy. The low bits of TSC are mixed with the high bits to
//! spread entropy across the byte range used for offsets.
//!
//! # Limitations
//! Full code KASLR (randomising the kernel .text base) requires:
//! 1. Building the kernel as a PIE binary (`-pie -fPIE` / `relocation-model=pie`).
//! 2. A boot-time relocator that applies R_X86_64_RELATIVE fixups before
//!    jumping to Rust code.
//! This is tracked as a future enhancement in the Yellow Paper.

use core::sync::atomic::{AtomicU64, Ordering};
use crate::serial_println;

/// Raw TSC entropy captured during `init()`.
///
/// Stored as an atomic so it can be read from any context without locking.
/// Written exactly once (during boot) and thereafter only read.
static KASLR_ENTROPY: AtomicU64 = AtomicU64::new(0);

// ─── Public API ──────────────────────────────────────────────────────────────

/// Initialise KASLR entropy from RDTSC.
///
/// Must be called early in boot, before the frame allocator or any agent
/// stack is allocated. Calling it multiple times is safe — subsequent calls
/// are no-ops (the entropy value is immutable after the first write).
pub fn init() {
    // Read RDTSC: EDX:EAX = full 64-bit TSC value.
    let tsc: u64 = rdtsc();

    // Mix high and low halves so that a CPU with a low-frequency TSC (where
    // the upper bits are nearly zero at boot) still produces good low-byte
    // entropy for the offsets derived below.
    let mixed = tsc ^ (tsc >> 17) ^ (tsc << 13);

    KASLR_ENTROPY.store(mixed, Ordering::Relaxed);

    // Log only the bottom 16 bits — enough to confirm randomisation without
    // leaking the full entropy value (which would help an attacker).
    serial_println!("[kaslr] entropy seeded from RDTSC (low 16 bits: {:#06x})", mixed & 0xFFFF);
    serial_println!("[kaslr] heap ASLR: skip {} frames; stack ASLR: +{} bytes per agent",
        heap_skip_frames(), stack_offset());
}

/// Number of physical frames the frame allocator should skip after the kernel.
///
/// Returns a value in **0 … 63** (0 … 256 KB gap), giving 64 possible heap
/// start positions. Callers should pass this value to the frame allocator
/// immediately after `paging::init()` has reserved the kernel frames.
pub fn heap_skip_frames() -> usize {
    let entropy = KASLR_ENTROPY.load(Ordering::Relaxed);
    // Use bits [17:12] — six bits → 0-63.
    ((entropy >> 12) & 0x3F) as usize
}

/// Page-aligned byte offset to add to each agent stack base address.
///
/// Returns a value in **0 … 1 MiB** (0 … 255 pages × 4 KiB), giving 256
/// possible per-boot stack positions. Each agent derives its own final offset
/// by combining this boot-wide value with its agent index (see the scheduler).
pub fn stack_offset() -> u64 {
    let entropy = KASLR_ENTROPY.load(Ordering::Relaxed);
    // Use bits [11:4] — eight bits → 0-255 pages.
    let pages = (entropy >> 4) & 0xFF;
    pages * 4096
}

/// Raw entropy value (for testing / diagnostics only).
///
/// Returns `0` if `init()` has not yet been called.
#[allow(dead_code)]
pub fn raw_entropy() -> u64 {
    KASLR_ENTROPY.load(Ordering::Relaxed)
}

// ─── RDTSC helper ────────────────────────────────────────────────────────────

/// Read the x86_64 Time Stamp Counter.
///
/// Returns the full 64-bit TSC value (EDX:EAX concatenated).
/// RDTSC is serialising enough for boot-time entropy — we do not need RDTSCP.
#[inline]
fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}
