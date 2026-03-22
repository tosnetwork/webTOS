//! AOS x86_64 Paging - Simple Frame Allocator
//!
//! Provides a basic bitmap frame allocator for physical 4KB pages.
//! Identity mapping is set up by boot.asm; this module manages frame
//! allocation for future use (agent address spaces, stacks, etc.).

use core::sync::atomic::{AtomicU64, Ordering};
use crate::serial_println;

/// Page/frame size: 4 KiB.
pub const PAGE_SIZE: usize = 4096;

/// Maximum physical memory managed (128 MB).
const MAX_MEMORY: usize = 128 * 1024 * 1024;

/// Total number of frames in the managed region.
const MAX_FRAMES: usize = MAX_MEMORY / PAGE_SIZE;

/// Number of u64 bitmap entries needed (each covers 64 frames).
const BITMAP_SIZE: usize = (MAX_FRAMES + 63) / 64;

/// Start of allocatable physical memory (skip first 2 MB for kernel/boot).
const ALLOC_START: usize = 2 * 1024 * 1024;

/// Start frame index (first allocatable frame).
const START_FRAME: usize = ALLOC_START / PAGE_SIZE;

// Bitmap: bit set = frame is allocated, bit clear = frame is free.
// Safety: single-core access in Stage-1.
static mut BITMAP: [u64; BITMAP_SIZE] = [0u64; BITMAP_SIZE];

// Next frame index to check (simple bump hint for fast allocation).
static NEXT_FREE: AtomicU64 = AtomicU64::new(START_FRAME as u64);

/// Initialize the frame allocator.
///
/// In Stage-1 this just marks the first 2MB as reserved (used by kernel/boot).
pub fn init() {
    unsafe {
        // Mark all frames below ALLOC_START as used
        for i in 0..START_FRAME {
            let word = i / 64;
            let bit = i % 64;
            BITMAP[word] |= 1u64 << bit;
        }
    }
    serial_println!("[paging] Frame allocator initialized: {} frames available ({} MB)",
        MAX_FRAMES - START_FRAME,
        (MAX_FRAMES - START_FRAME) * PAGE_SIZE / (1024 * 1024));
}

/// Allocate a single 4KB physical frame.
///
/// Returns the physical address of the frame, or None if out of memory.
pub fn alloc_frame() -> Option<u64> {
    let start = NEXT_FREE.load(Ordering::Relaxed) as usize;

    unsafe {
        // Search from hint forward
        for i in start..MAX_FRAMES {
            let word = i / 64;
            let bit = i % 64;
            if BITMAP[word] & (1u64 << bit) == 0 {
                // Found a free frame -- mark it allocated
                BITMAP[word] |= 1u64 << bit;
                NEXT_FREE.store((i + 1) as u64, Ordering::Relaxed);
                return Some((i * PAGE_SIZE) as u64);
            }
        }

        // Wrap around and search from START_FRAME to start
        for i in START_FRAME..start {
            let word = i / 64;
            let bit = i % 64;
            if BITMAP[word] & (1u64 << bit) == 0 {
                BITMAP[word] |= 1u64 << bit;
                NEXT_FREE.store((i + 1) as u64, Ordering::Relaxed);
                return Some((i * PAGE_SIZE) as u64);
            }
        }
    }

    None // Out of memory
}

/// Free a previously allocated 4KB physical frame.
///
/// # Safety
/// The address must have been returned by `alloc_frame()` and must not
/// be freed more than once.
pub fn dealloc_frame(addr: u64) {
    let frame = addr as usize / PAGE_SIZE;
    if frame >= MAX_FRAMES {
        return;
    }
    let word = frame / 64;
    let bit = frame % 64;
    unsafe {
        BITMAP[word] &= !(1u64 << bit);
    }
    // Update hint if this frame is earlier
    let current = NEXT_FREE.load(Ordering::Relaxed) as usize;
    if frame < current {
        NEXT_FREE.store(frame as u64, Ordering::Relaxed);
    }
}

/// Read the current value of CR3 (page table base register).
pub fn read_cr3() -> u64 {
    let cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    }
    cr3
}
