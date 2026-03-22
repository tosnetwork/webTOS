//! AOS x86_64 Timer (PIT)
//!
//! Programs the 8254 PIT channel 0 for periodic interrupts at ~100 Hz.
//! Maintains a monotonic tick counter incremented by the timer ISR.

use core::sync::atomic::{AtomicU64, Ordering};
use crate::serial_println;
use crate::arch::x86_64::serial::outb;

const PIT_CHANNEL0: u16 = 0x40;
const PIT_COMMAND: u16 = 0x43;

const PIT_FREQUENCY: u32 = 1_193_182;
const TARGET_HZ: u32 = 100;
const PIT_DIVISOR: u16 = (PIT_FREQUENCY / TARGET_HZ) as u16; // 11931 ~ 0x2E9B

static TICKS: AtomicU64 = AtomicU64::new(0);

/// Program the PIT for periodic interrupts at ~100 Hz.
pub fn init() {
    unsafe {
        // Channel 0, lo/hi byte access, mode 3 (square wave generator)
        outb(PIT_COMMAND, 0x36);
        // Send divisor low byte then high byte
        outb(PIT_CHANNEL0, (PIT_DIVISOR & 0xFF) as u8);
        outb(PIT_CHANNEL0, (PIT_DIVISOR >> 8) as u8);
    }

    serial_println!("[timer] PIT programmed: divisor={} (~{} Hz)", PIT_DIVISOR, TARGET_HZ);
}

/// Get the current tick count.
pub fn get_ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

/// Increment the tick counter. Called from the timer interrupt handler.
pub fn tick() {
    TICKS.fetch_add(1, Ordering::Relaxed);
}
