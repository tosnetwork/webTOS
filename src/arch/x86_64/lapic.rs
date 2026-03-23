//! AOS Local APIC Driver
//!
//! Provides access to the x86_64 Local APIC for:
//! - Per-core timer interrupts (replaces PIT for SMP)
//! - Inter-Processor Interrupts (IPI) for AP bootstrap
//! - End-of-interrupt signaling

use crate::serial_println;
use core::sync::atomic::{AtomicBool, Ordering};

// ─── LAPIC Register Offsets (from LAPIC base) ────────────────────────────

const LAPIC_ID: u32 = 0x020;         // Local APIC ID
const LAPIC_VERSION: u32 = 0x030;
const LAPIC_TPR: u32 = 0x080;        // Task Priority Register
const LAPIC_EOI: u32 = 0x0B0;        // End Of Interrupt
const LAPIC_SVR: u32 = 0x0F0;        // Spurious Interrupt Vector Register
const LAPIC_ICR_LOW: u32 = 0x300;    // Interrupt Command Register (low)
const LAPIC_ICR_HIGH: u32 = 0x310;   // Interrupt Command Register (high)
const LAPIC_TIMER_LVT: u32 = 0x320;  // Timer Local Vector Table entry
const LAPIC_LINT0_LVT: u32 = 0x350;
const LAPIC_LINT1_LVT: u32 = 0x360;
const LAPIC_TIMER_INIT: u32 = 0x380; // Timer Initial Count
const LAPIC_TIMER_CURR: u32 = 0x390; // Timer Current Count
const LAPIC_TIMER_DIV: u32 = 0x3E0;  // Timer Divide Configuration

// ─── Constants ───────────────────────────────────────────────────────────

const SVR_ENABLE: u32 = 1 << 8;      // APIC Software Enable bit
const TIMER_PERIODIC: u32 = 1 << 17; // Periodic timer mode
const TIMER_VECTOR: u32 = 32;        // Same IRQ vector as PIT (vector 32)
const TIMER_DIVIDER: u32 = 0x03;     // Divide by 16
const SPURIOUS_VECTOR: u32 = 0xFF;

// ICR delivery modes
const ICR_INIT: u32 = 0x00000500;    // INIT IPI
const ICR_STARTUP: u32 = 0x00000600; // Startup IPI
const ICR_LEVEL_ASSERT: u32 = 0x00004000;
const ICR_DELIVERY_STATUS: u32 = 0x00001000;

// ─── State ───────────────────────────────────────────────────────────────

static mut LAPIC_BASE_ADDR: u64 = 0;
static LAPIC_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Check if LAPIC is active (used by interrupt handlers to choose EOI method)
pub fn is_active() -> bool {
    LAPIC_ACTIVE.load(Ordering::Relaxed)
}

// ─── MMIO Read/Write ─────────────────────────────────────────────────────

unsafe fn read(offset: u32) -> u32 {
    let addr = LAPIC_BASE_ADDR + offset as u64;
    core::ptr::read_volatile(addr as *const u32)
}

unsafe fn write(offset: u32, value: u32) {
    let addr = LAPIC_BASE_ADDR + offset as u64;
    core::ptr::write_volatile(addr as *mut u32, value);
}

// ─── Public API ──────────────────────────────────────────────────────────

/// Initialize the Local APIC.
///
/// `base` is the physical address of the LAPIC MMIO region (from ACPI MADT).
/// In AOS Stage-3 with identity mapping, the physical address is directly usable.
pub fn init(base: u64) {
    unsafe {
        LAPIC_BASE_ADDR = base;

        // Enable LAPIC via Spurious Vector Register
        let svr = read(LAPIC_SVR);
        write(LAPIC_SVR, svr | SVR_ENABLE | SPURIOUS_VECTOR);

        // Set Task Priority to 0 (accept all interrupts)
        write(LAPIC_TPR, 0);

        // Configure APIC timer: periodic mode, vector 32, divider 16
        write(LAPIC_TIMER_DIV, TIMER_DIVIDER);
        write(LAPIC_TIMER_LVT, TIMER_PERIODIC | TIMER_VECTOR);

        // Set initial timer count (approximate 100 Hz)
        // QEMU's APIC timer runs at ~1 GHz bus clock / divider
        // A count of ~625000 with divider 16 gives ~100 Hz on QEMU
        // This is approximate; real hardware would need PIT-based calibration
        write(LAPIC_TIMER_INIT, 625_000);

        // Mask LINT0 and LINT1 (we don't use legacy interrupt lines)
        write(LAPIC_LINT0_LVT, 1 << 16); // masked
        write(LAPIC_LINT1_LVT, 1 << 16); // masked

        LAPIC_ACTIVE.store(true, Ordering::Relaxed);
    }

    let apic_id = id();
    serial_println!("[LAPIC] Initialized: base={:#x} APIC_ID={} timer=vector {} periodic",
        base, apic_id, TIMER_VECTOR);
}

/// Initialize LAPIC for an Application Processor (AP).
/// Same as init() but uses the already-stored base address.
pub fn init_ap() {
    unsafe {
        // Enable LAPIC
        let svr = read(LAPIC_SVR);
        write(LAPIC_SVR, svr | SVR_ENABLE | SPURIOUS_VECTOR);
        write(LAPIC_TPR, 0);

        // Configure timer (same as BSP)
        write(LAPIC_TIMER_DIV, TIMER_DIVIDER);
        write(LAPIC_TIMER_LVT, TIMER_PERIODIC | TIMER_VECTOR);
        write(LAPIC_TIMER_INIT, 625_000);

        write(LAPIC_LINT0_LVT, 1 << 16);
        write(LAPIC_LINT1_LVT, 1 << 16);
    }

    serial_println!("[LAPIC] AP {} initialized", id());
}

/// Send End-of-Interrupt to LAPIC.
pub fn eoi() {
    unsafe { write(LAPIC_EOI, 0); }
}

/// Get this core's LAPIC ID.
pub fn id() -> u8 {
    unsafe { (read(LAPIC_ID) >> 24) as u8 }
}

/// Send an INIT IPI to a target processor.
pub fn send_init_ipi(target_apic_id: u8) {
    unsafe {
        // Set target APIC ID in ICR high
        write(LAPIC_ICR_HIGH, (target_apic_id as u32) << 24);
        // Send INIT IPI
        write(LAPIC_ICR_LOW, ICR_INIT | ICR_LEVEL_ASSERT);
        // Wait for delivery
        while read(LAPIC_ICR_LOW) & ICR_DELIVERY_STATUS != 0 {
            core::hint::spin_loop();
        }
    }
}

/// Send a Startup IPI (SIPI) to a target processor.
/// `vector` is the page number of the AP entry code (e.g., 0x08 for 0x8000).
pub fn send_sipi(target_apic_id: u8, vector: u8) {
    unsafe {
        write(LAPIC_ICR_HIGH, (target_apic_id as u32) << 24);
        write(LAPIC_ICR_LOW, ICR_STARTUP | vector as u32);
        while read(LAPIC_ICR_LOW) & ICR_DELIVERY_STATUS != 0 {
            core::hint::spin_loop();
        }
    }
}

/// Send a generic IPI to a target processor.
pub fn send_ipi(target_apic_id: u8, vector: u8) {
    unsafe {
        write(LAPIC_ICR_HIGH, (target_apic_id as u32) << 24);
        write(LAPIC_ICR_LOW, vector as u32);
        while read(LAPIC_ICR_LOW) & ICR_DELIVERY_STATUS != 0 {
            core::hint::spin_loop();
        }
    }
}

/// Disable the PIT timer (IRQ0) at the PIC.
/// Called after LAPIC timer is configured, since LAPIC timer replaces PIT.
pub fn disable_pit() {
    unsafe {
        // Mask IRQ0 at PIC1
        let mask = crate::arch::x86_64::serial::inb(0x21);
        crate::arch::x86_64::serial::outb(0x21, mask | 0x01);
    }
    serial_println!("[LAPIC] PIT disabled (APIC timer active)");
}
