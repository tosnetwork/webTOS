//! AOS SMP Bootstrap
//!
//! Orchestrates Application Processor (AP) startup via INIT+SIPI IPI sequence.
//! APs execute the trampoline code, enter long mode, and call ap_entry().

use crate::serial_println;
use crate::arch::x86_64::{acpi::AcpiInfo, lapic};
use core::sync::atomic::{AtomicU8, Ordering};

/// Number of APs that have completed initialization
pub static AP_STARTED: AtomicU8 = AtomicU8::new(0);

/// Trampoline code location in physical memory
const AP_TRAMPOLINE_ADDR: u64 = 0x8000;
/// Data area within the trampoline page
const AP_DATA_CR3: u64 = 0x8FF0;
const AP_DATA_STACK: u64 = 0x8FF8;

extern "C" {
    static ap_trampoline_start: u8;
    static ap_trampoline_end: u8;
}

/// Boot all Application Processors discovered via ACPI.
pub fn boot_aps(acpi_info: &AcpiInfo) {
    if acpi_info.cpu_count <= 1 {
        serial_println!("[SMP] Only 1 CPU detected, skipping AP boot");
        return;
    }

    let bsp_apic_id = lapic::id();
    serial_println!(
        "[SMP] BSP APIC ID = {}, booting {} APs",
        bsp_apic_id,
        acpi_info.cpu_count - 1
    );

    // Get current CR3 for APs to share the same page tables
    let cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack));
    }

    // Copy trampoline code to 0x8000
    let trampoline_size = unsafe {
        &ap_trampoline_end as *const u8 as usize - &ap_trampoline_start as *const u8 as usize
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            &ap_trampoline_start as *const u8,
            AP_TRAMPOLINE_ADDR as *mut u8,
            trampoline_size,
        );
    }
    serial_println!(
        "[SMP] Trampoline copied to {:#x} ({} bytes)",
        AP_TRAMPOLINE_ADDR,
        trampoline_size
    );

    // Write shared CR3 to trampoline data area
    unsafe {
        core::ptr::write_volatile(AP_DATA_CR3 as *mut u64, cr3);
    }

    // Boot each AP
    for i in 0..acpi_info.cpu_count as usize {
        let apic_id = acpi_info.cpu_apic_ids[i];
        if apic_id == bsp_apic_id {
            continue; // Skip BSP
        }

        // Allocate a stack for this AP (two 4K frames = 8 KiB)
        let stack_phys = crate::arch::x86_64::paging::alloc_frame()
            .expect("Failed to allocate AP stack frame 1");
        let stack_phys2 = crate::arch::x86_64::paging::alloc_frame()
            .expect("Failed to allocate AP stack frame 2");
        // Use the higher of the two frames as stack top (stack grows down)
        let stack_top = if stack_phys2 > stack_phys {
            stack_phys2 + 4096
        } else {
            stack_phys + 4096
        };

        // Write per-AP stack top to trampoline data area
        unsafe {
            core::ptr::write_volatile(AP_DATA_STACK as *mut u64, stack_top);
        }

        serial_println!(
            "[SMP] Sending INIT IPI to AP {} (APIC ID {})",
            i,
            apic_id
        );

        // Send INIT IPI
        lapic::send_init_ipi(apic_id);

        // Wait ~10ms (busy loop, approximately 10M iterations on QEMU)
        for _ in 0..10_000_000u64 {
            core::hint::spin_loop();
        }

        // Send SIPI with vector 0x08 (entry at 0x8000)
        serial_println!(
            "[SMP] Sending SIPI to AP {} (vector 0x08 -> {:#x})",
            i,
            AP_TRAMPOLINE_ADDR
        );
        lapic::send_sipi(apic_id, 0x08);

        // Wait for AP to signal ready (up to ~100ms)
        let expected = AP_STARTED.load(Ordering::Relaxed) + 1;
        let mut waited = 0u64;
        while AP_STARTED.load(Ordering::Acquire) < expected {
            core::hint::spin_loop();
            waited += 1;
            if waited > 100_000_000 {
                serial_println!("[SMP] WARNING: AP {} did not start (timeout)", apic_id);
                break;
            }
        }

        if AP_STARTED.load(Ordering::Relaxed) >= expected {
            serial_println!(
                "[SMP] AP {} (APIC ID {}) started successfully",
                i,
                apic_id
            );
        }
    }

    let total = AP_STARTED.load(Ordering::Relaxed);
    serial_println!("[SMP] {} AP(s) booted, total {} cores active", total, total + 1);
}

/// Entry point for Application Processors (called from trampoline).
///
/// Each AP arrives here in 64-bit long mode with its own stack.
/// It initializes its local APIC and enters an idle loop.
#[no_mangle]
pub extern "C" fn ap_entry() -> ! {
    // Initialize this core's LAPIC
    lapic::init_ap();

    // Signal to BSP that this AP is ready
    AP_STARTED.fetch_add(1, Ordering::Release);

    let apic_id = lapic::id();
    serial_println!("[SMP] AP (APIC ID {}) entered idle loop", apic_id);

    // Idle loop -- this core will be woken by IPIs for future work
    loop {
        unsafe {
            core::arch::asm!("hlt");
        }
    }
}
