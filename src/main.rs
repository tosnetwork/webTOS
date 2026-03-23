//! AOS Stage-1 Kernel Entry Point
//!
//! Rust entry point called by boot.asm after transitioning to 64-bit long mode.

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

pub mod arch;
mod heap;
mod panic;
mod logger;
mod agent;
mod mailbox;
mod capability;
mod energy;
mod event;
mod state;
mod persist;
mod sched;
mod syscall;
mod trap;
mod init;
mod agents;
mod ebpf;
mod wasm;
mod loader;
mod sync;
mod deterministic;
mod cost;
mod merkle;
mod checkpoint;
mod replay;
mod large_msg;
mod smp;

/// Kernel entry point, called from boot.asm after long mode transition.
#[no_mangle]
pub extern "C" fn kernel_main(multiboot_magic: u32, multiboot_info: u64) -> ! {
    // 1. Initialize serial output first
    arch::x86_64::serial::init();

    serial_println!("AOS boot ok");
    serial_println!("AOS v0.1 - AI-native Operating System");
    serial_println!("multiboot magic: 0x{:x}, info: 0x{:x}", multiboot_magic, multiboot_info);

    // 2. Validate multiboot magic
    if multiboot_magic != 0x2BADB002 {
        serial_println!("[WARN] Invalid multiboot magic, continuing anyway");
    }

    // 3. Initialize architecture (GDT, IDT, timer)
    arch::x86_64::init();
    serial_println!("[OK] Architecture initialized");

    // 4. Initialize memory (frame allocator)
    arch::x86_64::paging::init();
    serial_println!("[OK] Memory initialized");

    // 5. Initialize kernel subsystems
    sched::init();
    serial_println!("[OK] Scheduler initialized");

    // 6. Emit boot event
    event::boot();

    // 7. Create agents and set up the system
    init::init();
    serial_println!("[OK] System initialization complete");

    // 8. Discover CPUs and boot APs (if multi-core)
    if let Some(acpi_info) = arch::x86_64::acpi::init() {
        serial_println!("[SMP] {} CPU(s) detected", acpi_info.cpu_count);
        if acpi_info.cpu_count > 1 {
            // Initialize LAPIC on BSP
            arch::x86_64::lapic::init(acpi_info.lapic_base);
            // Disable PIT since LAPIC timer replaces it
            arch::x86_64::lapic::disable_pit();
            // Boot Application Processors
            smp::boot_aps(&acpi_info);
        }
    } else {
        serial_println!("[SMP] ACPI not found, running single-core");
    }

    // 9. Start scheduling
    serial_println!("[AOS] Entering scheduler loop");
    sched::start();

    // Should not reach here
    serial_println!("[AOS] Scheduler returned - halting");
    loop {
        unsafe { core::arch::asm!("hlt"); }
    }
}
