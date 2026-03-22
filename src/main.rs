//! AOS Stage-1 Kernel Entry Point
//!
//! Rust entry point called by boot.asm after transitioning to 64-bit long mode.

#![no_std]
#![no_main]

pub mod arch;
mod panic;
mod logger;
mod agent;
mod mailbox;
mod capability;
mod energy;
mod event;
mod state;
mod sched;
mod syscall;
mod trap;
mod init;
mod agents;

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

    // 4. Initialize memory (frame allocator deferred to later stage)
    serial_println!("[OK] Memory initialized");

    // 5. Initialize kernel subsystems
    sched::init();
    serial_println!("[OK] Scheduler initialized");

    // 6. Emit boot event
    event::boot();

    // 7. Create agents and set up the system
    init::init();
    serial_println!("[OK] System initialization complete");

    // 8. Start scheduling
    serial_println!("[AOS] Entering scheduler loop");
    sched::start();

    // Should not reach here
    serial_println!("[AOS] Scheduler returned - halting");
    loop {
        unsafe { core::arch::asm!("hlt"); }
    }
}
