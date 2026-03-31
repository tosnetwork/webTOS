//! ATOS Stage-1 Kernel Entry Point
//!
//! Rust entry point called by boot.asm after transitioning to 64-bit long mode.

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

mod agent;
mod agent_loader;
mod agents;
pub mod arch;
mod attestation;
mod block;
mod capability;
mod checkpoint;
mod contract;
mod contract_call;
mod cost;
mod crypto;
mod deterministic;
mod ebpf;
mod energy;
mod event;
mod heap;
mod init;
mod large_msg;
pub mod linux_compat;
mod loader;
mod logger;
mod mailbox;
mod merkle;
pub mod metrics;
mod net;
mod node;
pub mod package;
mod panic;
mod persist;
mod policy;
mod proof;
mod receipts;
mod replay;
mod ringbuf;
mod sched;
mod smp;
mod state;
mod sync;
mod syscall;
pub mod tcp_interface;
mod trap;
mod wasm;

/// Kernel entry point, called from boot.asm after long mode transition.
#[no_mangle]
pub extern "C" fn kernel_main(multiboot_magic: u32, multiboot_info: u64) -> ! {
    // 1. Initialize serial output first
    arch::x86_64::serial::init();

    // 2. Detect boot method
    const MULTIBOOT_MAGIC: u32 = 0x2BADB002;
    const UEFI_MAGIC: u32 = 0xAE51_0EF1;

    match multiboot_magic {
        MULTIBOOT_MAGIC => {
            serial_println!("ATOS boot ok (Multiboot)");
        }
        UEFI_MAGIC => {
            serial_println!("ATOS boot ok (UEFI)");

            // Initialize framebuffer console if UEFI GOP provided FB info
            if multiboot_info != 0 {
                let boot_info_ptr = multiboot_info as *const arch::x86_64::paging::BootInfo;
                let bi = unsafe { &*boot_info_ptr };
                if bi.fb_addr != 0 {
                    arch::x86_64::framebuffer::init(
                        bi.fb_addr,
                        bi.fb_width,
                        bi.fb_height,
                        bi.fb_stride,
                        bi.fb_pixel_format,
                    );
                    serial_println!(
                        "[OK] Framebuffer console: {}x{} @ 0x{:x}",
                        bi.fb_width,
                        bi.fb_height,
                        bi.fb_addr
                    );
                }
            }
        }
        _ => {
            serial_println!(
                "[WARN] Unknown boot magic: 0x{:x}, continuing",
                multiboot_magic
            );
        }
    }
    serial_println!("ATOS v0.1 - AI-native Operating System");

    // 3. Initialize architecture (GDT, IDT, timer)
    arch::x86_64::init();
    serial_println!("[OK] Architecture initialized");

    // 4. Initialize memory (frame allocator)
    //    UEFI boot: parse the firmware memory map passed by the UEFI stub.
    //    Multiboot / unknown: use the conservative init() that reserves
    //    everything below __kernel_end and treats the rest as available.
    if multiboot_magic == UEFI_MAGIC && multiboot_info != 0 {
        // The UEFI stub placed a BootInfo struct at the physical address
        // stored in multiboot_info (typically 0x7000).
        let boot_info_ptr = multiboot_info as *const arch::x86_64::paging::BootInfo;
        let boot_info = unsafe { &*boot_info_ptr };
        if boot_info.magic == UEFI_MAGIC
            && boot_info.mmap_addr != 0
            && boot_info.mmap_size != 0
            && boot_info.desc_size != 0
        {
            arch::x86_64::paging::init_from_uefi_mmap(
                boot_info.mmap_addr,
                boot_info.mmap_size as usize,
                boot_info.desc_size as usize,
            );
        } else {
            serial_println!("[WARN] UEFI BootInfo magic/fields invalid, using default init()");
            arch::x86_64::paging::init();
        }
    } else {
        arch::x86_64::paging::init();
    }
    serial_println!("[OK] Memory initialized");

    // 4b. Enumerate PCI devices
    arch::x86_64::pci::init();
    serial_println!("[OK] PCI bus enumerated");

    // 4c. TPM 2.0 initialization (measured boot)
    if arch::x86_64::tpm::init() {
        serial_println!("[OK] TPM 2.0 initialized");
        arch::x86_64::tpm::measured_boot();
        serial_println!("[OK] Measured boot complete");
    } else {
        serial_println!("[WARN] No TPM 2.0 detected, measured boot skipped");
    }

    // 5. Initialize kernel subsystems
    sched::init();
    serial_println!("[OK] Scheduler initialized");

    // 5b. Initialize persistent storage (ATA disk detection + state log replay)
    persist::init();
    serial_println!("[OK] Persistent storage initialized");

    // 6. Emit boot event
    event::boot();

    // Disable interrupts during agent creation and subsystem init to prevent
    // the timer from preempting into agents before sched::start() is called.
    unsafe {
        core::arch::asm!("cli", options(nomem, nostack));
    }

    // 7. Create agents and set up the system
    init::init();
    serial_println!("[OK] System initialization complete");

    // Defer optional device and SMP bring-up while stabilizing qemu64
    // runtime execution. These subsystems are not required for the
    // syscall/runtime validation path.
    serial_println!("[OK] Optional device init deferred");
    serial_println!("[SMP] Deferred, running single-core");

    // 10. Start scheduling with interrupts still disabled.
    // The first agent entry trampoline enables interrupts after the
    // initial context switch, which avoids timer IRQs racing with the
    // BSP's final agent-table scans in sched::start().
    serial_println!("[ATOS] Entering scheduler loop");
    sched::start();

    // Should not reach here
    serial_println!("[ATOS] Scheduler returned - halting");
    loop {
        unsafe {
            core::arch::asm!("hlt");
        }
    }
}
