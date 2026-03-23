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
mod net;
mod node;
mod ringbuf;
mod block;
mod proof;
mod attestation;

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
            serial_println!("AOS boot ok (Multiboot)");
        }
        UEFI_MAGIC => {
            serial_println!("AOS boot ok (UEFI)");

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
                    serial_println!("[OK] Framebuffer console: {}x{} @ 0x{:x}",
                        bi.fb_width, bi.fb_height, bi.fb_addr);
                }
            }
        }
        _ => {
            serial_println!("[WARN] Unknown boot magic: 0x{:x}, continuing", multiboot_magic);
        }
    }
    serial_println!("AOS v0.1 - AI-native Operating System");

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
    unsafe { core::arch::asm!("cli", options(nomem, nostack)); }

    // 7. Create agents and set up the system
    init::init();
    serial_println!("[OK] System initialization complete");

    // 8. Initialize virtio-net (if present)
    let virtio_ok = arch::x86_64::virtio_net::init();

    // 8a. If virtio-net is not available, try the e1000 NIC
    if !virtio_ok {
        if arch::x86_64::e1000::init() {
            serial_println!("[OK] e1000 NIC initialized");
        } else {
            serial_println!("[WARN] No network device found (neither virtio-net nor e1000)");
        }
    }

    // 8b. Detect and initialize NVMe storage (if present)
    arch::x86_64::nvme::init();

    // 9. Discover CPUs and boot APs (if multi-core)
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

    // 10. Re-enable interrupts and start scheduling
    // Interrupts were disabled since before init::init() to prevent
    // the timer from preempting kernel_main into agents prematurely.
    unsafe { core::arch::asm!("sti", options(nomem, nostack)); }
    serial_println!("[AOS] Entering scheduler loop");
    sched::start();

    // Should not reach here
    serial_println!("[AOS] Scheduler returned - halting");
    loop {
        unsafe { core::arch::asm!("hlt"); }
    }
}
