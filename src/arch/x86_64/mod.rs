// AOS x86_64 Architecture Layer
//
// Provides GDT, IDT, serial I/O, paging, timer, and context switching
// for the AOS kernel running on x86_64 (QEMU target).

pub mod gdt;
pub mod idt;
pub mod serial;
pub mod paging;
pub mod timer;
pub mod context;
pub mod syscall_msr;
pub mod ata;
pub mod acpi;
pub mod lapic;
pub mod pci;
pub mod virtio_net;
pub mod e1000;
pub mod nvme;
pub mod security;
pub mod framebuffer;

pub use serial::{serial_print, serial_println};

/// Initialize all architecture subsystems in the correct order.
///
/// Must be called early in kernel boot, after basic stack and BSS are set up.
pub fn init() {
    gdt::init();
    syscall_msr::init();
    idt::init();
    // Paging: identity mapping is set up by boot.asm.
    // The frame allocator is initialized separately via paging::init()
    // once the multiboot memory map is available.
    timer::init();
    security::init();
}
