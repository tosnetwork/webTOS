// ATOS x86_64 Architecture Layer
//
// Provides GDT, IDT, serial I/O, paging, timer, and context switching
// for the ATOS kernel running on x86_64 (QEMU target).

pub mod acpi;
pub mod ata;
pub mod context;
pub mod e1000;
pub mod framebuffer;
pub(crate) mod frame_alloc;
pub(crate) mod frame_meta;
pub mod gdt;
pub mod idt;
pub mod kaslr;
pub mod lapic;
pub mod nvme;
pub mod paging;
pub mod pci;
pub mod security;
pub mod serial;
pub mod syscall_msr;
pub mod timer;
#[allow(dead_code)]
pub mod tpm;
pub mod virtio_net;

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
