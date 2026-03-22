//! AOS Panic Handler
//!
//! Provides the #[panic_handler] required by #![no_std] binaries.
//! On panic, prints the panic info to the serial console and halts the CPU.

use core::panic::PanicInfo;

/// Panic handler: prints the panic message and location to COM1, then halts.
///
/// In Stage-1, a panic is always fatal. The CPU enters a halt loop with
/// interrupts disabled to prevent further execution.
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Print the panic header
    crate::serial_println!("\n!!! KERNEL PANIC !!!");

    // Print location if available
    if let Some(location) = info.location() {
        crate::serial_println!(
            "  at {}:{}:{}",
            location.file(),
            location.line(),
            location.column()
        );
    }

    // Print the panic message
    crate::serial_println!("  {}", info.message());

    // Halt with interrupts disabled
    loop {
        unsafe {
            core::arch::asm!("cli; hlt", options(nomem, nostack));
        }
    }
}
