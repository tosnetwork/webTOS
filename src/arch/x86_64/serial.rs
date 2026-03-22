// AOS x86_64 Serial Port Driver (COM1)
//
// Provides serial output over COM1 (port 0x3F8) for kernel logging
// and audit event emission. This is the primary output channel in Stage-1.

use core::fmt;

const COM1: u16 = 0x3F8;

// ─── Port I/O helpers ────────────────────────────────────────────────────────

/// Write a byte to an x86 I/O port.
///
/// # Safety
/// Caller must ensure the port address is valid and the write is intentional.
#[inline]
pub unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!(
        "out dx, al",
        in("dx") port,
        in("al") val,
        options(nomem, nostack, preserves_flags),
    );
}

/// Read a byte from an x86 I/O port.
///
/// # Safety
/// Caller must ensure the port address is valid.
#[inline]
pub unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    core::arch::asm!(
        "in al, dx",
        out("al") val,
        in("dx") port,
        options(nomem, nostack, preserves_flags),
    );
    val
}

// ─── Serial port ─────────────────────────────────────────────────────────────

/// Minimal COM1 serial port driver.
pub struct SerialPort {
    base: u16,
}

impl SerialPort {
    /// Create a new serial port handle for the given base I/O address.
    pub const fn new(base: u16) -> Self {
        SerialPort { base }
    }

    /// Initialize the serial port (8N1, 115200 baud, no interrupts).
    ///
    /// # Safety
    /// Must only be called once during early boot. Writes to hardware I/O ports.
    pub unsafe fn init(&self) {
        let base = self.base;

        // Disable all interrupts
        outb(base + 1, 0x00);

        // Enable DLAB (set baud rate divisor)
        outb(base + 3, 0x80);

        // Set divisor to 1 (115200 baud): low byte
        outb(base + 0, 0x01);
        // High byte
        outb(base + 1, 0x00);

        // 8 bits, no parity, one stop bit (8N1), clear DLAB
        outb(base + 3, 0x03);

        // Enable FIFO, clear them, 14-byte threshold
        outb(base + 2, 0xC7);

        // IRQs enabled, RTS/DSR set
        outb(base + 4, 0x0B);

        // Set in loopback mode, test the serial chip
        outb(base + 4, 0x1E);

        // Test: send byte 0xAE
        outb(base + 0, 0xAE);

        // Check that we received the same byte back
        if inb(base + 0) != 0xAE {
            // Serial port is faulty; nothing we can do at this stage
            return;
        }

        // Serial is working — set it in normal operation mode
        // (not-loopback, IRQs enabled, OUT1 and OUT2 bits enabled)
        outb(base + 4, 0x0F);
    }

    /// Check if the transmit holding register is empty (ready to send).
    fn is_transmit_empty(&self) -> bool {
        // Safety: reading the line status register is benign
        unsafe { inb(self.base + 5) & 0x20 != 0 }
    }

    /// Write a single byte, busy-waiting until the transmitter is ready.
    pub fn write_byte(&self, byte: u8) {
        // Busy-wait for transmitter to be ready
        while !self.is_transmit_empty() {
            core::hint::spin_loop();
        }
        // Safety: writing a data byte to an initialized COM port
        unsafe { outb(self.base, byte) };
    }

    /// Write a string as a sequence of bytes.
    pub fn write_string(&self, s: &str) {
        for byte in s.bytes() {
            self.write_byte(byte);
        }
    }
}

impl fmt::Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_string(s);
        Ok(())
    }
}

// ─── Global serial port access ──────────────────────────────────────────────

/// Global COM1 serial port instance.
///
/// In Stage-1 we use a simple static. This is safe because:
/// - init() is called once during single-threaded boot
/// - subsequent writes are byte-level and idempotent on conflict
/// - Stage-1 is single-core
static SERIAL: SerialPort = SerialPort::new(COM1);

/// Initialize the global serial port. Call once during early boot.
pub fn init() {
    // Safety: called once during single-threaded boot
    unsafe { SERIAL.init() };
}

/// Write formatted arguments to COM1.
///
/// Used by the serial_print! and serial_println! macros.
#[doc(hidden)]
pub fn _serial_print(args: fmt::Arguments) {
    use fmt::Write;
    // We need a mutable reference for fmt::Write, but SERIAL is a static.
    // Safety: Stage-1 is single-core and interrupt handlers do not contend
    // for serial output in a way that corrupts state (worst case: interleaved bytes).
    let serial = unsafe { &mut *core::ptr::addr_of!(SERIAL).cast_mut() };
    serial.write_fmt(args).unwrap();
}

/// Print to the serial console (COM1).
#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {
        $crate::arch::x86_64::serial::_serial_print(format_args!($($arg)*))
    };
}

/// Print to the serial console (COM1) with a trailing newline.
#[macro_export]
macro_rules! serial_println {
    () => { $crate::serial_print!("\n") };
    ($($arg:tt)*) => {
        $crate::arch::x86_64::serial::_serial_print(format_args!("{}\n", format_args!($($arg)*)))
    };
}

// Re-export the macros at module level for `pub use serial::{serial_print, serial_println}`
pub use serial_print;
pub use serial_println;
