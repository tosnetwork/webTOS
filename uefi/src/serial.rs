//! Minimal COM1 serial output for UEFI stub debugging.
//!
//! Direct port I/O to 0x3F8 — works in UEFI context because OVMF
//! does not restrict I/O port access.

const COM1: u16 = 0x3F8;

pub fn init() {
    unsafe {
        outb(COM1 + 1, 0x00); // Disable interrupts
        outb(COM1 + 3, 0x80); // Enable DLAB
        outb(COM1 + 0, 0x01); // Baud rate divisor low (115200)
        outb(COM1 + 1, 0x00); // Baud rate divisor high
        outb(COM1 + 3, 0x03); // 8N1
        outb(COM1 + 2, 0xC7); // Enable FIFO
        outb(COM1 + 4, 0x0B); // RTS/DSR set
    }
}

pub fn putchar(c: u8) {
    unsafe {
        // Wait for transmit buffer empty
        while (inb(COM1 + 5) & 0x20) == 0 {
            core::hint::spin_loop();
        }
        outb(COM1, c);
    }
}

pub fn print(s: &str) {
    for b in s.bytes() {
        if b == b'\n' {
            putchar(b'\r');
        }
        putchar(b);
    }
}

pub fn println(s: &str) {
    print(s);
    putchar(b'\r');
    putchar(b'\n');
}

pub fn print_hex(val: u64) {
    let hex = b"0123456789abcdef";
    print("0x");
    for i in (0..16).rev() {
        let nibble = ((val >> (i * 4)) & 0xF) as usize;
        putchar(hex[nibble]);
    }
}

#[inline(always)]
unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack));
}

#[inline(always)]
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    core::arch::asm!("in al, dx", out("al") val, in("dx") port, options(nomem, nostack));
    val
}
