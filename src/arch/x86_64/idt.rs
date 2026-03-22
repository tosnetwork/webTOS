//! AOS x86_64 IDT (Interrupt Descriptor Table)
//!
//! Sets up a 256-entry IDT for CPU exceptions and hardware interrupts.
//! Remaps the 8259 PIC so that IRQ0-7 map to vectors 32-39 and
//! IRQ8-15 map to vectors 40-47. Only IRQ0 (timer) is unmasked.

use crate::serial_println;
use crate::arch::x86_64::serial::{outb, inb};
use crate::arch::x86_64::gdt::KERNEL_CS;

// ---- IDT entry ----

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    type_attr: u8,
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}

impl IdtEntry {
    const fn empty() -> Self {
        IdtEntry {
            offset_low: 0,
            selector: 0,
            ist: 0,
            type_attr: 0,
            offset_mid: 0,
            offset_high: 0,
            reserved: 0,
        }
    }

    fn new(handler: u64, selector: u16, ist: u8, type_attr: u8) -> Self {
        IdtEntry {
            offset_low: (handler & 0xFFFF) as u16,
            selector,
            ist: ist & 0x07,
            type_attr,
            offset_mid: ((handler >> 16) & 0xFFFF) as u16,
            offset_high: ((handler >> 32) & 0xFFFF_FFFF) as u32,
            reserved: 0,
        }
    }
}

// ---- IDT pointer ----

#[repr(C, packed)]
struct IdtPtr {
    limit: u16,
    base: u64,
}

// ---- Static storage ----

static mut IDT: [IdtEntry; 256] = [IdtEntry::empty(); 256];

// ---- External assembly trap stubs ----

// The trap_stub_table is a table of 34 function pointers (vectors 0..33)
// defined in trap_entry.asm. We use it to populate the IDT.
extern "C" {
    static trap_stub_table: [u64; 34];
}

// ---- PIC constants ----

const PIC1_CMD: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_CMD: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;
const PIC_EOI: u8 = 0x20;

/// Send End-Of-Interrupt to the PIC(s) for the given IRQ number.
pub fn pic_eoi(irq: u8) {
    unsafe {
        if irq >= 8 {
            outb(PIC2_CMD, PIC_EOI);
        }
        outb(PIC1_CMD, PIC_EOI);
    }
}

/// Remap the 8259 PIC: IRQ0-7 -> vectors 32-39, IRQ8-15 -> vectors 40-47.
unsafe fn remap_pic() {
    // Save masks
    let mask1 = inb(PIC1_DATA);
    let mask2 = inb(PIC2_DATA);

    // ICW1: init + ICW4 needed
    outb(PIC1_CMD, 0x11);
    outb(PIC2_CMD, 0x11);

    // ICW2: vector offsets
    outb(PIC1_DATA, 32); // PIC1 starts at vector 32
    outb(PIC2_DATA, 40); // PIC2 starts at vector 40

    // ICW3: cascade wiring
    outb(PIC1_DATA, 4);  // PIC1 has slave at IRQ2
    outb(PIC2_DATA, 2);  // PIC2 cascade identity = 2

    // ICW4: 8086 mode
    outb(PIC1_DATA, 0x01);
    outb(PIC2_DATA, 0x01);

    // Mask all except IRQ0 (timer) on master, all on slave
    let _ = (mask1, mask2); // Discard old masks
    outb(PIC1_DATA, 0xFE); // Only IRQ0 (timer) unmasked
    outb(PIC2_DATA, 0xFF); // All slave IRQs masked
}

/// Initialize the IDT, remap PIC, load IDT, and enable interrupts.
pub fn init() {
    unsafe {
        // Populate IDT from the trap_stub_table.
        // The table has entries for vectors 0..33 (34 entries total).
        for i in 0..34 {
            let addr = trap_stub_table[i];
            if addr != 0 {
                // Vector 8 (Double Fault) uses IST1 for a separate stack
                let ist = if i == 8 { 1u8 } else { 0u8 };
                // 0x8E = Present | DPL=0 | Interrupt Gate (64-bit)
                IDT[i] = IdtEntry::new(addr, KERNEL_CS, ist, 0x8E);
            }
        }

        // Remap the PIC
        remap_pic();

        // Load the IDT
        let idt_ptr = IdtPtr {
            limit: (core::mem::size_of_val(&IDT) - 1) as u16,
            base: IDT.as_ptr() as u64,
        };

        core::arch::asm!(
            "lidt [{}]",
            in(reg) &idt_ptr,
            options(nostack)
        );

        // Enable interrupts
        core::arch::asm!("sti", options(nomem, nostack));
    }

    serial_println!("[idt] IDT loaded ({} entries), PIC remapped, interrupts enabled", 256);
}
