//! AOS ATA PIO Block Device Driver
//!
//! Minimal driver for the primary ATA channel in PIO mode.
//! Supports 28-bit LBA addressing, 512-byte sectors.
//! Used with QEMU: `-hda state.img`
//!
//! Reference: AOS Yellow Paper §24.5 (persistent state storage backend).

use super::serial::{inb, outb};

// ─── ATA Primary Channel I/O Ports ─────────────────────────────────────────

const ATA_DATA: u16 = 0x1F0;
const ATA_ERROR: u16 = 0x1F1;
const ATA_SECTOR_COUNT: u16 = 0x1F2;
const ATA_LBA_LOW: u16 = 0x1F3;
const ATA_LBA_MID: u16 = 0x1F4;
const ATA_LBA_HIGH: u16 = 0x1F5;
const ATA_DRIVE_HEAD: u16 = 0x1F6;
const ATA_STATUS: u16 = 0x1F7;
const ATA_COMMAND: u16 = 0x1F7;

// ─── ATA Commands ───────────────────────────────────────────────────────────

const ATA_CMD_READ_SECTORS: u8 = 0x20;
const ATA_CMD_WRITE_SECTORS: u8 = 0x30;
const ATA_CMD_CACHE_FLUSH: u8 = 0xE7;
const ATA_CMD_IDENTIFY: u8 = 0xEC;

// ─── ATA Status Bits ────────────────────────────────────────────────────────

const ATA_STATUS_BSY: u8 = 0x80;
const ATA_STATUS_DRDY: u8 = 0x40;
const ATA_STATUS_DRQ: u8 = 0x08;
const ATA_STATUS_ERR: u8 = 0x01;

/// Sector size in bytes (always 512 for ATA).
pub const SECTOR_SIZE: usize = 512;

/// Maximum number of sectors per single read/write operation.
const MAX_SECTORS_PER_OP: u8 = 128;

// ─── 16-bit Port I/O ────────────────────────────────────────────────────────

/// Read a 16-bit word from an x86 I/O port.
#[inline]
unsafe fn inw(port: u16) -> u16 {
    let val: u16;
    core::arch::asm!(
        "in ax, dx",
        out("ax") val,
        in("dx") port,
        options(nomem, nostack, preserves_flags),
    );
    val
}

/// Write a 16-bit word to an x86 I/O port.
#[inline]
unsafe fn outw(port: u16, val: u16) {
    core::arch::asm!(
        "out dx, ax",
        in("dx") port,
        in("ax") val,
        options(nomem, nostack, preserves_flags),
    );
}

// ─── Internal Helpers ───────────────────────────────────────────────────────

/// Wait until the BSY bit clears. Returns the final status byte.
fn wait_not_busy() -> u8 {
    loop {
        let status = unsafe { inb(ATA_STATUS) };
        if status & ATA_STATUS_BSY == 0 {
            return status;
        }
        core::hint::spin_loop();
    }
}

/// Wait until BSY clears and DRQ is set. Returns Err on error.
fn wait_drq() -> Result<(), &'static str> {
    loop {
        let status = unsafe { inb(ATA_STATUS) };
        if status & ATA_STATUS_ERR != 0 {
            return Err("ATA error");
        }
        if status & ATA_STATUS_BSY == 0 && status & ATA_STATUS_DRQ != 0 {
            return Ok(());
        }
        core::hint::spin_loop();
    }
}

/// Perform a 400ns delay by reading the alternate status register 4 times.
fn ata_delay() {
    for _ in 0..4 {
        // Reading port 0x3F6 (alternate status) causes ~100ns delay each.
        unsafe { inb(0x3F6); }
    }
}

/// Select master drive and set up 28-bit LBA address fields.
fn select_drive_lba(lba: u32, count: u8) {
    unsafe {
        // Drive/head: bit 6 = LBA mode, bit 5 = 1, bits 0-3 = LBA bits 24-27
        outb(ATA_DRIVE_HEAD, 0xE0 | ((lba >> 24) as u8 & 0x0F));
        outb(ATA_SECTOR_COUNT, count);
        outb(ATA_LBA_LOW, lba as u8);
        outb(ATA_LBA_MID, (lba >> 8) as u8);
        outb(ATA_LBA_HIGH, (lba >> 16) as u8);
    }
}

// ─── Public API ─────────────────────────────────────────────────────────────

/// Initialize the ATA driver. Returns `true` if a disk is present on the
/// primary master channel.
pub fn init() -> bool {
    // Select master drive
    unsafe { outb(ATA_DRIVE_HEAD, 0xA0); }
    ata_delay();

    // Zero out sector count and LBA registers
    unsafe {
        outb(ATA_SECTOR_COUNT, 0);
        outb(ATA_LBA_LOW, 0);
        outb(ATA_LBA_MID, 0);
        outb(ATA_LBA_HIGH, 0);
    }

    // Send IDENTIFY command
    unsafe { outb(ATA_COMMAND, ATA_CMD_IDENTIFY); }

    // If status is 0, no device
    let status = unsafe { inb(ATA_STATUS) };
    if status == 0 {
        return false;
    }

    // Wait for BSY to clear
    let _status = wait_not_busy();

    // Check LBA mid/high — if non-zero, it's not ATA (could be ATAPI)
    let lba_mid = unsafe { inb(ATA_LBA_MID) };
    let lba_high = unsafe { inb(ATA_LBA_HIGH) };
    if lba_mid != 0 || lba_high != 0 {
        return false; // not an ATA device
    }

    // Wait for DRQ or ERR
    loop {
        let s = unsafe { inb(ATA_STATUS) };
        if s & ATA_STATUS_ERR != 0 {
            return false;
        }
        if s & ATA_STATUS_DRQ != 0 {
            break;
        }
        core::hint::spin_loop();
    }

    // Read and discard 256 words of identify data
    for _ in 0..256 {
        unsafe { inw(ATA_DATA); }
    }

    true
}

/// Read `count` sectors starting at `lba` into `buf`.
///
/// `buf` must be at least `count as usize * SECTOR_SIZE` bytes.
/// `lba` must fit in 28 bits (max 0x0FFFFFFF).
/// `count` must be 1..=128.
pub fn read_sectors(lba: u32, count: u8, buf: &mut [u8]) -> Result<(), &'static str> {
    if count == 0 || count > MAX_SECTORS_PER_OP {
        return Err("invalid sector count");
    }
    if lba > 0x0FFF_FFFF {
        return Err("LBA out of 28-bit range");
    }
    let needed = count as usize * SECTOR_SIZE;
    if buf.len() < needed {
        return Err("buffer too small");
    }

    wait_not_busy();
    select_drive_lba(lba, count);

    // Send READ SECTORS command
    unsafe { outb(ATA_COMMAND, ATA_CMD_READ_SECTORS); }
    ata_delay();

    for sector in 0..count as usize {
        wait_drq()?;
        let offset = sector * SECTOR_SIZE;
        for i in 0..256 {
            let word = unsafe { inw(ATA_DATA) };
            buf[offset + i * 2] = word as u8;
            buf[offset + i * 2 + 1] = (word >> 8) as u8;
        }
    }

    Ok(())
}

/// Write `count` sectors starting at `lba` from `buf`.
///
/// `buf` must be at least `count as usize * SECTOR_SIZE` bytes.
/// `lba` must fit in 28 bits (max 0x0FFFFFFF).
/// `count` must be 1..=128.
pub fn write_sectors(lba: u32, count: u8, buf: &[u8]) -> Result<(), &'static str> {
    if count == 0 || count > MAX_SECTORS_PER_OP {
        return Err("invalid sector count");
    }
    if lba > 0x0FFF_FFFF {
        return Err("LBA out of 28-bit range");
    }
    let needed = count as usize * SECTOR_SIZE;
    if buf.len() < needed {
        return Err("buffer too small");
    }

    wait_not_busy();
    select_drive_lba(lba, count);

    // Send WRITE SECTORS command
    unsafe { outb(ATA_COMMAND, ATA_CMD_WRITE_SECTORS); }
    ata_delay();

    for sector in 0..count as usize {
        wait_drq()?;
        let offset = sector * SECTOR_SIZE;
        for i in 0..256 {
            let word = (buf[offset + i * 2] as u16)
                | ((buf[offset + i * 2 + 1] as u16) << 8);
            unsafe { outw(ATA_DATA, word); }
        }
    }

    // Flush the write cache
    unsafe { outb(ATA_COMMAND, ATA_CMD_CACHE_FLUSH); }
    wait_not_busy();

    Ok(())
}
