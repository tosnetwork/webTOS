//! AOS Block Device Abstraction
//!
//! Provides a common interface for block storage drivers (ATA PIO, NVMe).
//! The persist and checkpoint modules use this trait for disk I/O.

/// Block device trait for storage abstraction
pub trait BlockDevice {
    /// Read sectors from the device
    fn read(&self, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), &'static str>;
    /// Write sectors to the device
    fn write(&self, lba: u64, count: u32, buf: &[u8]) -> Result<(), &'static str>;
    /// Sector size in bytes
    fn sector_size(&self) -> usize;
    /// Device name for logging
    fn name(&self) -> &'static str;
}

/// ATA PIO block device wrapper
pub struct AtaDevice;

impl BlockDevice for AtaDevice {
    fn read(&self, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), &'static str> {
        crate::arch::x86_64::ata::read_sectors(lba as u32, count as u8, buf)
    }
    fn write(&self, lba: u64, count: u32, buf: &[u8]) -> Result<(), &'static str> {
        crate::arch::x86_64::ata::write_sectors(lba as u32, count as u8, buf)
    }
    fn sector_size(&self) -> usize { 512 }
    fn name(&self) -> &'static str { "ATA PIO" }
}

/// NVMe block device wrapper (stub for Stage-4)
pub struct NvmeDevice;

impl BlockDevice for NvmeDevice {
    fn read(&self, _lba: u64, _count: u32, _buf: &mut [u8]) -> Result<(), &'static str> {
        Err("NVMe not yet initialized")
    }
    fn write(&self, _lba: u64, _count: u32, _buf: &[u8]) -> Result<(), &'static str> {
        Err("NVMe not yet initialized")
    }
    fn sector_size(&self) -> usize { 512 }
    fn name(&self) -> &'static str { "NVMe" }
}
