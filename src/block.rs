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
    /// Whether the device is available/initialized
    fn is_available(&self) -> bool;
}

/// ATA PIO block device wrapper
pub struct AtaDevice;

impl BlockDevice for AtaDevice {
    fn read(&self, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), &'static str> {
        // ATA uses u32 LBA (28-bit) and u8 count (max 128)
        if lba > 0x0FFF_FFFF {
            return Err("LBA out of 28-bit ATA range");
        }
        if count == 0 || count > 128 {
            return Err("invalid sector count for ATA (must be 1..=128)");
        }
        crate::arch::x86_64::ata::read_sectors(lba as u32, count as u8, buf)
    }
    fn write(&self, lba: u64, count: u32, buf: &[u8]) -> Result<(), &'static str> {
        if lba > 0x0FFF_FFFF {
            return Err("LBA out of 28-bit ATA range");
        }
        if count == 0 || count > 128 {
            return Err("invalid sector count for ATA (must be 1..=128)");
        }
        crate::arch::x86_64::ata::write_sectors(lba as u32, count as u8, buf)
    }
    fn sector_size(&self) -> usize { 512 }
    fn name(&self) -> &'static str { "ATA PIO" }
    fn is_available(&self) -> bool {
        crate::arch::x86_64::ata::init()
    }
}

/// NVMe DMA block device wrapper
pub struct NvmeDevice;

impl BlockDevice for NvmeDevice {
    fn read(&self, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), &'static str> {
        crate::arch::x86_64::nvme::read_sectors(lba, count, buf)
    }
    fn write(&self, lba: u64, count: u32, buf: &[u8]) -> Result<(), &'static str> {
        crate::arch::x86_64::nvme::write_sectors(lba, count, buf)
    }
    fn sector_size(&self) -> usize { 512 }
    fn name(&self) -> &'static str { "NVMe" }
    fn is_available(&self) -> bool {
        crate::arch::x86_64::nvme::is_initialized()
    }
}

/// Unified storage device — selects NVMe when available, falls back to ATA.
///
/// Because this kernel is `#![no_std]` and lacks a global allocator at early
/// boot, we avoid `dyn BlockDevice` trait objects and use a plain enum with
/// forwarded method calls instead.
pub enum StorageDevice {
    Ata(AtaDevice),
    Nvme(NvmeDevice),
}

impl StorageDevice {
    /// Detect and return the best available storage device.
    ///
    /// Preference order: NVMe (DMA) > ATA PIO.
    /// Returns `None` if no storage device is available.
    pub fn detect() -> Option<Self> {
        // Prefer NVMe when it has been initialized (init() already called in main)
        if crate::arch::x86_64::nvme::is_initialized() {
            return Some(StorageDevice::Nvme(NvmeDevice));
        }
        // Fall back to ATA PIO
        if crate::arch::x86_64::ata::init() {
            return Some(StorageDevice::Ata(AtaDevice));
        }
        None
    }

    /// Read `count` sectors starting at `lba` into `buf`.
    pub fn read(&self, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), &'static str> {
        match self {
            StorageDevice::Ata(dev) => dev.read(lba, count, buf),
            StorageDevice::Nvme(dev) => dev.read(lba, count, buf),
        }
    }

    /// Write `count` sectors starting at `lba` from `buf`.
    pub fn write(&self, lba: u64, count: u32, buf: &[u8]) -> Result<(), &'static str> {
        match self {
            StorageDevice::Ata(dev) => dev.write(lba, count, buf),
            StorageDevice::Nvme(dev) => dev.write(lba, count, buf),
        }
    }

    /// Sector size in bytes (always 512).
    pub fn sector_size(&self) -> usize {
        match self {
            StorageDevice::Ata(dev) => dev.sector_size(),
            StorageDevice::Nvme(dev) => dev.sector_size(),
        }
    }

    /// Human-readable name of the active storage backend.
    pub fn name(&self) -> &'static str {
        match self {
            StorageDevice::Ata(dev) => dev.name(),
            StorageDevice::Nvme(dev) => dev.name(),
        }
    }

    /// Whether the underlying device reports itself as available.
    pub fn is_available(&self) -> bool {
        match self {
            StorageDevice::Ata(dev) => dev.is_available(),
            StorageDevice::Nvme(dev) => dev.is_available(),
        }
    }
}
