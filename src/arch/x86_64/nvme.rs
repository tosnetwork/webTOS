//! AOS NVMe Storage Driver
//!
//! Minimal NVMe driver for QEMU. Uses memory-mapped command queues
//! and DMA for block I/O. Replaces ATA PIO for high-performance storage.
//!
//! QEMU: -device nvme,drive=d0,serial=aos-nvme -drive file=disk.img,id=d0,format=raw,if=none

use crate::serial_println;
use super::paging;

// ─── NVMe Controller Registers (MMIO offsets from BAR0) ─────────────────

const REG_CAP: u64 = 0x00;      // Controller Capabilities
#[allow(dead_code)]
const REG_VS: u64 = 0x08;       // Version
const REG_CC: u64 = 0x14;       // Controller Configuration
const REG_CSTS: u64 = 0x1C;     // Controller Status
const REG_AQA: u64 = 0x24;      // Admin Queue Attributes
const REG_ASQ: u64 = 0x28;      // Admin Submission Queue Base
const REG_ACQ: u64 = 0x30;      // Admin Completion Queue Base

// ─── NVMe Command Opcodes ───────────────────────────────────────────────

#[allow(dead_code)]
const NVME_CMD_IDENTIFY: u8 = 0x06;
const NVME_CMD_CREATE_IO_CQ: u8 = 0x05;
const NVME_CMD_CREATE_IO_SQ: u8 = 0x01;
const NVME_CMD_READ: u8 = 0x02;
const NVME_CMD_WRITE: u8 = 0x01;

// ─── NVMe Submission Queue Entry (64 bytes) ─────────────────────────────

/// NVMe submission queue entry (64 bytes)
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
pub struct NvmeCommand {
    pub opcode: u8,
    pub flags: u8,
    pub command_id: u16,
    pub nsid: u32,
    pub reserved: [u64; 2],
    pub prp1: u64,       // Physical Region Page 1
    pub prp2: u64,       // Physical Region Page 2 or PRP list
    pub cdw10: u32,
    pub cdw11: u32,
    pub cdw12: u32,
    pub cdw13: u32,
    pub cdw14: u32,
    pub cdw15: u32,
}

// ─── NVMe Completion Queue Entry (16 bytes) ─────────────────────────────

/// NVMe completion queue entry (16 bytes)
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
pub struct NvmeCompletion {
    pub command_specific: u32,
    pub reserved: u32,
    pub sq_head: u16,
    pub sq_id: u16,
    pub command_id: u16,
    pub status: u16,     // Phase bit in bit 0, status in bits 1-15
}

// ─── NVMe Controller State ──────────────────────────────────────────────

/// NVMe controller state
pub struct NvmeController {
    pub bar0: u64,           // MMIO base address
    pub initialized: bool,
    pub doorbell_stride: u32,
    pub max_queue_entries: u16,
    pub asq: u64,
    pub acq: u64,
    pub sq_tail: u16,
    pub cq_head: u16,
    pub cq_phase: bool,
    pub io_sq: u64,
    pub io_cq: u64,
    pub io_sq_tail: u16,
    pub io_cq_head: u16,
    pub io_cq_phase: bool,
}

static mut NVME: NvmeController = NvmeController {
    bar0: 0,
    initialized: false,
    doorbell_stride: 4,
    max_queue_entries: 64,
    asq: 0,
    acq: 0,
    sq_tail: 0,
    cq_head: 0,
    cq_phase: true,
    io_sq: 0,
    io_cq: 0,
    io_sq_tail: 0,
    io_cq_head: 0,
    io_cq_phase: true,
};

// ─── PCI Discovery ──────────────────────────────────────────────────────

/// PCI config space I/O ports
const PCI_CONFIG_ADDR: u16 = 0xCF8;
const PCI_CONFIG_DATA: u16 = 0xCFC;

#[inline]
unsafe fn pci_outl(port: u16, val: u32) {
    core::arch::asm!(
        "out dx, eax",
        in("dx") port,
        in("eax") val,
        options(nomem, nostack, preserves_flags),
    );
}

#[inline]
unsafe fn pci_inl(port: u16) -> u32 {
    let val: u32;
    core::arch::asm!(
        "in eax, dx",
        out("eax") val,
        in("dx") port,
        options(nomem, nostack, preserves_flags),
    );
    val
}

/// Read a 32-bit PCI config register.
unsafe fn pci_config_read(bus: u32, dev: u32, func: u32, offset: u32) -> u32 {
    let addr = 0x80000000 | (bus << 16) | (dev << 11) | (func << 8) | (offset & 0xFC);
    pci_outl(PCI_CONFIG_ADDR, addr);
    pci_inl(PCI_CONFIG_DATA)
}

/// Write a 32-bit PCI config register.
unsafe fn pci_config_write(bus: u32, dev: u32, func: u32, offset: u32, val: u32) {
    let addr = 0x80000000 | (bus << 16) | (dev << 11) | (func << 8) | (offset & 0xFC);
    pci_outl(PCI_CONFIG_ADDR, addr);
    pci_outl(PCI_CONFIG_DATA, val);
}

/// Scan PCI bus for NVMe controller (class 01h, subclass 08h).
/// Returns (bus, dev, func) if found.
fn find_nvme_pci() -> Option<(u32, u32, u32)> {
    for bus in 0..256u32 {
        for dev in 0..32u32 {
            for func in 0..8u32 {
                unsafe {
                    let id = pci_config_read(bus, dev, func, 0x00);
                    let vendor = (id & 0xFFFF) as u16;
                    if vendor == 0xFFFF || vendor == 0x0000 {
                        continue;
                    }

                    // Read class code (offset 0x08): bits 31:24=class, 23:16=subclass, 15:8=prog_if
                    let class_reg = pci_config_read(bus, dev, func, 0x08);
                    let class_code = (class_reg >> 24) as u8;
                    let subclass = ((class_reg >> 16) & 0xFF) as u8;

                    // NVMe: class=0x01 (Mass Storage), subclass=0x08 (NVM Express)
                    if class_code == 0x01 && subclass == 0x08 {
                        let device_id = ((id >> 16) & 0xFFFF) as u16;
                        serial_println!("[NVMe] Found at PCI {:02x}:{:02x}.{} vendor={:#06x} device={:#06x}",
                            bus, dev, func, vendor, device_id);
                        return Some((bus, dev, func));
                    }

                    // If func 0 and not multi-function, skip funcs 1-7
                    if func == 0 {
                        let header_type = pci_config_read(bus, dev, func, 0x0C);
                        if (header_type >> 16) & 0x80 == 0 {
                            break; // not multi-function
                        }
                    }
                }
            }
        }
    }
    None
}

// ─── Initialization ─────────────────────────────────────────────────────

/// Initialize NVMe controller by scanning PCI and reading BAR0.
/// Returns true if controller was detected and is responsive.
pub fn init() -> bool {
    let (bus, dev, func) = match find_nvme_pci() {
        Some(bdf) => bdf,
        None => {
            serial_println!("[NVMe] No NVMe controller found on PCI bus");
            return false;
        }
    };

    unsafe {
        // Read BAR0 (offset 0x10) — NVMe uses MMIO
        let bar0_low = pci_config_read(bus, dev, func, 0x10);

        // Check BAR type
        if bar0_low & 1 != 0 {
            serial_println!("[NVMe] BAR0 is I/O port, expected MMIO");
            return false;
        }

        let bar0_mmio: u64;
        let bar_type = (bar0_low >> 1) & 0x03;
        if bar_type == 0x02 {
            // 64-bit MMIO BAR: read upper 32 bits from BAR1 (offset 0x14)
            let bar0_high = pci_config_read(bus, dev, func, 0x14);
            bar0_mmio = ((bar0_high as u64) << 32) | ((bar0_low & 0xFFFFFFF0) as u64);
        } else {
            // 32-bit MMIO BAR
            bar0_mmio = (bar0_low & 0xFFFFFFF0) as u64;
        }

        if bar0_mmio == 0 {
            serial_println!("[NVMe] BAR0 MMIO address is zero");
            return false;
        }

        serial_println!("[NVMe] BAR0 MMIO base: {:#018x}", bar0_mmio);

        // Enable bus mastering and memory space access in PCI command register
        let cmd = pci_config_read(bus, dev, func, 0x04);
        let cmd_new = cmd | 0x06; // bit 1 = Memory Space, bit 2 = Bus Master
        pci_config_write(bus, dev, func, 0x04, cmd_new);

        init_controller(bar0_mmio)
    }
}

/// Initialize NVMe controller from BAR0 MMIO address.
unsafe fn init_controller(bar0_mmio: u64) -> bool {
    NVME.bar0 = bar0_mmio;

    // Read capabilities
    let cap = read_reg64(REG_CAP);
    let mqes = (cap & 0xFFFF) as u16 + 1; // Maximum Queue Entries Supported
    let dstrd = ((cap >> 32) & 0xF) as u32; // Doorbell Stride (2^(2+dstrd))
    let version = read_reg32(REG_VS);

    serial_println!("[NVMe] CAP={:#018x} MQES={} DSTRD={} VS={:#010x}",
        cap, mqes, dstrd, version);

    NVME.doorbell_stride = 4 << dstrd;
    NVME.max_queue_entries = mqes;

    // Disable controller
    let mut cc = read_reg32(REG_CC);
    cc &= !1; // Clear EN bit
    write_reg32(REG_CC, cc);

    // Wait for not ready (CSTS.RDY = 0)
    let mut timeout = 0u32;
    while read_reg32(REG_CSTS) & 1 != 0 {
        timeout += 1;
        if timeout > 1_000_000 {
            serial_println!("[NVMe] Timeout waiting for controller disable");
            return false;
        }
        core::hint::spin_loop();
    }

    serial_println!("[NVMe] Controller disabled, ready for configuration");

    // 1. Allocate Admin Submission Queue (ASQ) — 64 entries x 64 bytes = 4KB
    let asq_phys = match paging::alloc_frame() {
        Some(f) => f,
        None => { serial_println!("[NVMe] Failed to allocate ASQ frame"); return false; }
    };
    core::ptr::write_bytes(asq_phys as *mut u8, 0, 4096);

    // 2. Allocate Admin Completion Queue (ACQ) — 64 entries x 16 bytes = 1KB (4KB frame)
    let acq_phys = match paging::alloc_frame() {
        Some(f) => f,
        None => { serial_println!("[NVMe] Failed to allocate ACQ frame"); return false; }
    };
    core::ptr::write_bytes(acq_phys as *mut u8, 0, 4096);

    // 3. Configure Admin Queue Attributes (AQA) — 63 entries each (0-indexed)
    write_reg32(REG_AQA, (63 << 16) | 63);

    // 4. Write ASQ and ACQ base addresses
    write_reg64(REG_ASQ, asq_phys);
    write_reg64(REG_ACQ, acq_phys);

    // 5. Enable controller: CC.EN=1, CSS=0, MPS=0 (4KB pages), AMS=0
    //    CC bits: EN(0), CSS(4-6)=0, MPS(7-10)=0, AMS(11-13)=0,
    //    SHN(14-15)=0, IOSQES(16-19)=6(64B), IOCQES(20-23)=4(16B)
    let cc_val: u32 = 1 | (6 << 16) | (4 << 20);
    write_reg32(REG_CC, cc_val);

    // 6. Wait for CSTS.RDY=1
    let mut timeout2 = 0u32;
    while read_reg32(REG_CSTS) & 1 == 0 {
        timeout2 += 1;
        if timeout2 > 1_000_000 {
            serial_println!("[NVMe] Timeout waiting for controller ready");
            return false;
        }
        core::hint::spin_loop();
    }
    serial_println!("[NVMe] Controller enabled and ready");

    // Store queue pointers
    NVME.asq = asq_phys;
    NVME.acq = acq_phys;
    NVME.sq_tail = 0;
    NVME.cq_head = 0;
    NVME.cq_phase = true;

    // 7. Create IO Completion Queue (queue ID=1) via admin command
    let io_cq_phys = match paging::alloc_frame() {
        Some(f) => f,
        None => { serial_println!("[NVMe] Failed to allocate IO CQ frame"); return false; }
    };
    core::ptr::write_bytes(io_cq_phys as *mut u8, 0, 4096);

    let create_cq = NvmeCommand {
        opcode: NVME_CMD_CREATE_IO_CQ,
        flags: 0,
        command_id: 10,
        nsid: 0,
        reserved: [0; 2],
        prp1: io_cq_phys,
        prp2: 0,
        cdw10: (63 << 16) | 1, // size=63 (0-indexed) | QID=1
        cdw11: 1,              // physically contiguous
        cdw12: 0, cdw13: 0, cdw14: 0, cdw15: 0,
    };
    submit_admin_cmd(&create_cq);
    match poll_admin_completion(10) {
        Ok(_) => serial_println!("[NVMe] IO Completion Queue created"),
        Err(e) => { serial_println!("[NVMe] Create IO CQ failed: {}", e); return false; }
    }

    // 8. Create IO Submission Queue (queue ID=1, CQ ID=1) via admin command
    let io_sq_phys = match paging::alloc_frame() {
        Some(f) => f,
        None => { serial_println!("[NVMe] Failed to allocate IO SQ frame"); return false; }
    };
    core::ptr::write_bytes(io_sq_phys as *mut u8, 0, 4096);

    let create_sq = NvmeCommand {
        opcode: NVME_CMD_CREATE_IO_SQ,
        flags: 0,
        command_id: 11,
        nsid: 0,
        reserved: [0; 2],
        prp1: io_sq_phys,
        prp2: 0,
        cdw10: (63 << 16) | 1, // size=63 (0-indexed) | QID=1
        cdw11: (1 << 16) | 1,  // CQID=1 | physically contiguous
        cdw12: 0, cdw13: 0, cdw14: 0, cdw15: 0,
    };
    submit_admin_cmd(&create_sq);
    match poll_admin_completion(11) {
        Ok(_) => serial_println!("[NVMe] IO Submission Queue created"),
        Err(e) => { serial_println!("[NVMe] Create IO SQ failed: {}", e); return false; }
    }

    NVME.io_sq = io_sq_phys;
    NVME.io_cq = io_cq_phys;
    NVME.io_sq_tail = 0;
    NVME.io_cq_head = 0;
    NVME.io_cq_phase = true;

    NVME.initialized = true;
    serial_println!("[NVMe] Fully initialized with admin + IO queues");

    true
}

/// Check if NVMe is available
pub fn is_initialized() -> bool {
    unsafe { NVME.initialized }
}

// ─── MMIO Register Access ───────────────────────────────────────────────

unsafe fn read_reg32(offset: u64) -> u32 {
    core::ptr::read_volatile((NVME.bar0 + offset) as *const u32)
}

unsafe fn read_reg64(offset: u64) -> u64 {
    core::ptr::read_volatile((NVME.bar0 + offset) as *const u64)
}

unsafe fn write_reg32(offset: u64, val: u32) {
    core::ptr::write_volatile((NVME.bar0 + offset) as *mut u32, val);
}

unsafe fn write_reg64(offset: u64, val: u64) {
    core::ptr::write_volatile((NVME.bar0 + offset) as *mut u64, val);
}

// ─── Admin Queue Operations ─────────────────────────────────────────────

/// Submit a command to the admin submission queue.
/// Returns the command_id for later completion polling.
unsafe fn submit_admin_cmd(cmd: &NvmeCommand) -> u16 {
    let sq = NVME.asq as *mut NvmeCommand;
    let tail = NVME.sq_tail;
    core::ptr::write_volatile(sq.add(tail as usize), *cmd);
    NVME.sq_tail = (tail + 1) % 64;
    // Ring ASQ doorbell at BAR0 + 0x1000 (SQ 0 tail doorbell)
    write_reg32(0x1000, NVME.sq_tail as u32);
    cmd.command_id
}

/// Poll admin completion queue for a specific command.
unsafe fn poll_admin_completion(cmd_id: u16) -> Result<u32, &'static str> {
    for _ in 0..1_000_000u32 {
        let cq = NVME.acq as *const NvmeCompletion;
        let entry = core::ptr::read_volatile(cq.add(NVME.cq_head as usize));
        let phase = (entry.status & 1) != 0;
        if phase == NVME.cq_phase && entry.command_id == cmd_id {
            // Advance CQ head
            NVME.cq_head = (NVME.cq_head + 1) % 64;
            if NVME.cq_head == 0 {
                NVME.cq_phase = !NVME.cq_phase;
            }
            // Ring ACQ doorbell: CQ 0 head doorbell at 0x1000 + doorbell_stride
            write_reg32(0x1000 + NVME.doorbell_stride as u64, NVME.cq_head as u32);
            let status_code = (entry.status >> 1) & 0xFF;
            if status_code != 0 {
                return Err("NVMe admin command failed");
            }
            return Ok(entry.command_specific);
        }
        core::hint::spin_loop();
    }
    Err("NVMe admin completion timeout")
}

// ─── IO Queue Operations ────────────────────────────────────────────────

/// Submit a command to the IO submission queue (QID=1).
unsafe fn submit_io_cmd(cmd: &NvmeCommand) -> u16 {
    let sq = NVME.io_sq as *mut NvmeCommand;
    let tail = NVME.io_sq_tail;
    core::ptr::write_volatile(sq.add(tail as usize), *cmd);
    NVME.io_sq_tail = (tail + 1) % 64;
    // IO SQ 1 tail doorbell: 0x1000 + 2 * 1 * doorbell_stride
    let doorbell_off = 0x1000u64 + 2 * NVME.doorbell_stride as u64;
    write_reg32(doorbell_off, NVME.io_sq_tail as u32);
    cmd.command_id
}

/// Poll IO completion queue (QID=1) for a specific command.
unsafe fn poll_io_completion(cmd_id: u16) -> Result<u32, &'static str> {
    for _ in 0..1_000_000u32 {
        let cq = NVME.io_cq as *const NvmeCompletion;
        let entry = core::ptr::read_volatile(cq.add(NVME.io_cq_head as usize));
        let phase = (entry.status & 1) != 0;
        if phase == NVME.io_cq_phase && entry.command_id == cmd_id {
            NVME.io_cq_head = (NVME.io_cq_head + 1) % 64;
            if NVME.io_cq_head == 0 {
                NVME.io_cq_phase = !NVME.io_cq_phase;
            }
            // IO CQ 1 head doorbell: 0x1000 + (2*1 + 1) * doorbell_stride
            let doorbell_off = 0x1000u64 + 3 * NVME.doorbell_stride as u64;
            write_reg32(doorbell_off, NVME.io_cq_head as u32);
            let status_code = (entry.status >> 1) & 0xFF;
            if status_code != 0 {
                return Err("NVMe IO command failed");
            }
            return Ok(entry.command_specific);
        }
        core::hint::spin_loop();
    }
    Err("NVMe IO completion timeout")
}

// ─── Public Read / Write API ────────────────────────────────────────────

static mut CMD_SEQ: u16 = 100;

/// Allocate a unique command ID.
unsafe fn next_cmd_id() -> u16 {
    let id = CMD_SEQ;
    CMD_SEQ = CMD_SEQ.wrapping_add(1);
    id
}

/// Read sectors from NVMe namespace 1 via the IO queue.
///
/// * `lba`   — starting logical block address
/// * `count` — number of 512-byte sectors to read (max limited by single PRP)
/// * `buf`   — destination buffer (must be identity-mapped, at least `count * 512` bytes)
pub fn read_sectors(lba: u64, count: u32, buf: &mut [u8]) -> Result<(), &'static str> {
    if !is_initialized() {
        return Err("NVMe not initialized");
    }
    let needed = count as usize * 512;
    if buf.len() < needed {
        return Err("NVMe read: buffer too small");
    }
    unsafe {
        let data_phys = buf.as_mut_ptr() as u64; // identity-mapped
        let cid = next_cmd_id();
        let cmd = NvmeCommand {
            opcode: NVME_CMD_READ,
            flags: 0,
            command_id: cid,
            nsid: 1,
            reserved: [0; 2],
            prp1: data_phys,
            prp2: 0,
            cdw10: lba as u32,
            cdw11: (lba >> 32) as u32,
            cdw12: count - 1, // 0-based count
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        };
        submit_io_cmd(&cmd);
        poll_io_completion(cid)?;
        Ok(())
    }
}

/// Write sectors to NVMe namespace 1 via the IO queue.
///
/// * `lba`   — starting logical block address
/// * `count` — number of 512-byte sectors to write
/// * `buf`   — source buffer (must be identity-mapped, at least `count * 512` bytes)
pub fn write_sectors(lba: u64, count: u32, buf: &[u8]) -> Result<(), &'static str> {
    if !is_initialized() {
        return Err("NVMe not initialized");
    }
    let needed = count as usize * 512;
    if buf.len() < needed {
        return Err("NVMe write: buffer too small");
    }
    unsafe {
        let data_phys = buf.as_ptr() as u64; // identity-mapped
        let cid = next_cmd_id();
        let cmd = NvmeCommand {
            opcode: NVME_CMD_WRITE,
            flags: 0,
            command_id: cid,
            nsid: 1,
            reserved: [0; 2],
            prp1: data_phys,
            prp2: 0,
            cdw10: lba as u32,
            cdw11: (lba >> 32) as u32,
            cdw12: count - 1, // 0-based count
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        };
        submit_io_cmd(&cmd);
        poll_io_completion(cid)?;
        Ok(())
    }
}
