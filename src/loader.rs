//! ATOS ELF64 Binary Loader
//!
//! Parses ELF64 executable binaries and extracts loadable segments.
//! Used to load native agent binaries from an embedded initramfs or disk.

/// ELF64 magic: 0x7F 'E' 'L' 'F'
const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];

/// ELF class: 64-bit
const ELFCLASS64: u8 = 2;
/// ELF data: little-endian
const ELFDATA2LSB: u8 = 1;
/// ELF type: executable
const ET_EXEC: u16 = 2;
/// ELF machine: x86_64
const EM_X86_64: u16 = 62;
/// Program header type: loadable segment
const PT_LOAD: u32 = 1;

/// Maximum number of loadable segments
const MAX_SEGMENTS: usize = 8;

#[derive(Debug)]
pub enum ElfError {
    InvalidMagic,
    Not64Bit,
    NotLittleEndian,
    NotExecutable,
    NotX86_64,
    TooSmall,
    NoLoadableSegments,
    TooManySegments,
    SegmentOutOfBounds,
}

/// A loadable segment from the ELF file
#[derive(Debug, Clone, Copy)]
pub struct LoadSegment {
    /// Virtual address where this segment should be loaded
    pub vaddr: u64,
    /// Size in memory (may be larger than file_size for BSS)
    pub mem_size: u64,
    /// Size in file (data to copy from ELF binary)
    pub file_size: u64,
    /// Offset in the ELF file where data starts
    pub file_offset: u64,
    /// Flags: bit 0 = execute, bit 1 = write, bit 2 = read
    pub flags: u32,
}

/// Parsed ELF64 binary information
#[derive(Debug)]
pub struct ElfInfo {
    /// Entry point virtual address
    pub entry_point: u64,
    /// Loadable segments
    pub segments: [Option<LoadSegment>; MAX_SEGMENTS],
    /// Number of loadable segments
    pub segment_count: usize,
}

/// ELF64 file header (64 bytes)
#[repr(C, packed)]
struct Elf64Header {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,      // program header table offset
    e_shoff: u64,      // section header table offset
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,  // size of program header entry
    e_phnum: u16,      // number of program header entries
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

/// ELF64 program header (56 bytes)
#[repr(C, packed)]
struct Elf64Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

/// Parse an ELF64 binary from a byte slice.
/// Returns the entry point and loadable segments.
pub fn parse_elf64(data: &[u8]) -> Result<ElfInfo, ElfError> {
    // Validate minimum size (64 bytes for ELF64 header)
    if data.len() < 64 {
        return Err(ElfError::TooSmall);
    }

    // Safety: we verified the slice is at least 64 bytes
    let header = unsafe { &*(data.as_ptr() as *const Elf64Header) };

    // Validate magic
    if header.e_ident[0..4] != ELF_MAGIC {
        return Err(ElfError::InvalidMagic);
    }
    if header.e_ident[4] != ELFCLASS64 {
        return Err(ElfError::Not64Bit);
    }
    if header.e_ident[5] != ELFDATA2LSB {
        return Err(ElfError::NotLittleEndian);
    }

    // Read fields from packed struct using read_unaligned for safety
    let e_type = unsafe { core::ptr::addr_of!(header.e_type).read_unaligned() };
    let e_machine = unsafe { core::ptr::addr_of!(header.e_machine).read_unaligned() };
    let e_entry = unsafe { core::ptr::addr_of!(header.e_entry).read_unaligned() };
    let e_phoff = unsafe { core::ptr::addr_of!(header.e_phoff).read_unaligned() };
    let e_phentsize = unsafe { core::ptr::addr_of!(header.e_phentsize).read_unaligned() };
    let e_phnum = unsafe { core::ptr::addr_of!(header.e_phnum).read_unaligned() };

    if e_type != ET_EXEC {
        return Err(ElfError::NotExecutable);
    }
    if e_machine != EM_X86_64 {
        return Err(ElfError::NotX86_64);
    }

    let mut info = ElfInfo {
        entry_point: e_entry,
        segments: [const { None }; MAX_SEGMENTS],
        segment_count: 0,
    };

    // Parse program headers
    for i in 0..e_phnum as usize {
        let ph_offset = e_phoff as usize + i * e_phentsize as usize;
        if ph_offset + core::mem::size_of::<Elf64Phdr>() > data.len() {
            return Err(ElfError::SegmentOutOfBounds);
        }

        // Safety: we verified bounds above
        let phdr = unsafe { &*(data.as_ptr().add(ph_offset) as *const Elf64Phdr) };
        let p_type = unsafe { core::ptr::addr_of!(phdr.p_type).read_unaligned() };

        if p_type == PT_LOAD {
            if info.segment_count >= MAX_SEGMENTS {
                return Err(ElfError::TooManySegments);
            }

            let p_offset = unsafe { core::ptr::addr_of!(phdr.p_offset).read_unaligned() };
            let p_vaddr = unsafe { core::ptr::addr_of!(phdr.p_vaddr).read_unaligned() };
            let p_filesz = unsafe { core::ptr::addr_of!(phdr.p_filesz).read_unaligned() };
            let p_memsz = unsafe { core::ptr::addr_of!(phdr.p_memsz).read_unaligned() };
            let p_flags = unsafe { core::ptr::addr_of!(phdr.p_flags).read_unaligned() };

            // Validate file data is within bounds
            let end = (p_offset as usize).checked_add(p_filesz as usize);
            match end {
                Some(e) if e <= data.len() => {}
                _ => return Err(ElfError::SegmentOutOfBounds),
            }

            info.segments[info.segment_count] = Some(LoadSegment {
                vaddr: p_vaddr,
                mem_size: p_memsz,
                file_size: p_filesz,
                file_offset: p_offset,
                flags: p_flags,
            });
            info.segment_count += 1;
        }
    }

    if info.segment_count == 0 {
        return Err(ElfError::NoLoadableSegments);
    }

    Ok(info)
}

/// Load an ELF64 binary's segments into memory at their specified virtual addresses.
///
/// In Stage-2 (identity-mapped), this copies segment data directly to the
/// physical addresses matching the ELF virtual addresses. When per-agent
/// page tables are added, this will instead map segments into the agent's
/// address space.
///
/// # Safety
///
/// The caller must ensure that the target virtual addresses are valid,
/// writable physical memory regions that do not overlap with kernel code/data.
///
/// Returns the entry point address.
pub unsafe fn load_elf64(data: &[u8]) -> Result<u64, ElfError> {
    let info = parse_elf64(data)?;

    for i in 0..info.segment_count {
        if let Some(seg) = &info.segments[i] {
            let dst = seg.vaddr as *mut u8;
            let src = &data[seg.file_offset as usize..];

            // Copy file data
            core::ptr::copy(src.as_ptr(), dst, seg.file_size as usize);

            // Zero BSS region (mem_size > file_size)
            if seg.mem_size > seg.file_size {
                let bss_start = dst.add(seg.file_size as usize);
                let bss_size = (seg.mem_size - seg.file_size) as usize;
                core::ptr::write_bytes(bss_start, 0, bss_size);
            }
        }
    }

    Ok(info.entry_point)
}
