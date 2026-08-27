use crate::{
    Cpu,
    debug_info::DebugInfo,
    mem::{AllocLayout, Mapping, perm},
};

use object::{Endianness, FileKind, elf, read::elf::ProgramHeader};
use tracing::{info, warn};

#[derive(Debug, Clone, Default)]
pub struct ElfMetadata {
    /// The offset the binary has been relocated by.
    pub offset: u64,

    /// The program entry point.
    pub entry_ptr: u64,

    /// The address the elf file was loaded at (equal to the requested base address + offset).
    pub base_ptr: u64,

    /// The total length of the file.
    pub length: u64,

    /// The address of the program header (after relocation).
    pub phdr_ptr: u64,

    /// The number of entries in the program header.
    pub phdr_num: u64,
}

#[derive(Clone)]
pub struct LoadedElf {
    pub binary: ElfMetadata,
    pub interpreter: Option<ElfMetadata>,
    pub debug_info: DebugInfo,
}

pub trait ElfLoader {
    /// Configures whether the ELF loader should allocate new memory to load the binary into.
    ///
    /// If false, then the address space must be already configured before calling `load_elf`.
    const DYNAMIC_MEMORY: bool = true;

    /// Configures whether the loader should use the physical address specified by in the PHDR,
    /// instead of the virtual address.
    // @todo: Determine what the correct behavior is. This workaround was added since MSP430 ELF
    // binaries expect the physical address, but ARM ELF binaries expect the virtual address.
    const LOAD_AT_PHYSICAL_ADDRESS: bool = false;

    fn read_file(&mut self, path: &[u8]) -> Result<Vec<u8>, String> {
        let path = std::str::from_utf8(path)
            .map_err(|e| format!("@fixme: only utf-8 paths are supported: {e}"))?;
        std::fs::read(path).map_err(|e| format!("Failed to read {path}: {e}"))
    }

    fn load_elf(&mut self, cpu: &mut Cpu, path: &[u8]) -> Result<LoadedElf, String> {
        self.load_elf_at_depth(cpu, path, 0)
    }

    /// Loads the ELF at `path`, where `depth` counts interpreters: a binary is
    /// loaded at depth 0 and the interpreter it names at depth 1, and nothing
    /// deeper is loaded at all.
    fn load_elf_at_depth(
        &mut self,
        cpu: &mut Cpu,
        path: &[u8],
        depth: u32,
    ) -> Result<LoadedElf, String> {
        use object::read::elf::FileHeader;

        tracing::info!("Loading ELF file from: {}", path.escape_ascii());

        let file = self.read_file(path)?;
        let data: &[u8] = &file;

        // `FileKind::parse` reads only the magic and the class byte, so a file
        // truncated (or corrupted) anywhere after those still arrives here as
        // an ELF and then fails in `FileHeader::parse`. That is an error, not
        // an impossibility: an image streamed in from the network or read back
        // out of browser storage may be any prefix of a real one.
        let header_error = |e| format!("failed to parse elf header: {e}");
        let mut metadata = match FileKind::parse(data) {
            Ok(FileKind::Elf32) => {
                let header = elf::FileHeader32::<Endianness>::parse(data).map_err(header_error)?;
                load_elf(self, cpu, data, header, depth)?
            }
            Ok(FileKind::Elf64) => {
                let header = elf::FileHeader64::<Endianness>::parse(data).map_err(header_error)?;
                load_elf(self, cpu, data, header, depth)?
            }
            Ok(other) => return Err(format!("unsupported file type: {:?}", other)),
            Err(e) => return Err(format!("failed to parse file: {}", e)),
        };

        // Debug info is best-effort: unsupported formats (e.g. compressed
        // DWARF in Go binaries) must not prevent the binary from running.
        if let Err(e) = metadata.debug_info.add_file(data, metadata.binary.offset) {
            tracing::debug!("ignoring debug info: {e}");
        }

        Ok(metadata)
    }
}

fn load_elf<H, L>(
    loader: &mut L,
    cpu: &mut Cpu,
    data: &[u8],
    elf: &H,
    depth: u32,
) -> Result<LoadedElf, String>
where
    H: object::read::elf::FileHeader,
    L: ElfLoader + ?Sized,
{
    fn parse_error(e: object::Error) -> String {
        format!("error parsing elf: {}", e)
    }

    let endian = elf.endian().map_err(parse_error)?;
    let program_headers = elf.program_headers(endian, data).map_err(parse_error)?;

    let (requested_base_addr, layout) =
        get_layout(program_headers, endian, L::LOAD_AT_PHYSICAL_ADDRESS)?;

    let (base_addr, relocation_offset) = if L::DYNAMIC_MEMORY {
        let base_addr = cpu
            .mem
            .alloc_memory(layout, Mapping { perm: perm::MAP, value: 0xaa })
            .map_err(|e| format!("Failed to allocate memory: {e:?}"))?;

        // The image has to end somewhere inside the address space: the caller
        // computes where it ends to place the heap after it, and a claimed
        // length that runs past the top wraps that around to a low address.
        base_addr.checked_add(layout.size).ok_or_else(|| {
            format!("elf of {:#x} bytes does not fit at {base_addr:#x}", layout.size)
        })?;

        (base_addr, base_addr - requested_base_addr)
    }
    else {
        (requested_base_addr, 0)
    };

    info!(
        "base_addr={base_addr:0x}, relocation_offset={relocation_offset:0x}, size={:0x}",
        layout.size
    );

    let mut phdr_ptr = None;
    let mut interpreter_path = None;
    for header in program_headers {
        // Convert object permissions to our internal permissions
        let permission = get_permission(endian, header);

        match header.p_type(endian) {
            elf::PT_LOAD => {
                if header.p_memsz(endian).into() == 0 {
                    // We don't need to do anything for zero length load sections
                    continue;
                }
                let info = SegmentInfo::from_header(endian, header, L::LOAD_AT_PHYSICAL_ADDRESS)?;
                let relocated_base = info.base + relocation_offset;

                // For some targets we set memory permissions using an external configuration file
                // which might be more restrictive than what the ELF file specifies.
                //
                // Additionally, we currently only want to support code from the loaded binaries
                // directly (e.g., not generated code), so we let the ELF file control the execute
                // permission.
                if L::DYNAMIC_MEMORY || (permission & perm::EXEC != 0) {
                    // Update permissions for this segment
                    info!(
                        "Updating permisson for {:#0x}..{:#0x} to {}",
                        relocated_base,
                        relocated_base + info.size,
                        perm::display(permission)
                    );
                    if let Err(e) = cpu.mem.update_perm(relocated_base, info.size, permission) {
                        warn!("Write update permission for segment {:0x?}: {}", info, e);
                    }
                }

                let bytes =
                    header.data_as_array(endian, data).map_err(|_| "data invalid".to_string())?;
                let load_addr = relocated_base + info.offset;

                if let Err(e) = cpu.mem.write_bytes(load_addr, bytes, perm::NONE) {
                    warn!("Write failed for addr: {:#0x}: {:?}", load_addr, e);

                    // Try to partially write the data into memory. This is a workaround for
                    // binaries files generated by msp430-gcc that attempt to load the ELF header
                    // into unmapped memory.
                    if let Some((start, end)) =
                        cpu.mem.mapping.get_range((load_addr, load_addr + bytes.len() as u64))
                    {
                        let offset = start.saturating_sub(load_addr) as usize;
                        let len = (bytes.len() - offset).min((end - start) as usize);
                        let result =
                            cpu.mem.write_bytes(start, &bytes[offset..][..len], perm::NONE);
                        warn!("Attempted partial write to: {:#0x}: {:?}", start, result);
                    }
                }

                let loaded_len = bytes.len() as u64;

                // If the segment has a larger size in memory than in the file then there is
                // uninitialized data at the end of the segment.
                if loaded_len < info.size {
                    let zero_start = load_addr + loaded_len;

                    // On some platforms, this memory is expected to be zero initialized, including
                    // memory up to alignment size. This can be seen in the `calloc` implementation
                    // in the minimal memory allocator used by the glibc dynamic linker (i.e ld.so)
                    //
                    // TODO: Need to check whether the memory _before_ the mapped region also needs
                    // to be zeroed
                    let length = info.size - loaded_len - info.offset;
                    info!("Zeroing: {:#0x} to {:#0x}", zero_start, zero_start + length);
                    cpu.mem
                        .fill_mem(zero_start, length, 0)
                        .map_err(|e| format!("error zeroing BSS: {:?}", e))?;
                }

                let p = perm::display(permission);
                let (start, len) = header.file_range(endian);
                info!(
                    "Loaded {:#0x}..{:#0x} at {:#0x}..{:#0x} ({})",
                    start,
                    start + len,
                    load_addr,
                    load_addr + bytes.len() as u64,
                    p
                );
            }

            // Specifies that this section should be readonly after relocation. This is handled by
            // the linker
            elf::PT_GNU_RELRO => {
                // Eventually we may want to enforce that the section is made readonly, which we
                // could do by adjusting the permissions here:
                //
                // let region_start = relocations.translate(header.p_vaddr);
                // cpu.mem.set_perm(region_start, header.p_memsz, permission | perm::INIT);
            }

            elf::PT_PHDR => {
                phdr_ptr = Some(header.p_vaddr(endian).into());
            }

            elf::PT_INTERP => {
                let data =
                    header.data_as_array(endian, data).map_err(|_| "data invalid".to_string())?;
                if data.len() > 1 {
                    // Note: The path to the interpreter is null terminated.
                    interpreter_path = Some(&data[..data.len() - 1]);
                }
            }

            // These headers are either handled elsewhere, or not used
            elf::PT_TLS | elf::PT_DYNAMIC | elf::PT_NOTE | elf::PT_NULL => {}

            // These headers we may (or may not) care about but haven't been implemented yet so
            // print a warning message
            other => {
                warn!("p_type: {:#0x} ignored", other);
            }
        }
    }

    let binary = ElfMetadata {
        offset: relocation_offset,
        entry_ptr: elf.e_entry(endian).into() + relocation_offset,
        length: layout.size,
        base_ptr: base_addr,
        phdr_ptr: phdr_ptr
            .map_or(base_addr + elf.e_phoff(endian).into(), |addr| addr + relocation_offset),
        phdr_num: elf.e_phnum(endian) as u64,
    };

    // An image is free to name itself as its own interpreter, and following
    // that recurses until the stack is gone — which aborts the process outright
    // and cannot be caught. Linux allows exactly one interpreter; so does this.
    let interpreter = interpreter_path
        .map(|path| match depth {
            0 => loader.load_elf_at_depth(cpu, path, depth + 1),
            _ => Err(format!("an elf interpreter cannot name one itself: {}", path.escape_ascii())),
        })
        .transpose()?;
    let (interpreter, mut debug_info) = match interpreter {
        Some(entry) => (Some(entry.binary), entry.debug_info),
        None => (None, DebugInfo::default()),
    };

    if let Some(path) = interpreter_path {
        debug_info.dynamic_linker = path.to_vec();
    }

    Ok(LoadedElf { binary, interpreter, debug_info })
}

// Retrives the base address and layout requirements of the ELF when it is loaded into memory.
fn get_layout<H>(
    program_headers: &[H],
    endian: H::Endian,
    use_phy_addr: bool,
) -> Result<(u64, AllocLayout), String>
where
    H: ProgramHeader,
{
    let mut base = std::u64::MAX;
    let mut size = 0;
    let mut align = 0;
    let mut loadable = 0;

    for header in program_headers {
        if header.p_type(endian) != elf::PT_LOAD || header.p_memsz(endian).into() == 0 {
            continue;
        }

        let info = SegmentInfo::from_header(endian, header, use_phy_addr)?;
        // Where the segment says it ends. Every number here comes out of the
        // file, so a segment may claim to start near the top of the address
        // space and run for another terabyte past it.
        let end = info.base.checked_add(info.size).ok_or_else(|| {
            format!(
                "segment at {:#x} runs {:#x} bytes past the address space",
                info.base, info.size
            )
        })?;
        loadable += 1;
        base = base.min(info.base);
        size = size.max(end - base);
        align = align.max(info.alignment);
    }

    // Nothing to load is not an empty image, it is a broken one: describing it
    // as a zero-length region underflows the length inside the allocator.
    if loadable == 0 {
        return Err("elf has no loadable segments".to_string());
    }

    Ok((base, AllocLayout { addr: Some(base), size, align }))
}

#[derive(Copy, Clone, Debug)]
struct SegmentInfo {
    /// The aligned base address of this segment
    base: u64,

    /// The offset (from base) where the segment actually starts at
    offset: u64,

    /// The total length of the section including both alignment and memory between base..base +
    /// offset
    size: u64,

    /// The alignment requested for this segment
    alignment: u64,
}

impl SegmentInfo {
    fn from_header<H: ProgramHeader>(
        endian: H::Endian,
        header: &H,
        use_phy_addr: bool,
    ) -> Result<Self, String> {
        let addr: u64 = match use_phy_addr {
            true => header.p_paddr(endian).into(),
            false => header.p_vaddr(endian).into(),
        };
        let align: u64 = header.p_align(endian).into();
        let size: u64 = header.p_memsz(endian).into();

        // ELF requires `p_align` to be zero, one, or a power of two, the first
        // two meaning no alignment. A corrupt file says otherwise — one flipped
        // bit turns 0x1000 into 0 or into 0x1001 — and the value is then
        // divided by (zero divides) and asserted on inside `align_up`.
        let align = match align {
            0 | 1 => 1,
            align if align.is_power_of_two() => align,
            align => return Err(format!("segment alignment {align:#x} is not a power of two")),
        };
        let offset = addr % align;
        // What `utils::align_up` computes, except that a claimed length running
        // off the end of the address space is refused rather than wrapped.
        let size = size
            .checked_add(offset)
            .and_then(|size| size.checked_next_multiple_of(align))
            .ok_or_else(|| {
            format!("segment at {addr:#x} claims {size:#x} bytes, past the address space")
        })?;

        Ok(Self { base: addr - offset, offset, size, alignment: align })
    }
}

fn get_permission<H: ProgramHeader>(endian: H::Endian, header: &H) -> u8 {
    let flags = header.p_flags(endian);

    let mut perm = perm::MAP;
    perm |= if (flags & elf::PF_R) == 0 { perm::NONE } else { perm::READ };
    perm |= if (flags & elf::PF_W) == 0 { perm::NONE } else { perm::WRITE };
    perm |= if (flags & elf::PF_X) == 0 { perm::NONE } else { perm::EXEC };
    perm
}
