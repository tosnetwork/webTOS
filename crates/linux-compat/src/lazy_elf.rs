//! Bounded ELF64 metadata parser for manifest-backed executables.
//!
//! The generic Icicle loader takes an owned `Vec<u8>` and therefore clones an
//! entire executable before it can inspect its headers. This x86-64 loader
//! reads only the ELF header, program-header table, and interpreter pathname;
//! every `PT_LOAD` range is registered with the same pager guest `mmap` uses.

use icicle_cpu::{
    debug_info::DebugInfo,
    elf::{ElfMetadata, LoadedElf},
    mem::{perm, AllocLayout, Mapping},
    Cpu,
};

use crate::{chunk::ReadRange, pager::FileMapping, LinuxEnv, NodeKind, PAGE_SIZE};

const ELF_HEADER: usize = 64;
const PROGRAM_HEADER: usize = 56;
const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
const PT_PHDR: u32 = 6;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

#[derive(Clone)]
struct Segment {
    kind: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
}

struct Image {
    file: crate::chunk::ChunkedFile,
    entry: u64,
    phoff: u64,
    phnum: usize,
    segments: Vec<Segment>,
    requested_base: u64,
    image_end: u64,
    image_align: u64,
    interpreter_path: Option<Vec<u8>>,
}

fn u16_at(bytes: &[u8], at: usize) -> Result<u16, String> {
    bytes
        .get(at..at + 2)
        .and_then(|v| v.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or_else(|| "truncated ELF metadata".into())
}

fn u32_at(bytes: &[u8], at: usize) -> Result<u32, String> {
    bytes
        .get(at..at + 4)
        .and_then(|v| v.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| "truncated ELF metadata".into())
}

fn u64_at(bytes: &[u8], at: usize) -> Result<u64, String> {
    bytes
        .get(at..at + 8)
        .and_then(|v| v.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or_else(|| "truncated ELF metadata".into())
}

fn read_exact(env: &mut LinuxEnv, node: usize, offset: u64, len: usize) -> Result<Vec<u8>, String> {
    match env.vfs.read_node_range(node, offset, len) {
        Ok(ReadRange::Ready(bytes)) if bytes.len() == len => Ok(bytes),
        Ok(ReadRange::Ready(_)) => Err("truncated ELF metadata".into()),
        Ok(ReadRange::Missing(hash)) => {
            env.request_file_chunk(hash)?;
            Err("ELF metadata is waiting for an authenticated chunk".into())
        }
        Ok(ReadRange::Invalid(why)) => Err(format!("invalid ELF backing: {why}")),
        Err(errno) => Err(format!("cannot read ELF metadata: errno {errno}")),
    }
}

fn parse_segments(bytes: &[u8], count: usize) -> Result<Vec<Segment>, String> {
    let mut out = Vec::with_capacity(count);
    for index in 0..count {
        let at = index * PROGRAM_HEADER;
        let header = bytes
            .get(at..at + PROGRAM_HEADER)
            .ok_or("truncated program-header table")?;
        out.push(Segment {
            kind: u32_at(header, 0)?,
            flags: u32_at(header, 4)?,
            offset: u64_at(header, 8)?,
            vaddr: u64_at(header, 16)?,
            filesz: u64_at(header, 32)?,
            memsz: u64_at(header, 40)?,
            align: u64_at(header, 48)?,
        });
    }
    Ok(out)
}

fn segment_perm(flags: u32) -> u8 {
    let mut out = perm::INIT;
    if flags & PF_R != 0 {
        out |= perm::READ;
    }
    if flags & PF_W != 0 {
        out |= perm::WRITE;
    }
    if flags & PF_X != 0 {
        out |= perm::EXEC;
    }
    out
}

fn page_align(value: u64) -> Result<u64, String> {
    value
        .checked_next_multiple_of(PAGE_SIZE)
        .ok_or_else(|| "ELF segment range overflows page alignment".into())
}

fn inspect(env: &mut LinuxEnv, path: &[u8], depth: u32) -> Result<Image, String> {
    if depth > 1 {
        return Err("an ELF interpreter cannot name another interpreter".into());
    }
    // Machine::load checks the main path too, but PT_INTERP enters here
    // recursively. Every executable pathname must be bound to its own
    // manifest entry, including after namespace changes in a snapshot.
    env.verify_image(path)?;
    let node = env
        .vfs
        .resolve(env.proc.cwd, path, true)
        .map_err(|errno| format!("cannot resolve {}: errno {errno}", path.escape_ascii()))?
        .node
        .ok_or_else(|| format!("no such file: {}", path.escape_ascii()))?;
    let file = match &env.vfs.node(node).kind {
        NodeKind::ChunkedFile(file) => file.clone(),
        _ => return Err(format!("not a chunked file: {}", path.escape_ascii())),
    };

    let header = read_exact(env, node, 0, ELF_HEADER)?;
    if header[..4] != *b"\x7fELF" || header[4] != 2 || header[5] != 1 {
        return Err("lazy loader supports little-endian ELF64 only".into());
    }
    if u16_at(&header, 18)? != 62 {
        return Err("lazy loader supports x86-64 ELF files only".into());
    }
    let entry = u64_at(&header, 24)?;
    let phoff = u64_at(&header, 32)?;
    let phentsize = usize::from(u16_at(&header, 54)?);
    let phnum = usize::from(u16_at(&header, 56)?);
    if phentsize != PROGRAM_HEADER || phnum == 0 || phnum > 4096 {
        return Err("invalid or unbounded ELF program-header table".into());
    }
    let ph_len = phnum
        .checked_mul(PROGRAM_HEADER)
        .ok_or("ELF program-header table overflows")?;
    let phdrs = read_exact(env, node, phoff, ph_len)?;
    let segments = parse_segments(&phdrs, phnum)?;

    let mut requested_base = u64::MAX;
    let mut image_end = 0_u64;
    let mut image_align = PAGE_SIZE;
    let mut loadable = 0_usize;
    for segment in segments
        .iter()
        .filter(|segment| segment.kind == PT_LOAD && segment.memsz != 0)
    {
        if segment.filesz > segment.memsz
            || segment
                .offset
                .checked_add(segment.filesz)
                .is_none_or(|end| end > file.size)
        {
            return Err("ELF load segment lies outside the immutable file".into());
        }
        let align = match segment.align {
            0 | 1 => 1,
            value if value.is_power_of_two() && value <= (1 << 30) => value,
            _ => return Err("invalid ELF segment alignment".into()),
        };
        let start = segment.vaddr & !(PAGE_SIZE - 1);
        let offset = segment.vaddr - start;
        let size = page_align(
            segment
                .memsz
                .checked_add(offset)
                .ok_or("ELF segment range overflows")?,
        )?;
        let end = start
            .checked_add(size)
            .ok_or("ELF segment runs past the address space")?;
        requested_base = requested_base.min(start);
        image_end = image_end.max(end);
        image_align = image_align.max(align);
        loadable += 1;
    }
    if loadable == 0 {
        return Err("ELF has no loadable segments".into());
    }

    let mut interpreter_path = None;
    for segment in segments.iter().filter(|segment| segment.kind == PT_INTERP) {
        if depth != 0 {
            return Err("an ELF interpreter cannot name another interpreter".into());
        }
        if interpreter_path.is_some() {
            return Err("ELF names more than one interpreter".into());
        }
        let len =
            usize::try_from(segment.filesz).map_err(|_| "ELF interpreter path is too large")?;
        if !(2..=4096).contains(&len) {
            return Err("invalid ELF interpreter path length".into());
        }
        let mut bytes = read_exact(env, node, segment.offset, len)?;
        if bytes.pop() != Some(0) || bytes.contains(&0) {
            return Err("invalid ELF interpreter path".into());
        }
        interpreter_path = Some(bytes);
    }

    Ok(Image {
        file,
        entry,
        phoff,
        phnum,
        segments,
        requested_base,
        image_end,
        image_align,
        interpreter_path,
    })
}

/// Fetches and validates every bounded metadata range needed by execve before
/// the old address space is discarded. A missing range leaves the ordinary
/// file-chunk request installed so the syscall can retry without committing.
pub(crate) fn prepare(env: &mut LinuxEnv, path: &[u8], depth: u32) -> Result<(), String> {
    let image = inspect(env, path, depth)?;
    if let Some(interpreter) = image.interpreter_path {
        prepare(env, &interpreter, depth + 1)?;
    }
    Ok(())
}

pub(crate) fn load(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    path: &[u8],
    depth: u32,
) -> Result<LoadedElf, String> {
    let Image {
        file,
        entry,
        phoff,
        phnum,
        segments,
        requested_base,
        image_end,
        image_align,
        interpreter_path,
    } = inspect(env, path, depth)?;
    let image_len = image_end
        .checked_sub(requested_base)
        .ok_or("invalid ELF layout")?;
    let base = cpu
        .mem
        .alloc_memory(
            AllocLayout {
                addr: Some(requested_base),
                size: image_len,
                align: image_align,
            },
            Mapping {
                // Mapped and initialized, but inaccessible until page-in.
                perm: perm::INIT,
                value: 0,
            },
        )
        .map_err(|e| format!("failed to allocate lazy ELF image: {e:?}"))?;
    let relocation = base
        .checked_sub(requested_base)
        .ok_or("ELF relocation underflows")?;
    let mut phdr_ptr = None;
    for segment in &segments {
        match segment.kind {
            PT_LOAD if segment.memsz != 0 => {
                let start = (segment.vaddr & !(PAGE_SIZE - 1))
                    .checked_add(relocation)
                    .ok_or("relocated ELF segment start overflows")?;
                let in_page = segment.vaddr & (PAGE_SIZE - 1);
                let mapped_len = page_align(
                    segment
                        .memsz
                        .checked_add(in_page)
                        .ok_or("ELF segment range overflows")?,
                )?;
                let end = start
                    .checked_add(mapped_len)
                    .ok_or("relocated ELF segment end overflows")?;
                let data_start = segment
                    .vaddr
                    .checked_add(relocation)
                    .ok_or("relocated ELF data start overflows")?;
                let mapping = FileMapping::new(
                    start,
                    end,
                    data_start,
                    segment.offset,
                    segment.filesz,
                    segment_perm(segment.flags),
                    0xaa,
                    file.clone(),
                )?;
                env.pager.map(env.proc.asid, mapping);
            }
            PT_INTERP => {}
            PT_PHDR => {
                phdr_ptr = Some(
                    segment
                        .vaddr
                        .checked_add(relocation)
                        .ok_or("relocated ELF program headers overflow")?,
                );
            }
            _ => {}
        }
    }

    let entry_ptr = entry
        .checked_add(relocation)
        .ok_or("relocated ELF entry point overflows")?;
    let phdr_ptr = phdr_ptr.map(Ok).unwrap_or_else(|| {
        base.checked_add(phoff)
            .ok_or("ELF program-header pointer overflows")
    })?;
    let binary = ElfMetadata {
        offset: relocation,
        entry_ptr,
        base_ptr: base,
        length: image_len,
        phdr_ptr,
        phdr_num: phnum as u64,
    };
    let interpreter = interpreter_path
        .as_deref()
        .map(|interpreter| load(env, cpu, interpreter, depth + 1))
        .transpose()?;
    let (interpreter, mut debug_info) = match interpreter {
        Some(loaded) => (Some(loaded.binary), loaded.debug_info),
        None => (None, DebugInfo::default()),
    };
    if let Some(path) = interpreter_path {
        debug_info.dynamic_linker = path;
    }
    Ok(LoadedElf {
        binary,
        interpreter,
        debug_info,
    })
}
