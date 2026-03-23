//! Minimal ELF64 loader for the embedded ATOS kernel binary.
//!
//! Parses ELF64 headers, copies PT_LOAD segments to their physical
//! addresses, and returns the entry point and stack top.

use crate::serial;

const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
const PT_LOAD: u32 = 1;

/// ELF64 file header
#[repr(C)]
struct Elf64Ehdr {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

/// ELF64 section header
#[repr(C)]
struct Elf64Shdr {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
}

/// ELF64 symbol table entry
#[repr(C)]
struct Elf64Sym {
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
    st_size: u64,
}

const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;

/// ELF64 program header
#[repr(C)]
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

/// Result of loading the kernel ELF
pub struct KernelInfo {
    pub entry_point: u64, // kernel_main VMA (higher-half)
    pub stack_top: u64,   // Highest physical address used by kernel
}

/// Load the kernel ELF into physical memory.
///
/// Parses PT_LOAD segments and copies them from the embedded binary
/// to their physical addresses (p_paddr). UEFI provides identity
/// mapping so physical addresses are directly accessible.
pub fn load_kernel(elf_data: &[u8]) -> KernelInfo {
    // Validate ELF magic
    if elf_data.len() < 64 || elf_data[0..4] != ELF_MAGIC {
        serial::println("[UEFI] ERROR: Invalid ELF magic");
        loop { unsafe { core::arch::asm!("hlt"); } }
    }

    let ehdr = unsafe { &*(elf_data.as_ptr() as *const Elf64Ehdr) };

    // Find kernel_main symbol address (not _start which is the Multiboot entry)
    let kernel_main_addr = find_symbol(elf_data, ehdr, b"kernel_main\0")
        .unwrap_or(ehdr.e_entry);

    serial::print("[UEFI] kernel_main at: ");
    serial::print_hex(kernel_main_addr);
    serial::println("");

    serial::print("[UEFI] Program headers: ");
    serial::print_hex(ehdr.e_phnum as u64);
    serial::println("");

    let mut max_paddr_end: u64 = 0;

    // Process each program header
    for i in 0..ehdr.e_phnum as usize {
        let ph_offset = ehdr.e_phoff as usize + i * ehdr.e_phentsize as usize;
        if ph_offset + core::mem::size_of::<Elf64Phdr>() > elf_data.len() {
            break;
        }

        let phdr = unsafe { &*(elf_data.as_ptr().add(ph_offset) as *const Elf64Phdr) };

        if phdr.p_type != PT_LOAD {
            continue;
        }

        let paddr = phdr.p_paddr;
        let filesz = phdr.p_filesz as usize;
        let memsz = phdr.p_memsz as usize;
        let offset = phdr.p_offset as usize;

        serial::print("[UEFI] LOAD: paddr=");
        serial::print_hex(paddr);
        serial::print(" filesz=");
        serial::print_hex(filesz as u64);
        serial::print(" memsz=");
        serial::print_hex(memsz as u64);
        serial::println("");

        // Copy file data to physical address
        if filesz > 0 && offset + filesz <= elf_data.len() {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    elf_data.as_ptr().add(offset),
                    paddr as *mut u8,
                    filesz,
                );
            }
        }

        // Zero BSS (memsz > filesz region)
        if memsz > filesz {
            unsafe {
                core::ptr::write_bytes(
                    (paddr + filesz as u64) as *mut u8,
                    0,
                    memsz - filesz,
                );
            }
        }

        let end = paddr + memsz as u64;
        if end > max_paddr_end {
            max_paddr_end = end;
        }
    }

    // Stack top: scan for __stack_top symbol in ELF, or use
    // a convention. The kernel linker script puts __stack_top
    // at __kernel_end. We can compute it from the highest loaded
    // segment's VMA + size. But actually, we know the entry point
    // is kernel_main at its VMA. The stack top is at the VMA
    // corresponding to max_paddr_end.
    //
    // The kernel VMA offset: entry_point_vma - entry_point_paddr.
    // We know entry is in .text which starts near 0x106000 (physical).
    // VMA offset = ehdr.e_entry - physical_of_entry.
    // But we don't easily know physical_of_entry without checking.
    //
    // Simpler: stack_top_vma = max_paddr_end + KERNEL_VMA_OFFSET
    // where KERNEL_VMA_OFFSET = 0xFFFFFFFF80000000
    let kernel_vma_offset: u64 = 0xFFFF_FFFF_8000_0000;
    // Align max_paddr_end to page boundary for stack_top
    let stack_top_phys = (max_paddr_end + 0xFFF) & !0xFFF;
    let stack_top_vma = stack_top_phys + kernel_vma_offset;

    serial::print("[UEFI] Kernel loaded. Stack top VMA: ");
    serial::print_hex(stack_top_vma);
    serial::println("");

    KernelInfo {
        entry_point: kernel_main_addr,
        stack_top: stack_top_vma,
    }
}

/// Search the ELF symbol table for a named symbol and return its value.
fn find_symbol(elf_data: &[u8], ehdr: &Elf64Ehdr, name: &[u8]) -> Option<u64> {
    let shdr_size = core::mem::size_of::<Elf64Shdr>();

    // Find .symtab and .strtab sections
    let mut symtab_shdr: Option<&Elf64Shdr> = None;
    let mut strtab_offset: usize = 0;

    for i in 0..ehdr.e_shnum as usize {
        let off = ehdr.e_shoff as usize + i * ehdr.e_shentsize as usize;
        if off + shdr_size > elf_data.len() { break; }
        let shdr = unsafe { &*(elf_data.as_ptr().add(off) as *const Elf64Shdr) };

        if shdr.sh_type == SHT_SYMTAB {
            symtab_shdr = Some(shdr);
        }
    }

    let symtab = symtab_shdr?;

    // Get the linked string table
    let strtab_idx = symtab.sh_link as usize;
    let strtab_off = ehdr.e_shoff as usize + strtab_idx * ehdr.e_shentsize as usize;
    if strtab_off + shdr_size <= elf_data.len() {
        let strtab_shdr = unsafe { &*(elf_data.as_ptr().add(strtab_off) as *const Elf64Shdr) };
        if strtab_shdr.sh_type == SHT_STRTAB {
            strtab_offset = strtab_shdr.sh_offset as usize;
        }
    }

    if strtab_offset == 0 { return None; }

    // Search symbols
    let sym_size = core::mem::size_of::<Elf64Sym>();
    let sym_count = if symtab.sh_entsize > 0 {
        symtab.sh_size as usize / symtab.sh_entsize as usize
    } else {
        symtab.sh_size as usize / sym_size
    };

    for i in 0..sym_count {
        let off = symtab.sh_offset as usize + i * sym_size;
        if off + sym_size > elf_data.len() { break; }
        let sym = unsafe { &*(elf_data.as_ptr().add(off) as *const Elf64Sym) };

        if sym.st_name == 0 { continue; }

        // Compare symbol name
        let name_off = strtab_offset + sym.st_name as usize;
        if name_off + name.len() <= elf_data.len() {
            let sym_name = &elf_data[name_off..name_off + name.len()];
            if sym_name == name {
                return Some(sym.st_value);
            }
        }
    }

    None
}
