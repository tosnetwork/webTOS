//! Low-level x86_64 page-table backend.
//!
//! This module owns raw four-level page table walking and leaf PTE mutation so
//! higher-level policy code can stay focused on VMA bookkeeping.

use super::paging::{self, set_page_mapping, unmap_page, PAGE_SIZE, PTE_HUGE, PTE_PRESENT, PTE_USER};

/// Software-only leaf bit used to mark a reserved anonymous PROT_NONE mapping.
///
/// x86_64 leaves bits 9-11 available to software in leaf PTEs.
pub const PTE_SOFT_RESERVED: u64 = 1 << 9;

#[derive(Clone, Copy)]
pub struct LeafPte {
    raw: u64,
}

#[derive(Clone, Copy)]
pub struct PageMapping {
    pub phys_base: u64,
    pub is_huge: bool,
}

impl LeafPte {
    #[inline]
    pub const fn raw(self) -> u64 {
        self.raw
    }

    #[inline]
    pub const fn is_present(self) -> bool {
        self.raw & PTE_PRESENT != 0
    }

    #[inline]
    pub const fn is_soft_reserved(self) -> bool {
        self.raw & PTE_SOFT_RESERVED != 0
    }

    #[inline]
    pub const fn phys_addr(self) -> u64 {
        self.raw & 0x000F_FFFF_FFFF_F000
    }
}

/// Zero a physical frame via its identity-mapped address.
///
/// Safety: the frame must be a valid allocated physical page accessible through
/// the identity mapping.
pub unsafe fn zero_frame(phys: u64) {
    let ptr = paging::phys_to_virt(phys) as *mut u8;
    core::ptr::write_bytes(ptr, 0, PAGE_SIZE);
}

/// Walk the four-level page tables and return the raw 4 KiB leaf PTE.
///
/// This succeeds for present pages and for non-present reserved leaves that
/// retain metadata in software bits. Huge pages are intentionally ignored here
/// because Linux-compat user mappings are currently maintained as 4 KiB leaves.
pub fn leaf_pte(pml4_phys: u64, vaddr: u64) -> Option<LeafPte> {
    let pml4_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let pd_idx = ((vaddr >> 21) & 0x1FF) as usize;
    let pt_idx = ((vaddr >> 12) & 0x1FF) as usize;

    unsafe {
        let pml4 = paging::phys_to_virt(pml4_phys) as *const u64;
        let pml4e = core::ptr::read_volatile(pml4.add(pml4_idx));
        if pml4e & PTE_PRESENT == 0 {
            return None;
        }

        let pdpt = paging::phys_to_virt(pml4e & 0x000F_FFFF_FFFF_F000) as *const u64;
        let pdpte = core::ptr::read_volatile(pdpt.add(pdpt_idx));
        if pdpte & PTE_PRESENT == 0 {
            return None;
        }

        let pd = paging::phys_to_virt(pdpte & 0x000F_FFFF_FFFF_F000) as *const u64;
        let pde = core::ptr::read_volatile(pd.add(pd_idx));
        if pde & PTE_PRESENT == 0 {
            return None;
        }
        if pde & PTE_HUGE != 0 {
            return None;
        }

        let pt = paging::phys_to_virt(pde & 0x000F_FFFF_FFFF_F000) as *const u64;
        let pte = core::ptr::read_volatile(pt.add(pt_idx));
        if pte & 0x000F_FFFF_FFFF_F000 == 0 && (pte & PTE_SOFT_RESERVED == 0) {
            return None;
        }

        Some(LeafPte { raw: pte })
    }
}

/// Return the mapped physical page base for a virtual address and whether the
/// backing entry is a huge PDE.
pub fn mapped_page_base(pml4_phys: u64, vaddr: u64) -> Option<PageMapping> {
    let pml4_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let pd_idx = ((vaddr >> 21) & 0x1FF) as usize;

    unsafe {
        let pml4 = paging::phys_to_virt(pml4_phys) as *const u64;
        let pml4e = core::ptr::read_volatile(pml4.add(pml4_idx));
        if pml4e & PTE_PRESENT == 0 {
            return None;
        }

        let pdpt = paging::phys_to_virt(pml4e & 0x000F_FFFF_FFFF_F000) as *const u64;
        let pdpte = core::ptr::read_volatile(pdpt.add(pdpt_idx));
        if pdpte & PTE_PRESENT == 0 {
            return None;
        }

        let pd = paging::phys_to_virt(pdpte & 0x000F_FFFF_FFFF_F000) as *const u64;
        let pde = core::ptr::read_volatile(pd.add(pd_idx));
        if pde & PTE_PRESENT == 0 {
            return None;
        }

        if pde & PTE_HUGE != 0 {
            let base = pde & 0x000F_FFFF_FFE0_0000;
            return Some(PageMapping {
                phys_base: base + (vaddr & 0x1F_F000),
                is_huge: true,
            });
        }
    }

    let leaf = leaf_pte(pml4_phys, vaddr)?;
    if !leaf.is_present() {
        return None;
    }
    Some(PageMapping {
        phys_base: leaf.phys_addr(),
        is_huge: false,
    })
}

/// Return the mapped physical page base for a present 4 KiB leaf.
pub fn mapped_phys(pml4_phys: u64, vaddr: u64) -> Option<u64> {
    Some(mapped_page_base(pml4_phys, vaddr)?.phys_base)
}

/// Translate a user virtual address to a physical address.
pub fn translate_user_vaddr(pml4_phys: u64, vaddr: u64) -> Option<u64> {
    paging::translate_virt(pml4_phys, vaddr)
}

/// Read a 64-bit value from a mapped user virtual address.
pub fn read_user_u64(pml4_phys: u64, vaddr: u64) -> Option<u64> {
    let mut bytes = [0u8; 8];
    copy_from_user(pml4_phys, vaddr, &mut bytes).then(|| u64::from_ne_bytes(bytes))
}

/// Read a 32-bit value from a mapped user virtual address.
pub fn read_user_u32(pml4_phys: u64, vaddr: u64) -> Option<u32> {
    let mut bytes = [0u8; 4];
    copy_from_user(pml4_phys, vaddr, &mut bytes).then(|| u32::from_ne_bytes(bytes))
}

/// Copy bytes from a mapped user virtual range into a kernel buffer.
pub fn copy_from_user(pml4_phys: u64, user_addr: u64, dst: &mut [u8]) -> bool {
    let mut copied = 0usize;
    while copied < dst.len() {
        let vaddr = user_addr.saturating_add(copied as u64);
        let Some(phys) = translate_user_vaddr(pml4_phys, vaddr) else {
            return false;
        };
        let page_off = (vaddr as usize) & (PAGE_SIZE - 1);
        let chunk_len = (dst.len() - copied).min(PAGE_SIZE - page_off);
        unsafe {
            core::ptr::copy_nonoverlapping(
                paging::phys_to_virt(phys) as *const u8,
                dst.as_mut_ptr().add(copied),
                chunk_len,
            );
        }
        copied += chunk_len;
    }
    true
}

/// Copy bytes from a kernel buffer into a mapped user virtual range.
pub fn copy_to_user(pml4_phys: u64, user_addr: u64, src: &[u8]) -> bool {
    let mut copied = 0usize;
    while copied < src.len() {
        let vaddr = user_addr.saturating_add(copied as u64);
        let Some(phys) = translate_user_vaddr(pml4_phys, vaddr) else {
            return false;
        };
        let page_off = (vaddr as usize) & (PAGE_SIZE - 1);
        let chunk_len = (src.len() - copied).min(PAGE_SIZE - page_off);
        unsafe {
            core::ptr::copy_nonoverlapping(
                src.as_ptr().add(copied),
                paging::phys_to_virt(phys) as *mut u8,
                chunk_len,
            );
        }
        copied += chunk_len;
    }
    true
}

/// Install or replace a 4 KiB leaf mapping.
#[inline]
pub fn map_leaf(pml4_phys: u64, virt_addr: u64, phys_addr: u64, flags: u64) -> Result<(), ()> {
    set_page_mapping(pml4_phys, virt_addr, phys_addr, flags)
}

/// Install a non-present reserved leaf for anonymous PROT_NONE mappings.
#[inline]
pub fn map_reserved_leaf(pml4_phys: u64, virt_addr: u64) -> Result<(), ()> {
    set_page_mapping(pml4_phys, virt_addr, 0, PTE_USER | PTE_SOFT_RESERVED)
}

/// Remove a 4 KiB leaf mapping.
#[inline]
pub fn unmap_leaf(pml4_phys: u64, virt_addr: u64) {
    unmap_page(pml4_phys, virt_addr);
}

/// Invalidate the TLB entry for a single virtual address.
#[inline]
pub fn invalidate(virt_addr: u64) {
    paging::invlpg(virt_addr);
}
