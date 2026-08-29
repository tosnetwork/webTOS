//! Immutable file-backed virtual mappings and resumable page-in requests.
//!
//! The MMU remains the authority for resident pages. This table only
//! describes pages whose bytes still come from a manifest-pinned file. A
//! miss yields one content hash to the host; no guest state is advanced, so
//! delivery can validate the mapping generation and retry the same p-code.

use std::collections::{BTreeMap, HashSet};

use icicle_cpu::mem::perm;

use crate::{
    chunk::{ChunkedFile, Hash, ReadRange},
    vfs::Vfs,
};

pub const PAGE_SIZE: u64 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessKind {
    Read,
    Write,
    Execute,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageRequest {
    pub ticket: u64,
    pub hash: Hash,
    pub asid: u64,
    pub generation: u64,
    pub page: u64,
    pub access: AccessKind,
}

#[derive(Debug, Clone)]
pub struct FileMapping {
    /// Page-aligned virtual range occupied by the mapping.
    pub start: u64,
    pub end: u64,
    /// Exact subrange initialized from the file. The rest is zero-filled.
    pub data_start: u64,
    pub file_offset: u64,
    pub file_len: u64,
    pub final_perm: u8,
    /// Byte the eager allocator placed in mapped padding before segment data.
    /// Guest mmap uses zero; Icicle's ELF loader deliberately uses 0xaa.
    pub fill: u8,
    /// Immutable descriptor captured when the private mapping was created.
    pub file: ChunkedFile,
}

impl FileMapping {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        start: u64,
        end: u64,
        data_start: u64,
        file_offset: u64,
        file_len: u64,
        final_perm: u8,
        fill: u8,
        file: ChunkedFile,
    ) -> Result<Self, String> {
        if start >= end || !start.is_multiple_of(PAGE_SIZE) || !end.is_multiple_of(PAGE_SIZE) {
            return Err("file mapping range must be nonempty and page aligned".into());
        }
        let data_end = data_start
            .checked_add(file_len)
            .ok_or("file mapping data range overflows")?;
        if data_start < start || data_end > end {
            return Err("file mapping data lies outside its virtual range".into());
        }
        if file_offset
            .checked_add(file_len)
            .is_none_or(|end| end > file.size)
        {
            return Err("file mapping reads past its immutable file version".into());
        }
        Ok(Self {
            start,
            end,
            data_start,
            file_offset,
            file_len,
            final_perm,
            fill,
            file,
        })
    }

    fn data_end(&self) -> u64 {
        self.data_start + self.file_len
    }

    fn clipped(&self, start: u64, end: u64) -> Option<Self> {
        if start >= end || start >= self.end || end <= self.start {
            return None;
        }
        let start = start.max(self.start);
        let end = end.min(self.end);
        let data_start = self.data_start.max(start).min(end);
        let data_end = self.data_end().min(end).max(data_start);
        let skipped = data_start.saturating_sub(self.data_start);
        Some(Self {
            start,
            end,
            data_start,
            file_offset: self.file_offset + skipped,
            file_len: data_end - data_start,
            final_perm: self.final_perm,
            fill: self.fill,
            file: self.file.clone(),
        })
    }
}

#[derive(Debug, Default, Clone)]
struct AddressSpace {
    generation: u64,
    mappings: Vec<FileMapping>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FaultResolution {
    NotLazy,
    Ready { page: u64, bytes: Vec<u8>, perm: u8 },
    Missing(PageRequest),
    Invalid(String),
}

#[derive(Debug, Default)]
pub struct Pager {
    spaces: BTreeMap<u64, AddressSpace>,
    resident: HashSet<(u64, u64)>,
    pending: Option<PageRequest>,
    next_ticket: u64,
    page_ins: u64,
    page_ins_by_access: [u64; 3],
}

impl Pager {
    pub fn map(&mut self, asid: u64, mapping: FileMapping) {
        let space = self.spaces.entry(asid).or_default();
        space.generation = space.generation.wrapping_add(1).max(1);
        space.mappings.push(mapping);
    }

    pub fn generation(&self, asid: u64) -> u64 {
        self.spaces.get(&asid).map_or(0, |space| space.generation)
    }

    pub fn pending(&self) -> Option<&PageRequest> {
        self.pending.as_ref()
    }

    pub fn page_ins(&self) -> u64 {
        self.page_ins
    }

    pub fn page_ins_by_access(&self) -> [u64; 3] {
        self.page_ins_by_access
    }

    pub fn nonresident_pages(&self, asid: u64, start: u64, len: u64) -> Vec<u64> {
        let Some(space) = self.spaces.get(&asid) else {
            return Vec::new();
        };
        let end = start.saturating_add(len);
        let mut pages = Vec::new();
        let mut page = start & !(PAGE_SIZE - 1);
        while page < end {
            if !self.resident.contains(&(asid, page))
                && space
                    .mappings
                    .iter()
                    .any(|mapping| mapping.start <= page && page < mapping.end)
            {
                pages.push(page);
            }
            page = page.saturating_add(PAGE_SIZE);
        }
        pages
    }

    /// Final permission and residency for a page governed by a lazy VMA.
    /// Last mapping wins, matching page construction for overlapping PT_LOADs.
    pub fn page_state(&self, asid: u64, page: u64) -> Option<(bool, u8)> {
        let page = page & !(PAGE_SIZE - 1);
        let perm = self
            .spaces
            .get(&asid)?
            .mappings
            .iter()
            .rfind(|mapping| mapping.start <= page && page < mapping.end)?
            .final_perm;
        Some((self.resident.contains(&(asid, page)), perm))
    }

    pub fn resolve(
        &mut self,
        vfs: &Vfs,
        asid: u64,
        address: u64,
        access: AccessKind,
    ) -> FaultResolution {
        let mut page = address & !(PAGE_SIZE - 1);
        let Some(space) = self.spaces.get(&asid) else {
            return FaultResolution::NotLazy;
        };
        let mut touching: Vec<&FileMapping> = space
            .mappings
            .iter()
            .filter(|mapping| mapping.start <= page && page < mapping.end)
            .collect();
        if touching.is_empty() {
            return FaultResolution::NotLazy;
        }
        if self.resident.contains(&(asid, page)) {
            // Icicle reports a cross-page access fault at the operation's
            // starting address, which can be in an already-resident page.
            // This occurs for instruction translation and for unaligned
            // guest loads/stores. Resolve the adjacent cold page before
            // treating the fault as unrelated to laziness, but only when the
            // VMA actually grants this access on both sides.
            let required = match access {
                AccessKind::Read => perm::READ,
                AccessKind::Write => perm::WRITE,
                AccessKind::Execute => perm::EXEC,
            };
            if touching
                .last()
                .is_none_or(|mapping| mapping.final_perm & required == 0)
            {
                return FaultResolution::NotLazy;
            }
            let next = page.saturating_add(PAGE_SIZE);
            let next_touching: Vec<&FileMapping> = space
                .mappings
                .iter()
                .filter(|mapping| mapping.start <= next && next < mapping.end)
                .collect();
            if next_touching
                .last()
                .is_none_or(|mapping| mapping.final_perm & required == 0)
                || self.resident.contains(&(asid, next))
            {
                return FaultResolution::NotLazy;
            }
            page = next;
            touching = next_touching;
        }

        let mut bytes = vec![touching[0].fill; PAGE_SIZE as usize];
        let mut final_perm = perm::INIT;
        for mapping in touching {
            // ELF PT_LOAD ranges may share a page. Applying mappings in their
            // insertion order reproduces the eager loader's sequential writes
            // and last-permission-wins behaviour.
            final_perm = mapping.final_perm;
            // The eager ELF loader zeroes BSS and page tail after the file
            // payload, while preserving its 0xaa allocator sentinel before an
            // unaligned segment. mmap's fill is already zero, so this rule is
            // correct there too.
            let zero_start = mapping.data_end().max(page);
            let zero_end = mapping.end.min(page + PAGE_SIZE);
            if zero_start < zero_end {
                bytes[(zero_start - page) as usize..(zero_end - page) as usize].fill(0);
            }
            let copy_start = page.max(mapping.data_start);
            let copy_end = (page + PAGE_SIZE).min(mapping.data_end());
            if copy_start >= copy_end {
                continue;
            }
            let file_offset = mapping.file_offset + (copy_start - mapping.data_start);
            let len = (copy_end - copy_start) as usize;
            match vfs.read_chunked_range(&mapping.file, file_offset, len) {
                ReadRange::Ready(part) if part.len() == len => {
                    let at = (copy_start - page) as usize;
                    bytes[at..at + len].copy_from_slice(&part);
                }
                ReadRange::Ready(_) => {
                    return FaultResolution::Invalid(
                        "manifest-backed page resolved to a short range".into(),
                    );
                }
                ReadRange::Missing(hash) => {
                    if let Some(request) = &self.pending {
                        if request.hash == hash
                            && request.asid == asid
                            && request.generation == space.generation
                            && request.page == page
                        {
                            return FaultResolution::Missing(request.clone());
                        }
                        return FaultResolution::Invalid(
                            "a second page-in was requested while one is pending".into(),
                        );
                    }
                    self.next_ticket = self.next_ticket.wrapping_add(1).max(1);
                    let request = PageRequest {
                        ticket: self.next_ticket,
                        hash,
                        asid,
                        generation: space.generation,
                        page,
                        access,
                    };
                    self.pending = Some(request.clone());
                    return FaultResolution::Missing(request);
                }
                ReadRange::Invalid(why) => return FaultResolution::Invalid(why),
            }
        }
        FaultResolution::Ready {
            page,
            bytes,
            perm: final_perm,
        }
    }

    pub fn mark_resident(&mut self, asid: u64, page: u64, access: AccessKind) {
        if self.resident.insert((asid, page & !(PAGE_SIZE - 1))) {
            self.page_ins += 1;
            let index = match access {
                AccessKind::Read => 0,
                AccessKind::Write => 1,
                AccessKind::Execute => 2,
            };
            self.page_ins_by_access[index] += 1;
        }
    }

    /// Validates a completion before the bytes enter the shared store. A
    /// stale completion is harmless and is not cached: the ticket's authority
    /// was for one mapping generation, not merely for a hash.
    pub fn complete(&mut self, vfs: &mut Vfs, ticket: u64, bytes: Vec<u8>) -> Result<(), String> {
        let request = self.pending.as_ref().ok_or("no page-in is pending")?;
        if request.ticket != ticket {
            return Err("page-in ticket does not match the pending request".into());
        }
        let current = self.spaces.get(&request.asid).is_some_and(|space| {
            space.generation == request.generation
                && space
                    .mappings
                    .iter()
                    .any(|mapping| mapping.start <= request.page && request.page < mapping.end)
        });
        if !current {
            self.pending = None;
            return Err("stale page-in ticket".into());
        }
        vfs.put_chunk(request.hash, bytes)?;
        self.pending = None;
        Ok(())
    }

    pub fn unmap(&mut self, asid: u64, start: u64, len: u64) {
        let Some(end) = start.checked_add(len) else {
            self.drop_space(asid);
            return;
        };
        let Some(space) = self.spaces.get_mut(&asid) else {
            return;
        };
        let mut kept = Vec::new();
        for mapping in &space.mappings {
            if mapping.end <= start || mapping.start >= end {
                kept.push(mapping.clone());
                continue;
            }
            if let Some(left) = mapping.clipped(mapping.start, start) {
                kept.push(left);
            }
            if let Some(right) = mapping.clipped(end, mapping.end) {
                kept.push(right);
            }
        }
        space.mappings = kept;
        space.generation = space.generation.wrapping_add(1).max(1);
        self.resident
            .retain(|&(space_asid, page)| space_asid != asid || page < start || page >= end);
    }

    pub fn protect(&mut self, asid: u64, start: u64, len: u64, new_perm: u8) {
        let Some(end) = start.checked_add(len) else {
            return;
        };
        let Some(space) = self.spaces.get_mut(&asid) else {
            return;
        };
        let mut split = Vec::new();
        for mapping in &space.mappings {
            if mapping.end <= start || mapping.start >= end {
                split.push(mapping.clone());
                continue;
            }
            if let Some(left) = mapping.clipped(mapping.start, start) {
                split.push(left);
            }
            if let Some(mut middle) = mapping.clipped(start, end) {
                middle.final_perm = new_perm;
                split.push(middle);
            }
            if let Some(right) = mapping.clipped(end, mapping.end) {
                split.push(right);
            }
        }
        space.mappings = split;
        space.generation = space.generation.wrapping_add(1).max(1);
    }

    pub fn remap(&mut self, asid: u64, old_start: u64, old_len: u64, new_start: u64, new_len: u64) {
        let Some(space) = self.spaces.get_mut(&asid) else {
            return;
        };
        let old_end = old_start.saturating_add(old_len);
        let copy_len = old_len.min(new_len);
        let copy_end = old_start.saturating_add(copy_len);
        // Linux extends a file mapping over the following file offsets when
        // mremap grows it. Capture the last mapping at the old boundary before
        // splitting/moving the table; otherwise the new tail would stay as the
        // allocator's writable zero pages and bypass both immutable bytes and
        // the original protection.
        let tail_source = (new_len > old_len)
            .then(|| {
                space
                    .mappings
                    .iter()
                    .rfind(|mapping| mapping.start < old_end && old_end <= mapping.end)
                    .cloned()
            })
            .flatten();
        let mut kept = Vec::new();
        let mut moved = Vec::new();
        for mapping in &space.mappings {
            if mapping.end <= old_start || mapping.start >= old_end {
                kept.push(mapping.clone());
                continue;
            }
            if let Some(left) = mapping.clipped(mapping.start, old_start) {
                kept.push(left);
            }
            if let Some(right) = mapping.clipped(old_end, mapping.end) {
                kept.push(right);
            }
            if let Some(mut part) = mapping.clipped(old_start, copy_end) {
                let delta = new_start.wrapping_sub(old_start);
                part.start = part.start.wrapping_add(delta);
                part.end = part.end.wrapping_add(delta);
                part.data_start = part.data_start.wrapping_add(delta);
                moved.push(part);
            }
        }
        if let Some(source) = tail_source {
            let tail_start = new_start.saturating_add(old_len);
            let tail_end = new_start.saturating_add(new_len);
            if tail_start < tail_end {
                let offset_at_tail = source
                    .file_offset
                    .saturating_add(old_end.saturating_sub(source.data_start))
                    .min(source.file.size);
                let file_len = source
                    .file
                    .size
                    .saturating_sub(offset_at_tail)
                    .min(tail_end - tail_start);
                if let Ok(tail) = FileMapping::new(
                    tail_start,
                    tail_end,
                    tail_start,
                    offset_at_tail,
                    file_len,
                    source.final_perm,
                    source.fill,
                    source.file,
                ) {
                    moved.push(tail);
                }
            }
        }
        kept.extend(moved);
        space.mappings = kept;
        space.generation = space.generation.wrapping_add(1).max(1);

        let old_resident: Vec<u64> = self
            .resident
            .iter()
            .filter_map(|&(space_asid, page)| {
                (space_asid == asid && old_start <= page && page < copy_end).then_some(page)
            })
            .collect();
        self.resident.retain(|&(space_asid, page)| {
            space_asid != asid || page < old_start || page >= old_end
        });
        self.resident.extend(
            old_resident
                .into_iter()
                .map(|page| (asid, new_start + (page - old_start))),
        );
    }

    pub fn fork_space(&mut self, parent: u64, child: u64) {
        if let Some(space) = self.spaces.get(&parent).cloned() {
            self.spaces.insert(child, space);
            let inherited: Vec<u64> = self
                .resident
                .iter()
                .filter_map(|&(asid, page)| (asid == parent).then_some(page))
                .collect();
            self.resident
                .extend(inherited.into_iter().map(|page| (child, page)));
        }
    }

    pub fn drop_space(&mut self, asid: u64) {
        self.spaces.remove(&asid);
        self.resident.retain(|&(space, _)| space != asid);
        // A pending request deliberately remains until delivery, which then
        // observes the missing address space and classifies it as stale.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{chunk::ChunkedFile, digest::sha256};

    fn fixture() -> (Vfs, Pager, Vec<u8>, Hash) {
        let bytes = vec![0x5a; PAGE_SIZE as usize];
        let hash = sha256(&bytes);
        let file = ChunkedFile::new(PAGE_SIZE, PAGE_SIZE as u32, vec![hash]).expect("file");
        let mut pager = Pager::default();
        pager.map(
            7,
            FileMapping::new(
                0x20_0000,
                0x20_1000,
                0x20_0000,
                0,
                PAGE_SIZE,
                perm::READ | perm::EXEC | perm::INIT,
                0,
                file,
            )
            .expect("mapping"),
        );
        (Vfs::new(), pager, bytes, hash)
    }

    #[test]
    fn stale_unmap_completion_cannot_enter_the_store() {
        let (mut vfs, mut pager, bytes, _) = fixture();
        let FaultResolution::Missing(request) =
            pager.resolve(&vfs, 7, 0x20_0010, AccessKind::Execute)
        else {
            panic!("expected miss");
        };
        pager.unmap(7, 0x20_0000, PAGE_SIZE);
        assert_eq!(
            pager.complete(&mut vfs, request.ticket, bytes).unwrap_err(),
            "stale page-in ticket"
        );
        assert_eq!(vfs.chunk_bytes(), 0);
    }

    #[test]
    fn hash_and_storage_failures_are_closed() {
        let (mut vfs, mut pager, bytes, _) = fixture();
        let FaultResolution::Missing(request) = pager.resolve(&vfs, 7, 0x20_0000, AccessKind::Read)
        else {
            panic!("expected miss");
        };
        assert!(pager
            .complete(&mut vfs, request.ticket, b"substitution".to_vec())
            .unwrap_err()
            .contains("digest"));
        vfs.set_storage_budget(Some(bytes.len() - 1));
        assert!(pager
            .complete(&mut vfs, request.ticket, bytes)
            .unwrap_err()
            .contains("storage budget"));
        assert_eq!(vfs.chunk_bytes(), 0);
    }

    #[test]
    fn protection_and_remap_invalidate_inflight_coordinates() {
        for mutate in [0, 1] {
            let (mut vfs, mut pager, bytes, _) = fixture();
            let FaultResolution::Missing(request) =
                pager.resolve(&vfs, 7, 0x20_0000, AccessKind::Read)
            else {
                panic!("expected miss");
            };
            if mutate == 0 {
                pager.protect(7, 0x20_0000, PAGE_SIZE, perm::READ | perm::INIT);
            } else {
                pager.remap(7, 0x20_0000, PAGE_SIZE, 0x30_0000, PAGE_SIZE);
            }
            assert_eq!(
                pager.complete(&mut vfs, request.ticket, bytes).unwrap_err(),
                "stale page-in ticket"
            );
        }
    }

    #[test]
    fn map_fixed_and_exec_drop_make_late_completions_stale() {
        for replace in [true, false] {
            let (mut vfs, mut pager, bytes, _) = fixture();
            let FaultResolution::Missing(request) =
                pager.resolve(&vfs, 7, 0x20_0000, AccessKind::Execute)
            else {
                panic!("expected miss");
            };
            if replace {
                // The syscall's MAP_FIXED order: remove the old VMA, then
                // install a new immutable version at the same address.
                pager.unmap(7, 0x20_0000, PAGE_SIZE);
                let new_hash = sha256(b"replacement");
                let new_file =
                    ChunkedFile::new(11, PAGE_SIZE as u32, vec![new_hash]).expect("file");
                pager.map(
                    7,
                    FileMapping::new(
                        0x20_0000,
                        0x20_1000,
                        0x20_0000,
                        0,
                        11,
                        perm::READ | perm::INIT,
                        0,
                        new_file,
                    )
                    .expect("replacement mapping"),
                );
            } else {
                pager.drop_space(7);
            }
            assert_eq!(
                pager.complete(&mut vfs, request.ticket, bytes).unwrap_err(),
                "stale page-in ticket"
            );
            assert_eq!(vfs.chunk_bytes(), 0);
        }
    }

    #[test]
    fn fork_clones_vma_state_without_retargeting_parent_ticket() {
        let (mut vfs, mut pager, bytes, _) = fixture();
        let FaultResolution::Missing(request) = pager.resolve(&vfs, 7, 0x20_0000, AccessKind::Read)
        else {
            panic!("expected miss");
        };
        pager.fork_space(7, 8);
        pager
            .complete(&mut vfs, request.ticket, bytes)
            .expect("parent completion remains current");
        let FaultResolution::Ready { page, perm, .. } =
            pager.resolve(&vfs, 8, 0x20_0000, AccessKind::Read)
        else {
            panic!("child inherited no lazy VMA");
        };
        assert_eq!(page, 0x20_0000);
        assert_eq!(perm, perm::READ | perm::EXEC | perm::INIT);
        assert_eq!(request.asid, 7, "ticket authority moved to the child");
    }

    #[test]
    fn a_cross_page_fault_at_a_resident_start_requests_the_adjacent_page() {
        for access in [AccessKind::Read, AccessKind::Write, AccessKind::Execute] {
            let first = vec![0x11; PAGE_SIZE as usize];
            let second = vec![0x22; PAGE_SIZE as usize];
            let second_hash = sha256(&second);
            let file = ChunkedFile::new(
                PAGE_SIZE * 2,
                PAGE_SIZE as u32,
                vec![sha256(&first), second_hash],
            )
            .expect("file");
            let mut pager = Pager::default();
            pager.map(
                7,
                FileMapping::new(
                    0x20_0000,
                    0x20_2000,
                    0x20_0000,
                    0,
                    PAGE_SIZE * 2,
                    perm::READ | perm::WRITE | perm::EXEC | perm::INIT,
                    0,
                    file,
                )
                .expect("mapping"),
            );
            pager.mark_resident(7, 0x20_0000, access);
            let FaultResolution::Missing(request) =
                pager.resolve(&Vfs::new(), 7, 0x20_0ffe, access)
            else {
                panic!("expected adjacent miss for {access:?}");
            };
            assert_eq!(request.page, 0x20_1000);
            assert_eq!(request.hash, second_hash);
        }
    }

    #[test]
    fn growing_mremap_keeps_the_file_backed_tail_lazy_and_protected() {
        let first = vec![0x41; PAGE_SIZE as usize];
        let second = vec![0x42; PAGE_SIZE as usize];
        let second_hash = sha256(&second);
        let file = ChunkedFile::new(
            PAGE_SIZE * 2,
            PAGE_SIZE as u32,
            vec![sha256(&first), second_hash],
        )
        .expect("file");
        let mut pager = Pager::default();
        pager.map(
            7,
            FileMapping::new(
                0x20_0000,
                0x20_1000,
                0x20_0000,
                0,
                PAGE_SIZE,
                perm::READ | perm::INIT,
                0,
                file,
            )
            .expect("mapping"),
        );
        pager.remap(7, 0x20_0000, PAGE_SIZE, 0x30_0000, PAGE_SIZE * 2);
        let FaultResolution::Missing(request) =
            pager.resolve(&Vfs::new(), 7, 0x30_1000, AccessKind::Read)
        else {
            panic!("grown tail was not kept lazy");
        };
        assert_eq!(request.page, 0x30_1000);
        assert_eq!(request.hash, second_hash);
        assert_eq!(
            pager.page_state(7, 0x30_1000),
            Some((false, perm::READ | perm::INIT))
        );
    }
}
