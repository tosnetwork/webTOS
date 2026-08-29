//! Immutable, content-addressed chunks for lazy guest files.
//!
//! This is deliberately below the VFS and above the browser transport.  A
//! manifest names chunk hashes; a store can return verified bytes for one hash
//! without knowing which guest path or VMA requested it.  That separation is
//! what lets the mmap pager validate a page-in ticket before installing bytes
//! at a guest address.

use std::collections::BTreeMap;

use crate::digest::sha256;

/// The default transfer and cache unit.  It is a multiple of the 4 KiB guest
/// page size, so one fetched chunk can satisfy up to sixteen first touches.
pub const DEFAULT_CHUNK_SIZE: u32 = 64 * 1024;

/// SHA-256 identifies immutable chunk bytes.
pub type Hash = [u8; 32];

/// Immutable file layout supplied by an image manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkedFile {
    pub size: u64,
    pub chunk_size: u32,
    pub chunks: Vec<Hash>,
}

impl ChunkedFile {
    /// Constructs a layout only when it can describe exactly `size` bytes.
    /// A zero-length file has no chunks; every nonempty file has a nonzero,
    /// page-aligned chunk size and exactly `ceil(size / chunk_size)` hashes.
    pub fn new(size: u64, chunk_size: u32, chunks: Vec<Hash>) -> Result<Self, String> {
        if size == 0 {
            if chunks.is_empty() && chunk_size != 0 && chunk_size.is_multiple_of(4096) {
                return Ok(Self {
                    size,
                    chunk_size,
                    chunks,
                });
            }
            return Err(
                "zero-length chunked file needs no chunks and a page-aligned chunk size".into(),
            );
        }
        if chunk_size == 0 || !chunk_size.is_multiple_of(4096) {
            return Err("chunk size must be a nonzero multiple of 4096".into());
        }
        let expected = size.div_ceil(u64::from(chunk_size));
        if expected != chunks.len() as u64 {
            return Err(format!(
                "chunked file of {size} bytes at {chunk_size}-byte chunks needs {expected} hashes, got {}",
                chunks.len()
            ));
        }
        Ok(Self {
            size,
            chunk_size,
            chunks,
        })
    }

    /// The hash and byte range of the chunk containing `offset`.
    pub fn chunk_at(&self, offset: u64) -> Option<(usize, Hash, std::ops::Range<u64>)> {
        if offset >= self.size {
            return None;
        }
        let index = (offset / u64::from(self.chunk_size)) as usize;
        let start = index as u64 * u64::from(self.chunk_size);
        let end = (start + u64::from(self.chunk_size)).min(self.size);
        Some((index, self.chunks[index], start..end))
    }
}

/// Result of resolving a file range from a local content-addressed store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadRange {
    Ready(Vec<u8>),
    Missing(Hash),
    Invalid(String),
}

/// Verified resident chunks.  A miss is intentionally observable: it is the
/// input to a future deterministic page-in request, never an excuse to use
/// unchecked bytes or silently materialize the whole file.
#[derive(Debug, Default, Clone)]
pub struct ChunkStore {
    chunks: BTreeMap<Hash, Vec<u8>>,
}

impl ChunkStore {
    pub fn insert(&mut self, expected: Hash, bytes: Vec<u8>) -> Result<(), String> {
        let actual = sha256(&bytes);
        if actual != expected {
            return Err("chunk digest mismatch".into());
        }
        self.chunks.entry(expected).or_insert(bytes);
        Ok(())
    }

    pub fn get(&self, hash: &Hash) -> Option<&[u8]> {
        self.chunks.get(hash).map(Vec::as_slice)
    }

    pub fn contains(&self, hash: &Hash) -> bool {
        self.chunks.contains_key(hash)
    }

    pub fn first_missing(&self, file: &ChunkedFile) -> Option<Hash> {
        file.chunks
            .iter()
            .copied()
            .find(|hash| !self.chunks.contains_key(hash))
    }

    pub fn bytes(&self) -> usize {
        self.chunks.values().map(Vec::capacity).sum()
    }

    /// Reads an in-bounds range without fetching.  The first missing chunk is
    /// returned so a caller can request exactly the authority the manifest
    /// named.  Reading past EOF has Linux's short-read semantics.
    pub fn read_range(&self, file: &ChunkedFile, offset: u64, len: usize) -> ReadRange {
        let end = offset.saturating_add(len as u64).min(file.size);
        if offset >= end {
            return ReadRange::Ready(Vec::new());
        }
        let mut out = Vec::with_capacity((end - offset) as usize);
        let mut cursor = offset;
        while cursor < end {
            let (index, hash, range) = file.chunk_at(cursor).expect("cursor is in file");
            let Some(chunk) = self.get(&hash) else {
                return ReadRange::Missing(hash);
            };
            let expected_len = (range.end - range.start) as usize;
            if chunk.len() != expected_len {
                // The store never accepts an unchecked chunk, but a manifest
                // layout and a verified chunk can still disagree.  Treat this
                // as unavailable, not as a truncated executable image.
                return ReadRange::Invalid(format!(
                    "verified chunk {index} has {} bytes; manifest layout requires {expected_len}",
                    chunk.len()
                ));
            }
            let in_chunk = (cursor - range.start) as usize;
            let take = ((end - cursor) as usize).min(chunk.len() - in_chunk);
            out.extend_from_slice(&chunk[in_chunk..in_chunk + take]);
            cursor += take as u64;
            debug_assert_eq!(
                index,
                (cursor.saturating_sub(1) / u64::from(file.chunk_size)) as usize
            );
        }
        ReadRange::Ready(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(bytes: &[u8]) -> Hash {
        sha256(bytes)
    }

    #[test]
    fn chunked_range_requires_verified_resident_chunks() {
        let first = vec![1; 4096];
        let second = vec![2; 17];
        let file = ChunkedFile::new(4113, 4096, vec![hash(&first), hash(&second)]).expect("layout");
        let mut store = ChunkStore::default();
        store.insert(hash(&first), first).expect("verified first");
        assert_eq!(
            store.read_range(&file, 4090, 20),
            ReadRange::Missing(hash(&second))
        );
        store
            .insert(hash(&second), second)
            .expect("verified second");
        assert_eq!(
            store.read_range(&file, 4090, 20),
            ReadRange::Ready(vec![
                1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2
            ])
        );
    }

    #[test]
    fn bad_chunk_cannot_enter_store() {
        let mut store = ChunkStore::default();
        assert!(store.insert(hash(b"right"), b"wrong".to_vec()).is_err());
        assert_eq!(store.bytes(), 0);
    }
}
