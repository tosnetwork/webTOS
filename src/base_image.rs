//! Embedded base-image manifest support.
//!
//! Files declared in `base_image.manifest` or `base_image.runtime.manifest`
//! are embedded into the kernel image at build time and exposed through the
//! shared base-image namespace without being copied into `BASE_IMAGE_STORE`.

use crate::linux_compat::vfs::BaseImageNamespace;

pub struct EmbeddedBaseImageFile {
    pub path: &'static str,
    pub key: u64,
    pub data: &'static [u8],
}

include!(concat!(env!("OUT_DIR"), "/base_image_manifest.rs"));

#[inline]
fn copy_bytes(dst: &mut [u8], src: &[u8]) {
    let len = dst.len().min(src.len());
    for i in 0..len {
        dst[i] = src[i];
    }
}

/// Return the number of embedded base-image files.
pub fn embedded_file_count() -> usize {
    EMBEDDED_BASE_IMAGE_FILES.len()
}

/// Find an embedded file by its resolved base-image key.
pub fn find_by_key(key: u64) -> Option<&'static EmbeddedBaseImageFile> {
    EMBEDDED_BASE_IMAGE_FILES
        .iter()
        .find(|entry| entry.key == key)
}

/// Return an owned small-value copy or synthesized large-file metadata.
///
/// For files larger than 256 bytes this returns the same 6-byte metadata
/// shape used by multi-segment storage:
///   total_len(u32 LE) + segment_count(u16 LE)
pub fn state_get(key: u64) -> Option<([u8; crate::state::MAX_VALUE_SIZE], usize)> {
    let entry = find_by_key(key)?;
    let mut buf = [0u8; crate::state::MAX_VALUE_SIZE];

    if entry.data.len() <= crate::state::MAX_VALUE_SIZE {
        copy_bytes(&mut buf[..entry.data.len()], entry.data);
        return Some((buf, entry.data.len()));
    }

    let total_len = entry.data.len() as u32;
    let segment_count = ((entry.data.len() + crate::state::MULTI_SEGMENT_SIZE - 1)
        / crate::state::MULTI_SEGMENT_SIZE) as u16;
    buf[0..4].copy_from_slice(&total_len.to_le_bytes());
    buf[4..6].copy_from_slice(&segment_count.to_le_bytes());
    Some((buf, 6))
}

/// Return the full embedded file size.
pub fn file_size(key: u64) -> Option<usize> {
    Some(find_by_key(key)?.data.len())
}

/// Copy the full embedded file into `buf`, returning bytes written.
pub fn load_file(key: u64, buf: &mut [u8]) -> usize {
    let Some(entry) = find_by_key(key) else {
        return 0;
    };
    if entry.data.len() > buf.len() {
        return 0;
    }
    copy_bytes(&mut buf[..entry.data.len()], entry.data);
    entry.data.len()
}

/// Iterate over all embedded base-image paths as `(namespace, relative_path)`.
pub fn iter_paths<F>(mut f: F) -> usize
where
    F: FnMut(BaseImageNamespace, &[u8]) -> bool,
{
    let mut count = 0usize;
    for entry in EMBEDDED_BASE_IMAGE_FILES.iter() {
        if let Some((namespace, relative)) =
            crate::linux_compat::vfs::classify_base_image_path(entry.path.as_bytes())
        {
            count += 1;
            if !f(namespace, relative) {
                break;
            }
        }
    }
    count
}
