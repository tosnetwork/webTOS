//! ATOS Package Format — Stage 7
//!
//! Defines the `.tos` package format for agent distribution.
//! A package contains a manifest (metadata, capabilities, signature)
//! and the WASM binary payload. The manifest is fixed-size for `no_std`
//! compatibility.
//!
//! See PackageManager.md for the full design document.

extern crate alloc;
use alloc::vec::Vec;

pub type Hash256 = [u8; 32];

/// Package manifest header (fixed-size for no_std)
#[derive(Debug, Clone)]
pub struct PackageManifest {
    pub name: [u8; 64],
    pub name_len: u8,
    pub version_major: u16,
    pub version_minor: u16,
    pub version_patch: u16,
    pub author: [u8; 64],
    pub author_len: u8,
    pub required_capabilities: u32, // capability bitmask
    pub min_energy: u64,
    pub max_memory_pages: u32,
    pub code_hash: Hash256,
    pub manifest_hash: Hash256,
    pub signature: [u8; 64],
}

/// Package container (.tos format)
pub struct Package {
    pub manifest: PackageManifest,
    pub code: Vec<u8>,     // WASM binary
    pub metadata: Vec<u8>, // optional metadata
}

impl PackageManifest {
    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len as usize]).unwrap_or("")
    }

    pub fn author_str(&self) -> &str {
        core::str::from_utf8(&self.author[..self.author_len as usize]).unwrap_or("")
    }

    /// Verify code hash matches actual code (SHA-256).
    pub fn verify_code_hash(&self, code: &[u8]) -> bool {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(code);
        let mut computed = [0u8; 32];
        computed.copy_from_slice(&hash);
        computed == self.code_hash
    }
}

/// Parse a .tos package from raw bytes.
///
/// Wire format:
///   [manifest_size: u32 LE][manifest_bytes][code_size: u32 LE][code_bytes][metadata (rest)]
pub fn parse_package(data: &[u8]) -> Option<Package> {
    if data.len() < 8 {
        return None;
    }
    let manifest_size = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if data.len() < 4 + manifest_size + 4 {
        return None;
    }

    // Parse manifest fields from raw bytes
    let m = &data[4..4 + manifest_size];
    if manifest_size < 64 + 1 + 6 + 64 + 1 + 4 + 8 + 4 + 32 + 32 + 64 {
        // Not enough bytes for a full manifest
        return None;
    }

    let mut off = 0;
    let mut name = [0u8; 64];
    name.copy_from_slice(&m[off..off + 64]);
    off += 64;
    let name_len = m[off];
    off += 1;
    let version_major = u16::from_le_bytes([m[off], m[off + 1]]);
    off += 2;
    let version_minor = u16::from_le_bytes([m[off], m[off + 1]]);
    off += 2;
    let version_patch = u16::from_le_bytes([m[off], m[off + 1]]);
    off += 2;
    let mut author = [0u8; 64];
    author.copy_from_slice(&m[off..off + 64]);
    off += 64;
    let author_len = m[off];
    off += 1;
    let required_capabilities = u32::from_le_bytes([m[off], m[off + 1], m[off + 2], m[off + 3]]);
    off += 4;
    let min_energy = u64::from_le_bytes([
        m[off],
        m[off + 1],
        m[off + 2],
        m[off + 3],
        m[off + 4],
        m[off + 5],
        m[off + 6],
        m[off + 7],
    ]);
    off += 8;
    let max_memory_pages = u32::from_le_bytes([m[off], m[off + 1], m[off + 2], m[off + 3]]);
    off += 4;
    let mut code_hash = [0u8; 32];
    code_hash.copy_from_slice(&m[off..off + 32]);
    off += 32;
    let mut manifest_hash = [0u8; 32];
    manifest_hash.copy_from_slice(&m[off..off + 32]);
    off += 32;
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&m[off..off + 64]);

    let manifest = PackageManifest {
        name,
        name_len,
        version_major,
        version_minor,
        version_patch,
        author,
        author_len,
        required_capabilities,
        min_energy,
        max_memory_pages,
        code_hash,
        manifest_hash,
        signature,
    };

    // Parse code section
    let code_off = 4 + manifest_size;
    let code_size = u32::from_le_bytes([
        data[code_off],
        data[code_off + 1],
        data[code_off + 2],
        data[code_off + 3],
    ]) as usize;
    let code_start = code_off + 4;
    if data.len() < code_start + code_size {
        return None;
    }
    let code = data[code_start..code_start + code_size].to_vec();

    // Remaining bytes are metadata
    let meta_start = code_start + code_size;
    let metadata = if meta_start < data.len() {
        data[meta_start..].to_vec()
    } else {
        Vec::new()
    };

    Some(Package {
        manifest,
        code,
        metadata,
    })
}

/// Maximum number of installed packages.
const MAX_PACKAGES: usize = 32;

/// Package registry (installed packages).
static mut PACKAGE_REGISTRY: [Option<PackageManifest>; MAX_PACKAGES] =
    [const { None }; MAX_PACKAGES];
static mut PACKAGE_COUNT: usize = 0;

/// Install a package manifest into the registry.
/// Returns the registry index on success.
pub fn install_package(manifest: PackageManifest) -> Option<usize> {
    unsafe {
        if PACKAGE_COUNT >= MAX_PACKAGES {
            return None;
        }
        let idx = PACKAGE_COUNT;
        PACKAGE_REGISTRY[idx] = Some(manifest);
        PACKAGE_COUNT += 1;
        crate::persist::save_packages_to_disk();
        Some(idx)
    }
}

/// Remove a package from the registry by index.
pub fn uninstall_package(idx: usize) -> bool {
    unsafe {
        if idx < MAX_PACKAGES {
            if PACKAGE_REGISTRY[idx].is_some() {
                PACKAGE_REGISTRY[idx] = None;
                return true;
            }
        }
        false
    }
}

/// Look up a package manifest by registry index.
pub fn get_package(idx: usize) -> Option<&'static PackageManifest> {
    unsafe { PACKAGE_REGISTRY.get(idx)?.as_ref() }
}

/// Return the number of installed packages.
pub fn package_count() -> usize {
    unsafe { PACKAGE_COUNT }
}
