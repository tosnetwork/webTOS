//! Virtual Filesystem for Linux Compatibility Layer
//!
//! Maps Linux file paths to TOS keyspace keys. Paths under `/lib/`,
//! `/usr/lib/`, `/jdk/`, and `/etc/` resolve to the shared
//! read-only base image keyspace, while `/app/` and all other mutable paths
//! resolve to the current Linux process keyspace.

use sha2::{Digest, Sha256};

/// Base image keyspace ID (system-level, shared read-only).
///
/// This is a logical ID used by the VFS resolver. It does not map to the
/// normal per-agent keyspace table — base image data is stored in a
/// dedicated static table (see [`crate::state`] multi-segment functions).
pub const BASE_IMAGE_KEYSPACE: u16 = 0xFFFE;

/// Special files that require bespoke handling rather than keyspace I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecialFile {
    /// `/dev/null` — reads return 0, writes are discarded.
    Null,
    /// `/dev/urandom` — reads return PRNG output.
    Urandom,
    /// `/proc/self/exe` — returns the agent binary path.
    ProcSelfExe,
    /// `/proc/self/maps` — synthetic VMA listing.
    ProcSelfMaps,
    /// `/proc/self/cgroup` — synthetic cgroup membership.
    ProcSelfCgroup,
    /// `/proc/meminfo` — synthetic memory summary.
    ProcMeminfo,
    /// `/proc/version_signature` — distro-style version probe.
    ProcVersionSignature,
    /// `/sys/devices/system/cpu/online` — synthetic online CPU range.
    SysCpuOnline,
    /// `/sys/fs/cgroup/memory.max` — synthetic cgroup memory ceiling.
    SysCgroupMemoryMax,
    /// `/sys/fs/cgroup/memory.high` — synthetic cgroup memory high watermark.
    SysCgroupMemoryHigh,
}

/// Logical namespaces inside the shared base image keyspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaseImageNamespace {
    Lib = 1,
    Jdk = 2,
    Etc = 3,
    UsrBin = 4,
}

/// Hash arbitrary data to a deterministic 64-bit key using the first 8
/// bytes of its SHA-256 digest.
pub fn sha256_key(data: &[u8]) -> u64 {
    let hash = Sha256::digest(data);
    u64::from_le_bytes([
        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
    ])
}

/// Detect special device / proc paths that require bespoke handling.
pub fn is_special_path(path: &[u8]) -> Option<SpecialFile> {
    if path == b"/dev/null" {
        Some(SpecialFile::Null)
    } else if path == b"/dev/urandom" || path == b"/dev/random" {
        Some(SpecialFile::Urandom)
    } else if path == b"/proc/self/exe" {
        Some(SpecialFile::ProcSelfExe)
    } else if path == b"/proc/self/maps" {
        Some(SpecialFile::ProcSelfMaps)
    } else if path == b"/proc/self/cgroup" {
        Some(SpecialFile::ProcSelfCgroup)
    } else if path == b"/proc/meminfo" {
        Some(SpecialFile::ProcMeminfo)
    } else if path == b"/proc/version_signature" {
        Some(SpecialFile::ProcVersionSignature)
    } else if path == b"/sys/devices/system/cpu/online" {
        Some(SpecialFile::SysCpuOnline)
    } else if path == b"/sys/fs/cgroup/memory.max" {
        Some(SpecialFile::SysCgroupMemoryMax)
    } else if path == b"/sys/fs/cgroup/memory.high" {
        Some(SpecialFile::SysCgroupMemoryHigh)
    } else {
        None
    }
}

/// Classify a Linux path into a base-image namespace and relative path.
///
/// `/lib/...`, `/lib64/...`, and `/usr/lib/...` intentionally share the same
/// namespace so the compatibility layer can expose the same library set
/// through both directory trees.
pub fn classify_base_image_path(path: &[u8]) -> Option<(BaseImageNamespace, &[u8])> {
    if path == b"/etc/ld.so.cache" {
        return Some((BaseImageNamespace::Etc, b"ld.so.cache"));
    }

    if starts_with(path, b"/etc/") {
        return Some((BaseImageNamespace::Etc, &path[5..]));
    }

    if starts_with(path, b"/lib/") {
        return Some((BaseImageNamespace::Lib, &path[5..]));
    }

    if starts_with(path, b"/lib64/") {
        return Some((BaseImageNamespace::Lib, &path[7..]));
    }

    if starts_with(path, b"/usr/lib/") {
        return Some((BaseImageNamespace::Lib, &path[9..]));
    }

    if starts_with(path, b"/usr/bin/") {
        return Some((BaseImageNamespace::UsrBin, &path[9..]));
    }

    if starts_with(path, b"/bin/") {
        return Some((BaseImageNamespace::UsrBin, &path[5..]));
    }

    if starts_with(path, b"/jdk/") {
        return Some((BaseImageNamespace::Jdk, &path[5..]));
    }

    None
}

/// Map a Linux path to a `(keyspace_id, key)` pair.
///
/// Returns the keyspace to search and the hashed key.
///
/// # Path routing
///
/// | Prefix | Keyspace | Key derivation |
/// |--------|----------|----------------|
/// | `/lib/` | `BASE_IMAGE_KEYSPACE` | `sha256_key("base:lib/" + filename)` |
/// | `/usr/lib/` | `BASE_IMAGE_KEYSPACE` | `sha256_key("base:lib/" + filename)` |
/// | `/usr/bin/` | `BASE_IMAGE_KEYSPACE` | `sha256_key("base:usrbin/" + relative)` |
/// | `/bin/` | `BASE_IMAGE_KEYSPACE` | `sha256_key("base:usrbin/" + relative)` |
/// | `/jdk/` | `BASE_IMAGE_KEYSPACE` | `sha256_key("base:jdk/" + relative)` |
/// | `/etc/*` | `BASE_IMAGE_KEYSPACE` | `sha256_key("base:etc/" + relative)` |
/// | `/app/` | current Linux process keyspace | `sha256_key(path)` |
/// | everything else | current Linux process keyspace | `sha256_key(path)` |
pub fn resolve_path(agent_id: u16, path: &[u8]) -> (u16, u64) {
    if let Some((namespace, relative)) = classify_base_image_path(path) {
        let key = match namespace {
            BaseImageNamespace::Lib => sha256_key_prefixed(b"base:lib/", relative),
            BaseImageNamespace::Jdk => sha256_key_prefixed(b"base:jdk/", relative),
            BaseImageNamespace::Etc => {
                if relative == b"ld.so.cache" {
                    sha256_key(b"base:ld.so.cache")
                } else {
                    sha256_key_prefixed(b"base:etc/", relative)
                }
            }
            BaseImageNamespace::UsrBin => sha256_key_prefixed(b"base:usrbin/", relative),
        };
        return (BASE_IMAGE_KEYSPACE, key);
    }

    // Mutable Linux paths are scoped to a process-family filesystem owner
    // rather than the individual agent slot. This keeps fork/vfork children
    // on the same synthetic filesystem view while still isolating unrelated
    // top-level launches from each other.
    (super::state::fs_owner(agent_id), sha256_key(path))
}

// ── Internal helpers ──────────────────────────────────────────────────────

/// Check if `haystack` starts with `needle`.
#[inline]
fn starts_with(haystack: &[u8], needle: &[u8]) -> bool {
    if haystack.len() < needle.len() {
        return false;
    }
    &haystack[..needle.len()] == needle
}

/// Compute `sha256_key(prefix + suffix)` without allocating.
fn sha256_key_prefixed(prefix: &[u8], suffix: &[u8]) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(prefix);
    hasher.update(suffix);
    let hash = hasher.finalize();
    u64::from_le_bytes([
        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
    ])
}
