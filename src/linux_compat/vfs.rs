//! Virtual Filesystem for Linux Compatibility Layer
//!
//! Maps Linux file paths to ATOS keyspace keys. Paths under `/lib/`,
//! `/usr/lib/`, `/jdk/`, and `/etc/ld.so.cache` resolve to the shared
//! read-only base image keyspace, while `/app/` and all other paths
//! resolve to the agent's own private keyspace.

use sha2::{Sha256, Digest};

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
}

/// Hash arbitrary data to a deterministic 64-bit key using the first 8
/// bytes of its SHA-256 digest.
pub fn sha256_key(data: &[u8]) -> u64 {
    let hash = Sha256::digest(data);
    u64::from_le_bytes([
        hash[0], hash[1], hash[2], hash[3],
        hash[4], hash[5], hash[6], hash[7],
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
    } else {
        None
    }
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
/// | `/jdk/` | `BASE_IMAGE_KEYSPACE` | `sha256_key("base:jdk/" + relative)` |
/// | `/etc/ld.so.cache` | `BASE_IMAGE_KEYSPACE` | `sha256_key("base:ld.so.cache")` |
/// | `/app/` | `agent_id` | `sha256_key(path)` |
/// | everything else | `agent_id` | `sha256_key(path)` |
pub fn resolve_path(agent_id: u16, path: &[u8]) -> (u16, u64) {
    // /etc/ld.so.cache → base image
    if path == b"/etc/ld.so.cache" {
        return (BASE_IMAGE_KEYSPACE, sha256_key(b"base:ld.so.cache"));
    }

    // /lib/<filename> → base image, key = "base:lib/<filename>"
    if starts_with(path, b"/lib/") {
        let filename = &path[5..]; // skip "/lib/"
        let key = sha256_key_prefixed(b"base:lib/", filename);
        return (BASE_IMAGE_KEYSPACE, key);
    }

    // /usr/lib/<filename> → base image, same key namespace as /lib/
    if starts_with(path, b"/usr/lib/") {
        let filename = &path[9..]; // skip "/usr/lib/"
        let key = sha256_key_prefixed(b"base:lib/", filename);
        return (BASE_IMAGE_KEYSPACE, key);
    }

    // /jdk/<relative_path> → base image
    if starts_with(path, b"/jdk/") {
        let relative = &path[5..]; // skip "/jdk/"
        let key = sha256_key_prefixed(b"base:jdk/", relative);
        return (BASE_IMAGE_KEYSPACE, key);
    }

    // /app/ and everything else → agent's own keyspace
    (agent_id, sha256_key(path))
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
        hash[0], hash[1], hash[2], hash[3],
        hash[4], hash[5], hash[6], hash[7],
    ])
}
