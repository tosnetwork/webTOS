//! ATOS pkgd — Package Manager Agent
//!
//! System agent that manages the package lifecycle: install, uninstall,
//! list, and upgrade `.tos` packages. Sits above skilld in the system
//! architecture — pkgd handles versioning, signing, and upgrade
//! orchestration while skilld handles WASM validation and agent spawning.
//!
//! Protocol (mailbox messages):
//!   INSTALL   (0x01): validate manifest, check capabilities, install to registry
//!   UNINSTALL (0x02): remove package from registry
//!   LIST      (0x03): return installed packages
//!   UPGRADE   (0x04): checkpoint -> install new -> migrate state -> verify

use crate::serial_println;
use crate::agent::*;
use crate::syscall;
use crate::package;

const OP_INSTALL: u8 = 0x01;
const OP_UNINSTALL: u8 = 0x02;
const OP_LIST: u8 = 0x03;
const OP_UPGRADE: u8 = 0x04;

/// pkgd entry point. Runs as a kernel-mode system agent.
pub extern "C" fn pkgd_entry() -> ! {
    serial_println!("[PKGD] Package manager started");

    let my_mailbox: u64 = 13; // pkgd's mailbox (agent slot 13)
    let mut recv_buf = [0u8; MAX_MESSAGE_PAYLOAD];

    loop {
        let len = syscall::syscall(
            SYS_RECV,
            my_mailbox,
            recv_buf.as_mut_ptr() as u64,
            recv_buf.len() as u64,
            0,
            0,
        );

        if len > 0 {
            let msg_len = len as usize;
            if msg_len >= 1 {
                match recv_buf[0] {
                    OP_INSTALL => handle_install(&recv_buf, msg_len),
                    OP_UNINSTALL => handle_uninstall(&recv_buf, msg_len),
                    OP_LIST => handle_list(),
                    OP_UPGRADE => handle_upgrade(&recv_buf, msg_len),
                    _ => serial_println!("[PKGD] Unknown op: {:#x}", recv_buf[0]),
                }
            }
        }

        syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0);
    }
}

/// Parse install manifest fields from a mailbox message.
///
/// A full `.tos` package (manifest alone is 280 bytes) does not fit
/// in a 256-byte mailbox message.  Instead, the sender serialises the
/// critical manifest fields individually:
///
///   Wire format (all integers little-endian):
///     [0]       op          (0x01, already consumed by caller)
///     [1]       name_len    (1 byte, 1..=64)
///     [2 .. 2+name_len)     name bytes
///     --- offset = 2 + name_len ---
///     +0..+2    version_major   (u16)
///     +2..+4    version_minor   (u16)
///     +4..+6    version_patch   (u16)
///     +6..+10   required_capabilities (u32)
///     +10..+18  min_energy      (u64)
///     +18..+22  max_memory_pages (u32)
///     +22..+54  code_hash       (32 bytes)
///     +54..+118 signature       (64 bytes)
///
///   Total fixed part after name: 118 bytes.
///   Minimum message size: 1 + 1 + 1 + 118 = 121 bytes (name_len=1).
///   Maximum (name_len=64): 1 + 1 + 64 + 118 = 184 bytes — fits in 256.
///
///   Fields omitted (not security-critical for install):
///     author/author_len — defaults to empty
///     manifest_hash     — can be computed post-install
const INSTALL_FIXED_TAIL: usize = 6 + 4 + 8 + 4 + 32 + 64; // 118 bytes

fn handle_install(recv_buf: &[u8], msg_len: usize) {
    // Minimum: op(1) + name_len(1) + name(>=1) + fixed_tail(118)
    if msg_len < 3 + INSTALL_FIXED_TAIL {
        serial_println!("[PKGD] Install failed: message too short ({} bytes)", msg_len);
        return;
    }

    let name_len = recv_buf[1] as usize;
    if name_len == 0 || name_len > 64 {
        serial_println!("[PKGD] Install failed: invalid name length {}", name_len);
        return;
    }

    let required = 2 + name_len + INSTALL_FIXED_TAIL;
    if msg_len < required {
        // Fall back: sender may have used the old short format (name + version only).
        serial_println!(
            "[PKGD] WARN: message too short for full manifest ({} < {}), \
             falling back to name+version only (code_hash/sig zeroed)",
            msg_len, required
        );
        handle_install_legacy(recv_buf, msg_len);
        return;
    }

    // --- name ---
    let mut name = [0u8; 64];
    let copy_len = name_len.min(64);
    name[..copy_len].copy_from_slice(&recv_buf[2..2 + copy_len]);

    // --- fixed fields ---
    let mut off = 2 + name_len;

    let version_major = u16::from_le_bytes([recv_buf[off], recv_buf[off + 1]]);
    off += 2;
    let version_minor = u16::from_le_bytes([recv_buf[off], recv_buf[off + 1]]);
    off += 2;
    let version_patch = u16::from_le_bytes([recv_buf[off], recv_buf[off + 1]]);
    off += 2;

    let required_capabilities =
        u32::from_le_bytes([recv_buf[off], recv_buf[off + 1], recv_buf[off + 2], recv_buf[off + 3]]);
    off += 4;

    let min_energy = u64::from_le_bytes([
        recv_buf[off],
        recv_buf[off + 1],
        recv_buf[off + 2],
        recv_buf[off + 3],
        recv_buf[off + 4],
        recv_buf[off + 5],
        recv_buf[off + 6],
        recv_buf[off + 7],
    ]);
    off += 8;

    let max_memory_pages =
        u32::from_le_bytes([recv_buf[off], recv_buf[off + 1], recv_buf[off + 2], recv_buf[off + 3]]);
    off += 4;

    let mut code_hash = [0u8; 32];
    code_hash.copy_from_slice(&recv_buf[off..off + 32]);
    off += 32;

    let mut signature = [0u8; 64];
    signature.copy_from_slice(&recv_buf[off..off + 64]);

    let name_str = core::str::from_utf8(&name[..copy_len]).unwrap_or("<invalid>");
    serial_println!(
        "[PKGD] Install request: '{}' v{}.{}.{} caps={:#x} energy={} mem={}p hash={:02x}{:02x}..{:02x}{:02x}",
        name_str,
        version_major,
        version_minor,
        version_patch,
        required_capabilities,
        min_energy,
        max_memory_pages,
        code_hash[0], code_hash[1], code_hash[30], code_hash[31],
    );

    let manifest = package::PackageManifest {
        name,
        name_len: copy_len as u8,
        version_major,
        version_minor,
        version_patch,
        author: [0u8; 64],
        author_len: 0,
        required_capabilities,
        min_energy,
        max_memory_pages,
        code_hash,
        manifest_hash: [0u8; 32], // not transmitted; can be computed later
        signature,
    };

    match package::install_package(manifest) {
        Some(idx) => {
            serial_println!("[PKGD] Package '{}' installed at index {}", name_str, idx);
        }
        None => {
            serial_println!("[PKGD] Package registry full, install failed");
        }
    }
}

/// Legacy fallback: only name + version are present in the message.
/// All security-relevant fields (code_hash, signature, capabilities)
/// are zeroed — this path logs a warning so callers are aware.
fn handle_install_legacy(recv_buf: &[u8], msg_len: usize) {
    if msg_len < 10 {
        serial_println!("[PKGD] Install (legacy) failed: message too short");
        return;
    }

    let name_len = recv_buf[1] as usize;
    if name_len == 0 || name_len > 64 {
        serial_println!("[PKGD] Install (legacy) failed: invalid name length {}", name_len);
        return;
    }
    if msg_len < 2 + name_len + 6 {
        serial_println!("[PKGD] Install (legacy) failed: payload too short for name + version");
        return;
    }

    let mut name = [0u8; 64];
    let copy_len = name_len.min(64);
    name[..copy_len].copy_from_slice(&recv_buf[2..2 + copy_len]);

    let ver_off = 2 + name_len;
    let version_major = u16::from_le_bytes([recv_buf[ver_off], recv_buf[ver_off + 1]]);
    let version_minor = u16::from_le_bytes([recv_buf[ver_off + 2], recv_buf[ver_off + 3]]);
    let version_patch = u16::from_le_bytes([recv_buf[ver_off + 4], recv_buf[ver_off + 5]]);

    let name_str = core::str::from_utf8(&name[..copy_len]).unwrap_or("<invalid>");
    serial_println!(
        "[PKGD] Install (legacy): '{}' v{}.{}.{} — code_hash/sig ZEROED",
        name_str, version_major, version_minor, version_patch
    );

    let manifest = package::PackageManifest {
        name,
        name_len: copy_len as u8,
        version_major,
        version_minor,
        version_patch,
        author: [0u8; 64],
        author_len: 0,
        required_capabilities: 0,
        min_energy: 0,
        max_memory_pages: 64,
        code_hash: [0u8; 32],
        manifest_hash: [0u8; 32],
        signature: [0u8; 64],
    };

    match package::install_package(manifest) {
        Some(idx) => {
            serial_println!("[PKGD] Package '{}' installed at index {} (legacy)", name_str, idx);
        }
        None => {
            serial_println!("[PKGD] Package registry full, install failed");
        }
    }
}

fn handle_uninstall(recv_buf: &[u8], msg_len: usize) {
    if msg_len < 3 {
        return;
    }
    let pkg_idx = u16::from_le_bytes([recv_buf[1], recv_buf[2]]) as usize;

    if package::uninstall_package(pkg_idx) {
        serial_println!("[PKGD] Package at index {} uninstalled", pkg_idx);
    } else {
        serial_println!("[PKGD] Uninstall failed: no package at index {}", pkg_idx);
    }
}

fn handle_list() {
    serial_println!("[PKGD] === Installed Packages ===");
    let count = package::package_count();
    for i in 0..count {
        if let Some(manifest) = package::get_package(i) {
            serial_println!(
                "[PKGD]   [{}] '{}' v{}.{}.{} caps={:#x}",
                i,
                manifest.name_str(),
                manifest.version_major,
                manifest.version_minor,
                manifest.version_patch,
                manifest.required_capabilities,
            );
        }
    }
    serial_println!("[PKGD] === End ({} packages) ===", count);
}

fn handle_upgrade(recv_buf: &[u8], msg_len: usize) {
    // Upgrade wire format:
    //   [0]       op (0x04)
    //   [1..3]    package index to upgrade (u16 LE)
    //   [3+]      manifest fields (same as install: name_len, name, version, caps, energy, memory, code_hash, signature)

    // Minimum: op(1) + pkg_idx(2) + name_len(1) + name(>=1) + fixed_tail(118)
    if msg_len < 3 + 2 + INSTALL_FIXED_TAIL {
        serial_println!("[PKGD] Upgrade failed: message too short ({} bytes)", msg_len);
        return;
    }

    let pkg_idx = u16::from_le_bytes([recv_buf[1], recv_buf[2]]) as usize;

    // Step 1: Retrieve the old package to verify it exists
    let (old_name_str_buf, old_name_len, old_major, old_minor, old_patch) = match package::get_package(pkg_idx) {
        Some(old) => {
            // Copy old version info before we modify the registry
            let mut buf = [0u8; 64];
            let len = old.name_len as usize;
            buf[..len].copy_from_slice(&old.name[..len]);
            (buf, len, old.version_major, old.version_minor, old.version_patch)
        }
        None => {
            serial_println!("[PKGD] Upgrade failed: no package at index {}", pkg_idx);
            return;
        }
    };

    // Step 2: Checkpoint current state before modifying the registry
    if !crate::checkpoint::save_to_disk() {
        serial_println!("[PKGD] Upgrade warning: checkpoint failed (no disk?), proceeding anyway");
    }

    // Step 3: Parse new manifest fields from bytes starting at offset 3
    let name_len = recv_buf[3] as usize;
    if name_len == 0 || name_len > 64 {
        serial_println!("[PKGD] Upgrade failed: invalid name length {}", name_len);
        return;
    }

    let required = 4 + name_len + INSTALL_FIXED_TAIL;
    if msg_len < required {
        serial_println!(
            "[PKGD] Upgrade failed: message too short for full manifest ({} < {})",
            msg_len, required
        );
        return;
    }

    let mut name = [0u8; 64];
    let copy_len = name_len.min(64);
    name[..copy_len].copy_from_slice(&recv_buf[4..4 + copy_len]);

    let mut off = 4 + name_len;

    let version_major = u16::from_le_bytes([recv_buf[off], recv_buf[off + 1]]);
    off += 2;
    let version_minor = u16::from_le_bytes([recv_buf[off], recv_buf[off + 1]]);
    off += 2;
    let version_patch = u16::from_le_bytes([recv_buf[off], recv_buf[off + 1]]);
    off += 2;

    let required_capabilities =
        u32::from_le_bytes([recv_buf[off], recv_buf[off + 1], recv_buf[off + 2], recv_buf[off + 3]]);
    off += 4;

    let min_energy = u64::from_le_bytes([
        recv_buf[off],
        recv_buf[off + 1],
        recv_buf[off + 2],
        recv_buf[off + 3],
        recv_buf[off + 4],
        recv_buf[off + 5],
        recv_buf[off + 6],
        recv_buf[off + 7],
    ]);
    off += 8;

    let max_memory_pages =
        u32::from_le_bytes([recv_buf[off], recv_buf[off + 1], recv_buf[off + 2], recv_buf[off + 3]]);
    off += 4;

    let mut code_hash = [0u8; 32];
    code_hash.copy_from_slice(&recv_buf[off..off + 32]);
    off += 32;

    let mut signature = [0u8; 64];
    signature.copy_from_slice(&recv_buf[off..off + 64]);

    let new_manifest = package::PackageManifest {
        name,
        name_len: copy_len as u8,
        version_major,
        version_minor,
        version_patch,
        author: [0u8; 64],
        author_len: 0,
        required_capabilities,
        min_energy,
        max_memory_pages,
        code_hash,
        manifest_hash: [0u8; 32],
        signature,
    };

    let new_name_str = core::str::from_utf8(&name[..copy_len]).unwrap_or("<invalid>");

    // Step 4: Uninstall the old package and install the new manifest
    if !package::uninstall_package(pkg_idx) {
        serial_println!("[PKGD] Upgrade failed: could not remove old package at index {}", pkg_idx);
        return;
    }

    match package::install_package(new_manifest) {
        Some(new_idx) => {
            // Step 5: Log the upgrade (old version -> new version)
            let old_name_str = core::str::from_utf8(
                &old_name_str_buf[..old_name_len]
            ).unwrap_or("<invalid>");
            serial_println!(
                "[PKGD] Upgrade complete: '{}' v{}.{}.{} -> '{}' v{}.{}.{} (old idx={}, new idx={})",
                old_name_str, old_major, old_minor, old_patch,
                new_name_str, version_major, version_minor, version_patch,
                pkg_idx, new_idx,
            );
        }
        None => {
            // Step 6: Log failure — registry full after removing old entry
            serial_println!(
                "[PKGD] Upgrade failed: package registry full, could not install new version of '{}'",
                new_name_str
            );
        }
    }
}
