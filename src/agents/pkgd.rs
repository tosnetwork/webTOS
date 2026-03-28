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

fn handle_install(recv_buf: &[u8], msg_len: usize) {
    // Minimum: op(1) + name_len(1) + name(1..) + version(6)
    if msg_len < 10 {
        serial_println!("[PKGD] Install failed: message too short");
        return;
    }

    let name_len = recv_buf[1] as usize;
    if name_len == 0 || name_len > 64 {
        serial_println!("[PKGD] Install failed: invalid name length {}", name_len);
        return;
    }
    if msg_len < 2 + name_len + 6 {
        serial_println!("[PKGD] Install failed: payload too short for name + version");
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
        "[PKGD] Install request: '{}' v{}.{}.{}",
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
            serial_println!("[PKGD] Package '{}' installed at index {}", name_str, idx);
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
    // Upgrade protocol: checkpoint old -> install new -> migrate state -> verify
    if msg_len < 3 {
        return;
    }
    let pkg_idx = u16::from_le_bytes([recv_buf[1], recv_buf[2]]) as usize;

    if let Some(old) = package::get_package(pkg_idx) {
        serial_println!(
            "[PKGD] Upgrade requested for '{}' v{}.{}.{}",
            old.name_str(),
            old.version_major,
            old.version_minor,
            old.version_patch,
        );
        // TODO: checkpoint old agent state via SYS_CHECKPOINT
        // TODO: parse new .tos from remaining message bytes
        // TODO: install new version, migrate state, verify
        serial_println!("[PKGD] Upgrade: checkpoint + migration not yet implemented");
    } else {
        serial_println!("[PKGD] Upgrade failed: no package at index {}", pkg_idx);
    }
}
