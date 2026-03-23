//! AOS skilld — Skill Module Manager
//!
//! System agent that manages skill module installation. Agents send
//! WASM bytecode + manifest to skilld, which validates, spawns a
//! child agent, and returns the skill's mailbox ID.
//!
//! Protocol:
//!   INSTALL: [op=0x01, name_len: u8, name: [u8], wasm_len: u16, wasm_bytes: [u8]]
//!   UNINSTALL: [op=0x02, skill_mailbox: u16]
//!   LIST: [op=0x03]

use crate::serial_println;
use crate::agent::*;
use crate::syscall;

const OP_INSTALL: u8 = 0x01;
const OP_UNINSTALL: u8 = 0x02;
const OP_LIST: u8 = 0x03;

/// Installed skill registry entry
#[derive(Clone, Copy)]
struct SkillEntry {
    name: [u8; 32],
    name_len: usize,
    agent_id: AgentId,
    mailbox_id: u16,
    parent_id: AgentId,
    active: bool,
}

const MAX_SKILLS: usize = 16;
static mut SKILL_REGISTRY: [Option<SkillEntry>; MAX_SKILLS] = [const { None }; MAX_SKILLS];
static mut SKILL_COUNT: usize = 0;

pub extern "C" fn skilld_entry() -> ! {
    serial_println!("[SKILLD] Skill module manager started");

    let my_mailbox: u64 = 11; // skilld's mailbox
    let mut recv_buf = [0u8; MAX_MESSAGE_PAYLOAD];

    loop {
        let len = syscall::syscall(
            SYS_RECV,
            my_mailbox,
            recv_buf.as_mut_ptr() as u64,
            recv_buf.len() as u64,
            0, 0,
        );

        if len > 0 {
            let msg_len = len as usize;
            if msg_len >= 1 {
                match recv_buf[0] {
                    OP_INSTALL => handle_install(&recv_buf, msg_len),
                    OP_UNINSTALL => handle_uninstall(&recv_buf, msg_len),
                    OP_LIST => handle_list(),
                    _ => serial_println!("[SKILLD] Unknown op: {:#x}", recv_buf[0]),
                }
            }
        }

        syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0);
    }
}

fn handle_install(recv_buf: &[u8], msg_len: usize) {
    if msg_len < 4 { return; }

    let name_len = recv_buf[1] as usize;
    if msg_len < 2 + name_len + 2 { return; }

    let mut name = [0u8; 32];
    let copy_len = name_len.min(32);
    name[..copy_len].copy_from_slice(&recv_buf[2..2 + copy_len]);

    let wasm_len = u16::from_le_bytes([
        recv_buf[2 + name_len],
        recv_buf[3 + name_len],
    ]) as usize;

    let wasm_start = 4 + name_len;
    if msg_len < wasm_start + wasm_len {
        serial_println!("[SKILLD] Install failed: payload too short");
        return;
    }

    let name_str = core::str::from_utf8(&name[..copy_len]).unwrap_or("<invalid>");
    serial_println!("[SKILLD] Install request: name='{}' wasm_size={} bytes", name_str, wasm_len);

    // Validate WASM module
    let wasm_bytes = &recv_buf[wasm_start..wasm_start + wasm_len];
    match crate::wasm::decoder::decode(wasm_bytes) {
        Ok(module) => {
            serial_println!("[SKILLD] WASM module validated: {} functions, {} exports",
                module.functions.len(), module.exports.len());

            // Register the skill
            unsafe {
                if SKILL_COUNT < MAX_SKILLS {
                    SKILL_REGISTRY[SKILL_COUNT] = Some(SkillEntry {
                        name,
                        name_len: copy_len,
                        agent_id: 0, // would be set after sys_spawn
                        mailbox_id: 0,
                        parent_id: crate::sched::current(),
                        active: true,
                    });
                    SKILL_COUNT += 1;
                    serial_println!("[SKILLD] Skill '{}' registered (index {})", name_str, SKILL_COUNT - 1);
                } else {
                    serial_println!("[SKILLD] Skill registry full");
                }
            }
        }
        Err(e) => {
            serial_println!("[SKILLD] WASM validation failed: {:?}", e);
        }
    }
}

fn handle_uninstall(recv_buf: &[u8], msg_len: usize) {
    if msg_len < 3 { return; }
    let skill_idx = u16::from_le_bytes([recv_buf[1], recv_buf[2]]) as usize;

    unsafe {
        if skill_idx < MAX_SKILLS {
            if let Some(ref mut entry) = SKILL_REGISTRY[skill_idx] {
                entry.active = false;
                let name_str = core::str::from_utf8(&entry.name[..entry.name_len]).unwrap_or("?");
                serial_println!("[SKILLD] Skill '{}' uninstalled", name_str);
            }
        }
    }
}

fn handle_list() {
    serial_println!("[SKILLD] === Installed Skills ===");
    unsafe {
        for i in 0..SKILL_COUNT {
            if let Some(ref entry) = SKILL_REGISTRY[i] {
                let name = core::str::from_utf8(&entry.name[..entry.name_len]).unwrap_or("?");
                serial_println!("[SKILLD]   [{}] '{}' active={} parent={}",
                    i, name, entry.active, entry.parent_id);
            }
        }
    }
    serial_println!("[SKILLD] === End ===");
}
