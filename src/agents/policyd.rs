//! ATOS policyd — Policy Engine
//!
//! System agent that manages eBPF-lite program loading and attachment.
//!
//! Protocol (mailbox message payload):
//!   ATTACH:       [op=0x01, attach_type: u8, attach_target: u16, priority: u8, prog_len: u16, bytecode: [u8]]
//!   DETACH:       [op=0x02, program_index: u16]
//!   LIST:         [op=0x03]
//!   ATTACH_CHUNK: [op=0x04, flags: u8, ...] (multi-message loading)
//!   REPLACE:      [op=0x05, program_index: u16, prog_len: u16, bytecode: [u8]]

use crate::serial_println;
use crate::agent::*;
use crate::ebpf;

const OP_ATTACH: u8 = 0x01;
const OP_DETACH: u8 = 0x02;
const OP_LIST: u8 = 0x03;
const OP_ATTACH_CHUNK: u8 = 0x04;
const OP_REPLACE: u8 = 0x05;

// Shared instruction buffer — avoids 8KB stack allocation per handler call.
// Safety: policyd is single-threaded; only one handler runs at a time.
static mut INSN_BUF: [ebpf::types::Insn; ebpf::types::MAX_INSNS] =
    [ebpf::types::Insn { opcode: 0, regs: 0, off: 0, imm: 0 }; ebpf::types::MAX_INSNS];

// Chunked loading state for programs larger than single mailbox message
static mut CHUNK_BUF: [u8; 8192] = [0u8; 8192]; // 1024 instructions * 8 bytes
static mut CHUNK_LEN: usize = 0;
static mut CHUNK_ATTACH_TYPE: u8 = 0;
static mut CHUNK_ATTACH_TARGET: u16 = 0;
static mut CHUNK_PRIORITY: u8 = 128;
static mut CHUNK_EXPECTED: usize = 0;

pub extern "C" fn policyd_entry() -> ! {
    serial_println!("[POLICYD] Policy engine started");

    let my_id: crate::agent::AgentId = 6;
    let my_mailbox: crate::agent::MailboxId = 6;

    loop {
        match crate::mailbox::recv_message(my_id, my_mailbox) {
            Ok(msg) => {
                let msg_len = msg.len as usize;
                if msg_len >= 1 {
                    let op = msg.payload[0];
                    match op {
                        OP_ATTACH => {
                            if !crate::capability::agent_has_cap(
                                msg.sender_id,
                                crate::capability::CapType::PolicyLoad,
                                0,
                            ) {
                                serial_println!(
                                    "[POLICYD] Agent {} denied OP_ATTACH: no CAP_POLICY_LOAD",
                                    msg.sender_id
                                );
                            } else {
                                handle_attach(&msg.payload, msg_len);
                            }
                        }
                        OP_DETACH => {
                            if !crate::capability::agent_has_cap(
                                msg.sender_id,
                                crate::capability::CapType::PolicyLoad,
                                0,
                            ) {
                                serial_println!(
                                    "[POLICYD] Agent {} denied OP_DETACH: no CAP_POLICY_LOAD",
                                    msg.sender_id
                                );
                            } else {
                                handle_detach(&msg.payload, msg_len);
                            }
                        }
                        OP_LIST => handle_list(),
                        OP_ATTACH_CHUNK => {
                            if !crate::capability::agent_has_cap(
                                msg.sender_id,
                                crate::capability::CapType::PolicyLoad,
                                0,
                            ) {
                                serial_println!("[POLICYD] Agent {} denied OP_ATTACH_CHUNK: no CAP_POLICY_LOAD", msg.sender_id);
                            } else {
                                handle_attach_chunk(&msg.payload, msg_len);
                            }
                        }
                        OP_REPLACE => {
                            if !crate::capability::agent_has_cap(
                                msg.sender_id,
                                crate::capability::CapType::PolicyLoad,
                                0,
                            ) {
                                serial_println!("[POLICYD] Agent {} denied OP_REPLACE: no CAP_POLICY_LOAD", msg.sender_id);
                            } else {
                                handle_replace(&msg.payload, msg_len);
                            }
                        }
                        _ => {
                            serial_println!("[POLICYD] Unknown opcode: {}", op);
                        }
                    }
                }
            }
            Err(_) => {} // no message available
        }

        // Yield to other agents
        crate::syscall::syscall(crate::agent::SYS_YIELD, 0, 0, 0, 0, 0);
    }
}

/// Handle OP_ATTACH in a separate function so the large insns array
/// is only on the stack when this function is actually called.
/// Format: [op=0x01, attach_type:u8, attach_target:u16, priority:u8, prog_len:u16, bytecode...]
#[inline(never)]
fn handle_attach(recv_buf: &[u8], msg_len: usize) {
    if msg_len < 7 { return; }

    let attach_type = recv_buf[1];
    let attach_target = u16::from_le_bytes([recv_buf[2], recv_buf[3]]);
    let priority = recv_buf[4];
    let prog_len = u16::from_le_bytes([recv_buf[5], recv_buf[6]]) as usize;
    let insn_count = prog_len / 8;

    if insn_count == 0 || insn_count > ebpf::types::MAX_INSNS {
        serial_println!("[POLICYD] Invalid program size");
        return;
    }

    // Safety: policyd is single-threaded; only one handler runs at a time.
    let insns = unsafe { &mut INSN_BUF };
    let bytecode_start = 7;
    let bytecode_end = (bytecode_start + prog_len).min(msg_len);

    for i in 0..insn_count {
        let base = bytecode_start + i * 8;
        if base + 8 > bytecode_end { break; }
        insns[i] = ebpf::types::Insn {
            opcode: recv_buf[base],
            regs: recv_buf[base + 1],
            off: i16::from_le_bytes([recv_buf[base + 2], recv_buf[base + 3]]),
            imm: i32::from_le_bytes([
                recv_buf[base + 4], recv_buf[base + 5],
                recv_buf[base + 6], recv_buf[base + 7],
            ]),
        };
    }

    let attach_point = match attach_type {
        0 => ebpf::attach::AttachPoint::SyscallEntry(attach_target as u64),
        1 => ebpf::attach::AttachPoint::SyscallExit(attach_target as u64),
        2 => ebpf::attach::AttachPoint::MailboxSend(attach_target),
        3 => ebpf::attach::AttachPoint::MailboxRecv(attach_target),
        4 => ebpf::attach::AttachPoint::AgentSpawn,
        5 => ebpf::attach::AttachPoint::TimerTick,
        _ => { serial_println!("[POLICYD] Invalid attach type"); return; }
    };

    match ebpf::attach::attach(&insns[..insn_count], attach_point, priority) {
        Ok(idx) => serial_println!("[POLICYD] Program attached: index={} priority={}", idx, priority),
        Err(_) => serial_println!("[POLICYD] Attach failed"),
    }
}

/// Handle OP_ATTACH_CHUNK for multi-message program loading.
/// First chunk: [op=0x04, flags, attach_type, attach_target:u16, priority, total_len:u16, bytecode...]
/// Continuation: [op=0x04, flags, bytecode...]
/// flags: bit 0 = first, bit 1 = last
#[inline(never)]
fn handle_attach_chunk(recv_buf: &[u8], msg_len: usize) {
    if msg_len < 2 { return; }

    let flags = recv_buf[1];
    let is_first = flags & 0x01 != 0;
    let is_last = flags & 0x02 != 0;

    unsafe {
        if is_first {
            // First chunk has header: [op, flags, attach_type, attach_target:u16, priority, total_len:u16, bytecode...]
            if msg_len < 9 { return; }
            CHUNK_ATTACH_TYPE = recv_buf[2];
            CHUNK_ATTACH_TARGET = u16::from_le_bytes([recv_buf[3], recv_buf[4]]);
            CHUNK_PRIORITY = recv_buf[5];
            CHUNK_EXPECTED = u16::from_le_bytes([recv_buf[6], recv_buf[7]]) as usize;
            CHUNK_LEN = 0;

            let data_start = 8;
            let data_len = msg_len - data_start;
            if CHUNK_LEN + data_len <= 8192 {
                CHUNK_BUF[CHUNK_LEN..CHUNK_LEN + data_len]
                    .copy_from_slice(&recv_buf[data_start..data_start + data_len]);
                CHUNK_LEN += data_len;
            }
        } else {
            // Continuation chunk: [op, flags, bytecode...]
            let data_start = 2;
            let data_len = msg_len - data_start;
            if CHUNK_LEN + data_len <= 8192 {
                CHUNK_BUF[CHUNK_LEN..CHUNK_LEN + data_len]
                    .copy_from_slice(&recv_buf[data_start..data_start + data_len]);
                CHUNK_LEN += data_len;
            }
        }

        if is_last {
            // Assemble and attach the program
            let insn_count = CHUNK_LEN / 8;
            if insn_count == 0 || insn_count > ebpf::types::MAX_INSNS {
                serial_println!("[POLICYD] Chunked program invalid size: {} instructions", insn_count);
                return;
            }

            // Safety: policyd is single-threaded; only one handler runs at a time.
    let insns = unsafe { &mut INSN_BUF };
            for i in 0..insn_count {
                let base = i * 8;
                insns[i] = ebpf::types::Insn {
                    opcode: CHUNK_BUF[base],
                    regs: CHUNK_BUF[base + 1],
                    off: i16::from_le_bytes([CHUNK_BUF[base + 2], CHUNK_BUF[base + 3]]),
                    imm: i32::from_le_bytes([
                        CHUNK_BUF[base + 4], CHUNK_BUF[base + 5],
                        CHUNK_BUF[base + 6], CHUNK_BUF[base + 7],
                    ]),
                };
            }

            let attach_point = match CHUNK_ATTACH_TYPE {
                0 => ebpf::attach::AttachPoint::SyscallEntry(CHUNK_ATTACH_TARGET as u64),
                1 => ebpf::attach::AttachPoint::SyscallExit(CHUNK_ATTACH_TARGET as u64),
                2 => ebpf::attach::AttachPoint::MailboxSend(CHUNK_ATTACH_TARGET),
                3 => ebpf::attach::AttachPoint::MailboxRecv(CHUNK_ATTACH_TARGET),
                4 => ebpf::attach::AttachPoint::AgentSpawn,
                5 => ebpf::attach::AttachPoint::TimerTick,
                _ => { serial_println!("[POLICYD] Invalid chunk attach type"); return; }
            };

            match ebpf::attach::attach(&insns[..insn_count], attach_point, CHUNK_PRIORITY) {
                Ok(idx) => serial_println!("[POLICYD] Chunked program attached: index={}", idx),
                Err(_) => serial_println!("[POLICYD] Chunked attach failed"),
            }
        }
    }
}

/// Handle OP_REPLACE: hot-replace bytecode of an existing program.
/// Format: [op=0x05, program_index:u16, prog_len:u16, bytecode...]
#[inline(never)]
fn handle_replace(recv_buf: &[u8], msg_len: usize) {
    if msg_len < 5 { return; }

    let index = u16::from_le_bytes([recv_buf[1], recv_buf[2]]) as usize;
    let prog_len = u16::from_le_bytes([recv_buf[3], recv_buf[4]]) as usize;
    let insn_count = prog_len / 8;

    if insn_count == 0 || insn_count > ebpf::types::MAX_INSNS {
        serial_println!("[POLICYD] Replace: invalid program size");
        return;
    }

    // Safety: policyd is single-threaded; only one handler runs at a time.
    let insns = unsafe { &mut INSN_BUF };
    let bytecode_start = 5;
    let bytecode_end = (bytecode_start + prog_len).min(msg_len);

    for i in 0..insn_count {
        let base = bytecode_start + i * 8;
        if base + 8 > bytecode_end { break; }
        insns[i] = ebpf::types::Insn {
            opcode: recv_buf[base],
            regs: recv_buf[base + 1],
            off: i16::from_le_bytes([recv_buf[base + 2], recv_buf[base + 3]]),
            imm: i32::from_le_bytes([
                recv_buf[base + 4], recv_buf[base + 5],
                recv_buf[base + 6], recv_buf[base + 7],
            ]),
        };
    }

    match ebpf::attach::replace(index, &insns[..insn_count]) {
        Ok(()) => serial_println!("[POLICYD] Program replaced: index={}", index),
        Err(_) => serial_println!("[POLICYD] Replace failed"),
    }
}

/// Handle OP_DETACH
#[inline(never)]
fn handle_detach(recv_buf: &[u8], msg_len: usize) {
    if msg_len >= 3 {
        let index = u16::from_le_bytes([recv_buf[1], recv_buf[2]]) as usize;
        ebpf::attach::detach(index);
        serial_println!("[POLICYD] Program detached: index={}", index);
    }
}

fn handle_list() {
    serial_println!("[POLICYD] Attached programs:");
    let count = crate::ebpf::attach::for_each_attached(|slot, point, len| {
        serial_println!("[POLICYD]   slot={} point={:?} len={}", slot, point, len);
    });
    serial_println!("[POLICYD] Total: {} programs", count);
}
