//! ATOS policyd — Policy Engine
//!
//! System agent that manages eBPF-lite program loading and attachment.
//!
//! Protocol (mailbox message payload):
//!   ATTACH: [op=0x01, attach_type: u8, attach_target: u16, prog_len: u16, bytecode: [u8]]
//!   DETACH: [op=0x02, program_index: u16]
//!   LIST:   [op=0x03]

use crate::serial_println;
use crate::agent::*;
use crate::ebpf;

const OP_ATTACH: u8 = 0x01;
const OP_DETACH: u8 = 0x02;
const OP_LIST: u8 = 0x03;

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
#[inline(never)]
fn handle_attach(recv_buf: &[u8], msg_len: usize) {
    if msg_len < 6 { return; }

    let attach_type = recv_buf[1];
    let attach_target = u16::from_le_bytes([recv_buf[2], recv_buf[3]]);
    let prog_len = u16::from_le_bytes([recv_buf[4], recv_buf[5]]) as usize;
    let insn_count = prog_len / 8;

    if insn_count == 0 || insn_count > ebpf::types::MAX_INSNS {
        serial_println!("[POLICYD] Invalid program size");
        return;
    }

    let mut insns = [ebpf::types::Insn { opcode: 0, regs: 0, off: 0, imm: 0 }; ebpf::types::MAX_INSNS];
    let bytecode_start = 6;
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

    match ebpf::attach::attach(&insns[..insn_count], attach_point) {
        Ok(idx) => serial_println!("[POLICYD] Program attached: index={}", idx),
        Err(_) => serial_println!("[POLICYD] Attach failed"),
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
