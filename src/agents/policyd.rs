//! AOS policyd — Policy Engine
//!
//! System agent that manages eBPF-lite program loading and attachment.
//!
//! Protocol (mailbox message payload):
//!   ATTACH: [op=0x01, attach_type: u8, attach_target: u16, prog_len: u16, bytecode: [u8]]
//!   DETACH: [op=0x02, program_index: u16]
//!   LIST:   [op=0x03]

use crate::serial_println;
use crate::agent::*;
use crate::syscall;
use crate::ebpf;

const OP_ATTACH: u8 = 0x01;
const OP_DETACH: u8 = 0x02;
const OP_LIST: u8 = 0x03;

pub extern "C" fn policyd_entry() -> ! {
    serial_println!("[POLICYD] Policy engine started");

    let my_mailbox: u64 = 6; // policyd's mailbox ID (agent ID = 6)
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

            if msg_len < 1 {
                syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0);
                continue;
            }

            let op = recv_buf[0];

            match op {
                OP_ATTACH => {
                    // Parse: [op(1), attach_type(1), attach_target(2), prog_len(2), bytecode(N)]
                    if msg_len >= 6 {
                        let attach_type = recv_buf[1];
                        let attach_target = u16::from_le_bytes([recv_buf[2], recv_buf[3]]);
                        let prog_len = u16::from_le_bytes([recv_buf[4], recv_buf[5]]) as usize;

                        // Each eBPF instruction is 8 bytes
                        let insn_count = prog_len / 8;
                        if insn_count == 0 || insn_count > ebpf::types::MAX_INSNS {
                            serial_println!("[POLICYD] Invalid program size: {} instructions", insn_count);
                            syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0);
                            continue;
                        }

                        // Parse bytecode into instructions
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

                        // Determine attachment point
                        let attach_point = match attach_type {
                            0 => ebpf::attach::AttachPoint::SyscallEntry(attach_target as u64),
                            1 => ebpf::attach::AttachPoint::SyscallExit(attach_target as u64),
                            2 => ebpf::attach::AttachPoint::MailboxSend(attach_target),
                            3 => ebpf::attach::AttachPoint::MailboxRecv(attach_target),
                            4 => ebpf::attach::AttachPoint::AgentSpawn,
                            5 => ebpf::attach::AttachPoint::TimerTick,
                            _ => {
                                serial_println!("[POLICYD] Invalid attach type: {}", attach_type);
                                syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0);
                                continue;
                            }
                        };

                        // Attach the program (verify + load)
                        match ebpf::attach::attach(&insns[..insn_count], attach_point) {
                            Ok(idx) => {
                                serial_println!("[POLICYD] Program attached: index={}", idx);
                            }
                            Err(_e) => {
                                serial_println!("[POLICYD] Attach failed");
                            }
                        }
                    }
                }

                OP_DETACH => {
                    if msg_len >= 3 {
                        let index = u16::from_le_bytes([recv_buf[1], recv_buf[2]]) as usize;
                        ebpf::attach::detach(index);
                        serial_println!("[POLICYD] Program detached: index={}", index);
                    }
                }

                OP_LIST => {
                    serial_println!("[POLICYD] Listing attached programs (not yet implemented)");
                }

                _ => {
                    serial_println!("[POLICYD] Unknown op: {:#x}", op);
                }
            }
        }

        syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0);
    }
}
