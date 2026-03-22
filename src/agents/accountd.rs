//! AOS accountd — Energy Accounting Reporter
//!
//! System agent that exposes per-agent cumulative energy consumption.
//! External systems query accountd via mailbox for billing data.
//!
//! Protocol:
//!   Request:  [op=0x01, agent_id: u16] -> query consumption for agent
//!   Response: [status: u8, energy_consumed: u64]

use crate::serial_println;
use crate::agent::*;
use crate::syscall;

const OP_QUERY: u8 = 0x01;
const OP_QUERY_ALL: u8 = 0x02;

pub extern "C" fn accountd_entry() -> ! {
    serial_println!("[ACCOUNTD] Energy accounting reporter started");

    let my_mailbox: u64 = 8; // accountd's mailbox (agent 8)
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
                    OP_QUERY => {
                        if msg_len >= 3 {
                            let target_id = u16::from_le_bytes([recv_buf[1], recv_buf[2]]);
                            let consumed = crate::cost::get_cumulative(target_id);
                            serial_println!("[ACCOUNTD] Agent {} consumed {} energy", target_id, consumed);
                        }
                    }
                    OP_QUERY_ALL => {
                        serial_println!("[ACCOUNTD] === Energy Report ===");
                        for id in 0..MAX_AGENTS as AgentId {
                            let consumed = crate::cost::get_cumulative(id);
                            if consumed > 0 {
                                serial_println!("[ACCOUNTD] Agent {}: {} energy consumed", id, consumed);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0);
    }
}
