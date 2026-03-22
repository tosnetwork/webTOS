//! AOS stated — State Persistence Manager
//!
//! System agent that manages durable key-value state for shared keyspaces.
//! Agents send state requests via mailbox; stated handles persistence.
//!
//! Protocol (mailbox message payload):
//!   Request: [op: u8, keyspace_id: u16, key: u64, len: u16, value: [u8]]
//!   Response: [status: i8, len: u16, value: [u8]]
//!
//! Operations:
//!   0x01 = GET (keyspace, key) -> value
//!   0x02 = PUT (keyspace, key, value) -> status
//!   0x03 = CREATE_KEYSPACE (keyspace) -> status

use crate::serial_println;
use crate::agent::*;
use crate::syscall;

const OP_GET: u8 = 0x01;
const OP_PUT: u8 = 0x02;
const OP_CREATE: u8 = 0x03;

pub extern "C" fn stated_entry() -> ! {
    serial_println!("[STATED] State persistence manager started");

    let my_mailbox: u64 = 5; // stated's mailbox ID (agent ID = 5)
    let mut recv_buf = [0u8; MAX_MESSAGE_PAYLOAD];
    let mut resp_buf = [0u8; MAX_MESSAGE_PAYLOAD];

    loop {
        // Receive a request
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
                OP_GET => {
                    // Parse: [op(1), keyspace_id(2), key(8)] = 11 bytes minimum
                    if msg_len >= 11 {
                        let keyspace_id = u16::from_le_bytes([recv_buf[1], recv_buf[2]]);
                        let key = u64::from_le_bytes([
                            recv_buf[3], recv_buf[4], recv_buf[5], recv_buf[6],
                            recv_buf[7], recv_buf[8], recv_buf[9], recv_buf[10],
                        ]);

                        // Use persist module for direct disk-backed state access
                        let result = crate::persist::get(keyspace_id, key);

                        match result {
                            Some(data) => {
                                resp_buf[0] = 0; // success
                                let copy_len = data.len().min(MAX_MESSAGE_PAYLOAD - 3);
                                resp_buf[1] = (copy_len & 0xFF) as u8;
                                resp_buf[2] = ((copy_len >> 8) & 0xFF) as u8;
                                resp_buf[3..3 + copy_len].copy_from_slice(&data[..copy_len]);
                                serial_println!("[STATED] GET keyspace={} key={} -> {} bytes",
                                    keyspace_id, key, copy_len);
                            }
                            None => {
                                resp_buf[0] = 0xFF; // not found
                                resp_buf[1] = 0;
                                resp_buf[2] = 0;
                                serial_println!("[STATED] GET keyspace={} key={} -> not found",
                                    keyspace_id, key);
                            }
                        }
                    }
                }

                OP_PUT => {
                    // Parse: [op(1), keyspace_id(2), key(8), len(2), value(N)]
                    if msg_len >= 13 {
                        let keyspace_id = u16::from_le_bytes([recv_buf[1], recv_buf[2]]);
                        let key = u64::from_le_bytes([
                            recv_buf[3], recv_buf[4], recv_buf[5], recv_buf[6],
                            recv_buf[7], recv_buf[8], recv_buf[9], recv_buf[10],
                        ]);
                        let value_len = u16::from_le_bytes([recv_buf[11], recv_buf[12]]) as usize;
                        let value_len = value_len.min(msg_len - 13);

                        let value = &recv_buf[13..13 + value_len];
                        let result = crate::persist::put(keyspace_id, key, value);

                        resp_buf[0] = if result.is_ok() { 0 } else { 0xFF };
                        serial_println!("[STATED] PUT keyspace={} key={} len={} -> ok={}",
                            keyspace_id, key, value_len, result.is_ok());
                    }
                }

                OP_CREATE => {
                    if msg_len >= 3 {
                        let keyspace_id = u16::from_le_bytes([recv_buf[1], recv_buf[2]]);
                        let result = crate::persist::create_keyspace(keyspace_id);
                        resp_buf[0] = if result.is_ok() { 0 } else { 0xFF };
                        serial_println!("[STATED] CREATE keyspace={} -> ok={}",
                            keyspace_id, result.is_ok());
                    }
                }

                _ => {
                    serial_println!("[STATED] Unknown op: {:#x}", op);
                    resp_buf[0] = 0xFE; // unknown op
                }
            }
        }

        // Yield to let other agents run
        syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0);
    }
}
