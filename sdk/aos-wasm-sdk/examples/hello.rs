//! Example AOS WASM agent — sends a hello message then yields forever

#![no_std]
#![no_main]

use aos_wasm_sdk::*;

#[no_mangle]
pub extern "C" fn run() {
    log_str("Hello from WASM agent!");

    // Send a message to mailbox 3
    let msg = b"hello from wasm";
    let result = send(3, msg);
    if result == 0 {
        log_str("Message sent successfully");
    }

    // Check energy
    let _fuel = energy_remaining();
    // Note: can't easily format in no_std without alloc

    // Yield forever
    loop {
        aos_yield();
    }
}
