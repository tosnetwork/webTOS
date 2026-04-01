//! tos deploy — send a WASM agent to a running TOS instance via serial
//!
//! Usage:
//!   tos deploy <agent.wasm> [serial_device]
//!
//! Reads the WASM binary and displays deployment information.
//! Full serial protocol deployment requires the TOS kernel to support
//! dynamic WASM loading (future enhancement).

use std::fs;

pub fn run(args: &[String]) {
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        println!("Usage: tos deploy <agent.wasm> [serial_device]");
        println!();
        println!("Deploy a WASM agent to a running TOS instance.");
        println!("The WASM binary is validated and its metadata displayed.");
        return;
    }

    let wasm_path = &args[0];
    let serial = args.get(1).map(|s| s.as_str()).unwrap_or("/dev/ttyS0");

    // Read and validate WASM binary
    let wasm_bytes = match fs::read(wasm_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[tos-deploy] Failed to read {}: {}", wasm_path, e);
            std::process::exit(1);
        }
    };

    // Validate WASM magic
    if wasm_bytes.len() < 8 || &wasm_bytes[0..4] != b"\0asm" {
        eprintln!("[tos-deploy] Invalid WASM binary (bad magic)");
        std::process::exit(1);
    }

    let version = u32::from_le_bytes([wasm_bytes[4], wasm_bytes[5], wasm_bytes[6], wasm_bytes[7]]);

    println!("[tos-deploy] WASM binary: {}", wasm_path);
    println!("[tos-deploy] Size: {} bytes", wasm_bytes.len());
    println!("[tos-deploy] WASM version: {}", version);
    println!("[tos-deploy] Target serial: {}", serial);

    // Count sections
    let mut offset = 8;
    let mut section_count = 0;
    while offset < wasm_bytes.len() {
        if offset + 1 > wasm_bytes.len() { break; }
        let _section_id = wasm_bytes[offset];
        offset += 1;
        // Read LEB128 section size
        let (size, bytes_read) = read_leb128(&wasm_bytes[offset..]);
        offset += bytes_read;
        offset += size as usize;
        section_count += 1;
    }
    println!("[tos-deploy] Sections: {}", section_count);

    // Validate size limits
    if wasm_bytes.len() > 65536 {
        eprintln!("[tos-deploy] WARNING: WASM binary exceeds TOS limit (64 KB)");
        eprintln!("[tos-deploy] TOS MAX_CODE_SIZE = 65536 bytes");
    }

    println!();
    println!("[tos-deploy] Agent validated. To deploy:");
    println!("  1. Start TOS with serial: qemu-system-x86_64 -m 512M -serial stdio ...");
    println!("  2. The skilld agent will load WASM modules from mailbox messages");
    println!("  3. Send the WASM binary as a message to skilld's mailbox");
}

fn read_leb128(bytes: &[u8]) -> (u32, usize) {
    let mut result = 0u32;
    let mut shift = 0;
    let mut i = 0;
    loop {
        if i >= bytes.len() { break; }
        let byte = bytes[i];
        result |= ((byte & 0x7F) as u32) << shift;
        i += 1;
        if byte & 0x80 == 0 { break; }
        shift += 7;
        if shift >= 35 { break; }
    }
    (result, i)
}
