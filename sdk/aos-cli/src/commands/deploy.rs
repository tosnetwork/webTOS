//! aos deploy — send a WASM agent to a running AOS instance via serial
//!
//! Usage:
//!   aos deploy <agent.wasm> [serial_device]
//!
//! Reads the WASM binary and displays deployment information.
//! Full serial protocol deployment requires the AOS kernel to support
//! dynamic WASM loading (future enhancement).

use std::fs;

pub fn run(args: &[String]) {
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        println!("Usage: aos deploy <agent.wasm> [serial_device]");
        println!();
        println!("Deploy a WASM agent to a running AOS instance.");
        println!("The WASM binary is validated and its metadata displayed.");
        return;
    }

    let wasm_path = &args[0];
    let serial = args.get(1).map(|s| s.as_str()).unwrap_or("/dev/ttyS0");

    // Read and validate WASM binary
    let wasm_bytes = match fs::read(wasm_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[aos-deploy] Failed to read {}: {}", wasm_path, e);
            std::process::exit(1);
        }
    };

    // Validate WASM magic
    if wasm_bytes.len() < 8 || &wasm_bytes[0..4] != b"\0asm" {
        eprintln!("[aos-deploy] Invalid WASM binary (bad magic)");
        std::process::exit(1);
    }

    let version = u32::from_le_bytes([wasm_bytes[4], wasm_bytes[5], wasm_bytes[6], wasm_bytes[7]]);

    println!("[aos-deploy] WASM binary: {}", wasm_path);
    println!("[aos-deploy] Size: {} bytes", wasm_bytes.len());
    println!("[aos-deploy] WASM version: {}", version);
    println!("[aos-deploy] Target serial: {}", serial);

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
    println!("[aos-deploy] Sections: {}", section_count);

    // Validate size limits
    if wasm_bytes.len() > 65536 {
        eprintln!("[aos-deploy] WARNING: WASM binary exceeds AOS limit (64 KB)");
        eprintln!("[aos-deploy] AOS MAX_CODE_SIZE = 65536 bytes");
    }

    println!();
    println!("[aos-deploy] Agent validated. To deploy:");
    println!("  1. Start AOS with serial: qemu-system-x86_64 -serial stdio ...");
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
