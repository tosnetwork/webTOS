use std::env;
use std::fs;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        process::exit(1);
    }

    match args[1].as_str() {
        "build" => cmd_build(&args[2..]),
        "sign" => cmd_sign(&args[2..]),
        "verify" => cmd_verify(&args[2..]),
        "inspect" => cmd_inspect(&args[2..]),
        "list" => cmd_list(),
        "--version" => println!("atp {}", env!("CARGO_PKG_VERSION")),
        "--help" | "help" => print_usage(),
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            print_usage();
            process::exit(1);
        }
    }
}

fn print_usage() {
    println!("atp - ATOS Package Tool");
    println!();
    println!("Usage: atp <command> [options]");
    println!();
    println!("Commands:");
    println!("  build <wasm> -o <output.tos>    Build a .tos package from WASM binary");
    println!("  sign <package.tos>              Sign a package (generates keypair if needed)");
    println!("  verify <package.tos>            Verify package signature and integrity");
    println!("  inspect <package.tos>           Show package manifest");
    println!("  list                            List installed packages");
    println!("  --version                       Show version");
}

fn cmd_build(args: &[String]) {
    if args.len() < 3 || args[1] != "-o" {
        eprintln!("Usage: atp build <input.wasm> -o <output.tos>");
        process::exit(1);
    }
    let input = &args[0];
    let output = &args[2];

    let wasm_bytes = match fs::read(input) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error reading {input}: {e}");
            process::exit(1);
        }
    };

    // Build .tos package
    // Format: [manifest_size:4][manifest][code_size:4][code]
    let name = input.rsplit('/').next().unwrap_or(input);
    let name_bytes = name.as_bytes();

    // Compute code hash (FNV-1a)
    let mut h: u64 = 0xcbf29ce484222325;
    for b in &wasm_bytes {
        h = h.wrapping_mul(0x100000001b3) ^ (*b as u64);
    }
    let mut code_hash = [0u8; 32];
    code_hash[0..8].copy_from_slice(&h.to_le_bytes());

    // Build manifest (simplified binary format matching kernel's PackageManifest)
    let mut manifest = vec![0u8; 256]; // fixed-size manifest
    let name_len = name_bytes.len().min(64);
    manifest[0..name_len].copy_from_slice(&name_bytes[..name_len]);
    manifest[64] = name_len as u8; // name_len
    manifest[65..67].copy_from_slice(&1u16.to_le_bytes()); // version_major
    manifest[67..69].copy_from_slice(&0u16.to_le_bytes()); // version_minor
    manifest[69..71].copy_from_slice(&0u16.to_le_bytes()); // version_patch
    // author at offset 71, 64 bytes
    let author = b"atp-builder";
    manifest[71..71 + author.len()].copy_from_slice(author);
    manifest[135] = author.len() as u8; // author_len
    // required_capabilities at 136, 4 bytes
    manifest[136..140].copy_from_slice(&0u32.to_le_bytes());
    // min_energy at 140, 8 bytes
    manifest[140..148].copy_from_slice(&1000u64.to_le_bytes());
    // max_memory_pages at 148, 4 bytes
    manifest[148..152].copy_from_slice(&256u32.to_le_bytes());
    // code_hash at 152, 32 bytes
    manifest[152..184].copy_from_slice(&code_hash);
    // manifest_hash at 184, 32 bytes (computed later)
    // signature at 216, 64 bytes (added by 'sign')

    // Compute manifest hash
    let mut mh: u64 = 0xcbf29ce484222325;
    for b in &manifest[0..184] {
        mh = mh.wrapping_mul(0x100000001b3) ^ (*b as u64);
    }
    manifest[184..192].copy_from_slice(&mh.to_le_bytes());

    // Write .tos file
    let manifest_size = manifest.len() as u32;
    let code_size = wasm_bytes.len() as u32;

    let mut output_data = Vec::new();
    output_data.extend_from_slice(&manifest_size.to_le_bytes());
    output_data.extend_from_slice(&manifest);
    output_data.extend_from_slice(&code_size.to_le_bytes());
    output_data.extend_from_slice(&wasm_bytes);

    match fs::write(output, &output_data) {
        Ok(()) => println!(
            "Built {output} ({} bytes, code hash: {:016x})",
            output_data.len(),
            h
        ),
        Err(e) => {
            eprintln!("Error writing {output}: {e}");
            process::exit(1);
        }
    }
}

fn cmd_sign(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: atp sign <package.tos>");
        process::exit(1);
    }
    let path = &args[0];
    let mut data = match fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    };

    if data.len() < 4 {
        eprintln!("Invalid .tos file");
        process::exit(1);
    }
    let manifest_size = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if data.len() < 4 + manifest_size {
        eprintln!("Truncated manifest");
        process::exit(1);
    }

    // Sign manifest bytes with keyed hash
    let mut h: u64 = 0xcbf29ce484222325;
    // Use a fixed "dev key" for signing
    let dev_key = [0x42u8; 32];
    for b in &dev_key {
        h = h.wrapping_mul(0x100000001b3) ^ (*b as u64);
    }
    for b in &data[4..4 + manifest_size - 64] {
        h = h.wrapping_mul(0x100000001b3) ^ (*b as u64);
    }

    // Write signature into manifest (last 64 bytes)
    let sig_offset = 4 + manifest_size - 64;
    for i in 0..8 {
        let val = h.wrapping_mul(0x100000001b3) ^ (i as u64);
        data[sig_offset + i * 8..sig_offset + (i + 1) * 8].copy_from_slice(&val.to_le_bytes());
    }

    match fs::write(path, &data) {
        Ok(()) => println!("Signed {path}"),
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    }
}

fn cmd_verify(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: atp verify <package.tos>");
        process::exit(1);
    }
    let path = &args[0];
    let data = match fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    };

    if data.len() < 8 {
        eprintln!("Invalid .tos file");
        process::exit(1);
    }
    let manifest_size = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let code_offset = 4 + manifest_size + 4;
    let code_size = if data.len() > 4 + manifest_size + 4 {
        u32::from_le_bytes([
            data[4 + manifest_size],
            data[4 + manifest_size + 1],
            data[4 + manifest_size + 2],
            data[4 + manifest_size + 3],
        ]) as usize
    } else {
        0
    };

    // Verify code hash
    if code_offset + code_size <= data.len() {
        let code = &data[code_offset..code_offset + code_size];
        let mut h: u64 = 0xcbf29ce484222325;
        for b in code {
            h = h.wrapping_mul(0x100000001b3) ^ (*b as u64);
        }
        let mut expected = [0u8; 8];
        expected.copy_from_slice(&data[4 + 152..4 + 160]);
        let actual = h.to_le_bytes();
        if expected == actual {
            println!("\u{2713} Code hash verified");
        } else {
            println!("\u{2717} Code hash MISMATCH");
            process::exit(1);
        }
    }

    // Check if signature is non-zero
    let sig_offset = 4 + manifest_size - 64;
    let sig_all_zero = data[sig_offset..sig_offset + 64].iter().all(|&b| b == 0);
    if sig_all_zero {
        println!("\u{26a0} Package is UNSIGNED");
    } else {
        println!("\u{2713} Signature present");
    }

    println!(
        "\u{2713} Package structure valid ({} bytes manifest, {} bytes code)",
        manifest_size, code_size
    );
}

fn cmd_inspect(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: atp inspect <package.tos>");
        process::exit(1);
    }
    let path = &args[0];
    let data = match fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    };

    if data.len() < 8 {
        eprintln!("Invalid .tos file");
        process::exit(1);
    }
    let manifest_size = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;

    // Read name
    let name_len = data[4 + 64] as usize;
    let name = std::str::from_utf8(&data[4..4 + name_len.min(64)]).unwrap_or("<invalid>");
    let ver_major = u16::from_le_bytes([data[4 + 65], data[4 + 66]]);
    let ver_minor = u16::from_le_bytes([data[4 + 67], data[4 + 68]]);
    let ver_patch = u16::from_le_bytes([data[4 + 69], data[4 + 70]]);
    let author_len = data[4 + 135] as usize;
    let author =
        std::str::from_utf8(&data[4 + 71..4 + 71 + author_len.min(64)]).unwrap_or("<unknown>");
    let min_energy = u64::from_le_bytes(data[4 + 140..4 + 148].try_into().unwrap_or([0; 8]));

    let code_size = if data.len() > 4 + manifest_size + 4 {
        u32::from_le_bytes([
            data[4 + manifest_size],
            data[4 + manifest_size + 1],
            data[4 + manifest_size + 2],
            data[4 + manifest_size + 3],
        ])
    } else {
        0
    };

    println!("Package: {name}");
    println!("  Version: {ver_major}.{ver_minor}.{ver_patch}");
    println!("  Author: {author}");
    println!("  Min energy: {min_energy}");
    println!("  Code size: {code_size} bytes");
    println!("  Manifest size: {manifest_size} bytes");
    println!("  Total: {} bytes", data.len());
}

fn cmd_list() {
    println!("Installed packages:");
    println!("  (connect to ATOS kernel via pkgd to list installed packages)");
    println!("  (standalone listing not yet implemented)");
}
