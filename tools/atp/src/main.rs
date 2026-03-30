use std::env;
use std::fs;
use std::path::PathBuf;
use std::process;

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};

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

    // Compute code hash (SHA-256)
    use sha2::{Sha256, Digest};
    let hash = Sha256::digest(&wasm_bytes);
    let mut code_hash = [0u8; 32];
    code_hash.copy_from_slice(&hash);

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

    // Compute manifest hash (SHA-256)
    let manifest_hash = Sha256::digest(&manifest[0..184]);
    manifest[184..216].copy_from_slice(&manifest_hash);

    // Write .tos file
    let manifest_size = manifest.len() as u32;
    let code_size = wasm_bytes.len() as u32;

    let mut output_data = Vec::new();
    output_data.extend_from_slice(&manifest_size.to_le_bytes());
    output_data.extend_from_slice(&manifest);
    output_data.extend_from_slice(&code_size.to_le_bytes());
    output_data.extend_from_slice(&wasm_bytes);

    match fs::write(output, &output_data) {
        Ok(()) => {
            let hash_hex: String = code_hash.iter().map(|b| format!("{b:02x}")).collect();
            println!(
                "Built {output} ({} bytes, code hash: {})",
                output_data.len(),
                hash_hex
            );
        }
        Err(e) => {
            eprintln!("Error writing {output}: {e}");
            process::exit(1);
        }
    }
}

/// Return the path to the Ed25519 key file (next to the binary, or in cwd).
fn key_file_path() -> PathBuf {
    let mut p = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    p.push("atp_ed25519.key");
    p
}

/// Load an existing Ed25519 signing key or generate (and persist) a new one.
fn load_or_generate_keypair() -> SigningKey {
    let path = key_file_path();
    if let Ok(bytes) = fs::read(&path) {
        if bytes.len() == 32 {
            let secret: [u8; 32] = bytes.try_into().unwrap();
            return SigningKey::from_bytes(&secret);
        }
        eprintln!("Warning: key file has unexpected size, generating new keypair");
    }
    // Generate a new keypair and save the 32-byte secret seed
    let mut rng = rand::thread_rng();
    let key = SigningKey::generate(&mut rng);
    if let Err(e) = fs::write(&path, key.to_bytes()) {
        eprintln!("Warning: could not save keypair to {}: {e}", path.display());
    } else {
        println!("Generated new Ed25519 keypair -> {}", path.display());
    }
    key
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
    if data.len() < 4 + manifest_size || manifest_size < 64 {
        eprintln!("Truncated manifest");
        process::exit(1);
    }

    // Load or generate the Ed25519 signing key
    let signing_key = load_or_generate_keypair();
    let verifying_key = signing_key.verifying_key();

    // The signable content is everything in the manifest *before* the 64-byte signature slot
    let signable = &data[4..4 + manifest_size - 64];

    // Sign with Ed25519
    let signature = signing_key.sign(signable);

    // Write the 64-byte Ed25519 signature into the manifest's signature field
    let sig_offset = 4 + manifest_size - 64;
    data[sig_offset..sig_offset + 64].copy_from_slice(&signature.to_bytes());

    match fs::write(path, &data) {
        Ok(()) => {
            let pk_hex: String = verifying_key
                .to_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            println!("Signed {path} (pubkey: {pk_hex})");
        }
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    }
}

fn cmd_verify(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: atp verify <package.tos> [--pubkey <hex>]");
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
    if manifest_size < 64 {
        eprintln!("Invalid manifest size");
        process::exit(1);
    }
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

    // Verify code hash (SHA-256)
    if code_offset + code_size <= data.len() {
        use sha2::{Sha256, Digest};
        let code = &data[code_offset..code_offset + code_size];
        let computed = Sha256::digest(code);
        let expected = &data[4 + 152..4 + 184];
        if computed.as_slice() == expected {
            println!("\u{2713} Code hash verified");
        } else {
            println!("\u{2717} Code hash MISMATCH");
            process::exit(1);
        }
    }

    // Verify Ed25519 signature
    let sig_offset = 4 + manifest_size - 64;
    let sig_all_zero = data[sig_offset..sig_offset + 64].iter().all(|&b| b == 0);
    if sig_all_zero {
        println!("\u{26a0} Package is UNSIGNED");
    } else {
        // Try to load the public key: either from --pubkey flag or from the key file
        let pubkey_bytes: Option<[u8; 32]> = if args.len() >= 3 && args[1] == "--pubkey" {
            // Parse hex-encoded 32-byte public key
            let hex = &args[2];
            if hex.len() != 64 {
                eprintln!("Error: --pubkey must be 64 hex characters (32 bytes)");
                process::exit(1);
            }
            let mut pk = [0u8; 32];
            for i in 0..32 {
                pk[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or_else(|_| {
                    eprintln!("Error: invalid hex in --pubkey");
                    process::exit(1);
                });
            }
            Some(pk)
        } else {
            // Try loading from key file
            let kp = key_file_path();
            if let Ok(bytes) = fs::read(&kp) {
                if bytes.len() == 32 {
                    let secret: [u8; 32] = bytes.try_into().unwrap();
                    let sk = SigningKey::from_bytes(&secret);
                    Some(sk.verifying_key().to_bytes())
                } else {
                    None
                }
            } else {
                None
            }
        };

        match pubkey_bytes {
            Some(pk_bytes) => {
                let verifying_key = match VerifyingKey::from_bytes(&pk_bytes) {
                    Ok(vk) => vk,
                    Err(e) => {
                        eprintln!("Error: invalid public key: {e}");
                        process::exit(1);
                    }
                };

                let sig_bytes: [u8; 64] = data[sig_offset..sig_offset + 64]
                    .try_into()
                    .expect("signature slice must be 64 bytes");
                let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

                let signable = &data[4..4 + manifest_size - 64];
                match verifying_key.verify(signable, &signature) {
                    Ok(()) => println!("\u{2713} Ed25519 signature VALID"),
                    Err(_) => {
                        println!("\u{2717} Ed25519 signature INVALID");
                        process::exit(1);
                    }
                }
            }
            None => {
                println!("\u{26a0} Signature present but no public key available for verification");
                println!("  Use: atp verify <package.tos> --pubkey <hex>");
                println!("  Or place the signing key at: {}", key_file_path().display());
            }
        }
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
