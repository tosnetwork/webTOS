//! aos build — compile an AOS agent
//!
//! Usage:
//!   aos build [--target native|wasm] <source_dir>
//!
//! For WASM agents: runs cargo build --target wasm32-unknown-unknown --release
//! For native agents: runs cargo build --target x86_64-unknown-none --release

use std::process::Command;

pub fn run(args: &[String]) {
    let mut target = "wasm";
    let mut source = ".";

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--target" => {
                if i + 1 < args.len() {
                    target = if args[i + 1] == "native" { "native" } else { "wasm" };
                    i += 1;
                }
            }
            "--help" | "-h" => {
                println!("Usage: aos build [--target native|wasm] [source_dir]");
                println!();
                println!("Options:");
                println!("  --target native   Build native x86_64 agent");
                println!("  --target wasm     Build WASM agent (default)");
                return;
            }
            other => source = other,
        }
        i += 1;
    }

    let rust_target = match target {
        "native" => "x86_64-unknown-none",
        _ => "wasm32-unknown-unknown",
    };

    println!("[aos-build] Building {} agent from {}", target, source);
    println!("[aos-build] Target: {}", rust_target);

    let status = Command::new("cargo")
        .args(["build", "--release", "--target", rust_target])
        .current_dir(source)
        .status();

    match status {
        Ok(s) if s.success() => {
            println!("[aos-build] Build successful");
            println!("[aos-build] Output: {}/target/{}/release/", source, rust_target);
        }
        Ok(s) => {
            eprintln!("[aos-build] Build failed with exit code: {:?}", s.code());
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("[aos-build] Failed to run cargo: {}", e);
            std::process::exit(1);
        }
    }
}
