//! TOS CLI — command-line tools for the TOS operating system
//!
//! Usage:
//!   tos build [--target native|wasm] <source>   Build an agent
//!   tos deploy <agent.wasm> <qemu-serial>       Deploy agent to running TOS
//!   tos replay <checkpoint.bin>                  Replay a checkpoint file
//!   tos inspect <event-log.txt>                  Inspect event log
//!   tos verify <proof.bin>                       Verify execution proof

mod commands;
mod proof;
mod checkpoint;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }
    match args[1].as_str() {
        "build" => commands::build::run(&args[2..]),
        "deploy" => commands::deploy::run(&args[2..]),
        "replay" => commands::replay::run(&args[2..]),
        "inspect" => commands::inspect::run(&args[2..]),
        "verify" => {
            if args.len() < 3 {
                eprintln!("Usage: tos verify <proof.bin>");
                std::process::exit(1);
            }
            proof::verify_file(&args[2]);
        }
        "help" | "--help" | "-h" => print_usage(),
        other => {
            eprintln!("Unknown command: {}", other);
            print_usage();
            std::process::exit(1);
        }
    }
}

fn print_usage() {
    println!("TOS CLI v0.1.0 — AI-native Operating System tools");
    println!();
    println!("Usage: tos <command> [options]");
    println!();
    println!("Commands:");
    println!("  build    Build an agent (native or WASM)");
    println!("  deploy   Deploy a WASM agent to a running TOS instance");
    println!("  replay   Replay a checkpoint file and display state");
    println!("  inspect  Parse and display event log from serial output");
    println!("  verify   Verify an execution proof file");
    println!();
    println!("Run 'tos <command> --help' for more information.");
}
