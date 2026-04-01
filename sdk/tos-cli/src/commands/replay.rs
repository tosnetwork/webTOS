//! tos replay — replay a checkpoint file
//!
//! Usage:
//!   tos replay <checkpoint.bin>

use std::fs;
use crate::checkpoint;

pub fn run(args: &[String]) {
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        println!("Usage: tos replay <checkpoint.bin>");
        println!();
        println!("Parse and display an TOS checkpoint file.");
        return;
    }

    let path = &args[0];
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[tos-replay] Failed to read {}: {}", path, e);
            std::process::exit(1);
        }
    };

    println!("[tos-replay] Reading checkpoint: {} ({} bytes)", path, data.len());
    checkpoint::parse_and_display(&data);
}
