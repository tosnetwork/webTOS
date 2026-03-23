//! aos replay — replay a checkpoint file
//!
//! Usage:
//!   aos replay <checkpoint.bin>

use std::fs;
use crate::checkpoint;

pub fn run(args: &[String]) {
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        println!("Usage: aos replay <checkpoint.bin>");
        println!();
        println!("Parse and display an AOS checkpoint file.");
        return;
    }

    let path = &args[0];
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[aos-replay] Failed to read {}: {}", path, e);
            std::process::exit(1);
        }
    };

    println!("[aos-replay] Reading checkpoint: {} ({} bytes)", path, data.len());
    checkpoint::parse_and_display(&data);
}
