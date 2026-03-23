//! `aos-ebpf` — AOS eBPF-lite SDK command-line tool.
//!
//! # Usage
//!
//! ```
//! aos-ebpf compile <input.ebpf> [-o <output.bin>]
//! aos-ebpf verify  <input.bin>
//! aos-ebpf disasm  <input.bin>
//! ```
//!
//! ## compile
//! Assembles the text assembly file, runs the offline static verifier, and
//! writes a binary `.bin` file in AEBF format.  If `-o` is omitted the output
//! is written to `<input>.bin` in the same directory.
//!
//! ## verify
//! Reads an existing `.bin` file and runs the offline static verifier on it.
//!
//! ## disasm
//! Reads an existing `.bin` file and prints human-readable assembly.

mod assembler;
mod binary;
mod disasm;
mod types;
mod verifier;

use std::path::PathBuf;
use std::process;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 3 {
        usage();
        process::exit(1);
    }

    let subcommand = args[1].as_str();
    match subcommand {
        "compile" => cmd_compile(&args[2..]),
        "verify"  => cmd_verify(&args[2..]),
        "disasm"  => cmd_disasm(&args[2..]),
        _ => {
            eprintln!("error: unknown subcommand '{}'\n", subcommand);
            usage();
            process::exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Subcommands
// ---------------------------------------------------------------------------

/// `compile <input.ebpf> [-o output.bin]`
fn cmd_compile(args: &[String]) {
    if args.is_empty() {
        eprintln!("error: compile requires an input file");
        usage();
        process::exit(1);
    }

    let input_path = PathBuf::from(&args[0]);

    // Determine output path: either -o <path> or <input>.bin
    let output_path: PathBuf = {
        let mut out = None;
        let mut i = 1;
        while i < args.len() {
            if args[i] == "-o" {
                if i + 1 >= args.len() {
                    eprintln!("error: -o requires an argument");
                    process::exit(1);
                }
                out = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            } else {
                i += 1;
            }
        }
        out.unwrap_or_else(|| {
            let mut p = input_path.clone();
            p.set_extension("bin");
            p
        })
    };

    // Read source
    let source = std::fs::read_to_string(&input_path).unwrap_or_else(|e| {
        eprintln!("error: cannot read '{}': {}", input_path.display(), e);
        process::exit(1);
    });

    // Assemble
    let insns = assembler::assemble(&source).unwrap_or_else(|e| {
        eprintln!("error: assembly failed: {}", e);
        process::exit(1);
    });

    println!(
        "assembled {} instruction{}",
        insns.len(),
        if insns.len() == 1 { "" } else { "s" }
    );

    // Verify
    verifier::verify(&insns).unwrap_or_else(|e| {
        eprintln!("error: {}", e);
        process::exit(1);
    });
    println!("verification passed");

    // Write binary
    let mut file = std::fs::File::create(&output_path).unwrap_or_else(|e| {
        eprintln!("error: cannot create '{}': {}", output_path.display(), e);
        process::exit(1);
    });
    binary::write_binary(&mut file, &insns).unwrap_or_else(|e| {
        eprintln!("error: write failed: {}", e);
        process::exit(1);
    });

    println!("written to '{}'", output_path.display());
}

/// `verify <input.bin>`
fn cmd_verify(args: &[String]) {
    if args.is_empty() {
        eprintln!("error: verify requires an input file");
        usage();
        process::exit(1);
    }

    let path = PathBuf::from(&args[0]);
    let insns = load_binary(&path);

    println!(
        "loaded {} instruction{}",
        insns.len(),
        if insns.len() == 1 { "" } else { "s" }
    );

    verifier::verify(&insns).unwrap_or_else(|e| {
        eprintln!("error: {}", e);
        process::exit(1);
    });

    println!("verification passed — program is safe to load");
}

/// `disasm <input.bin>`
fn cmd_disasm(args: &[String]) {
    if args.is_empty() {
        eprintln!("error: disasm requires an input file");
        usage();
        process::exit(1);
    }

    let path = PathBuf::from(&args[0]);
    let insns = load_binary(&path);

    println!(
        "; AOS eBPF-lite disassembly of '{}' ({} instruction{})",
        path.display(),
        insns.len(),
        if insns.len() == 1 { "" } else { "s" }
    );
    println!(";");
    print!("{}", disasm::disassemble(&insns));
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Load instructions from an AEBF binary file, exiting on error.
fn load_binary(path: &PathBuf) -> Vec<types::Insn> {
    let mut file = std::fs::File::open(path).unwrap_or_else(|e| {
        eprintln!("error: cannot open '{}': {}", path.display(), e);
        process::exit(1);
    });
    let bin = binary::read_binary(&mut file).unwrap_or_else(|e| {
        eprintln!("error: cannot parse '{}': {}", path.display(), e);
        process::exit(1);
    });
    bin.instructions
}

fn usage() {
    eprintln!(
        "AOS eBPF-lite SDK v{}\n\
         \n\
         USAGE:\n\
         \taos-ebpf compile <input.ebpf> [-o output.bin]   Assemble + verify\n\
         \taos-ebpf verify  <input.bin>                    Verify binary\n\
         \taos-ebpf disasm  <input.bin>                    Disassemble binary",
        env!("CARGO_PKG_VERSION")
    );
}
