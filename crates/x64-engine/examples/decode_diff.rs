//! Differential-decode harness.
//!
//! Scans the executable bytes of one or more x86-64 ELF files and, at every
//! offset, decodes one instruction with iced-x86 (the reference) and with
//! this engine's SLEIGH lifter, reporting where their decoded *lengths*
//! disagree. A length mismatch is the root cause of the "disassembly does
//! not match the bytes" faults that block Node/V8: once one instruction is
//! sized wrong, every later fetch is misaligned.
//!
//! Usage:
//!   cargo run --release -p x64-engine --example decode_diff -- FILE [FILE...]
//!
//! Strategy: iterate over the reference decoder's instruction stream (so we
//! walk real instruction boundaries, not arbitrary offsets), and at each
//! boundary compare the SLEIGH length. This finds both "SLEIGH decodes a
//! valid instruction with the wrong length" and "SLEIGH rejects an
//! instruction iced accepts" — the two ways a decode gap manifests.

use std::collections::BTreeMap;
use std::path::PathBuf;

use iced_x86::{Decoder as IcedDecoder, DecoderOptions};
use object::{Object, ObjectSection, SectionKind};
use x64_engine::{build::build_x64_vm, decode::decode_one, EngineConfig};

struct Stats {
    instructions: u64,
    agree: u64,
    len_mismatch: u64,
    sleigh_rejected: u64,
    /// Reference mnemonic -> count of disagreements, to cluster the gaps.
    by_mnemonic: BTreeMap<String, u64>,
    /// A few concrete examples per mnemonic (bytes, iced len, sleigh len).
    examples: Vec<(String, Vec<u8>, usize, Option<usize>, String)>,
}

fn main() {
    let files: Vec<PathBuf> = std::env::args().skip(1).map(PathBuf::from).collect();
    if files.is_empty() {
        eprintln!("usage: decode_diff FILE [FILE...]");
        std::process::exit(2);
    }

    let ldef = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs");
    let vm = build_x64_vm(&ldef, &EngineConfig::default()).expect("build engine");

    let mut stats = Stats {
        instructions: 0,
        agree: 0,
        len_mismatch: 0,
        sleigh_rejected: 0,
        by_mnemonic: BTreeMap::new(),
        examples: Vec::new(),
    };

    for file in &files {
        let data = std::fs::read(file).expect("read file");
        let obj = object::File::parse(&*data).expect("parse elf");
        for section in obj.sections() {
            if section.kind() != SectionKind::Text {
                continue;
            }
            let bytes = match section.data() {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
            let base = section.address();
            eprintln!(
                "scanning {} :: {} ({} bytes)",
                file.display(),
                section.name().unwrap_or("<?>"),
                bytes.len()
            );
            scan_section(&vm.cpu, bytes, base, &mut stats);
        }
    }

    report(&stats);
}

fn scan_section(cpu: &icicle_cpu::Cpu, bytes: &[u8], base: u64, stats: &mut Stats) {
    let mut iced = IcedDecoder::with_ip(64, bytes, base, DecoderOptions::NONE);
    let mut instr = iced_x86::Instruction::default();

    while iced.can_decode() {
        let offset = (iced.ip() - base) as usize;
        iced.decode_out(&mut instr);
        let iced_len = instr.len();

        // iced can also flag invalid encodings; skip those (not our gap).
        if instr.is_invalid() {
            continue;
        }
        stats.instructions += 1;

        let window = &bytes[offset..(offset + 16).min(bytes.len())];
        match decode_one(cpu, window) {
            Ok(decoded) if decoded.len == iced_len => {
                stats.agree += 1;
            }
            Ok(decoded) => {
                stats.len_mismatch += 1;
                record_gap(
                    stats,
                    &instr,
                    window,
                    iced_len,
                    Some(decoded.len),
                    decoded.disasm,
                );
            }
            Err(e) => {
                stats.sleigh_rejected += 1;
                record_gap(stats, &instr, window, iced_len, None, format!("{e:?}"));
            }
        }
    }
}

fn record_gap(
    stats: &mut Stats,
    instr: &iced_x86::Instruction,
    window: &[u8],
    iced_len: usize,
    sleigh_len: Option<usize>,
    sleigh_note: String,
) {
    let mnemonic = format!("{:?}", instr.mnemonic());
    *stats.by_mnemonic.entry(mnemonic.clone()).or_insert(0) += 1;
    // Keep at most three examples per mnemonic to bound output.
    let have = stats.examples.iter().filter(|e| e.0 == mnemonic).count();
    if have < 3 {
        stats.examples.push((
            mnemonic,
            window[..iced_len.min(window.len())].to_vec(),
            iced_len,
            sleigh_len,
            sleigh_note,
        ));
    }
}

fn report(stats: &Stats) {
    println!("\n=== differential decode report ===");
    println!("instructions compared : {}", stats.instructions);
    println!("agreed on length      : {}", stats.agree);
    println!("length mismatch       : {}", stats.len_mismatch);
    println!("sleigh rejected       : {}", stats.sleigh_rejected);
    let gaps = stats.len_mismatch + stats.sleigh_rejected;
    if stats.instructions > 0 {
        println!(
            "gap rate              : {:.4}% ({gaps} / {})",
            100.0 * gaps as f64 / stats.instructions as f64,
            stats.instructions
        );
    }

    if stats.by_mnemonic.is_empty() {
        println!("\nno decode gaps found.");
        return;
    }

    println!("\n--- gaps by reference mnemonic (most frequent first) ---");
    let mut ranked: Vec<_> = stats.by_mnemonic.iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    for (mnemonic, count) in ranked.iter().take(30) {
        println!("  {count:>8}  {mnemonic}");
    }

    println!("\n--- examples (bytes | iced_len | sleigh) ---");
    for (mnemonic, bytes, iced_len, sleigh_len, note) in stats.examples.iter().take(40) {
        let hex: String = bytes.iter().map(|b| format!("{b:02x} ")).collect();
        let sleigh = match sleigh_len {
            Some(len) => format!("len={len}"),
            None => "REJECTED".to_string(),
        };
        println!("  {mnemonic:<16} {hex:<40} iced={iced_len} {sleigh}  [{note}]");
    }
}
