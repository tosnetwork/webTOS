//! Guards the instruction decoder against length-decode regressions.
//!
//! Compiles a small C fixture, then compares this engine's SLEIGH decoder
//! against iced-x86 over the fixture's .text: every instruction the
//! reference decodes must get the same length from SLEIGH, and the only
//! acceptable rejections are AVX-512 / VEX vector instructions (the known,
//! documented gap). A regression that mis-sizes a general instruction — the
//! class of bug that misaligns every later fetch — fails here.

use std::path::PathBuf;
use std::process::Command;

use iced_x86::{Decoder, DecoderOptions};
use object::{Object, ObjectSection, SectionKind};
use x64_engine::{build::build_x64_vm, decode::decode_one, EngineConfig};

fn ldef() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

/// True for VEX/EVEX/XOP vector encodings — the AVX-family gap this engine
/// does not yet lift. Their prefix bytes are 0xC4/0xC5 (VEX), 0x62 (EVEX),
/// 0x8F (XOP).
fn is_vector_prefix(bytes: &[u8]) -> bool {
    matches!(bytes.first(), Some(0xc4 | 0xc5 | 0x62 | 0x8f))
}

#[test]
fn decoder_length_matches_reference_except_avx() {
    // A fixture with ordinary integer, memory, and control-flow code.
    let src = r#"
#include <stdint.h>
#include <string.h>
long work(long *a, long n) {
    long acc = 0;
    for (long i = 0; i < n; i++) {
        acc += a[i] ^ (acc >> 3);
        if ((acc & 0xff) == 0) acc -= i;
    }
    char buf[64];
    memset(buf, (int)acc, sizeof buf);
    return acc + buf[acc & 63];
}
int main(void) { long a[8] = {1,2,3,4,5,6,7,8}; return (int)work(a, 8); }
"#;
    let dir = std::env::temp_dir().join("webtos-decode-fixture");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let cpath = dir.join("work.c");
    let out = dir.join("work");
    std::fs::write(&cpath, src).expect("write source");
    // -mno-avx keeps the fixture itself free of the known gap.
    let status = Command::new("gcc")
        .args(["-O2", "-static", "-mno-avx", "-o"])
        .arg(&out)
        .arg(&cpath)
        .status();
    match status {
        Ok(s) if s.success() => {}
        _ => {
            eprintln!("skipping: gcc unavailable");
            return;
        }
    }

    let vm = build_x64_vm(&ldef(), &EngineConfig::default()).expect("build engine");
    let data = std::fs::read(&out).expect("read fixture");
    let obj = object::File::parse(&*data).expect("parse elf");

    let mut compared = 0_u64;
    let mut non_avx_gaps = Vec::new();
    for section in obj.sections() {
        if section.kind() != SectionKind::Text {
            continue;
        }
        let bytes = section.data().expect("section data");
        let base = section.address();
        let mut iced = Decoder::with_ip(64, bytes, base, DecoderOptions::NONE);
        let mut instr = iced_x86::Instruction::default();
        while iced.can_decode() {
            let offset = (iced.ip() - base) as usize;
            iced.decode_out(&mut instr);
            if instr.is_invalid() {
                continue;
            }
            compared += 1;
            let window = &bytes[offset..(offset + 16).min(bytes.len())];
            match decode_one(&vm.cpu, window) {
                Ok(d) if d.len == instr.len() => {}
                other => {
                    if !is_vector_prefix(window) {
                        non_avx_gaps.push((window[..instr.len().min(window.len())].to_vec(), format!("{other:?}")));
                    }
                }
            }
        }
    }

    assert!(compared > 100, "fixture produced too few instructions ({compared})");
    assert!(
        non_avx_gaps.is_empty(),
        "non-AVX decode gaps found ({} of {compared} instrs): {:02x?}",
        non_avx_gaps.len(),
        &non_avx_gaps[..non_avx_gaps.len().min(5)]
    );
}
