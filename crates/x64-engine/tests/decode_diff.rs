//! Guards the instruction decoder against length-decode regressions.
//!
//! Compiles a small C fixture, then compares this engine's SLEIGH decoder
//! against iced-x86 over the fixture's .text: every instruction the
//! reference decodes must get the same length from SLEIGH. M9 publishes a
//! VEX/EVEX-capable CPU profile, so vector-prefix instructions are no longer
//! exempt: a rejection or mis-sized decode can desynchronize every later
//! fetch even when execution of that particular opcode remains fail-closed.

use std::path::PathBuf;
use std::process::Command;

use iced_x86::{Decoder, DecoderOptions};
use object::{Object, ObjectSection, SectionKind};
use x64_engine::{build::build_x64_vm, decode::decode_one, EngineConfig};

fn ldef() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

#[test]
fn decoder_length_matches_reference_for_icelake_fixture() {
    // A fixture with ordinary integer, memory, control-flow, and compiler
    // selected Ice Lake SIMD code. The entire linked text corpus is checked;
    // no VEX or EVEX prefix receives an exception.
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
    let status = Command::new("gcc")
        .args(["-O3", "-static", "-march=icelake-server", "-o"])
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
    let mut gaps = Vec::new();
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
                other => gaps.push((
                    window[..instr.len().min(window.len())].to_vec(),
                    format!("{other:?}"),
                )),
            }
        }
    }

    assert!(
        compared > 100,
        "fixture produced too few instructions ({compared})"
    );
    assert!(
        gaps.is_empty(),
        "decode gaps found ({} of {compared} instrs): {:02x?}",
        gaps.len(),
        &gaps[..gaps.len().min(5)]
    );
}
