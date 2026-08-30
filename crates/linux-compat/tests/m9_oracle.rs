//! Portable replay of the M9 native execution authority.
//!
//! `x64-engine/tests/native_oracle.rs` compares individual instructions,
//! xstate, memory, and faults against ptrace. This fixture composes one
//! deterministic path through every AVX-family extension published by the
//! virtual profile, then runs the exact bytes through both interpreter and
//! JIT. The same ELF and expected fingerprint are consumed by the browser
//! matrix.

use std::path::PathBuf;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::process::Command;

use jit_wasmi::WasmiJit;
use linux_compat::Machine;
use x64_engine::{CpuExit, EngineConfig};

const EXPECTED: &str = "M9_ORACLE_FNV1A64=0a7c58fd00cdfc14\n";
const IMAGE: &[u8] = include_bytes!("../../../test_data/m9_icelake_oracle.elf");

fn ldef_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

fn run(jit: bool) -> (CpuExit, String, u64) {
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    if jit {
        machine.set_jit(Box::new(WasmiJit::new()));
        machine.set_jit_tiering(Some(1));
    }
    machine
        .add_file(b"/bin/m9-oracle", IMAGE.to_vec(), 0o755)
        .expect("install oracle fixture");
    machine.set_args(vec![b"m9-oracle".to_vec()], vec![b"PATH=/bin".to_vec()]);
    machine
        .load(b"/bin/m9-oracle")
        .expect("load oracle fixture");
    machine.vm_mut().icount_limit = 1_000_000;
    let exit = machine.run();
    let output = String::from_utf8(machine.take_output()).expect("ASCII oracle output");
    (exit, output, machine.jit_dispatch_count())
}

#[test]
fn portable_icelake_oracle_matches_native_in_interpreter_and_jit() {
    let interpreted = run(false);
    assert_eq!(interpreted.0, CpuExit::Halt { code: Some(0) });
    assert_eq!(interpreted.1, EXPECTED);
    assert_eq!(interpreted.2, 0);

    let compiled = run(true);
    assert_eq!(compiled.0, CpuExit::Halt { code: Some(0) });
    assert_eq!(compiled.1, EXPECTED);
    assert!(
        compiled.2 > 0,
        "the JIT replay never dispatched compiled code"
    );
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn committed_fingerprint_is_the_native_hardware_result() {
    for (name, present) in [
        ("aes", std::is_x86_feature_detected!("aes")),
        ("pclmulqdq", std::is_x86_feature_detected!("pclmulqdq")),
        ("bmi1", std::is_x86_feature_detected!("bmi1")),
        ("bmi2", std::is_x86_feature_detected!("bmi2")),
        ("avx2", std::is_x86_feature_detected!("avx2")),
        ("avx512f", std::is_x86_feature_detected!("avx512f")),
        ("avx512bw", std::is_x86_feature_detected!("avx512bw")),
        ("avx512cd", std::is_x86_feature_detected!("avx512cd")),
        ("avx512vl", std::is_x86_feature_detected!("avx512vl")),
        ("avx512vbmi2", std::is_x86_feature_detected!("avx512vbmi2")),
        (
            "avx512vpopcntdq",
            std::is_x86_feature_detected!("avx512vpopcntdq"),
        ),
    ] {
        assert!(present, "native M9 replay host lacks {name}");
    }

    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_data/m9_icelake_oracle.elf");
    let output = Command::new(path)
        .output()
        .expect("run native oracle fixture");
    assert!(
        output.status.success(),
        "native oracle exited as {:?}",
        output.status
    );
    assert_eq!(output.stdout, EXPECTED.as_bytes());
    assert!(output.stderr.is_empty());
}
