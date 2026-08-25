//! Dynamic execution-differential harness.
//!
//! Runs the *same* dynamically linked ELF through a full `linux-compat`
//! Machine twice — once under a reference SLEIGH spec, once under a
//! candidate spec — single stepping both in lockstep and comparing
//! architectural state after each instruction. The first divergence names
//! the instruction whose execution semantics differ between the two specs.
//!
//! Unlike `x64-engine`'s static `exec_diff`, this drives the real loader and
//! syscall layer, so it can reach divergences that only appear deep in
//! glibc/ld.so startup (CPUID feature detection, resolver selection, …).
//!
//! Usage:
//!   exec_diff_dyn REF_LDEF CAND_LDEF [MAX_STEPS]
//!
//! The guest is a host-compiled `printf` hello, mounted with the host glibc,
//! so both machines execute an identical instruction stream until they
//! disagree.

use std::path::{Path, PathBuf};
use std::process::Command;

use linux_compat::Machine;
use x64_engine::EngineConfig;

const GPRS: &[&str] = &[
    "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "R8", "R9", "R10", "R11", "R12", "R13",
    "R14", "R15",
];

fn build(ldef: &Path, image: &[u8]) -> Machine {
    let mut m = Machine::from_ldef(ldef, &EngineConfig::default()).expect("machine build failed");
    for lib in [
        "/lib64/ld-linux-x86-64.so.2",
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib/x86_64-linux-gnu/libgcc_s.so.1",
    ] {
        m.add_file(lib.as_bytes(), std::fs::read(lib).expect("host lib"), 0o755)
            .expect("add lib");
    }
    m.add_file(b"/bin/hello", image.to_vec(), 0o755)
        .expect("add fixture");
    m.set_args(vec![b"hello".to_vec()], vec![b"HOME=/root".to_vec()]);
    m.load(b"/bin/hello").expect("ELF load failed");
    m
}

fn state(m: &mut Machine) -> (u64, Vec<(String, u64)>) {
    let vm = m.vm_mut();
    let pc = vm.cpu.read_pc();
    let regs = GPRS
        .iter()
        .filter_map(|n| {
            vm.cpu
                .arch
                .sleigh
                .get_varnode(n)
                .map(|v| (n.to_string(), vm.cpu.read_reg(v)))
        })
        .collect();
    (pc, regs)
}

fn step(m: &mut Machine) {
    let vm = m.vm_mut();
    vm.icount_limit = vm.cpu.icount + 1;
    let _ = vm.run();
}

fn read16(m: &mut Machine, addr: u64) -> [u8; 16] {
    let mut buf = [0u8; 16];
    let _ = m
        .vm_mut()
        .cpu
        .mem
        .read_bytes(addr, &mut buf, icicle_mem::perm::NONE);
    buf
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!("usage: exec_diff_dyn REF_LDEF CAND_LDEF [MAX_STEPS]");
        std::process::exit(2);
    }
    let max_steps: u64 = args
        .get(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(5_000_000);

    // Compile the fixture once; both machines get identical bytes.
    let dir = std::env::temp_dir().join("webtos-glibc-fixture");
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("hello.c");
    let out = dir.join("hello");
    std::fs::write(
        &src,
        "#include <stdio.h>\nint main(void){printf(\"glibc dynamic hello\\n\");return 0;}\n",
    )
    .unwrap();
    assert!(Command::new("gcc")
        .arg("-o")
        .arg(&out)
        .arg(&src)
        .status()
        .unwrap()
        .success());
    let image = std::fs::read(&out).unwrap();

    let mut reference = build(&PathBuf::from(&args[0]), &image);
    let mut candidate = build(&PathBuf::from(&args[1]), &image);

    let mut prev_pc = 0u64;
    for step_i in 0..max_steps {
        let (rpc, _) = state(&mut reference);
        let (cpc, _) = state(&mut candidate);
        if rpc != cpc {
            println!("\n=== PC diverged before step {step_i} ===");
            println!("prev PC {prev_pc:#x}  ref {rpc:#x}  cand {cpc:#x}");
            let hex: String = read16(&mut reference, prev_pc)
                .iter()
                .map(|b| format!("{b:02x} "))
                .collect();
            println!("bytes@prev: {hex}");
            return;
        }

        step(&mut reference);
        step(&mut candidate);

        let (rpc2, rs) = state(&mut reference);
        let (cpc2, cs) = state(&mut candidate);
        let reg_diffs: Vec<_> = rs
            .iter()
            .zip(&cs)
            .filter(|((_, a), (_, b))| a != b)
            .map(|((n, a), (_, b))| (n.clone(), *a, *b))
            .collect();

        if !reg_diffs.is_empty() || rpc2 != cpc2 {
            println!("\n=== execution divergence at step {step_i} ===");
            println!("instruction PC: {rpc:#x}  (icount {})", reference.icount());
            if rpc2 != cpc2 {
                println!("PC after: ref {rpc2:#x}  cand {cpc2:#x}");
            }
            for (n, a, b) in &reg_diffs {
                println!("  {n}: ref {a:#x}  cand {b:#x}");
            }
            let hex: String = read16(&mut reference, rpc)
                .iter()
                .map(|b| format!("{b:02x} "))
                .collect();
            println!("bytes@insn: {hex}");
            return;
        }
        prev_pc = rpc;
    }
    println!("no divergence in {max_steps} steps (last PC {prev_pc:#x})");
}
