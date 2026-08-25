//! Execution-differential harness.
//!
//! Runs the same static x86-64 ELF through two engines built from two
//! different SLEIGH specifications (a reference and a candidate), single
//! stepping both in lockstep and comparing architectural state after each
//! instruction. The first divergence names the instruction whose *execution
//! semantics* differ between the specs — the class of regression that a
//! pure decode diff (which only compares length) cannot see.
//!
//! Usage:
//!   exec_diff REF_LDEF CAND_LDEF ELF [MAX_STEPS]
//!
//! Both specs must agree on the SLEIGH register names compared below.

use std::path::{Path, PathBuf};

use icicle_cpu::ValueSource;
use x64_engine::{build::build_x64_vm, EngineConfig, InterpVm};

const GPRS: &[&str] = &[
    "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "R8", "R9", "R10", "R11", "R12", "R13",
    "R14", "R15",
];

struct Runner {
    vm: InterpVm,
    reg_ids: Vec<(String, pcode::VarNode)>,
}

impl Runner {
    fn new(ldef: &Path) -> Self {
        let vm = build_x64_vm(ldef, &EngineConfig::default()).expect("build engine");
        let reg_ids = GPRS
            .iter()
            .filter_map(|name| vm.cpu.arch.sleigh.get_varnode(name).map(|v| (name.to_string(), v)))
            .collect();
        Self { vm, reg_ids }
    }

    /// Loads a static ELF into a flat mapping and points RIP at its entry.
    fn load_static(&mut self, elf: &[u8]) {
        use icicle_cpu::{
            elf::ElfLoader,
            mem::{perm, Mapping},
        };
        struct Bytes<'a>(&'a [u8]);
        impl ElfLoader for Bytes<'_> {
            fn read_file(&mut self, _: &[u8]) -> Result<Vec<u8>, String> {
                Ok(self.0.to_vec())
            }
        }
        self.vm.cpu.mem.reset_virtual();
        self.vm.cpu.reset();
        self.vm.cpu.mem.map_memory_len(
            0,
            0x1000,
            Mapping { perm: perm::NONE, value: 0 },
        );
        let meta = Bytes(elf).load_elf(&mut self.vm.cpu, b"guest").expect("load elf");
        // A stack so pushes during startup do not fault.
        self.vm.cpu.mem.map_memory_len(
            0x7fff_0000_0000,
            0x10_0000,
            Mapping { perm: perm::READ | perm::WRITE | perm::INIT, value: 0 },
        );
        let sp = self.vm.cpu.arch.reg_sp;
        self.vm.cpu.write_var(sp, 0x7fff_0010_0000_u64 & !0xf);
        (self.vm.cpu.arch.on_boot)(&mut self.vm.cpu, meta.binary.entry_ptr);
    }

    fn step(&mut self) -> x64_engine::VmExit {
        self.vm.icount_limit = self.vm.cpu.icount + 1;
        self.vm.run()
    }

    fn pc(&self) -> u64 {
        self.vm.cpu.read_pc()
    }

    fn state(&mut self) -> Vec<(String, u64)> {
        self.reg_ids.iter().map(|(n, v)| (n.clone(), self.vm.cpu.read_reg(*v))).collect()
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 3 {
        eprintln!("usage: exec_diff REF_LDEF CAND_LDEF ELF [MAX_STEPS]");
        std::process::exit(2);
    }
    let max_steps: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(2_000_000);

    let elf = std::fs::read(&args[2]).expect("read elf");
    let mut reference = Runner::new(&PathBuf::from(&args[0]));
    let mut candidate = Runner::new(&PathBuf::from(&args[1]));
    reference.load_static(&elf);
    candidate.load_static(&elf);

    let mut prev_pc = reference.pc();
    for step in 0..max_steps {
        let pc_before = reference.pc();
        // Both engines must be at the same PC before stepping.
        if reference.pc() != candidate.pc() {
            report_divergence(step, prev_pc, &mut reference, &mut candidate, "PC before step");
            return;
        }
        let r_exit = reference.step();
        let c_exit = candidate.step();

        // Compare architectural state after the instruction.
        let (rs, cs) = (reference.state(), candidate.state());
        let diffs: Vec<_> = rs
            .iter()
            .zip(&cs)
            .filter(|((_, a), (_, b))| a != b)
            .map(|((n, a), (_, b))| (n.clone(), *a, *b))
            .collect();
        let pc_diff = reference.pc() != candidate.pc();

        if !diffs.is_empty() || pc_diff || format!("{r_exit:?}") != format!("{c_exit:?}") {
            println!("\n=== execution divergence at step {step} ===");
            println!("instruction PC: {pc_before:#x}");
            println!("ref exit: {r_exit:?}   cand exit: {c_exit:?}");
            if pc_diff {
                println!("PC after: ref {:#x}  cand {:#x}", reference.pc(), candidate.pc());
            }
            for (name, a, b) in &diffs {
                println!("  {name}: ref {a:#x}  cand {b:#x}");
            }
            // Show the instruction bytes at the divergence site.
            let mut bytes = [0_u8; 16];
            let _ = reference.vm.cpu.mem.read_bytes(pc_before, &mut bytes, icicle_mem::perm::NONE);
            let hex: String = bytes.iter().map(|b| format!("{b:02x} ")).collect();
            println!("bytes: {hex}");
            return;
        }

        if matches!(r_exit, x64_engine::VmExit::Halt | x64_engine::VmExit::UnhandledException(_)) {
            println!("both engines exited identically at step {step}: {r_exit:?}");
            return;
        }
        prev_pc = pc_before;
    }
    println!("no divergence in {max_steps} steps (last PC {prev_pc:#x})");
}

fn report_divergence(step: u64, prev_pc: u64, r: &mut Runner, c: &mut Runner, why: &str) {
    println!("\n=== divergence at step {step}: {why} ===");
    println!("previous PC: {prev_pc:#x}");
    println!("ref PC {:#x}  cand PC {:#x}", r.pc(), c.pc());
}
