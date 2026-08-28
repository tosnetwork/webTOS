//! JIT dispatch in the run loop: a hot, register-only block must execute as
//! compiled wasm and produce exactly what the interpreter would.
//!
//! A tiny x86 loop is run twice through `InterpVm::run` — once purely
//! interpreted, once with a JIT backend installed and tiering set so the loop
//! body compiles on its first entry. The final register state and the retired
//! instruction count must match, and the JIT must actually have fired (so a
//! silently-never-dispatched run cannot pass).
//!
//! The backend here is wasmi over a copied register buffer — enough to prove
//! the dispatch, fuel accounting, and block-exit hand-off are correct. The
//! browser backend shares memory instead of copying; that is a separate wiring.

use std::path::PathBuf;

use icicle_cpu::mem::{perm, Mapping};
use icicle_cpu::ValueSource;
use x64_engine::build::{build_x64_vm, EngineConfig};
use x64_engine::jit::{JitBackend, JitOutcome, REG_SPACE_BYTES};

fn ldef_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

/// A wasmi backend that runs each compiled block against a copy of the register
/// space. Register-only blocks need only `env.regs` and `env.regs_base` (0), so
/// there are no host imports here.
struct WasmiJit {
    engine: wasmi::Engine,
    store: wasmi::Store<()>,
    memory: wasmi::Memory,
    linker: wasmi::Linker<()>,
    instances: Vec<wasmi::Instance>,
}

impl WasmiJit {
    fn new() -> Self {
        let engine = wasmi::Engine::default();
        let mut store = wasmi::Store::new(&engine, ());
        let mem_ty = wasmi::MemoryType::new(REG_SPACE_BYTES / 65536, None);
        let memory = wasmi::Memory::new(&mut store, mem_ty).expect("memory");
        let mut linker = wasmi::Linker::new(&engine);
        linker.define("env", "regs", memory).expect("define regs");
        let regs_base =
            wasmi::Global::new(&mut store, wasmi::Val::I32(0), wasmi::Mutability::Const);
        linker
            .define("env", "regs_base", regs_base)
            .expect("define regs_base");
        Self {
            engine,
            store,
            memory,
            linker,
            instances: Vec::new(),
        }
    }
}

impl JitBackend for WasmiJit {
    fn compile(&mut self, bytes: &[u8]) -> Option<u32> {
        let module = wasmi::Module::new(&self.engine, bytes).ok()?;
        let instance = self
            .linker
            .instantiate(&mut self.store, &module)
            .ok()?
            .start(&mut self.store)
            .ok()?;
        self.instances.push(instance);
        Some((self.instances.len() - 1) as u32)
    }

    fn call(&mut self, handle: u32, regs: &mut [u8]) -> JitOutcome {
        if self.memory.write(&mut self.store, 0, regs).is_err() {
            return JitOutcome::Unavailable;
        }
        let instance = self.instances[handle as usize];
        let run = match instance.get_typed_func::<(), ()>(&self.store, "run") {
            Ok(run) => run,
            Err(_) => return JitOutcome::Unavailable,
        };
        if run.call(&mut self.store, ()).is_err() {
            return JitOutcome::Unavailable;
        }
        if self.memory.read(&self.store, 0, regs).is_err() {
            return JitOutcome::Unavailable;
        }
        JitOutcome::Completed
    }
}

/// Runs the register loop and returns (final RAX, retired instructions, JIT
/// dispatches). With `jit`, a backend is installed and the body compiles on its
/// first entry.
fn run_loop(jit: bool, count: u64) -> (u64, u64, u64) {
    let mut vm = build_x64_vm(&ldef_path(), &EngineConfig::default()).expect("build vm");
    vm.cpu.mem.reset_virtual();
    vm.cpu.reset();

    // loop:  add rax, rbx ; add rax, rcx ; dec rdx ; jnz loop ; hlt
    // The body (add/add/dec) is register-only with narrow flags; jnz is the
    // block exit. RAX accumulates (1 + (rbx+rcx)*count) so a wrong result shows
    // as a distinct value. (imul is avoided on purpose: its overflow flag needs
    // a 128-bit multiply, which has no wasm type and bails the whole block — a
    // real limit, not a bug.)
    let code: [u8; 12] = [
        0x48, 0x01, 0xD8, // add rax, rbx
        0x48, 0x01, 0xC8, // add rax, rcx
        0x48, 0xFF, 0xCA, // dec rdx
        0x75, 0xF5, // jnz loop
        0xF4, // hlt
    ];
    let base = 0x40_0000u64;
    vm.cpu.mem.map_memory_len(
        base,
        0x1000,
        Mapping {
            perm: perm::READ | perm::EXEC,
            value: 0,
        },
    );
    vm.cpu
        .mem
        .write_bytes(base, &code, perm::NONE)
        .expect("write code");
    vm.cpu.mem.map_memory_len(
        0x7fff_0000_0000,
        0x10_0000,
        Mapping {
            perm: perm::READ | perm::WRITE | perm::INIT,
            value: 0,
        },
    );
    let sp = vm.cpu.arch.reg_sp;
    vm.cpu.write_var(sp, 0x7fff_0010_0000u64 & !0xf);

    // Boot first — it resets the GPRs and sets PC — then seed the loop's
    // registers, so RDX (the counter) survives to make the loop terminate.
    (vm.cpu.arch.on_boot)(&mut vm.cpu, base);
    let set = |vm: &mut x64_engine::InterpVm, name: &str, value: u64| {
        let var = vm.cpu.arch.sleigh.get_varnode(name).expect("varnode");
        vm.cpu.write_var(var, value);
    };
    set(&mut vm, "RAX", 1);
    set(&mut vm, "RBX", 3);
    set(&mut vm, "RCX", 5);
    set(&mut vm, "RDX", count);
    // hlt does not return from run(); bound the slice so it stops just after
    // the loop. Both engines stop at the same icount, so state still matches.
    vm.icount_limit = 8 * count + 100;

    if jit {
        vm.set_jit(Box::new(WasmiJit::new()));
        vm.set_jit_tiering(Some(1));
    }

    let _ = vm.run();

    let rax = vm
        .cpu
        .arch
        .sleigh
        .get_varnode("RAX")
        .map(|v| vm.cpu.read_reg(v))
        .expect("RAX");
    (rax, vm.cpu.icount(), vm.jit_dispatch_count())
}

#[test]
fn a_hot_register_block_jits_to_the_same_result_as_the_interpreter() {
    let count = 3_000;
    let (interp_rax, interp_icount, interp_disp) = run_loop(false, count);
    let (jit_rax, jit_icount, jit_disp) = run_loop(true, count);

    assert_eq!(interp_disp, 0, "the interpreter run must not JIT");
    assert!(
        jit_disp > 0,
        "the JIT run never dispatched a compiled block — the test proves nothing"
    );
    assert_eq!(
        interp_rax, jit_rax,
        "final RAX diverged: interp {interp_rax:#x}, jit {jit_rax:#x}"
    );
    assert_eq!(
        interp_icount, jit_icount,
        "retired instruction count diverged: interp {interp_icount}, jit {jit_icount}"
    );
}
