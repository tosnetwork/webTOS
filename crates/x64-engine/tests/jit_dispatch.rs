//! JIT dispatch in the run loop: a hot block — register-only, or one that
//! touches guest memory — must execute as compiled wasm and produce exactly
//! what the interpreter would.
//!
//! Each x86 loop is run twice through `InterpVm::run`, once interpreted and once
//! with a wasmi JIT backend installed and tiering set so the body compiles on
//! its first entry. The final register state and the retired instruction count
//! must match, and the JIT must actually fire.
//!
//! The backend is wasmi over a copied register buffer, with the load/store/
//! fault/raise callbacks routed through the live `Cpu` — enough to prove the
//! dispatch, the softmmu hand-off, and the fuel accounting. The browser backend
//! shares memory instead of copying; that is a separate wiring.

use std::path::PathBuf;

use icicle_cpu::mem::{perm, Mapping};
use icicle_cpu::{Cpu, ValueSource};
use x64_engine::build::{build_x64_vm, EngineConfig};
use x64_engine::jit::{JitBackend, JitOutcome, RegionOutcome, REG_SPACE_BYTES};
use x64_engine::ExceptionCode;

fn ldef_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

/// State the wasmi imports act on during a call: the live CPU (guest memory and
/// the exception it sets), the register memory the load import writes into, and
/// the resume index a fault reports. `cpu` is set for the duration of one call
/// and null otherwise.
struct HostData {
    cpu: *mut Cpu,
    memory: Option<wasmi::Memory>,
    fault: Option<u32>,
}

/// A wasmi backend that runs each compiled block against a copy of the register
/// space, routing guest-memory callbacks through the live CPU.
struct WasmiJit {
    engine: wasmi::Engine,
    store: wasmi::Store<HostData>,
    memory: wasmi::Memory,
    linker: wasmi::Linker<HostData>,
    instances: Vec<wasmi::Instance>,
}

impl WasmiJit {
    fn new() -> Self {
        let engine = wasmi::Engine::default();
        let mut store = wasmi::Store::new(
            &engine,
            HostData {
                cpu: std::ptr::null_mut(),
                memory: None,
                fault: None,
            },
        );
        let mem_ty = wasmi::MemoryType::new(REG_SPACE_BYTES / 65536, None);
        let memory = wasmi::Memory::new(&mut store, mem_ty).expect("memory");
        store.data_mut().memory = Some(memory);

        let mut linker = wasmi::Linker::new(&engine);
        linker.define("env", "regs", memory).expect("regs");

        // Safety in the callbacks: `cpu` is set to the live CPU for the duration
        // of one `run.call`, during which these run synchronously; it is never
        // aliased with the `&mut Cpu` in `call`, which only touches `cpu.regs`
        // before and after the run while the callbacks touch `cpu.mem`.
        linker
            .func_wrap(
                "env",
                "load",
                |mut caller: wasmi::Caller<HostData>, addr: i64, dst_off: i32, size: i32| -> i32 {
                    let addr = addr as u64;
                    let cpu = unsafe { &mut *caller.data().cpu };
                    let res = match size {
                        1 => cpu.mem.read::<1>(addr, perm::READ).map(|b| b.to_vec()),
                        2 => cpu.mem.read::<2>(addr, perm::READ).map(|b| b.to_vec()),
                        4 => cpu.mem.read::<4>(addr, perm::READ).map(|b| b.to_vec()),
                        8 => cpu.mem.read::<8>(addr, perm::READ).map(|b| b.to_vec()),
                        _ => return 0,
                    };
                    match res {
                        Ok(bytes) => {
                            let mem = caller.data().memory.expect("memory");
                            mem.write(&mut caller, dst_off as usize, &bytes)
                                .expect("write");
                            1
                        }
                        Err(e) => {
                            cpu.exception.code = ExceptionCode::from_load_error(e) as u32;
                            cpu.exception.value = addr;
                            0
                        }
                    }
                },
            )
            .expect("load");
        linker
            .func_wrap(
                "env",
                "store",
                |caller: wasmi::Caller<HostData>, addr: i64, value: i64, size: i32| -> i32 {
                    let addr = addr as u64;
                    let v = value as u64;
                    let cpu = unsafe { &mut *caller.data().cpu };
                    let res = match size {
                        1 => cpu
                            .mem
                            .write::<1>(addr, (v as u8).to_le_bytes(), perm::WRITE),
                        2 => cpu
                            .mem
                            .write::<2>(addr, (v as u16).to_le_bytes(), perm::WRITE),
                        4 => cpu
                            .mem
                            .write::<4>(addr, (v as u32).to_le_bytes(), perm::WRITE),
                        8 => cpu.mem.write::<8>(addr, v.to_le_bytes(), perm::WRITE),
                        _ => return 0,
                    };
                    match res {
                        Ok(()) => 1,
                        Err(e) => {
                            cpu.exception.code = ExceptionCode::from_store_error(e) as u32;
                            cpu.exception.value = addr;
                            0
                        }
                    }
                },
            )
            .expect("store");
        linker
            .func_wrap(
                "env",
                "fault",
                |mut caller: wasmi::Caller<HostData>, index: i32| {
                    caller.data_mut().fault = Some(index as u32);
                },
            )
            .expect("fault");
        linker
            .func_wrap(
                "env",
                "raise",
                |mut caller: wasmi::Caller<HostData>, code: i32, value: i64, index: i32| {
                    let cpu = unsafe { &mut *caller.data().cpu };
                    cpu.exception.code = ExceptionCode::from_u32(code as u32) as u32;
                    cpu.exception.value = value as u64;
                    caller.data_mut().fault = Some(index as u32);
                },
            )
            .expect("raise");

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

    fn call(&mut self, handle: u32, cpu: &mut Cpu) -> JitOutcome {
        if self
            .memory
            .write(&mut self.store, 0, cpu.regs.as_bytes())
            .is_err()
        {
            return JitOutcome::Unavailable;
        }
        self.store.data_mut().cpu = cpu as *mut Cpu;
        self.store.data_mut().fault = None;

        let instance = self.instances[handle as usize];
        let run = match instance.get_typed_func::<i32, ()>(&self.store, "run") {
            Ok(run) => run,
            Err(_) => return JitOutcome::Unavailable,
        };
        let ran = run.call(&mut self.store, 0i32);
        self.store.data_mut().cpu = std::ptr::null_mut();
        if ran.is_err() {
            return JitOutcome::Unavailable;
        }

        let mut buf = vec![0u8; cpu.regs.as_bytes().len()];
        if self.memory.read(&self.store, 0, &mut buf).is_err() {
            return JitOutcome::Unavailable;
        }
        cpu.regs.as_bytes_mut().copy_from_slice(&buf);

        match self.store.data().fault {
            Some(i) => JitOutcome::Faulted(i),
            None => JitOutcome::Completed,
        }
    }

    fn call_region(&mut self, handle: u32, cpu: &mut Cpu, max_iters: u64) -> RegionOutcome {
        if self
            .memory
            .write(&mut self.store, 0, cpu.regs.as_bytes())
            .is_err()
        {
            return RegionOutcome::Unavailable;
        }
        self.store.data_mut().cpu = cpu as *mut Cpu;
        self.store.data_mut().fault = None;

        let instance = self.instances[handle as usize];
        // A region is `run(regs_base: i32, max_iters: i64) -> i64`, returning the
        // iterations it executed.
        let run = match instance.get_typed_func::<(i32, i64), i64>(&self.store, "run") {
            Ok(run) => run,
            Err(_) => return RegionOutcome::Unavailable,
        };
        let ran = run.call(&mut self.store, (0i32, max_iters as i64));
        self.store.data_mut().cpu = std::ptr::null_mut();
        let iters = match ran {
            Ok(iters) => iters as u64,
            Err(_) => return RegionOutcome::Unavailable,
        };

        let mut buf = vec![0u8; cpu.regs.as_bytes().len()];
        if self.memory.read(&self.store, 0, &mut buf).is_err() {
            return RegionOutcome::Unavailable;
        }
        cpu.regs.as_bytes_mut().copy_from_slice(&buf);

        // A register-only region cannot fault, so a normal return is the only
        // successful outcome; the iteration count charges fuel in the caller.
        RegionOutcome::Ran(iters)
    }
}

/// Assembles a flat code region, seeds registers, optionally maps a data
/// buffer, and runs the loop. Returns (final RAX, retired instructions, JIT
/// dispatches).
fn run_program(
    jit: bool,
    code: &[u8],
    regs: &[(&str, u64)],
    data: Option<(u64, Vec<u8>)>,
    icount_limit: u64,
) -> (u64, u64, u64) {
    let mut vm = build_x64_vm(&ldef_path(), &EngineConfig::default()).expect("build vm");
    vm.cpu.mem.reset_virtual();
    vm.cpu.reset();

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
        .write_bytes(base, code, perm::NONE)
        .expect("code");
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
    if let Some((addr, bytes)) = &data {
        let len = ((bytes.len() as u64 + 0xfff) / 0x1000) * 0x1000;
        vm.cpu.mem.map_memory_len(
            *addr,
            len,
            Mapping {
                perm: perm::READ | perm::WRITE,
                value: 0,
            },
        );
        vm.cpu
            .mem
            .write_bytes(*addr, bytes, perm::NONE)
            .expect("data");
    }

    (vm.cpu.arch.on_boot)(&mut vm.cpu, base);
    for &(name, value) in regs {
        let var = vm.cpu.arch.sleigh.get_varnode(name).expect("varnode");
        vm.cpu.write_var(var, value);
    }
    vm.icount_limit = icount_limit;

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

fn assert_matches(label: &str, count: u64, interp: (u64, u64, u64), jit: (u64, u64, u64)) {
    assert_eq!(interp.2, 0, "{label}: the interpreter run must not JIT");
    assert!(
        jit.2 > 0,
        "{label}: the JIT run never dispatched — proves nothing"
    );
    assert_eq!(
        interp.0, jit.0,
        "{label}: final RAX diverged after {count} iters (interp {:#x}, jit {:#x})",
        interp.0, jit.0
    );
    assert_eq!(
        interp.1, jit.1,
        "{label}: retired instruction count diverged (interp {}, jit {})",
        interp.1, jit.1
    );
}

#[test]
fn a_hot_register_block_matches_the_interpreter() {
    // add rax, rbx ; add rax, rcx ; dec rdx ; jnz loop ; hlt
    let code = [
        0x48, 0x01, 0xD8, 0x48, 0x01, 0xC8, 0x48, 0xFF, 0xCA, 0x75, 0xF5, 0xF4,
    ];
    let count = 3_000;
    let regs = [("RAX", 1), ("RBX", 3), ("RCX", 5), ("RDX", count)];
    let interp = run_program(false, &code, &regs, None, 8 * count + 100);
    let jit = run_program(true, &code, &regs, None, 8 * count + 100);
    assert_matches("register loop", count, interp, jit);
}

#[test]
fn a_self_loop_region_matches_the_interpreter() {
    // add rax, rbx ; add rax, rcx ; dec rdx ; jnz loop ; hlt
    //
    // A register-only self-loop: the branch at the end goes back to the block's
    // own start. It is region-compiled — the whole loop is one wasm function
    // with an internal back-edge — so thousands of iterations are a handful of
    // dispatches, not one per iteration, and the result still matches the
    // interpreter exactly.
    let code = [
        0x48, 0x01, 0xD8, 0x48, 0x01, 0xC8, 0x48, 0xFF, 0xCA, 0x75, 0xF5, 0xF4,
    ];
    let count = 3_000;
    let regs = [("RAX", 1), ("RBX", 3), ("RCX", 5), ("RDX", count)];
    let interp = run_program(false, &code, &regs, None, 8 * count + 100);
    let jit = run_program(true, &code, &regs, None, 8 * count + 100);
    assert_matches("self-loop region", count, interp, jit);
    // The region ran the loop to completion in one fuel slice: a handful of
    // dispatches, far fewer than the per-block path's one-per-iteration. A large
    // count here would be ~`count` dispatches without region compilation, so a
    // small count is what proves the region fired rather than the fallback.
    assert!(
        (1..=8).contains(&jit.2),
        "self-loop region: expected a few region dispatches, got {} (per-iteration would be ~{count})",
        jit.2
    );
}

#[test]
fn a_self_loop_region_stops_at_the_fuel_budget() {
    // The same loop, but the instruction limit cuts it off before the counter
    // reaches zero. The region must stop at exactly the iteration the
    // interpreter would, with the same registers and retired-instruction count,
    // and leave control in the loop (re-dispatched, then halted by the limit).
    let code = [
        0x48, 0x01, 0xD8, 0x48, 0x01, 0xC8, 0x48, 0xFF, 0xCA, 0x75, 0xF5, 0xF4,
    ];
    let count = 5_000; // more iterations than the budget allows
    let limit = 4_000; // 1000 full iterations of the 4-instruction body
    let regs = [("RAX", 1), ("RBX", 3), ("RCX", 5), ("RDX", count)];
    let interp = run_program(false, &code, &regs, None, limit);
    let jit = run_program(true, &code, &regs, None, limit);
    assert_matches("self-loop budget", count, interp, jit);
    assert_eq!(
        interp.1, limit,
        "self-loop budget: the interpreter should stop at the instruction limit"
    );
}

#[test]
fn a_hot_memory_block_matches_the_interpreter() {
    // loop: add rax, [rsi] ; add rsi, 8 ; dec rcx ; jnz loop ; hlt
    // A host block: the load goes through the softmmu callback on every entry.
    let code = [
        0x48, 0x03, 0x06, // add rax, [rsi]
        0x48, 0x83, 0xC6, 0x08, // add rsi, 8
        0x48, 0xFF, 0xC9, // dec rcx
        0x75, 0xF4, // jnz loop
        0xF4, // hlt
    ];
    let count = 2_000u64;
    let buf_base = 0x20_0000u64;
    let data: Vec<u8> = (0..count)
        .flat_map(|i| (i.wrapping_mul(0x9e37_79b9) ^ 0x1234).to_le_bytes())
        .collect();
    let regs = [("RAX", 0), ("RSI", buf_base), ("RCX", count)];
    let interp = run_program(
        false,
        &code,
        &regs,
        Some((buf_base, data.clone())),
        12 * count + 100,
    );
    let jit = run_program(true, &code, &regs, Some((buf_base, data)), 12 * count + 100);
    assert_matches("memory loop", count, interp, jit);
}

/// Runs a single faulting instruction and returns the post-fault state:
/// (exception code, exception value, PC, retired instructions, JIT dispatches).
fn run_fault(jit: bool) -> (u32, u64, u64, u64, u64) {
    let mut vm = build_x64_vm(&ldef_path(), &EngineConfig::default()).expect("build vm");
    vm.cpu.mem.reset_virtual();
    vm.cpu.reset();
    let base = 0x40_0000u64;
    vm.cpu.mem.map_memory_len(
        base,
        0x1000,
        Mapping {
            perm: perm::READ | perm::EXEC,
            value: 0,
        },
    );
    // add rax, [rsi] ; hlt   — with RSI unmapped, the load faults.
    vm.cpu
        .mem
        .write_bytes(base, &[0x48, 0x03, 0x06, 0xF4], perm::NONE)
        .expect("code");
    (vm.cpu.arch.on_boot)(&mut vm.cpu, base);
    let rsi = vm.cpu.arch.sleigh.get_varnode("RSI").unwrap();
    vm.cpu.write_var(rsi, 0xdead_0000u64);
    vm.icount_limit = 1000;
    if jit {
        vm.set_jit(Box::new(WasmiJit::new()));
        vm.set_jit_tiering(Some(1));
    }
    let _ = vm.run();
    (
        vm.cpu.exception.code,
        vm.cpu.exception.value,
        vm.cpu.read_pc(),
        vm.cpu.icount(),
        vm.jit_dispatch_count(),
    )
}

#[test]
fn a_faulting_memory_block_matches_the_interpreter() {
    let interp = run_fault(false);
    let jit = run_fault(true);
    assert_eq!(interp.4, 0, "the interpreter run must not JIT");
    assert!(jit.4 > 0, "the JIT run never dispatched — proves nothing");
    // Same exception (code + faulting address), same PC at the faulting
    // instruction, same retired-instruction count.
    assert_eq!(
        (interp.0, interp.1, interp.2, interp.3),
        (jit.0, jit.1, jit.2, jit.3),
        "post-fault state diverged: interp (code {:#06x}, val {:#x}, pc {:#x}, icount {}), \
         jit (code {:#06x}, val {:#x}, pc {:#x}, icount {})",
        interp.0,
        interp.1,
        interp.2,
        interp.3,
        jit.0,
        jit.1,
        jit.2,
        jit.3
    );
}
