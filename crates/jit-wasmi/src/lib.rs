//! A wasmi-backed [`JitBackend`] for the x64 engine.
//!
//! wasmi is a wasm *interpreter*, so this is not a speedup backend — it is
//! ~1.5–2x slower than the p-code interpreter (see
//! `feasibility/jit_native_wasmi.md`). Its value is correctness: it executes the
//! wasm `translate_block`/`translate_region` emit exactly as a real engine
//! would, so a native test can prove the JIT reproduces the interpreter
//! bit-for-bit — per block (`x64-engine/tests/jit_dispatch.rs`) and across a
//! whole recorded workload (`linux-compat/tests/trace.rs`). The browser backend
//! (`webtos-web`) shares the engine's memory instead of copying; that is a
//! separate wiring, and wasmi never enters the browser build.
//!
//! The backend copies the register file into a dedicated wasmi memory and
//! installs an all-invalid TLB, so the inline softmmu fast path never has a live
//! TLB to hit and every guest access defers to the load/store callbacks over the
//! live `Cpu`. The warm fast path is exercised by the `fastmem` gate in
//! `x64-engine/tests/jit.rs` and by the browser Node gates.

use icicle_cpu::mem::perm;
use icicle_cpu::Cpu;
use x64_engine::jit::{JitBackend, JitOutcome, RegionOutcome, REG_SPACE_BYTES};
use x64_engine::ExceptionCode;

/// State the wasmi imports act on during a call: the live CPU (guest memory and
/// the exception it sets), the register memory the load import writes into, and
/// the resume index a fault reports. `cpu` is set for the duration of one call
/// and null otherwise.
struct HostData {
    cpu: *mut Cpu,
    memory: Option<wasmi::Memory>,
    fault: Option<u32>,
}

/// Bytes of an `icicle_mem::tlb::TranslationCache` image (read + write arrays,
/// 1024 × 16 bytes each).
const TLB_BYTES: u32 = 2 * 1024 * 16;

/// A wasmi backend that runs each compiled block against a copy of the register
/// space, routing guest-memory callbacks through the live CPU.
pub struct WasmiJit {
    engine: wasmi::Engine,
    store: wasmi::Store<HostData>,
    memory: wasmi::Memory,
    /// Byte offset of the all-invalid TLB image within `memory`. This backend
    /// copies the register file into a dedicated memory rather than sharing the
    /// engine's, so the inline fast path never has a live TLB to hit; an
    /// all-`0xFF` (invalid) TLB makes every access defer to the host callbacks.
    tlb_base: u32,
    linker: wasmi::Linker<HostData>,
    /// Compiled instances by handle (the index). `None` once evicted, so the
    /// slot's module and instance are dropped while later handles keep their
    /// indices.
    instances: Vec<Option<wasmi::Instance>>,
}

impl WasmiJit {
    pub fn new() -> Self {
        let engine = wasmi::Engine::default();
        let mut store = wasmi::Store::new(
            &engine,
            HostData {
                cpu: std::ptr::null_mut(),
                memory: None,
                fault: None,
            },
        );
        // Register file, then an all-invalid TLB image (see `tlb_base`).
        let tlb_base = REG_SPACE_BYTES;
        let total = REG_SPACE_BYTES + TLB_BYTES;
        let mem_ty = wasmi::MemoryType::new(total.div_ceil(65536), None);
        let memory = wasmi::Memory::new(&mut store, mem_ty).expect("memory");
        memory
            .write(
                &mut store,
                tlb_base as usize,
                &vec![0xffu8; TLB_BYTES as usize],
            )
            .expect("invalidate tlb");
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
            tlb_base,
            linker,
            instances: Vec::new(),
        }
    }
}

impl Default for WasmiJit {
    fn default() -> Self {
        Self::new()
    }
}

impl JitBackend for WasmiJit {
    fn compile(&mut self, bytes: &[u8]) -> Option<u32> {
        let module = wasmi::Module::new(&self.engine, bytes).ok()?;
        // Our modules declare no start function, so instantiate-and-start is a
        // plain instantiation (the deprecated split `instantiate().start()` warns).
        let instance = self
            .linker
            .instantiate_and_start(&mut self.store, &module)
            .ok()?;
        self.instances.push(Some(instance));
        Some((self.instances.len() - 1) as u32)
    }

    fn evict(&mut self, handle: u32) {
        if let Some(slot) = self.instances.get_mut(handle as usize) {
            *slot = None;
        }
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

        let Some(instance) = self.instances.get(handle as usize).copied().flatten() else {
            return JitOutcome::Unavailable;
        };
        let run = match instance.get_typed_func::<(i32, i32), ()>(&self.store, "run") {
            Ok(run) => run,
            Err(_) => return JitOutcome::Unavailable,
        };
        let ran = run.call(&mut self.store, (0i32, self.tlb_base as i32));
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

        let Some(instance) = self.instances.get(handle as usize).copied().flatten() else {
            return RegionOutcome::Unavailable;
        };
        // A region is `run(regs_base: i32, tlb_base: i32, max_iters: i64) -> i64`,
        // returning the iterations it executed.
        let run = match instance.get_typed_func::<(i32, i32, i64), i64>(&self.store, "run") {
            Ok(run) => run,
            Err(_) => return RegionOutcome::Unavailable,
        };
        let ran = run.call(
            &mut self.store,
            (0i32, self.tlb_base as i32, max_iters as i64),
        );
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

        // A host region can fault mid-loop: the load/store/raise callback set the
        // exception and recorded the resume index in the fault tracker, exactly
        // as on the per-block path. If it fired, `iters` is the count of fully
        // completed iterations and the tracker is the faulting index. A
        // register-only region never faults, so the tracker stays clear.
        match self.store.data().fault {
            Some(index) => RegionOutcome::Faulted(iters, index),
            None => RegionOutcome::Ran(iters),
        }
    }
}
