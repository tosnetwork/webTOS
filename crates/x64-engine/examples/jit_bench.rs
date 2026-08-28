//! JIT throughput benchmark: the p-code interpreter vs the translated block
//! run through wasmi.
//!
//! This measures the JIT *mechanism* on native, before it is wired into the
//! main execution loop. A representative hot block is run many times two ways —
//! straight through `interpret_block_unchecked`, and as the wasm `translate_block`
//! emits, executed by wasmi — over register state that stays resident (no
//! per-iteration copy either way), and the two final register spaces are
//! compared to prove the run was correct before its time is believed.
//!
//! wasmi is itself a wasm *interpreter*, so this isolates the win from
//! eliminating p-code decode-and-dispatch, not the far larger win a real wasm
//! JIT (the browser, or a compiling native runtime) would add on top. It is the
//! honest first number, and it validates the emitted blocks run and agree.
//!
//! Usage: jit_bench [iterations]   (default 20_000_000)

use std::path::PathBuf;
use std::time::Instant;

use icicle_cpu::mem::{perm, Mapping};
use pcode::{Op, Value, VarNode};
use x64_engine::build::{build_x64_vm, EngineConfig};
use x64_engine::jit::{translate_block, var_offset, REG_SPACE_BYTES};
use x64_engine::InterpVm;

fn ldef_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

fn reg(id: i16, size: u8) -> VarNode {
    VarNode::new(id, size)
}

fn konst(v: u64, size: u8) -> Value {
    Value::Const(v, size)
}

/// A benchmark: a name, a block, its register seeds, and an optional guest
/// region to map and fill (for the memory-touching block).
struct Bench {
    name: String,
    block: pcode::Block,
    seeds: Vec<(VarNode, u64)>,
    region: Option<(u64, Vec<u8>)>,
    /// How many logical steps one execution of the block performs. When a block
    /// is unrolled `repeat` times, one `run()`/interpret call does `repeat`
    /// steps, so the per-call overhead is amortised across them and the reported
    /// ns/step reflects steady-state throughput rather than call setup.
    steps_per_call: u64,
    /// The varnode whose value is printed as a checksum, to show both engines
    /// computed the same thing.
    result: VarNode,
}

const BUF_BASE: u64 = 0x1_0000;
const BUF_LEN: usize = 0x1_0000;

/// A splitmix64-style mixing step, four register ops on a u64 accumulator,
/// unrolled `repeat` times into one block.
fn register_block(repeat: u32) -> Bench {
    let (x, t) = (reg(1, 8), reg(2, 8));
    let mut block = pcode::Block::new();
    for _ in 0..repeat {
        block.push((t, Op::IntRight, x, konst(30, 1)));
        block.push((x, Op::IntXor, x, Value::Var(t)));
        block.push((x, Op::IntMul, x, konst(0xbf58_476d_1ce4_e5b9, 8)));
        block.push((x, Op::IntAdd, x, konst(0x9e37_79b9_7f4a_7c15, 8)));
    }
    Bench {
        name: format!("register-only (splitmix, 4 ops/step) x{repeat}"),
        block,
        seeds: vec![(x, 0x1234_5678_9abc_def0)],
        region: None,
        steps_per_call: repeat as u64,
        result: x,
    }
}

/// An FNV-1a-style scan: load a byte from a wrapping cursor, fold it into the
/// hash, advance. One guest load per step, unrolled `repeat` times.
fn memory_block(repeat: u32) -> Bench {
    let (h, off, addr, b1, b8) = (reg(1, 8), reg(2, 8), reg(3, 8), reg(4, 1), reg(5, 8));
    let mut block = pcode::Block::new();
    for _ in 0..repeat {
        block.push((addr, Op::IntAdd, off, konst(BUF_BASE, 8)));
        block.push((b1, Op::Load(pcode::RAM_SPACE), addr));
        block.push((b8, Op::ZeroExtend, Value::Var(b1)));
        block.push((h, Op::IntXor, h, Value::Var(b8)));
        block.push((h, Op::IntMul, h, konst(0x0000_0100_0000_01b3, 8)));
        block.push((off, Op::IntAdd, off, konst(1, 8)));
        block.push((off, Op::IntAnd, off, konst((BUF_LEN as u64) - 1, 8)));
    }

    let data: Vec<u8> = (0..BUF_LEN)
        .map(|i| (i as u64).wrapping_mul(0x9e37) as u8)
        .collect();
    Bench {
        name: format!("memory scan (FNV, 7 ops/step incl. 1 load) x{repeat}"),
        block,
        seeds: vec![(h, 0xcbf2_9ce4_8422_2325), (off, 0)],
        region: Some((BUF_BASE, data)),
        steps_per_call: repeat as u64,
        result: h,
    }
}

fn seed_bytes(seeds: &[(VarNode, u64)]) -> Vec<u8> {
    let mut regs = vec![0u8; REG_SPACE_BYTES as usize];
    for &(var, value) in seeds {
        let off = var_offset(var) as usize;
        let n = var.size as usize;
        regs[off..off + n].copy_from_slice(&value.to_le_bytes()[..n]);
    }
    regs
}

fn map_region(vm: &mut InterpVm, region: &Option<(u64, Vec<u8>)>) {
    if let Some((base, data)) = region {
        let len = ((data.len() as u64 + 0xfff) / 0x1000) * 0x1000;
        vm.cpu.mem.map_memory_len(
            *base,
            len,
            Mapping {
                perm: perm::READ | perm::WRITE,
                value: 0,
            },
        );
        vm.cpu
            .mem
            .write_bytes(*base, data, perm::NONE)
            .expect("seed guest");
    }
}

/// Runs the block `iters` times through the interpreter, returning the final
/// register space and the elapsed time.
fn run_interp(bench: &Bench, calls: u64) -> (Vec<u8>, std::time::Duration) {
    let mut vm = build_x64_vm(&ldef_path(), &EngineConfig::default()).expect("build vm");
    vm.cpu.regs.fill(0);
    map_region(&mut vm, &bench.region);
    let seed = seed_bytes(&bench.seeds);
    vm.cpu.regs.as_bytes_mut().copy_from_slice(&seed);

    let start = Instant::now();
    for _ in 0..calls {
        // Safety: the block is well-formed p-code built above.
        unsafe {
            vm.cpu.interpret_block_unchecked(&bench.block, 0);
        }
    }
    let elapsed = start.elapsed();
    (vm.cpu.regs.as_bytes().to_vec(), elapsed)
}

/// State the wasmi memory imports act on for the memory block.
struct Host {
    vm: InterpVm,
    regs: Option<wasmi::Memory>,
}

/// Runs the translated block `iters` times through wasmi, returning the final
/// register space and the elapsed time.
fn run_jit(bench: &Bench, calls: u64) -> (Vec<u8>, std::time::Duration) {
    let bytes = translate_block(&bench.block).expect("block translates");
    let engine = wasmi::Engine::default();
    let module = wasmi::Module::new(&engine, &bytes[..]).expect("valid wasm");

    let mut vm = build_x64_vm(&ldef_path(), &EngineConfig::default()).expect("build vm");
    vm.cpu.regs.fill(0);
    map_region(&mut vm, &bench.region);

    let mut store = wasmi::Store::new(&engine, Host { vm, regs: None });
    let mem_ty = wasmi::MemoryType::new(REG_SPACE_BYTES / 65536, None);
    let memory = wasmi::Memory::new(&mut store, mem_ty).expect("memory");
    store.data_mut().regs = Some(memory);
    memory
        .write(&mut store, 0, &seed_bytes(&bench.seeds))
        .expect("seed regs");

    let mut linker = wasmi::Linker::new(&engine);
    linker.define("env", "regs", memory).expect("define regs");
    let regs_base = wasmi::Global::new(&mut store, wasmi::Val::I32(0), wasmi::Mutability::Const);
    linker
        .define("env", "regs_base", regs_base)
        .expect("define regs_base");

    // The block only loads, but a host block declares all four imports; the
    // unused ones are inert stubs.
    linker
        .func_wrap(
            "env",
            "load",
            |mut caller: wasmi::Caller<Host>, addr: i64, dst_off: i32, size: i32| -> i32 {
                let addr = addr as u64;
                let loaded = {
                    let mem = &mut caller.data_mut().vm.cpu.mem;
                    match size {
                        1 => mem.read::<1>(addr, perm::READ).map(|b| b.to_vec()),
                        2 => mem.read::<2>(addr, perm::READ).map(|b| b.to_vec()),
                        4 => mem.read::<4>(addr, perm::READ).map(|b| b.to_vec()),
                        8 => mem.read::<8>(addr, perm::READ).map(|b| b.to_vec()),
                        _ => return 0,
                    }
                };
                match loaded {
                    Ok(b) => {
                        let regs = caller.data().regs.expect("regs");
                        regs.write(&mut caller, dst_off as usize, &b)
                            .expect("write");
                        1
                    }
                    Err(_) => 0,
                }
            },
        )
        .expect("define load");
    linker
        .func_wrap(
            "env",
            "store",
            |_c: wasmi::Caller<Host>, _a: i64, _v: i64, _s: i32| -> i32 { 1 },
        )
        .expect("define store");
    linker
        .func_wrap("env", "fault", |_c: wasmi::Caller<Host>, _i: i32| {})
        .expect("define fault");
    linker
        .func_wrap(
            "env",
            "raise",
            |_c: wasmi::Caller<Host>, _code: i32, _v: i64, _i: i32| {},
        )
        .expect("define raise");

    let instance = linker
        .instantiate(&mut store, &module)
        .expect("instantiate")
        .start(&mut store)
        .expect("start");
    let run = instance
        .get_typed_func::<(), ()>(&store, "run")
        .expect("run export");

    let start = Instant::now();
    for _ in 0..calls {
        run.call(&mut store, ()).expect("run");
    }
    let elapsed = start.elapsed();

    let mut regs = vec![0u8; REG_SPACE_BYTES as usize];
    memory.read(&store, 0, &mut regs).expect("read regs");
    (regs, elapsed)
}

fn checksum(regs: &[u8], var: VarNode) -> u64 {
    let off = var_offset(var) as usize;
    let n = var.size as usize;
    let mut bytes = [0u8; 8];
    bytes[..n].copy_from_slice(&regs[off..off + n]);
    u64::from_le_bytes(bytes)
}

fn run_bench(bench: &Bench, total_steps: u64) {
    let calls = (total_steps / bench.steps_per_call).max(1);
    let steps = calls * bench.steps_per_call;

    // Warm up so cold effects do not skew the timing.
    let warm = (calls / 20).max(1);
    let _ = run_interp(bench, warm);
    let _ = run_jit(bench, warm);

    let (interp_regs, interp_t) = run_interp(bench, calls);
    let (jit_regs, jit_t) = run_jit(bench, calls);

    let ok = interp_regs == jit_regs;
    let interp_ns = interp_t.as_secs_f64() * 1e9 / steps as f64;
    let jit_ns = jit_t.as_secs_f64() * 1e9 / steps as f64;
    let speedup = interp_t.as_secs_f64() / jit_t.as_secs_f64();

    println!("  {}", bench.name);
    println!(
        "    checksum: interp {:#018x}  jit {:#018x}  {}",
        checksum(&interp_regs, bench.result),
        checksum(&jit_regs, bench.result),
        if ok { "MATCH" } else { "*** MISMATCH ***" }
    );
    println!(
        "    interpreter {interp_ns:7.2} ns/step   wasmi JIT {jit_ns:7.2} ns/step   {speedup:5.2}x ({})",
        if speedup >= 1.0 { "JIT faster" } else { "JIT slower" }
    );
    println!();
    assert!(ok, "engines disagree — the measurement is meaningless");
}

fn main() {
    let total_steps: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(20_000_000);

    println!("JIT mechanism benchmark — {total_steps} steps per block");
    println!("(wasmi interprets the emitted wasm; a real wasm JIT would add more)");
    println!("x1 = one step per call (call overhead dominates); xN = N unrolled\n");

    for repeat in [1u32, 64] {
        run_bench(&register_block(repeat), total_steps);
        run_bench(&memory_block(repeat), total_steps);
    }
}
