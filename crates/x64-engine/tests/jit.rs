//! The JIT gate: a p-code block translated to wasm must produce the
//! interpreter's register state, bit for bit.
//!
//! This is the block-level form of the trace-suite gate, and the standard
//! every op handler is held to. It runs a block two ways — through the real
//! interpreter, and through the wasm the JIT emits, executed by wasmi over a
//! copy of the same initial register bytes — and compares the whole register
//! space. If a handler emits wasm that computes even one byte differently, the
//! comparison fails and names the block.
//!
//! `IntAdd` is the worked reference. Each op slice adds its ops to
//! `translate_instruction` and a case to `CASES` below; the gate then holds
//! them all to the interpreter.

use std::path::PathBuf;

use pcode::{Op, VarNode};
use x64_engine::build::{build_x64_vm, EngineConfig};
use x64_engine::jit::{translate_block, REG_SPACE_BYTES};

fn ldef_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

/// One gate case: a name, the register seeds (varnode → value), and the block
/// to run. The block is built from p-code instructions; the seeds are written
/// into both the interpreter and the wasm's memory before it runs.
struct Case {
    name: &'static str,
    seeds: Vec<(VarNode, u64)>,
    block: pcode::Block,
}

/// A register-space varnode of `size` bytes at slot `id`.
fn reg(id: i16, size: u8) -> VarNode {
    VarNode::new(id, size)
}

fn cases() -> Vec<Case> {
    let mut out = Vec::new();

    // The reference: out(1) = a(2) + b(3), 4 bytes, with a carry across the
    // wrap so a wrong width would show.
    {
        let (o, a, b) = (reg(1, 4), reg(2, 4), reg(3, 4));
        let mut block = pcode::Block::new();
        block.push((o, Op::IntAdd, a, b));
        out.push(Case {
            name: "IntAdd u32 with wraparound",
            seeds: vec![(a, 0xffff_fff0), (b, 0x20)],
            block,
        });
    }

    // IntAdd on 8 bytes, to exercise the i64 path.
    {
        let (o, a, b) = (reg(1, 8), reg(2, 8), reg(3, 8));
        let mut block = pcode::Block::new();
        block.push((o, Op::IntAdd, a, b));
        out.push(Case {
            name: "IntAdd u64",
            seeds: vec![(a, 0x1_0000_0000), (b, 0xff)],
            block,
        });
    }

    out
}

/// Runs a block through the interpreter, returning the full register space.
fn interpret(case: &Case) -> Vec<u8> {
    let mut vm = build_x64_vm(&ldef_path(), &EngineConfig::default()).expect("build vm");
    vm.cpu.regs.fill(0);
    // Seed by writing each varnode's little-endian bytes at its offset — the
    // same way the wasm memory is seeded, so the two runs start identical.
    for &(var, value) in &case.seeds {
        let off = x64_engine::jit::var_offset(var) as usize;
        let n = var.size as usize;
        vm.cpu.regs.as_bytes_mut()[off..off + n].copy_from_slice(&value.to_le_bytes()[..n]);
    }
    // Safety: the block is well-formed p-code built above.
    unsafe {
        vm.cpu.interpret_block_unchecked(&case.block, 0);
    }
    vm.cpu.regs.as_bytes().to_vec()
}

/// Runs the JIT'd wasm for a block through wasmi over the same seeds,
/// returning the full register space, or None if the block did not translate.
fn jit(case: &Case) -> Option<Vec<u8>> {
    let bytes = translate_block(&case.block)?;

    let engine = wasmi::Engine::default();
    let module = wasmi::Module::new(&engine, &bytes[..]).expect("emitted wasm is valid");
    let mut store = wasmi::Store::new(&engine, ());
    let mem_ty = wasmi::MemoryType::new(REG_SPACE_BYTES / 65536, None);
    let memory = wasmi::Memory::new(&mut store, mem_ty).expect("memory");

    // Seed the register space the same way the interpreter was seeded, by
    // writing each varnode's little-endian bytes at its offset.
    let mut regs = vec![0u8; REG_SPACE_BYTES as usize];
    for &(var, value) in &case.seeds {
        let off = x64_engine::jit::var_offset(var) as usize;
        let n = var.size as usize;
        regs[off..off + n].copy_from_slice(&value.to_le_bytes()[..n]);
    }
    memory.write(&mut store, 0, &regs).expect("seed memory");

    let mut linker = wasmi::Linker::new(&engine);
    linker.define("env", "regs", memory).expect("define memory");
    let instance = linker
        .instantiate(&mut store, &module)
        .expect("instantiate")
        .start(&mut store)
        .expect("start");
    let run = instance
        .get_typed_func::<(), ()>(&store, "run")
        .expect("run export");
    run.call(&mut store, ()).expect("run");

    let mut out = vec![0u8; REG_SPACE_BYTES as usize];
    memory.read(&store, 0, &mut out).expect("read memory");
    Some(out)
}

#[test]
fn translated_blocks_match_the_interpreter() {
    let mut failures = Vec::new();
    let mut ran = 0;
    for case in cases() {
        let Some(jit_regs) = jit(&case) else {
            // A case that does not translate is a hole in the JIT, not a pass:
            // every case here is built from ops the JIT is meant to handle.
            failures.push(format!("{}: did not translate", case.name));
            continue;
        };
        let interp_regs = interpret(&case);
        ran += 1;
        if let Some(offset) = first_difference(&interp_regs, &jit_regs) {
            failures.push(format!(
                "{}: diverged at register byte {offset:#x} (interp {:#04x}, jit {:#04x})",
                case.name, interp_regs[offset], jit_regs[offset]
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of the gated blocks diverged from the interpreter:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
    assert!(ran > 0, "no cases ran");
}

fn first_difference(a: &[u8], b: &[u8]) -> Option<usize> {
    a.iter().zip(b).position(|(x, y)| x != y)
}
