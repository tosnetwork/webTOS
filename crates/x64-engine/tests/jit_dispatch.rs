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
use icicle_cpu::ValueSource;
use jit_wasmi::WasmiJit;
use x64_engine::build::{build_x64_vm, EngineConfig};

fn ldef_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
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

/// Runs a memory self-loop that both loads and stores — a prefix-sum scan that
/// reads src[i] into the accumulator and writes the running sum to dst[i] — and
/// returns (final RAX, retired instructions, JIT dispatches, the dst buffer).
/// The whole loop is a host self-loop (Load and Store on every iteration); the
/// region routes both callbacks through the live CPU's MMU.
fn run_scan(jit: bool, count: u64) -> (u64, u64, u64, Vec<u8>) {
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
    // loop: add rax,[rsi] ; mov [rdi],rax ; add rsi,8 ; add rdi,8 ; dec rcx ;
    //       jnz loop ; hlt
    let code = [
        0x48, 0x03, 0x06, // add rax, [rsi]
        0x48, 0x89, 0x07, // mov [rdi], rax
        0x48, 0x83, 0xC6, 0x08, // add rsi, 8
        0x48, 0x83, 0xC7, 0x08, // add rdi, 8
        0x48, 0xFF, 0xC9, // dec rcx
        0x75, 0xED, // jnz loop
        0xF4, // hlt
    ];
    vm.cpu
        .mem
        .write_bytes(base, &code, perm::NONE)
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

    let src_base = 0x20_0000u64;
    let dst_base = 0x30_0000u64;
    let src: Vec<u8> = (0..count)
        .flat_map(|i| i.wrapping_mul(0x9e37_79b9).to_le_bytes())
        .collect();
    let bytes = count * 8;
    let map_len = ((bytes + 0xfff) / 0x1000) * 0x1000;
    for addr in [src_base, dst_base] {
        vm.cpu.mem.map_memory_len(
            addr,
            map_len,
            Mapping {
                perm: perm::READ | perm::WRITE,
                value: 0,
            },
        );
    }
    vm.cpu
        .mem
        .write_bytes(src_base, &src, perm::NONE)
        .expect("src");

    (vm.cpu.arch.on_boot)(&mut vm.cpu, base);
    for (name, value) in [
        ("RAX", 0),
        ("RSI", src_base),
        ("RDI", dst_base),
        ("RCX", count),
    ] {
        let var = vm.cpu.arch.sleigh.get_varnode(name).expect("varnode");
        vm.cpu.write_var(var, value);
    }
    vm.icount_limit = 20 * count + 100;

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
    let mut dst = vec![0u8; bytes as usize];
    vm.cpu
        .mem
        .read_bytes(dst_base, &mut dst, perm::READ)
        .expect("dst");
    (rax, vm.cpu.icount(), vm.jit_dispatch_count(), dst)
}

#[test]
fn a_memory_self_loop_region_matches_the_interpreter() {
    // A host self-loop — Load and Store on every iteration — region-compiled:
    // the whole loop is one wasm function, so thousands of iterations are a
    // handful of dispatches, and the loads/stores route through the live CPU's
    // MMU exactly as the per-block path does. Final registers, retired
    // instruction count, and the written-back memory must all match the
    // interpreter.
    let count = 3_000u64;
    let interp = run_scan(false, count);
    let jit = run_scan(true, count);
    assert_eq!(
        interp.2, 0,
        "memory self-loop: the interpreter run must not JIT"
    );
    assert!(jit.2 > 0, "memory self-loop: the JIT run never dispatched");
    assert_eq!(
        interp.0, jit.0,
        "memory self-loop: final RAX diverged (interp {:#x}, jit {:#x})",
        interp.0, jit.0
    );
    assert_eq!(
        interp.1, jit.1,
        "memory self-loop: retired instruction count diverged (interp {}, jit {})",
        interp.1, jit.1
    );
    assert_eq!(
        interp.3, jit.3,
        "memory self-loop: written-back guest memory diverged"
    );
    // Region-dispatched: a handful of fuel slices, not one dispatch per
    // iteration (which would be ~count).
    assert!(
        (1..=8).contains(&jit.2),
        "memory self-loop: expected a few region dispatches, got {} (per-iteration would be ~{count})",
        jit.2
    );
}

/// Runs a memory self-loop whose source pointer walks off the end of a
/// one-page buffer after exactly 512 eight-byte reads, so the load faults on
/// the 513th iteration. Returns the post-fault state:
/// (RAX, exception code, exception value, PC, retired instructions,
/// block offset, JIT dispatches).
fn run_scan_fault(jit: bool) -> (u64, u32, u64, u64, u64, u64, u64) {
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
    // loop: add rax,[rsi] ; add rsi,8 ; dec rcx ; jnz loop ; hlt
    let code = [
        0x48, 0x03, 0x06, // add rax, [rsi]
        0x48, 0x83, 0xC6, 0x08, // add rsi, 8
        0x48, 0xFF, 0xC9, // dec rcx
        0x75, 0xF4, // jnz loop
        0xF4, // hlt
    ];
    vm.cpu
        .mem
        .write_bytes(base, &code, perm::NONE)
        .expect("code");

    // Exactly one mapped page for the source; the page after it is unmapped, so
    // the 513th read (offset 0x1000) faults.
    let src_base = 0x20_0000u64;
    vm.cpu.mem.map_memory_len(
        src_base,
        0x1000,
        Mapping {
            perm: perm::READ | perm::WRITE,
            value: 0,
        },
    );
    let src: Vec<u8> = (0u64..512)
        .flat_map(|i| i.wrapping_mul(0x9e37_79b9).to_le_bytes())
        .collect();
    vm.cpu
        .mem
        .write_bytes(src_base, &src, perm::NONE)
        .expect("src");

    (vm.cpu.arch.on_boot)(&mut vm.cpu, base);
    // RCX far exceeds the 512 readable slots, so the fault — not the counter —
    // ends the loop.
    for (name, value) in [("RAX", 0), ("RSI", src_base), ("RCX", 2_000)] {
        let var = vm.cpu.arch.sleigh.get_varnode(name).expect("varnode");
        vm.cpu.write_var(var, value);
    }
    vm.icount_limit = 1_000_000;

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
    (
        rax,
        vm.cpu.exception.code,
        vm.cpu.exception.value,
        vm.cpu.read_pc(),
        vm.cpu.icount(),
        vm.cpu.block_offset,
        vm.jit_dispatch_count(),
    )
}

#[test]
fn a_faulting_memory_self_loop_region_matches_the_interpreter() {
    // The whole point: a region that faults partway must reproduce the
    // interpreter's mid-loop stop exactly — the completed iterations charged in
    // full, and the partial faulting iteration's PC, fuel, exception, and resume
    // offset all matching. RAX must match too: on the faulting iteration the
    // load faults before the add, so the accumulator is not updated.
    let interp = run_scan_fault(false);
    let jit = run_scan_fault(true);
    assert_eq!(interp.6, 0, "the interpreter run must not JIT");
    assert!(jit.6 > 0, "the JIT run never dispatched — proves nothing");
    assert_eq!(
        (interp.0, interp.1, interp.2, interp.3, interp.4, interp.5),
        (jit.0, jit.1, jit.2, jit.3, jit.4, jit.5),
        "post-fault state diverged: interp (rax {:#x}, code {:#06x}, val {:#x}, pc {:#x}, \
         icount {}, offset {}), jit (rax {:#x}, code {:#06x}, val {:#x}, pc {:#x}, icount {}, \
         offset {})",
        interp.0,
        interp.1,
        interp.2,
        interp.3,
        interp.4,
        interp.5,
        jit.0,
        jit.1,
        jit.2,
        jit.3,
        jit.4,
        jit.5
    );
    // 512 whole iterations of the 4-instruction body, plus the one faulting
    // guest instruction (`add rax,[rsi]`, whose load faults).
    assert_eq!(jit.4, 512 * 4 + 1, "retired instruction count off");
    // Region-dispatched, not one per iteration.
    assert!(
        (1..=8).contains(&jit.6),
        "faulting self-loop: expected a few region dispatches, got {}",
        jit.6
    );
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
