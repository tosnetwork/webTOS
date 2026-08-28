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

// ── JIT cache identity: a compiled handle must never outlive the bytes it was
//    built from at the same virtual address ───────────────────────────────────
//
// Both JIT caches are keyed by block start. When a block is re-lifted at the
// same VA — self-modifying code (the run loop calls `flush_code`), or a new
// image at that VA in a fresh address space (`execve` bumps the asid) — the
// stale handle must not be reused. Each test compiles one loop, then runs a
// different loop at the same address and checks the result matches the
// interpreter and that the new bytes actually recompiled.

/// add rax, rbx ; dec rcx ; jnz -8 ; hlt  — RAX ends at +N.
const LOOP_ADD: [u8; 9] = [0x48, 0x01, 0xD8, 0x48, 0xFF, 0xC9, 0x75, 0xF8, 0xF4];
/// sub rax, rbx ; dec rcx ; jnz -8 ; hlt  — same layout, RAX ends at -N.
const LOOP_SUB: [u8; 9] = [0x48, 0x29, 0xD8, 0x48, 0xFF, 0xC9, 0x75, 0xF8, 0xF4];

fn seed_loop(vm: &mut x64_engine::InterpVm, n: u64) {
    for (name, val) in [("RAX", 0u64), ("RBX", 1), ("RCX", n)] {
        let v = vm.cpu.arch.sleigh.get_varnode(name).expect("varnode");
        vm.cpu.write_var(v, val);
    }
}

fn jit_vm_with_writable_code(base: u64) -> x64_engine::InterpVm {
    let mut vm = build_x64_vm(&ldef_path(), &EngineConfig::default()).expect("build vm");
    vm.cpu.mem.reset_virtual();
    vm.cpu.reset();
    vm.cpu.mem.map_memory_len(
        base,
        0x1000,
        Mapping {
            perm: perm::READ | perm::WRITE | perm::EXEC | perm::INIT,
            value: 0,
        },
    );
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
    vm.set_jit(Box::new(WasmiJit::new()));
    vm.set_jit_tiering(Some(1));
    vm
}

#[test]
fn self_modifying_code_drops_the_stale_jit_handle() {
    let base = 0x40_0000u64;
    let n = 100u64;
    let want = run_program(
        false,
        &LOOP_SUB,
        &[("RAX", 0), ("RBX", 1), ("RCX", n)],
        None,
        100_000,
    )
    .0;

    let mut vm = jit_vm_with_writable_code(base);
    let rax = vm.cpu.arch.sleigh.get_varnode("RAX").expect("RAX");

    vm.cpu
        .mem
        .write_bytes(base, &LOOP_ADD, perm::NONE)
        .expect("write add");
    (vm.cpu.arch.on_boot)(&mut vm.cpu, base);
    seed_loop(&mut vm, n);
    vm.icount_limit = vm.cpu.icount() + 100_000;
    let _ = vm.run();
    assert_eq!(vm.cpu.read_reg(rax), n, "phase 1 (add) result");
    assert!(vm.jit_dispatch_count() > 0, "phase 1 must actually JIT");

    vm.cpu
        .mem
        .write_bytes(base, &LOOP_SUB, perm::NONE)
        .expect("write sub");
    vm.flush_code();
    vm.cpu.block_id = u64::MAX;
    vm.cpu.block_offset = 0;
    vm.cpu.write_pc(base);
    seed_loop(&mut vm, n);
    vm.icount_limit = vm.cpu.icount() + 100_000;
    let before = vm.jit_dispatch_count();
    let _ = vm.run();
    assert_eq!(
        vm.cpu.read_reg(rax),
        want,
        "after flush the JIT ran the stale add handle instead of the re-lifted sub block"
    );
    assert!(
        vm.jit_dispatch_count() > before,
        "the re-lifted block must recompile and dispatch, not sit on a stale entry"
    );
}

#[test]
fn a_new_address_space_does_not_reuse_the_jit_handle() {
    let base = 0x40_0000u64;
    let n = 100u64;
    let want = run_program(
        false,
        &LOOP_SUB,
        &[("RAX", 0), ("RBX", 1), ("RCX", n)],
        None,
        100_000,
    )
    .0;

    x64_engine::vm::set_current_asid(1);
    let mut vm = jit_vm_with_writable_code(base);
    let rax = vm.cpu.arch.sleigh.get_varnode("RAX").expect("RAX");

    vm.cpu
        .mem
        .write_bytes(base, &LOOP_ADD, perm::NONE)
        .expect("write add");
    (vm.cpu.arch.on_boot)(&mut vm.cpu, base);
    seed_loop(&mut vm, n);
    vm.icount_limit = vm.cpu.icount() + 100_000;
    let _ = vm.run();
    assert_eq!(vm.cpu.read_reg(rax), n, "asid 1 (add) result");
    assert!(vm.jit_dispatch_count() > 0, "asid 1 must actually JIT");

    x64_engine::vm::set_current_asid(2);
    vm.cpu
        .mem
        .write_bytes(base, &LOOP_SUB, perm::NONE)
        .expect("write sub");
    vm.cpu.block_id = u64::MAX;
    vm.cpu.block_offset = 0;
    vm.cpu.write_pc(base);
    seed_loop(&mut vm, n);
    vm.icount_limit = vm.cpu.icount() + 100_000;
    let before = vm.jit_dispatch_count();
    let _ = vm.run();
    x64_engine::vm::set_current_asid(0);
    assert_eq!(
        vm.cpu.read_reg(rax),
        want,
        "the JIT served the asid-1 add handle for the asid-2 sub block at the same VA"
    );
    assert!(
        vm.jit_dispatch_count() > before,
        "the asid-2 block must recompile and dispatch"
    );
}

// ── Compiled-code budget: over the cap, the least-recently-used compiled block
//    is evicted and recompiled on demand, and results stay correct ────────────

#[test]
fn the_code_budget_evicts_and_recompiles() {
    let base = 0x40_0000u64;
    let n = 100u64;
    // A register self-loop: RAX ends at n. Compiles as a region.
    let want = run_program(
        false,
        &LOOP_ADD,
        &[("RAX", 0), ("RBX", 1), ("RCX", n)],
        None,
        100_000,
    )
    .0;

    let mut vm = jit_vm_with_writable_code(base);
    vm.cpu
        .mem
        .write_bytes(base, &LOOP_ADD, perm::NONE)
        .expect("code");
    (vm.cpu.arch.on_boot)(&mut vm.cpu, base);
    let rax = vm.cpu.arch.sleigh.get_varnode("RAX").expect("RAX");

    let mut run_under = |vm: &mut x64_engine::InterpVm, asid: u64| {
        x64_engine::vm::set_current_asid(asid);
        seed_loop(vm, n);
        vm.cpu.write_pc(base);
        vm.cpu.block_id = u64::MAX;
        vm.cpu.block_offset = 0;
        vm.icount_limit = vm.cpu.icount() + 100_000;
        let _ = vm.run();
    };

    // Learn one address space's total compiled size with no budget in force.
    run_under(&mut vm, 1);
    let one = vm.jit_code_stats();
    assert!(
        one.live >= 1 && one.total_bytes > 0,
        "something compiled: {one:?}"
    );

    // Cap the budget at one address space's worth, then run the same program
    // under many address spaces — each a distinct block identity and set of
    // handles — so the cap is exceeded and older handles are evicted.
    let baseline = one.total_bytes;
    vm.set_jit_code_budget(baseline);
    for asid in 2..12u64 {
        run_under(&mut vm, asid);
        assert_eq!(
            vm.cpu.read_reg(rax),
            want,
            "asid {asid} produced the wrong result under the budget"
        );
        let s = vm.jit_code_stats();
        assert!(
            s.total_bytes <= s.budget,
            "asid {asid} held more than the budget: {s:?}"
        );
    }
    let s = vm.jit_code_stats();
    assert!(s.evictions > 0, "the budget should have evicted: {s:?}");
    assert!(s.compiles >= 11, "each new address space recompiles: {s:?}");

    // Asid 1 was evicted long ago; running it again must recompile and be correct.
    let before = vm.jit_code_stats().compiles;
    run_under(&mut vm, 1);
    x64_engine::vm::set_current_asid(0);
    assert_eq!(
        vm.cpu.read_reg(rax),
        want,
        "evicted asid 1 recompiled wrong"
    );
    assert!(
        vm.jit_code_stats().compiles > before,
        "asid 1 should have recompiled after eviction, not stayed bailed"
    );
}

// ── Resumable page-in: a fault on a non-resident page is served and the faulting
//    instruction retried, identically to an eager run ──────────────────────────
//
// Synthetic demand-paging prototype (feasibility/lazy_chunk_fs.md, Phase 0): a
// data page is mapped but left non-resident (no READ), with its bytes registered
// to fill on first access. The first guest load faults; the engine fills the page
// and retries the same pcode; the rest of the scan finds it resident. The result,
// the retired instruction count, and the page-in count must be exactly what an
// eager run produces — for the interpreter and for the JIT (region) path, which
// faults out and lets the interpreter retry at the faulting offset.

fn run_page_in_scan(code: &[u8], count: u64, jit: bool, lazy: bool) -> (u64, u64, u64) {
    let base = 0x40_0000u64;
    let buf = 0x20_0000u64;
    let data: Vec<u8> = (0..count).map(|i| (i & 0xff) as u8).collect();

    let mut vm = build_x64_vm(&ldef_path(), &EngineConfig::default()).expect("build vm");
    vm.cpu.mem.reset_virtual();
    vm.cpu.reset();
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

    if lazy {
        // Mapped but not resident: writable and initialized, but not readable, so
        // the first load faults. Register the page's bytes to fill on that fault.
        vm.cpu.mem.map_memory_len(
            buf,
            0x1000,
            Mapping {
                perm: perm::WRITE | perm::INIT,
                value: 0,
            },
        );
        let mut page = vec![0u8; 0x1000];
        page[..data.len()].copy_from_slice(&data);
        vm.register_lazy_page(buf, page, perm::READ | perm::WRITE | perm::INIT);
    } else {
        vm.cpu.mem.map_memory_len(
            buf,
            0x1000,
            Mapping {
                perm: perm::READ | perm::WRITE | perm::INIT,
                value: 0,
            },
        );
        vm.cpu
            .mem
            .write_bytes(buf, &data, perm::NONE)
            .expect("data");
    }

    (vm.cpu.arch.on_boot)(&mut vm.cpu, base);
    for (n, v) in [("RAX", 0u64), ("RSI", buf), ("RCX", count)] {
        let var = vm.cpu.arch.sleigh.get_varnode(n).expect("varnode");
        vm.cpu.write_var(var, v);
    }
    vm.icount_limit = 20 * count + 100;
    if jit {
        vm.set_jit(Box::new(WasmiJit::new()));
        vm.set_jit_tiering(Some(1));
    }
    let _ = vm.run();
    let rax = vm
        .cpu
        .read_reg(vm.cpu.arch.sleigh.get_varnode("RAX").expect("RAX"));
    (rax, vm.cpu.icount(), vm.page_in_count())
}

#[test]
fn a_page_in_retries_identically_to_an_eager_run() {
    // A single-block self-loop (the JIT compiles it as a region), and a two-block
    // loop whose memory-reading header is not a self-loop (the JIT compiles it on
    // the per-block path). Both, interpreted and JIT'd, must page in once and
    // match the eager run.
    // region form: movzx edx,[rsi]; add rax,rdx; inc rsi; dec rcx; jnz; hlt
    let region_loop = [
        0x0f, 0xb6, 0x16, 0x48, 0x01, 0xd0, 0x48, 0xff, 0xc6, 0x48, 0xff, 0xc9, 0x75, 0xf2, 0xf4,
    ];
    // per-block form: header A reads memory and conditionally exits (a branch, so
    // A is its own block, not a self-loop); block B advances and jumps back to A.
    //   A: movzx edx,[rsi]; add rax,rdx; test rcx,rcx; jz done
    //   B: inc rsi; dec rcx; jmp A
    //   done: hlt
    let per_block_loop = [
        0x0f, 0xb6, 0x16, 0x48, 0x01, 0xd0, 0x48, 0x85, 0xc9, 0x74, 0x08, 0x48, 0xff, 0xc6, 0x48,
        0xff, 0xc9, 0xeb, 0xed, 0xf4,
    ];
    for (label, code) in [
        ("region", &region_loop[..]),
        ("per-block", &per_block_loop[..]),
    ] {
        for jit in [false, true] {
            let mode = if jit { "JIT" } else { "interp" };
            let eager = run_page_in_scan(code, 512, jit, false);
            let lazy = run_page_in_scan(code, 512, jit, true);
            assert_eq!(eager.2, 0, "{label}/{mode}: eager run must not page in");
            assert_eq!(
                lazy.2, 1,
                "{label}/{mode}: lazy run must page in exactly once, got {}",
                lazy.2
            );
            assert_eq!(
                eager.0, lazy.0,
                "{label}/{mode}: result diverged (eager {:#x}, lazy {:#x})",
                eager.0, lazy.0
            );
            assert_eq!(
                eager.1, lazy.1,
                "{label}/{mode}: retired instruction count diverged (eager {}, lazy {})",
                eager.1, lazy.1
            );
        }
    }
}
