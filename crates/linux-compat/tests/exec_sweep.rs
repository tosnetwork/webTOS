//! Decoding bytes is one surface; running them is another. The p-code the
//! lifter produces is executed by an interpreter, and an instruction's
//! effective address is computed from registers the guest also chose — so
//! every memory translation the MMU performs is on an address an attacker
//! picked, reached without a syscall at all.
//!
//! Faulting is correct: a page fault or an illegal instruction is an
//! exception the guest sees. Panicking is the defect.

use std::cell::Cell;
use std::collections::HashMap;
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::{Mutex, Once};

use icicle_cpu::ValueSource;
use linux_compat::Machine;
use x64_engine::EngineConfig;

fn ldef_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

/// Byte sequences that change how everything after them decodes: operand and
/// address size, the REX register extensions, the lock and repeat prefixes,
/// segment overrides, and the three vector encodings that redefine the
/// opcode map entirely.
const PREFIXES: &[(&[u8], &str)] = &[
    (&[], "none"),
    (&[0x66], "66 operand size"),
    (&[0x67], "67 address size"),
    (&[0xf0], "lock"),
    (&[0xf2], "repne"),
    (&[0xf3], "rep"),
    (&[0x2e], "cs segment"),
    (&[0x64], "fs segment"),
    (&[0x65], "gs segment"),
    (&[0x48], "rex.w"),
    (&[0x4f], "rex.wrxb"),
    (&[0x66, 0x48], "66 + rex.w"),
    (&[0xf3, 0x48], "rep + rex.w"),
    (&[0xf2, 0x66, 0x67, 0x4f], "four prefixes"),
    (&[0xc5, 0xf8], "vex2"),
    (&[0xc4, 0xe2, 0x7d], "vex3"),
    (&[0x62, 0xf1, 0x7c, 0x48], "evex"),
];

/// The opcode maps. An escape byte moves the opcode into a different table,
/// and each table has its own holes.
const MAPS: &[(&[u8], &str)] = &[
    (&[], "1-byte"),
    (&[0x0f], "0f"),
    (&[0x0f, 0x38], "0f 38"),
    (&[0x0f, 0x3a], "0f 3a"),
];

/// What follows the opcode. The ModRM byte decides how many more bytes an
/// instruction has, so each of its addressing forms is a different length
/// calculation — and a length calculation is where a decoder runs off the end.
const TAILS: &[([u8; 10], &str)] = &[
    ([0x00; 10], "modrm 00, zeros"),
    ([0xc0; 10], "modrm c0, register direct"),
    (
        [0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        "sib",
    ),
    (
        [0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        "rip-relative",
    ),
    (
        [0x94, 0xc8, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00],
        "sib + disp32",
    ),
    ([0xff; 10], "all ones"),
];

/// Bytes per case in the scratch region. Long enough for the longest legal
/// instruction (15 bytes) plus a boundary.
const STRIDE: u64 = 32;

static PANICS: Mutex<Option<HashMap<std::thread::ThreadId, String>>> = Mutex::new(None);
static HOOK: Once = Once::new();
thread_local! {
    static IN_LIFT: Cell<bool> = const { Cell::new(false) };
}

fn install_hook() {
    HOOK.call_once(|| {
        let default = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if !IN_LIFT.with(Cell::get) {
                return default(info);
            }
            PANICS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get_or_insert_with(HashMap::new)
                .insert(
                    std::thread::current().id(),
                    format!("{info}").replace('\n', " "),
                );
        }));
    });
}

struct Probe {
    machine: Machine,
    /// A writable, executable region the guest asked for, the way a guest
    /// that wanted to run bytes of its own choosing would.
    base: u64,
    len: u64,
}

impl Probe {
    fn new(len: u64) -> Self {
        install_hook();
        let mut machine =
            Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build");
        let image = std::fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_data/hello_linux.elf"),
        )
        .expect("in-repo fixture");
        machine.add_file(b"/bin/probe", image, 0o755).expect("seed");
        machine.set_args(vec![b"probe".to_vec()], vec![]);
        machine.load(b"/bin/probe").expect("load");
        const PROT_READ_WRITE_EXEC: u64 = 7;
        const MAP_PRIVATE_ANONYMOUS: u64 = 0x22;
        let (base, _) = machine.issue_syscall(
            9,
            [
                0,
                len,
                PROT_READ_WRITE_EXEC,
                MAP_PRIVATE_ANONYMOUS,
                u64::MAX,
                0,
            ],
        );
        assert!(base > 0, "mmap of an executable region returned {base}");
        Probe {
            machine,
            base: base as u64,
            len,
        }
    }

    /// A fresh address space with a fresh executable region, for after a case
    /// ends the task.
    fn reload(&mut self) {
        self.machine.set_args(vec![b"probe".to_vec()], vec![]);
        self.machine.load(b"/bin/probe").expect("reload");
        const PROT_READ_WRITE_EXEC: u64 = 7;
        const MAP_PRIVATE_ANONYMOUS: u64 = 0x22;
        let (base, _) = self.machine.issue_syscall(
            9,
            [
                0,
                self.len,
                PROT_READ_WRITE_EXEC,
                MAP_PRIVATE_ANONYMOUS,
                u64::MAX,
                0,
            ],
        );
        assert!(base > 0, "remapping the executable region returned {base}");
        self.base = base as u64;
    }

    /// Empties the block cache so the next write is not refused as a change
    /// to code already lifted, and so an address can be reused.
    fn clear(&mut self) {
        self.machine.vm_mut().flush_code();
        self.machine.vm_mut().cpu.mem.clear_code_cache();
    }

    fn write(&mut self, at: u64, bytes: &[u8]) {
        self.machine
            .vm_mut()
            .cpu
            .mem
            .write_bytes(at, bytes, icicle_mem::perm::NONE)
            .expect("the sweep owns this region");
    }

    /// Decodes at `at`, catching a panic rather than taking the test binary
    /// down: a sweep that stops at its first panic reports neither which
    /// bytes caused it nor what else is behind it.
    fn lift(&mut self, at: u64) -> Result<bool, String> {
        IN_LIFT.with(|c| c.set(true));
        let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| self.machine.vm_mut().lift(at)));
        IN_LIFT.with(|c| c.set(false));
        match outcome {
            Ok(result) => Ok(result.is_ok()),
            Err(_) => Err(PANICS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_mut()
                .and_then(|p| p.remove(&std::thread::current().id()))
                .unwrap_or_else(|| "panicked".into())),
        }
    }
}

/// One case: the bytes, and a name that identifies them if they break something.
fn cases() -> Vec<(Vec<u8>, String)> {
    let mut out = Vec::new();
    for (prefix, pname) in PREFIXES {
        for (map, mname) in MAPS {
            for opcode in 0..=0xff_u8 {
                for (tail, tname) in TAILS {
                    let mut bytes = Vec::with_capacity(16);
                    bytes.extend_from_slice(prefix);
                    bytes.extend_from_slice(map);
                    bytes.push(opcode);
                    bytes.extend_from_slice(tail);
                    while bytes.len() < 16 {
                        let next = tail[bytes.len() % tail.len()];
                        bytes.push(next);
                    }
                    bytes.truncate(16);
                    out.push((
                        bytes,
                        format!("{pname} / {mname} / {opcode:#04x} / {tname}"),
                    ));
                }
            }
        }
    }
    out
}

/// The registers an effective address is computed from. Naming them here
/// rather than taking whatever the loaded program left behind is the point:
/// the guest chooses these, so the sweep must too.
const GPRS: &[&str] = &[
    "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "R8", "R9", "R10", "R11", "R12", "R13",
    "R14", "R15",
];

/// How many instructions a case is allowed before the sweep moves on. Enough
/// for a prefix, the instruction, and a few of whatever follows; small enough
/// that a case which lands in a loop does not hold up the sweep.
const STEPS: u64 = 8;

#[test]
fn no_executed_bytes_take_the_interpreter_down() {
    let all = cases();
    let region = (all.len() as u64 + 1) * STRIDE;
    let mut probe = Probe::new(region.next_multiple_of(4096));
    let base = probe.base;
    let regs: Vec<_> = GPRS
        .iter()
        .map(|name| {
            probe
                .machine
                .vm_mut()
                .cpu
                .arch
                .sleigh
                .get_varnode(name)
                .unwrap_or_else(|| panic!("SLEIGH spec is missing {name}"))
        })
        .collect();

    probe.clear();
    for (i, (bytes, _)) in all.iter().enumerate() {
        probe.write(base + i as u64 * STRIDE, bytes);
    }

    // A register value that is a valid address reaches translation; one that
    // is not stops at the fault. Both are worth running, and a usable stack
    // pointer is worth one pattern of its own, because the instructions that
    // touch the stack are otherwise turned away before they compute anything.
    let stack = base + probe.len / 2;
    let patterns: &[(u64, Option<u64>, &str)] = &[
        (0, None, "zeros"),
        (u64::MAX, None, "all ones"),
        (base, None, "the region itself"),
        (base + 4095, None, "a page boundary"),
        (0x0000_8000_0000_0000, None, "first non-canonical"),
        (0xffff_8000_0000_0000, None, "kernel half"),
        (0x1_0000_0000, None, "2^32"),
        (u64::MAX, Some(stack), "all ones, usable stack"),
        (base + 4095, Some(stack), "page boundary, usable stack"),
    ];

    let mut failures: Vec<String> = Vec::new();
    let mut executed = 0_u64;
    let mut faulted = 0_u64;
    let mut restarts = 0_u64;
    let mut cases_run = 0_u64;

    for (pattern, stack_at, pname) in patterns {
        for (i, (_, name)) in all.iter().enumerate() {
            let at = base + i as u64 * STRIDE;
            {
                let cpu = &mut probe.machine.vm_mut().cpu;
                for (slot, reg) in regs.iter().enumerate() {
                    let value = match (stack_at, GPRS[slot]) {
                        (Some(sp), "RSP") | (Some(sp), "RBP") => *sp,
                        _ => *pattern,
                    };
                    cpu.write_var(*reg, value);
                }
                cpu.write_pc(at);
            }
            probe.machine.vm_mut().icount_limit = probe.machine.icount() + STEPS;
            cases_run += 1;

            IN_LIFT.with(|c| c.set(true));
            let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| probe.machine.run()));
            IN_LIFT.with(|c| c.set(false));

            match outcome {
                Ok(exit) => {
                    if format!("{exit:?}").contains("Fault") {
                        faulted += 1;
                    } else {
                        executed += 1;
                    }
                }
                Err(_) => {
                    if failures.len() < 40 {
                        let message = PANICS
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .as_mut()
                            .and_then(|p| p.remove(&std::thread::current().id()))
                            .unwrap_or_else(|| "panicked".into());
                        failures.push(format!("{name} with registers {pname}: {message}"));
                    }
                }
            }

            // Executed bytes can end the task — a `syscall` instruction is two
            // bytes and appears in this corpus. Rebuild rather than sweep the
            // rest against a machine with no process on it.
            if probe.machine.exit_code().is_some() {
                restarts += 1;
                probe.reload();
                probe.clear();
                for (j, (bytes, _)) in all.iter().enumerate() {
                    probe.write(probe.base + j as u64 * STRIDE, bytes);
                }
            }
        }
    }

    println!(
        "ran {cases_run} byte sequences against {} register patterns; \
         {executed} ran to the step limit or stopped for another reason, \
         {faulted} faulted, {restarts} ended the task and needed a rebuild",
        patterns.len()
    );

    // If everything faulted before executing anything, the sweep never
    // reached the interpreter and would report "no panics" regardless.
    assert!(
        executed > cases_run / 20,
        "only {executed} of {cases_run} cases got past the first fault; \
         the sweep is not reaching the interpreter"
    );
    assert!(
        failures.is_empty(),
        "{} of {cases_run} cases panicked:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}
