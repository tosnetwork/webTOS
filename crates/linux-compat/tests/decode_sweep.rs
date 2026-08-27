//! The guest picks the bytes it executes. It can map a page writable and
//! executable, fill it with anything, and jump there — so the decoder is fed
//! attacker-chosen input before any syscall is involved, and a decoder that
//! panics is a tab a page can kill from inside.
//!
//! Refusing bytes is correct: `DecodeError` becomes an illegal-instruction
//! exception the guest sees. Panicking on them is the defect, and so is
//! reading past the end of what the guest mapped — an instruction that starts
//! four bytes before an unmapped page must not decode by reading into it.

use std::cell::Cell;
use std::collections::HashMap;
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::{Mutex, Once};

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
                    // Every case is exactly sixteen bytes — one more than the
                    // longest legal instruction — so the truncation pass can
                    // take any prefix of it without running out of case.
                    while bytes.len() < 16 {
                        let next = tail[(bytes.len()) % tail.len()];
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

#[test]
fn no_instruction_bytes_take_the_decoder_down() {
    let all = cases();
    let region = (all.len() as u64 + 1) * STRIDE;
    let mut probe = Probe::new(region.next_multiple_of(4096));

    // Written in one pass, then decoded in one pass: a block lifted from one
    // case runs on into the next, which marks those bytes as code and makes a
    // later write to them a self-modification. Filling first avoids paying a
    // cache flush per case.
    probe.clear();
    for (i, (bytes, _)) in all.iter().enumerate() {
        let at = probe.base + i as u64 * STRIDE;
        probe.write(at, bytes);
    }

    let mut failures: Vec<String> = Vec::new();
    let mut decoded = 0_u64;
    for (i, (_, name)) in all.iter().enumerate() {
        let at = probe.base + i as u64 * STRIDE;
        match probe.lift(at) {
            Ok(true) => decoded += 1,
            Ok(false) => {}
            Err(message) => {
                if failures.len() < 40 {
                    failures.push(format!("{name}: {message}"));
                }
            }
        }
    }

    println!(
        "decoded {} of {} byte sequences; the rest were refused",
        decoded,
        all.len()
    );

    // A sweep where nothing decodes has not reached the decoder — it would
    // report "no panics" whether or not the decoder was sound.
    assert!(
        decoded > all.len() as u64 / 10,
        "only {decoded} of {} sequences decoded; the sweep is not reaching \
         the decoder",
        all.len()
    );
    assert!(
        failures.is_empty(),
        "{} of {} sequences panicked the decoder:\n  {}",
        failures.len(),
        all.len(),
        failures.join("\n  ")
    );
}

/// An instruction that starts a few bytes before the end of what the guest
/// mapped must not be decoded by reading into what it did not map.
///
/// This is the same corpus placed differently: every start offset from one to
/// fifteen bytes short of a boundary is a different length calculation
/// running out of input. The region alternates readable and unreadable pages,
/// so one cache flush serves a whole batch of boundaries rather than one.
#[test]
fn the_decoder_stops_at_the_end_of_what_the_guest_mapped() {
    const PAGES: u64 = 512;
    let mut probe = Probe::new(PAGES * 4096);

    // Take away every other page. What remains is 256 readable pages, each
    // ending at a boundary the decoder must not read across.
    const SYS_MPROTECT: u64 = 10;
    const PROT_NONE: u64 = 0;
    let mut boundaries = Vec::new();
    for page in (1..PAGES).step_by(2) {
        let at = probe.base + page * 4096;
        let (ret, _) = probe
            .machine
            .issue_syscall(SYS_MPROTECT, [at, 4096, PROT_NONE, 0, 0, 0]);
        assert_eq!(
            ret, 0,
            "mprotect of a page in our own region returned {ret}"
        );
        boundaries.push(at);
    }
    assert!(
        probe
            .machine
            .vm_mut()
            .cpu
            .mem
            .read_bytes(boundaries[0], &mut [0_u8; 1], icicle_mem::perm::READ)
            .is_err(),
        "a page taken away is still readable, so this test proves nothing \
         about reading past the end"
    );

    // The tail is truncated away in every case, so one is enough; the axes
    // that matter here are the prefix, the opcode, and how few bytes are left.
    let all: Vec<(Vec<u8>, String)> = cases()
        .into_iter()
        .filter(|(_, name)| name.ends_with("all ones"))
        .collect();

    let mut failures: Vec<String> = Vec::new();
    let mut decoded = 0_u64;
    let mut cases_run = 0_u64;
    let mut batch: Vec<(u64, String)> = Vec::new();

    let mut flush_batch = |probe: &mut Probe,
                           batch: &mut Vec<(u64, String)>,
                           failures: &mut Vec<String>,
                           decoded: &mut u64| {
        for (at, name) in batch.drain(..) {
            match probe.lift(at) {
                Ok(true) => *decoded += 1,
                Ok(false) => {}
                Err(message) => {
                    if failures.len() < 40 {
                        failures.push(format!("{name}: {message}"));
                    }
                }
            }
        }
        probe.clear();
    };

    for (bytes, name) in &all {
        for short in 1..=15_u64 {
            if batch.len() == boundaries.len() {
                flush_batch(&mut probe, &mut batch, &mut failures, &mut decoded);
            }
            let at = boundaries[batch.len()] - short;
            probe.write(at, &bytes[..short as usize]);
            batch.push((at, format!("{name}, {short} bytes short")));
            cases_run += 1;
        }
    }
    flush_batch(&mut probe, &mut batch, &mut failures, &mut decoded);

    println!(
        "ran {cases_run} truncated sequences against a mapping boundary; \
         {decoded} decoded within the bytes available"
    );
    assert!(
        failures.is_empty(),
        "{} of {cases_run} truncated sequences panicked the decoder:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}
