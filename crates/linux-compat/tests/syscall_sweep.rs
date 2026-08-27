//! The guest is the untrusted party. That is the whole claim: a browser tab
//! runs a binary nobody vouched for, and the tab survives. So every argument
//! of every syscall is attacker-controlled, and the property worth proving is
//! that no value of them panics the host, aborts it, or reaches memory the
//! guest does not own. A refusal is correct. A panic is a denial of service
//! at best, and at worst the first half of an escape.
//!
//! The sweep is structured rather than random: for each syscall number, each
//! argument position takes each value from a corpus of the ways a number
//! breaks code that trusts it, while the others hold a benign default. Two
//! passes, because a wild pointer tells you nothing about a syscall that
//! rejects the fd before it ever reads memory — one pass with zeros around
//! it, one with plausible values that get past the early checks.

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

/// The highest syscall number the table defines. Numbers above the implemented
/// set are swept too: answering an unknown call with `ENOSYS` is as much a
/// requirement as answering a known one correctly.
const MAX_NR: u64 = 450;

/// Syscalls the sweep does not drive, each for a reason that is about the
/// sweep rather than about the syscall being safe.
///
/// Nothing here is exempt from the property — `execve` and `clone` are
/// exercised for real by the process tests, and `exit_group` has one argument
/// that is a status code. They are left out because a sweep cannot survive
/// them: they replace, duplicate, or end the task doing the sweeping.
const NOT_SWEPT: &[(u64, &str)] = &[
    (57, "fork: 13k processes"),
    (58, "vfork: 13k processes, each blocking its parent"),
    (56, "clone: same"),
    (435, "clone3: same"),
    (59, "execve: replaces the image the sweep runs in"),
    (322, "execveat: same"),
    (60, "exit: ends the sweeping task"),
    (231, "exit_group: ends every task"),
    (
        15,
        "rt_sigreturn: sets pc and every register from guest memory",
    ),
];

/// The ways a number breaks code that trusts it.
///
/// Pointer values are described relative to the page the guest owns rather
/// than baked in, because a reset gives the guest a new address space and a
/// corpus computed once would spend the rest of the sweep aiming at nothing.
#[derive(Clone, Copy)]
enum Value {
    Fixed(u64, &'static str),
    Owned(i64, &'static str),
}

const VALUES: &[Value] = &[
    Value::Fixed(0, "zero"),
    Value::Fixed(1, "one"),
    Value::Fixed(u64::MAX, "-1"),
    Value::Fixed(0x8000_0000_0000_0000, "i64::MIN"),
    Value::Fixed(0x7fff_ffff_ffff_ffff, "i64::MAX"),
    Value::Fixed(0xffff_ffff, "u32::MAX"),
    // 64-bit arithmetic done at `usize` width is correct on this host and
    // wrong on wasm32; the boundary is where that shows.
    Value::Fixed(0x1_0000_0000, "2^32"),
    Value::Fixed(0x0000_8000_0000_0000, "first non-canonical"),
    Value::Fixed(0xffff_8000_0000_0000, "kernel half"),
    Value::Fixed(0xdead_0000, "unmapped"),
    Value::Fixed(0x1000, "low page"),
    Value::Fixed(0xfff, "unaligned and low"),
    Value::Fixed(0x4000_0000_0000, "mid, unmapped"),
    Value::Owned(0, "a page the guest owns"),
    // A structure read from here straddles into the next page, which the
    // guest does not own: the length check has to cover the whole read.
    Value::Owned(4095, "last byte of an owned page"),
    Value::Owned(-1, "one before an owned page"),
];

impl Value {
    fn resolve(self, page: u64) -> u64 {
        match self {
            Value::Fixed(v, _) => v,
            Value::Owned(offset, _) => page.wrapping_add(offset as u64),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Value::Fixed(_, name) | Value::Owned(_, name) => name,
        }
    }
}

/// Values that get past an early argument check, so the sweep reaches code
/// that a pass of zeros never would.
const PLAUSIBLE: [u64; 6] = [1, 0, 16, 0, 0, 0];

/// What the page a pointer argument aims at contains.
///
/// A pointer argument is only half of the input: the syscall then reads a
/// structure through it — an `iovec` array, a `msghdr`, a `sockaddr`, a
/// `timespec` — and every field of that structure is as attacker-controlled
/// as the pointer was. A sweep that always aims at a zeroed page tests the
/// pointer and nothing behind it.
const PATTERNS: &[(u64, &str)] = &[
    (0x0000_0000_0000_0000, "zeros"),
    // Every field reads as -1 or u64::MAX: counts that overflow when scaled,
    // pointers that are not addresses, every flag bit set.
    (0xffff_ffff_ffff_ffff, "all ones"),
    // Every field is an address plus a length away from the end of the
    // address space, so `pointer + length` wraps.
    (0xffff_ffff_ffff_f000, "near the top"),
    // The width boundary: correct at 64 bits, truncated at 32.
    (0x0000_0001_0000_0000, "2^32"),
];

static PANICS: Mutex<Option<HashMap<std::thread::ThreadId, String>>> = Mutex::new(None);
static HOOK: Once = Once::new();
thread_local! {
    static IN_CALL: Cell<bool> = const { Cell::new(false) };
}

fn install_hook() {
    HOOK.call_once(|| {
        // A sweep that trips thousands of panics would bury its own output,
        // so a panic from inside a call is kept rather than printed. Every
        // other panic, including this file's own assertions, still reaches
        // the default hook.
        let default = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if !IN_CALL.with(Cell::get) {
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
    /// A page the guest owns, in the current address space.
    page: u64,
    /// Calls that returned a success rather than an errno. A sweep that only
    /// ever collects refusals has not reached the code it is aiming at.
    reached: std::collections::HashSet<u64>,
    /// What to fill the owned page with. A reset gives a zeroed page, so the
    /// pattern has to be reapplied or the sweep quietly reverts to zeros.
    pattern: u64,
}

impl Probe {
    fn new() -> Self {
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
        let page = Self::map_page(&mut machine);
        Probe {
            machine,
            page,
            reached: std::collections::HashSet::new(),
            pattern: 0,
        }
    }

    fn set_pattern(&mut self, pattern: u64) {
        self.pattern = pattern;
        self.fill_page();
    }

    fn fill_page(&mut self) {
        let bytes: Vec<u8> = std::iter::repeat(self.pattern.to_le_bytes())
            .take(512)
            .flatten()
            .collect();
        self.machine
            .vm_mut()
            .cpu
            .mem
            .write_bytes(self.page, &bytes, icicle_mem::perm::NONE)
            .expect("the sweep owns this page");
    }

    /// A fresh address space for the next case, with a fresh page to aim at.
    /// Cheap — `load` resets the mappings — where building a machine costs
    /// about two seconds.
    fn reset(&mut self) {
        self.machine.set_args(vec![b"probe".to_vec()], vec![]);
        self.machine.load(b"/bin/probe").expect("reload");
        self.page = Self::map_page(&mut self.machine);
        self.fill_page();
    }

    /// A page the guest genuinely owns, obtained the way the guest would.
    fn map_page(machine: &mut Machine) -> u64 {
        const PROT_READ_WRITE: u64 = 3;
        const MAP_PRIVATE_ANONYMOUS: u64 = 0x22;
        let (ret, _) = machine.issue_syscall(
            9,
            [0, 4096, PROT_READ_WRITE, MAP_PRIVATE_ANONYMOUS, u64::MAX, 0],
        );
        assert!(
            ret > 0,
            "the sweep needs a page the guest owns; mmap returned {ret}"
        );
        ret as u64
    }

    /// One call, with a panic caught rather than taking the test binary down:
    /// a sweep that aborts on its first panic reports neither which case
    /// caused it nor what else is behind it.
    fn call(&mut self, nr: u64, args: [u64; 6]) -> Result<bool, String> {
        IN_CALL.with(|c| c.set(true));
        let outcome =
            std::panic::catch_unwind(AssertUnwindSafe(|| self.machine.issue_syscall(nr, args)));
        IN_CALL.with(|c| c.set(false));
        match outcome {
            Ok((ret, ended)) => {
                if ret >= 0 {
                    self.reached.insert(nr);
                }
                Ok(ended)
            }
            Err(_) => Err(PANICS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_mut()
                .and_then(|p| p.remove(&std::thread::current().id()))
                .unwrap_or_else(|| "panicked".into())),
        }
    }
}

#[test]
fn no_syscall_argument_takes_the_host_down() {
    let mut probe = Probe::new();
    let skipped: Vec<u64> = NOT_SWEPT.iter().map(|(nr, _)| *nr).collect();

    let mut failures: Vec<String> = Vec::new();
    let mut cases = 0_u64;
    let mut ended = 0_u64;

    let mut run = |probe: &mut Probe, nr: u64, args: [u64; 6], label: &dyn Fn() -> String| {
        cases += 1;
        match probe.call(nr, args) {
            Ok(false) => {}
            // The task blocked or exited. Both are legitimate answers to some
            // of these arguments; the next case needs a task that can run.
            Ok(true) => {
                ended += 1;
                probe.reset();
            }
            Err(message) => {
                if failures.len() < 40 {
                    failures.push(format!("{}: {message}", label()));
                }
                probe.reset();
            }
        }
    };

    for (pattern, pattern_name) in PATTERNS {
        probe.set_pattern(*pattern);
        for nr in 0..=MAX_NR {
            if skipped.contains(&nr) {
                continue;
            }

            // One bad argument at a time, twice: with zeros around it, and with
            // values that get past the checks a zero would fail.
            for (base, base_name) in [([0_u64; 6], "zeros"), (PLAUSIBLE, "plausible")] {
                for slot in 0..6 {
                    for value in VALUES {
                        let mut args = base;
                        args[slot] = value.resolve(probe.page);
                        let name = value.name();
                        run(&mut probe, nr, args, &|| {
                            format!("nr={nr} arg{slot}={name} ({base_name}, page {pattern_name})")
                        });
                    }
                }
            }

            // Two at a time. One bad argument is usually rejected on its own
            // terms; what gets past that is a plausible argument paired with
            // a hostile one — a pointer the guest really owns with a length
            // that runs off the end of it, which no single-slot case can
            // express.
            for a in 0..6 {
                for b in (a + 1)..6 {
                    for first in VALUES {
                        for second in VALUES {
                            let mut args = [0_u64; 6];
                            args[a] = first.resolve(probe.page);
                            args[b] = second.resolve(probe.page);
                            let (fname, sname) = (first.name(), second.name());
                            run(&mut probe, nr, args, &|| {
                                format!(
                                    "nr={nr} arg{a}={fname} arg{b}={sname} (page {pattern_name})"
                                )
                            });
                        }
                    }
                }
            }
        }
    }

    // Wrapped arithmetic is silent unless the profile checks for it, and four
    // of the five defects this sweep found were wraps. Saying so is the
    // difference between "no defects" and "no defects this profile can see".
    println!(
        "overflow checks: {}",
        if cfg!(debug_assertions) {
            "on"
        } else {
            "OFF — wrapped arithmetic is invisible in this profile; \
             run with --profile relcheck for the sweep to mean what it says"
        }
    );
    println!(
        "swept {cases} cases over syscalls 0..={MAX_NR}, each against {} page contents; \
         {ended} ended or parked the task; \
         {} syscalls returned a success rather than only refusals; \
         {} not swept: {}",
        PATTERNS.len(),
        probe.reached.len(),
        NOT_SWEPT.len(),
        NOT_SWEPT
            .iter()
            .map(|(nr, why)| format!("{nr} ({why})"))
            .collect::<Vec<_>>()
            .join(", ")
    );

    // A sweep that only ever collects refusals has bounced off the argument
    // checks without reaching the code behind them, and would report "no
    // panics" whether or not the code behind them was sound.
    assert!(
        probe.reached.len() >= 40,
        "only {} syscalls got past their argument checks; the sweep is not \
         reaching the code it is aiming at",
        probe.reached.len()
    );

    assert!(
        failures.is_empty(),
        "{} of {cases} cases panicked:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

/// The sweep's page patterns are only worth their cost if the syscall behind
/// the pointer actually reads them. If the fill wrote to the wrong place, or
/// a reset quietly reverted it to zeros, every pattern would produce the same
/// result and the sweep would report four passes having done one.
///
/// `nanosleep` reads a `timespec` through its first argument and rejects a
/// nanosecond field outside [0, 1e9). Zeros are a valid zero-length sleep;
/// all-ones is not a valid anything.
#[test]
fn the_page_a_pointer_aims_at_reaches_the_syscall() {
    const SYS_NANOSLEEP: u64 = 35;
    let mut probe = Probe::new();

    probe.set_pattern(0);
    let (zeroed, _) = probe
        .machine
        .issue_syscall(SYS_NANOSLEEP, [probe.page, 0, 0, 0, 0, 0]);

    probe.set_pattern(u64::MAX);
    let (ones, _) = probe
        .machine
        .issue_syscall(SYS_NANOSLEEP, [probe.page, 0, 0, 0, 0, 0]);

    assert_eq!(zeroed, 0, "a zeroed timespec is a valid zero-length sleep");
    assert!(
        ones < 0,
        "a timespec of all ones was accepted ({ones}); the page pattern is \
         not reaching the syscall, so the sweep's four passes are one pass \
         run four times"
    );
}
