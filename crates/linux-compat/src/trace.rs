//! Architectural execution traces.
//!
//! A trace records what a run did in terms the *architecture* defines —
//! retired instruction counts, register and flag values, the syscall stream —
//! and deliberately not how the engine went about it. That distinction is the
//! whole point: two implementations of the CPU may cache, translate, or
//! schedule differently, and a trace exists to say whether they nevertheless
//! agreed. Milestone 8's gate for a translation tier is that it produces the
//! same trace as the interpreter.
//!
//! It also turns determinism from a claim into a record. Runs can already be
//! compared against each other; a trace committed to the repository lets a run
//! be compared against a fixed baseline that a reviewer can read.
//!
//! # Format
//!
//! Line-oriented text, because a reference trace lives in version control and
//! its value is that a person can diff it. Comment lines carry a
//! self-describing header; every other line is `<icount> <kind> <fields…>`.
//!
//! ```text
//! # webtos-trace 1
//! # image path=/bin/hello len=8816 hash=b3d4…
//! # argv hello
//! # env PATH=/bin
//! # registers RAX RBX … RIP CF ZF …
//! # sample-every 1000
//! 0 state 0x0 0x0 … 0x40000000 0 0 …
//! 23 syscall pid=1000 nr=1 args=0x1,0x400010a0,0x1e,0x0,0x0,0x0 ret=0x1e
//! 2713 exit code=0
//! ```
//!
//! Sample points are chosen by instruction count, not by wall time or host
//! scheduling, so two runs sample at exactly the same places.
//!
//! # What the hashes are and are not
//!
//! The image hash is FNV-1a: enough to notice that a fixture changed, and not
//! a security primitive. Receipts that a third party verifies need a
//! cryptographic digest and a signature, which is a separate layer from this
//! one.

use std::fmt::Write as _;

use icicle_cpu::{Cpu, ValueSource};

/// Format version. Bump when a reader would misinterpret an older file.
pub const FORMAT_VERSION: u32 = 1;

/// Registers a trace samples, in the order they appear on a `state` line.
/// Every name is resolved against the loaded specification; one that is
/// missing is dropped from both the header and the samples, so a trace always
/// describes the columns it actually contains.
const SAMPLED: &[&str] = &[
    "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "R8", "R9", "R10", "R11", "R12", "R13",
    "R14", "R15", "RIP", "CF", "ZF", "SF", "OF", "AF", "PF", "DF",
];

/// A change detector over bytes, not a security digest — see the module note.
pub fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for &byte in bytes {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    hash
}

/// One architecturally observable moment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Register and flag values at a sample point.
    State { icount: u64, values: Vec<u64> },
    /// A syscall the guest issued.
    Syscall {
        icount: u64,
        pid: u64,
        nr: u64,
        args: [u64; 6],
        ret: SyscallResult,
    },
    /// A signal delivered to a task's handler.
    Signal { icount: u64, pid: u64, signal: u64 },
    /// The root process exited.
    Exit { icount: u64, code: i32 },
    /// The run stopped on something other than an exit: a fault, an illegal
    /// instruction, a deadlock.
    Stop { icount: u64, reason: String },
}

/// What a syscall did with the CPU, which is not always "returned a value".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallResult {
    /// Returned to the caller with this value in RAX.
    Value(u64),
    /// Parked the task; the result is written when it is scheduled again,
    /// which this format does not yet attribute back to the entry.
    Blocked,
    /// Did not return: the task exited, or the machine stopped.
    NoReturn,
}

/// Collected events plus the header that makes them self-describing.
pub struct Trace {
    version: u32,
    image: Option<(String, usize, u64)>,
    argv: Vec<String>,
    envp: Vec<String>,
    registers: Vec<(String, pcode::VarNode)>,
    sample_every: u64,
    next_sample: u64,
    events: Vec<Event>,
}

impl Trace {
    /// `sample_every` is in retired instructions; 0 records events only.
    pub fn new(cpu: &Cpu, sample_every: u64) -> Self {
        let registers = SAMPLED
            .iter()
            .filter_map(|name| {
                cpu.arch
                    .sleigh
                    .get_varnode(name)
                    .map(|node| ((*name).to_owned(), node))
            })
            .collect();
        Self {
            version: FORMAT_VERSION,
            image: None,
            argv: Vec::new(),
            envp: Vec::new(),
            registers,
            sample_every,
            next_sample: 0,
            events: Vec::new(),
        }
    }

    /// Records what was run, so a trace identifies its own subject.
    pub fn set_image(&mut self, path: &[u8], bytes: &[u8]) {
        self.image = Some((
            String::from_utf8_lossy(path).into_owned(),
            bytes.len(),
            fnv1a(bytes),
        ));
    }

    pub fn set_args(&mut self, argv: &[Vec<u8>], envp: &[Vec<u8>]) {
        let text = |items: &[Vec<u8>]| {
            items
                .iter()
                .map(|item| String::from_utf8_lossy(item).into_owned())
                .collect()
        };
        self.argv = text(argv);
        self.envp = text(envp);
    }

    pub fn push(&mut self, event: Event) {
        self.events.push(event);
    }

    pub fn events(&self) -> &[Event] {
        &self.events
    }

    /// The instruction count at which the next state sample is due, or None
    /// when sampling is off.
    pub fn next_sample(&self) -> Option<u64> {
        (self.sample_every > 0).then_some(self.next_sample)
    }

    /// Reads the sampled registers and records them. Each is read at its own
    /// width — the flags are single bytes in this specification, and reading
    /// one as a word is a fault, not a wide zero.
    pub fn sample(&mut self, cpu: &mut Cpu) {
        let icount = cpu.icount();
        let values = self
            .registers
            .iter()
            .map(|(_, node)| match node.size {
                1 => cpu.read_var::<u8>(*node) as u64,
                2 => cpu.read_var::<u16>(*node) as u64,
                4 => cpu.read_var::<u32>(*node) as u64,
                _ => cpu.read_var::<u64>(*node),
            })
            .collect();
        self.events.push(Event::State { icount, values });
        if self.sample_every > 0 {
            // Skip past any samples the run overshot, so the schedule stays a
            // function of the instruction count rather than of how far a
            // single `run` happened to get.
            self.next_sample = icount
                .saturating_add(self.sample_every)
                .max(self.next_sample.saturating_add(self.sample_every));
        }
    }

    /// Renders the trace in the format this module documents.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "# webtos-trace {}", self.version);
        if let Some((path, len, hash)) = &self.image {
            let _ = writeln!(out, "# image path={path} len={len} hash={hash:016x}");
        }
        if !self.argv.is_empty() {
            let _ = writeln!(out, "# argv {}", self.argv.join(" "));
        }
        for env in &self.envp {
            let _ = writeln!(out, "# env {env}");
        }
        let names: Vec<&str> = self.registers.iter().map(|(n, _)| n.as_str()).collect();
        let _ = writeln!(out, "# registers {}", names.join(" "));
        let _ = writeln!(out, "# sample-every {}", self.sample_every);

        for event in &self.events {
            match event {
                Event::State { icount, values } => {
                    let _ = write!(out, "{icount} state");
                    for value in values {
                        let _ = write!(out, " {value:#x}");
                    }
                    out.push('\n');
                }
                Event::Syscall {
                    icount,
                    pid,
                    nr,
                    args,
                    ret,
                } => {
                    let args = args
                        .iter()
                        .map(|a| format!("{a:#x}"))
                        .collect::<Vec<_>>()
                        .join(",");
                    let _ = write!(out, "{icount} syscall pid={pid} nr={nr} args={args}");
                    match ret {
                        SyscallResult::Value(value) => {
                            let _ = writeln!(out, " ret={value:#x}");
                        }
                        SyscallResult::Blocked => {
                            let _ = writeln!(out, " ret=blocked");
                        }
                        SyscallResult::NoReturn => {
                            let _ = writeln!(out, " ret=noreturn");
                        }
                    }
                }
                Event::Signal {
                    icount,
                    pid,
                    signal,
                } => {
                    let _ = writeln!(out, "{icount} signal pid={pid} nr={signal}");
                }
                Event::Exit { icount, code } => {
                    let _ = writeln!(out, "{icount} exit code={code}");
                }
                Event::Stop { icount, reason } => {
                    let _ = writeln!(out, "{icount} stop {reason}");
                }
            }
        }
        out
    }
}
