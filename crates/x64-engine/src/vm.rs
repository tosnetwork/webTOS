//! Interpreter-only VM loop.
//!
//! Ported from the upstream icicle `icicle-vm` crate (see
//! `third_party/icicle/PROVENANCE.md`), with the JIT, code injectors, and
//! snapshot machinery removed so the loop has no native-code dependencies and
//! compiles for `wasm32-unknown-unknown`.

use icicle_cpu::{
    lifter::{self, Target},
    BlockKey, BlockTable, Cpu, Environment, EnvironmentAny, Exception, ExceptionCode,
    InternalError, ValueSource, VmExit,
};

// Mirrors of the running machine's state, for code that cannot reach the CPU
// — memory-write hooks, and the block cache's key.
//
// These are per-thread, not per-process. A machine belongs to the thread
// running it: in a browser there is one, but a test binary runs several at
// once, and process-wide statics let those machines overwrite each other's
// address-space id. The symptom was an engine-level `InternalError` that
// moved between tests, roughly four runs in fourteen, and never appeared
// single-threaded.
//
// `const`-initialised `Cell`s, so access is a TLS offset rather than a lazy
// initialisation check — `set_current_block_start` runs once per basic block.
thread_local! {
    static BLOCK_START: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static ASID: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static ICOUNT: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Guest address of the basic block currently executing in the interpreter.
/// A diagnostic mirror for memory-write hooks, which cannot see the CPU.
pub fn current_block_start() -> u64 {
    BLOCK_START.with(std::cell::Cell::get)
}

pub fn set_current_block_start(addr: u64) {
    BLOCK_START.with(|c| c.set(addr));
}

/// Current guest address-space id. The OS layer bumps it whenever the memory
/// behind the guest's virtual addresses changes wholesale (execve, or a
/// switch to a different address space), so the VA-keyed block cache never
/// reuses a block lifted from a different image at the same VA.
pub fn current_asid() -> u64 {
    ASID.with(std::cell::Cell::get)
}

pub fn set_current_asid(asid: u64) {
    ASID.with(|c| c.set(asid));
}

/// Instruction count mirror, updated alongside [`current_block_start`].
pub fn current_icount() -> u64 {
    ICOUNT.with(std::cell::Cell::get)
}

pub fn set_current_icount(icount: u64) {
    ICOUNT.with(|c| c.set(icount));
}

/// A block group already lifted at some virtual address, kept so a different
/// address space can reuse it rather than lift the same bytes again.
struct LiftedCode {
    group: lifter::BlockGroup,
    /// The SLEIGH context the group was lifted under.
    context: u64,
    /// The guest bytes it was lifted from. Lifting is a pure function of the
    /// bytes, the address and the context, so identical inputs produce an
    /// identical block — and requiring the bytes to still match is what stops
    /// a different image at the same address from ever being mistaken for
    /// this one.
    source: Vec<u8>,
}

/// Longest group whose source is kept for reuse. A group that chains many
/// blocks is rare and would cost more to remember than re-lifting costs.
const MAX_LIFTED_SOURCE: usize = 64 * 1024;
/// Distinct images remembered at one address. More than a handful means
/// address reuse is churning, and verifying each candidate stops being cheap.
const MAX_LIFTED_CANDIDATES: usize = 4;

/// Entries before a block is re-lifted with the p-code optimizer.
///
/// Chosen by measurement rather than taste. A real agent's cold start takes
/// 5.1 s optimizing every block, 1.4 s at a threshold of 200, 1.2 s at 1000
/// and 1.1 s at 5000, while a compute loop is unaffected across all of them —
/// its inner blocks are entered millions of times and promote immediately
/// either way. 1000 sits where the startup curve has flattened while leaving
/// room for merely warm code to earn optimization.
const DEFAULT_PROMOTE_AFTER: u64 = 1000;

pub struct InterpVm {
    pub cpu: Box<Cpu>,
    pub env: Box<dyn EnvironmentAny>,
    pub lifter: lifter::BlockLifter,
    pub code: BlockTable,
    /// Stop with `VmExit::InstructionLimit` once `cpu.icount` reaches this.
    pub icount_limit: u64,
    /// Cooperative cancellation: set from another thread (or the browser
    /// host) to make `run` return `VmExit::Interrupted`.
    pub interrupt_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
    next_timer: u64,
    prev_isa_mode: u8,
    /// Lifted groups indexed by `(vaddr, isa_mode)` and *not* by address
    /// space, so a process can find code another process already lifted from
    /// the same bytes at the same address. `code.map` stays keyed per address
    /// space and remains the hot path; this is consulted only when that
    /// misses, which is exactly when a lift was about to happen anyway.
    lifted: std::collections::HashMap<(u64, u64), Vec<LiftedCode>>,
    /// The context `update_context` last installed in the lifter.
    lift_context: u64,
    /// Re-lift a block with the p-code optimizer once it has been entered
    /// this many times. `None` optimizes everything, as before.
    ///
    /// Measured: optimizing every block costs 94% of the lifting on a cold
    /// agent start, and such a start has no hot blocks to justify it — 29,347
    /// distinct blocks, the hottest worth 1.5%. A compute loop is the
    /// opposite, and there the optimizer is worth about 12%. So blocks are
    /// lifted cheaply and earn optimization by being run.
    promote_after: Option<u64>,
    /// Entries per block address, counted where a lookup already happens.
    entries: std::collections::HashMap<u64, u64>,
    /// Addresses already promoted, so a block is optimized once.
    promoted: std::collections::HashSet<u64>,
    /// Per-block entry counts and retired instructions, when profiling is on.
    /// Off by default: a translator should be pointed at blocks that were
    /// measured to be hot, and the measurement should not be a cost the rest
    /// of the time.
    profile: Option<std::collections::HashMap<u64, BlockProfile>>,
    /// The JIT backend, if one is installed: compiles translated blocks and
    /// runs them (see [`InterpVm::set_jit`]).
    jit: Option<Box<dyn crate::jit::JitBackend>>,
    /// Entries after which a block is JIT-compiled; `None` = JIT off.
    jit_after: Option<u64>,
    /// Per-block-address compiled handles: `Some(handle)` once compiled,
    /// `None` once the block is known not to JIT (so it is never retried).
    jit_cache: std::collections::HashMap<u64, Option<u32>>,
    /// Per-block-address compiled *region* (self-loop) handles, keyed the same
    /// way: `Some(handle)` once the block compiled as a region, `None` once it
    /// is known not to (not a self-loop, or not region-translatable), so it is
    /// never retried. Separate from `jit_cache` because a region is a different
    /// wasm module (an internal loop) than the per-block function.
    jit_region_cache: std::collections::HashMap<u64, Option<u32>>,
    /// Per-block-address entry counts, to decide when a block is hot enough to
    /// compile. Separate from `entries`, which counts only external re-entries.
    jit_entries: std::collections::HashMap<u64, u64>,
    /// How many times a compiled block ran in place of the interpreter.
    jit_dispatches: u64,
}

/// See [`InterpVm::lift_stats`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiftStats {
    pub blocks: usize,
    pub indexed: usize,
    pub promoted: usize,
    pub counted: usize,
}

/// How much of a run one basic block accounted for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BlockProfile {
    /// Times the interpreter entered this block.
    pub entries: u64,
    /// Guest instructions in it, so entries can be weighted by real work.
    pub instructions: u64,
}

/// How well the JIT covers a profiled run's executed blocks. See
/// [`InterpVm::jit_coverage`].
#[derive(Debug, Clone, Default)]
pub struct JitCoverage {
    /// Weighted guest instructions executed across profiled blocks
    /// (`entries * instructions`).
    pub hot_insns: u64,
    /// Of those, the weight in blocks that translate whole.
    pub covered_insns: u64,
    /// Distinct hot blocks profiled.
    pub blocks: usize,
    /// Bail causes as `"Op@width" -> weight`, heaviest first.
    pub bails: Vec<(String, u64)>,
}

impl InterpVm {
    pub fn new(cpu: Box<Cpu>, lifter: lifter::BlockLifter) -> Self {
        Self {
            cpu,
            env: Box::new(()),
            lifter,
            code: BlockTable::default(),
            icount_limit: u64::MAX,
            interrupt_flag: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            next_timer: 0,
            prev_isa_mode: u8::MAX,
            lifted: std::collections::HashMap::new(),
            lift_context: 0,
            promote_after: Some(DEFAULT_PROMOTE_AFTER),
            entries: std::collections::HashMap::new(),
            promoted: std::collections::HashSet::new(),
            profile: None,
            jit: None,
            jit_after: None,
            jit_cache: std::collections::HashMap::new(),
            jit_region_cache: std::collections::HashMap::new(),
            jit_entries: std::collections::HashMap::new(),
            jit_dispatches: 0,
        }
    }

    /// Installs a JIT backend. Blocks that grow hot (see [`set_jit_tiering`])
    /// are then translated to wasm, compiled by the backend, and dispatched to
    /// instead of interpreted. Without a backend, or with tiering off, execution
    /// is exactly as before.
    pub fn set_jit(&mut self, backend: Box<dyn crate::jit::JitBackend>) {
        self.jit = Some(backend);
    }

    /// Compiles a block to wasm and dispatches to it once it has been entered
    /// `after` times; `None` turns the JIT off. The interpreter remains the
    /// floor: a block that does not translate, or that a backend declines, stays
    /// interpreted forever.
    pub fn set_jit_tiering(&mut self, after: Option<u64>) {
        self.jit_after = after;
        self.jit_entries.clear();
        self.jit_cache.clear();
        self.jit_region_cache.clear();
    }

    /// How many times a compiled block ran in place of the interpreter.
    pub fn jit_dispatch_count(&self) -> u64 {
        self.jit_dispatches
    }

    /// How well the JIT covers the blocks a profiled run actually executed.
    ///
    /// Weighs each profiled block by `entries * instructions` (the guest
    /// instructions it retired), so the answer is about executed work, not the
    /// static op count. Requires [`profile_blocks`] to have been on during the
    /// run. `None` if it was not.
    pub fn jit_coverage(&self) -> Option<JitCoverage> {
        let profile = self.profile.as_ref()?;
        // Latest lifted block at each address (a re-lift replaces an earlier one).
        let mut by_addr: std::collections::HashMap<u64, &lifter::Block> =
            std::collections::HashMap::new();
        for block in &self.code.blocks {
            by_addr.insert(block.start, block);
        }
        let mut hot = 0u64;
        let mut covered = 0u64;
        let mut hist: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        for (addr, prof) in profile {
            let Some(block) = by_addr.get(addr) else {
                continue;
            };
            let weight = prof.entries.saturating_mul(prof.instructions);
            if weight == 0 {
                continue;
            }
            hot = hot.saturating_add(weight);
            match crate::jit::first_bail(&block.pcode) {
                None => covered = covered.saturating_add(weight),
                Some(b) => {
                    *hist.entry(format!("{}@{}", b.op, b.width)).or_default() += weight;
                }
            }
        }
        let mut bails: Vec<(String, u64)> = hist.into_iter().collect();
        bails.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        Some(JitCoverage {
            hot_insns: hot,
            covered_insns: covered,
            blocks: profile.len(),
            bails,
        })
    }

    /// Lifts blocks without the p-code optimizer until one has been entered
    /// `threshold` times, then re-lifts that block with it. `None` restores
    /// the previous behaviour of optimizing every block as it is lifted.
    pub fn set_lift_tiering(&mut self, threshold: Option<u64>) {
        self.promote_after = threshold;
        self.entries.clear();
        self.promoted.clear();
    }

    /// Starts counting block entries. A translator is only worth pointing at
    /// blocks that a real workload actually runs, and this is how that is
    /// established rather than assumed.
    pub fn profile_blocks(&mut self, enabled: bool) {
        self.profile = enabled.then(std::collections::HashMap::new);
    }

    /// Block entry counts collected so far, keyed by guest address.
    pub fn block_profile(&self) -> Option<&std::collections::HashMap<u64, BlockProfile>> {
        self.profile.as_ref()
    }

    pub fn set_env(&mut self, env: impl Environment + 'static) {
        self.env = Box::new(env);
    }

    pub fn env_ref<T: Environment + 'static>(&self) -> Option<&T> {
        self.env.as_any().downcast_ref::<T>()
    }

    pub fn env_mut<T: Environment + 'static>(&mut self) -> Option<&mut T> {
        self.env.as_mut_any().downcast_mut::<T>()
    }

    /// Runs the VM until it encounters an exit condition.
    pub fn run(&mut self) -> VmExit {
        if self.cpu.block_id == u64::MAX {
            if let Some((block, _)) = self.get_current_block() {
                self.cpu.block_id = block;
                self.cpu.block_offset = 0;
            }
        }

        self.update_timer();
        loop {
            if let Some(exception) = self.cpu.pending_exception.take() {
                self.cpu.exception = exception;
                match self.handle_exception() {
                    VmExit::Running => {}
                    exit => return exit,
                }
            }

            let instructions_to_exec = self.next_timer.saturating_sub(self.cpu.icount);
            if instructions_to_exec > 0 {
                self.cpu.update_fuel(instructions_to_exec);
                self.run_block_interpreter();
                // Clear fuel so `icount` is correct.
                self.cpu.update_fuel(0);
            } else {
                self.cpu.exception.code = ExceptionCode::InstructionLimit as u32;
            }

            match self.handle_exception() {
                VmExit::Running => {}
                exit => return exit,
            }
        }
    }

    pub fn reset(&mut self) {
        self.cpu.reset();
        self.cpu.mem.clear();
        self.flush_code();
        self.prev_isa_mode = u8::MAX;
    }

    /// Bytes the engine holds in lifted code: the p-code instruction vectors
    /// and the block records, plus the guest bytes the content-addressed
    /// index keeps so it can prove a candidate still matches memory.
    ///
    /// Allocator overhead and the hash maps' own tables are not counted, so
    /// this is a floor. It covers the terms that grow with the workload,
    /// which is what a budget needs.
    pub fn lifted_bytes(&self) -> usize {
        let per_block = std::mem::size_of::<lifter::Block>();
        let per_inst = std::mem::size_of::<pcode::Instruction>();
        let code: usize = self
            .code
            .blocks
            .iter()
            .map(|block| per_block + block.pcode.instructions.capacity() * per_inst)
            .sum();
        let sources: usize = self
            .lifted
            .values()
            .flat_map(|candidates| candidates.iter())
            .map(|candidate| candidate.source.capacity())
            .sum();
        code + sources
    }

    /// Counts for the structures tiered lifting grows: blocks in the arena,
    /// addresses in the content-addressed index, addresses promoted, and
    /// addresses being counted toward promotion. A soak asserts on these, and
    /// when it fails these say which one moved.
    pub fn lift_stats(&self) -> LiftStats {
        LiftStats {
            blocks: self.code.blocks.len(),
            indexed: self.lifted.len(),
            promoted: self.promoted.len(),
            counted: self.entries.len(),
        }
    }

    /// Drops every lifted block, including the content-addressed index.
    /// Prefer this to `vm.code.flush_code()`: emptying `code.blocks` on its
    /// own leaves the index holding block numbers that no longer mean
    /// anything.
    pub fn flush_code(&mut self) {
        self.code.flush_code();
        self.lifted.clear();
    }

    pub fn get_current_block(&self) -> Option<(u64, u64)> {
        match self.cpu.block_id != u64::MAX {
            true => Some((self.cpu.block_id, self.cpu.block_offset)),
            false => {
                let key = self.get_block_key(self.cpu.read_pc());
                let id = self.code.map.get(&key).map(|group| group.blocks.0)?;
                Some((id as u64, 0))
            }
        }
    }

    fn get_block_key(&self, vaddr: u64) -> BlockKey {
        let isa_mode = self.cpu.isa_mode() as u64;
        let asid = current_asid();
        BlockKey {
            vaddr,
            isa_mode,
            asid,
        }
    }

    fn handle_exception(&mut self) -> VmExit {
        if self
            .interrupt_flag
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return VmExit::Interrupted;
        }

        if let Some(exit) = self.env.handle_exception(&mut self.cpu) {
            return exit;
        }

        let code = ExceptionCode::from_u32(self.cpu.exception.code);
        match code {
            ExceptionCode::None | ExceptionCode::InstructionLimit => {
                if self.cpu.icount >= self.icount_limit {
                    return VmExit::InstructionLimit;
                }
                if self.code.breakpoints.contains(&self.cpu.read_pc()) {
                    return VmExit::Breakpoint;
                }
                self.update_timer();
                VmExit::Running
            }
            ExceptionCode::SoftwareBreakpoint => VmExit::Breakpoint,

            ExceptionCode::ExternalAddr => self.handle_external_address(self.cpu.exception.value),
            ExceptionCode::CodeNotTranslated => self.handle_code_not_translated(),
            ExceptionCode::UnimplementedOp => self.handle_unimplemented_op(),
            ExceptionCode::ShadowStackInvalid | ExceptionCode::ShadowStackOverflow => {
                // The block offset is wrong on shadow stack errors so fix it here.
                self.cpu.block_offset = self.code.blocks[self.cpu.block_id as usize]
                    .pcode
                    .instructions
                    .len() as u64;
                VmExit::UnhandledException((code, self.cpu.exception.value))
            }
            ExceptionCode::SelfModifyingCode => {
                // A write hit bytes that lifted blocks were built from
                // (real self-modifying code, or plain data sharing a page
                // range with executed code). Drop every lifted block and
                // the executable-page marks, then retry the faulting
                // instruction; the write proceeds and code is re-lifted on
                // next execution.
                tracing::debug!(
                    "self-modifying code near {:#x}; flushing the code cache",
                    self.cpu.exception.value
                );
                self.cpu.mem.clear_code_cache();
                self.flush_code();
                self.cpu.block_id = u64::MAX;
                self.cpu.block_offset = 0;
                let pc = self.cpu.read_pc();
                self.handle_external_address(pc)
            }
            ExceptionCode::Halt | ExceptionCode::Sleep => VmExit::Halt,
            ExceptionCode::OutOfMemory => VmExit::OutOfMemory,
            code => VmExit::UnhandledException((code, self.cpu.exception.value)),
        }
    }

    fn handle_external_address(&mut self, addr: u64) -> VmExit {
        self.cpu.write_pc(addr);

        let key = self.get_block_key(addr);
        match self.code.map.get(&key) {
            Some(group) => {
                self.cpu.block_id = group.blocks.0 as u64;
                self.cpu.block_offset = 0;
                VmExit::Running
            }
            None => self.handle_code_not_translated(),
        }
    }

    #[cold]
    fn handle_code_not_translated(&mut self) -> VmExit {
        let pc = self.cpu.read_pc();
        // Check for internal errors (e.g. if the code map is invalid).
        let key = self.get_block_key(pc);
        if self.code.map.contains_key(&key) {
            tracing::error!(
                "Internal error: `self.code.map` is invalid, \
                expected block at {key:x?} to be missing",
            );
            return VmExit::UnhandledException((
                ExceptionCode::InternalError,
                InternalError::CorruptedBlockMap as u64,
            ));
        }

        match self.lift(pc) {
            Ok(group) => {
                self.cpu.block_id = group.blocks.0 as u64;
                self.cpu.block_offset = 0;
                VmExit::Running
            }
            Err(e) => {
                tracing::trace!("DecodeError at {pc:#x}: {e:?}");
                self.cpu.exception = Exception::new(ExceptionCode::from(e), pc);
                self.cpu.block_id = u64::MAX;
                if self.cpu.icount >= self.icount_limit {
                    return VmExit::InstructionLimit;
                }
                self.handle_exception()
            }
        }
    }

    /// Handles an unhandled user-defined or unsupported p-code operation.
    #[cold]
    fn handle_unimplemented_op(&mut self) -> VmExit {
        use pcode::PcodeDisplay;

        if let Some(stmt) = self
            .code
            .blocks
            .get(self.cpu.block_id as usize)
            .and_then(|block| block.pcode.instructions.get(self.cpu.block_offset as usize))
        {
            tracing::error!(
                "[{:#0x}] unknown pcode operation: {}",
                self.cpu.read_pc(),
                stmt.display(&self.cpu.arch.sleigh)
            );
        }
        VmExit::UnhandledException((ExceptionCode::UnimplementedOp, self.cpu.exception.value))
    }

    #[cold]
    #[inline(never)]
    fn corrupted_block_map(&mut self, id: u64) {
        self.cpu.exception.code = ExceptionCode::InternalError as u32;
        self.cpu.exception.value = InternalError::CorruptedBlockMap as u64;
        tracing::error!(
            "Block map corrupted at: pc={:#x} id={id}",
            self.cpu.read_pc()
        );
    }

    fn update_timer(&mut self) {
        /// The number of instructions to wait before checking
        /// `vm.interrupt_flag`. Set quite high since checking causes a full
        /// VM exit.
        const CHECK_FOR_INTERRUPT_FLAG_TIMER: u64 = 0x10_0000;

        let user_exit = self.icount_limit;
        let env_exit = self.env.next_timer();
        self.next_timer = user_exit
            .min(env_exit)
            .min(CHECK_FOR_INTERRUPT_FLAG_TIMER + self.cpu.icount);
    }

    fn run_block_interpreter(&mut self) {
        self.cpu.exception.clear();
        if let Some((id, _)) = self.get_current_block() {
            if let Some(b) = self.code.blocks.get(id as usize) {
                set_current_block_start(b.start);
            }
        }

        let (mut block_id, mut offset) = match self.get_current_block() {
            Some(value) => value,
            None => {
                self.cpu.exception.code = ExceptionCode::CodeNotTranslated as u32;
                self.cpu.exception.value = self.cpu.read_pc();
                return;
            }
        };
        self.cpu.block_offset = 0;
        let Some(mut block) = self.code.blocks.get(block_id as usize) else {
            self.corrupted_block_map(block_id);
            return;
        };

        // Adjust the CPU fuel if we are entering the interpreter in the
        // middle of a block.
        adjust_cpu_fuel_for_block_reentry(&mut self.cpu, block, offset);

        loop {
            if let Some(profile) = self.profile.as_mut() {
                let entry = profile.entry(block.start).or_default();
                entry.entries += 1;
                entry.instructions = block.num_instructions as u64;
            }
            if block.has_breakpoint() {
                // Determine how many steps to execute before we hit the first
                // breakpoint in this block.
                for (i, inst) in block.pcode.instructions[offset as usize..]
                    .iter()
                    .filter(|inst| matches!(inst.op, pcode::Op::InstructionMarker))
                    .enumerate()
                {
                    if self
                        .code
                        .breakpoints
                        .contains(&inst.inputs.first().as_u64())
                    {
                        self.cpu.update_fuel(self.cpu.fuel.remaining.min(i as u64));
                        break;
                    }
                }
            }

            // JIT dispatch: at a fresh block entry (not a mid-block re-entry)
            // with no breakpoint, a hot fully-translatable block runs as
            // compiled wasm instead of being interpreted. A self-loop — a block
            // that conditionally branches back to its own start — compiles as a
            // region (one wasm function with an internal loop), so many
            // iterations are one dispatch; every other hot block runs as a
            // single-shot per-block function. Anything else — not hot, not
            // translatable, a block the backend declined, or one that would
            // cross the fuel limit — falls through to the interpreter, which
            // stays the floor.
            let mut jit_ran = false;
            if offset == 0 && !block.has_breakpoint() {
                if let Some(after) = self.jit_after {
                    let start = block.start;
                    let count = self.jit_entries.entry(start).or_insert(0);
                    *count += 1;
                    let hot = *count >= after;

                    // Region (self-loop) path. A register-only self-loop runs its
                    // whole loop in one call; a self-loop that needs the host
                    // caches a bail here and takes the per-block path below.
                    if let Some(cond) = self_loop_kind(block, block_id) {
                        let handle = match self.jit_region_cache.get(&start).copied() {
                            Some(decided) => decided,
                            None if hot => {
                                let compiled = crate::jit::translate_region(&block.pcode, cond)
                                    .and_then(|bytes| self.jit.as_mut()?.compile(&bytes));
                                self.jit_region_cache.insert(start, compiled);
                                compiled
                            }
                            None => None,
                        };
                        if let Some(handle) = handle {
                            let num = block.num_instructions as u64;
                            if num > 0 && self.cpu.fuel.remaining >= num {
                                // Bound the region to the fuel budget so it never
                                // retires more than the interpreter would in this
                                // slice; at least one iteration by the guard above.
                                let max_iters = self.cpu.fuel.remaining / num;
                                let outcome = match self.jit.as_mut() {
                                    Some(j) => j.call_region(handle, &mut self.cpu, max_iters),
                                    None => crate::jit::RegionOutcome::Unavailable,
                                };
                                if let crate::jit::RegionOutcome::Ran(iters) = outcome {
                                    // Each iteration retired the whole block and
                                    // ticks no per-instruction fuel; charge it here
                                    // so icount stays exact. The register file now
                                    // holds the post-iteration state, so block_exit
                                    // below reads the live condition and goes to the
                                    // loop target (budget spent, still live) or the
                                    // fallthrough (condition went false) exactly as
                                    // the interpreter would.
                                    self.cpu.fuel.remaining -= iters.saturating_mul(num);
                                    self.jit_dispatches += 1;
                                    jit_ran = true;
                                }
                            }
                        }
                    }

                    // Per-block (single-shot) path, when the region did not run.
                    if !jit_ran {
                        let handle = match self.jit_cache.get(&start).copied() {
                            Some(decided) => decided,
                            None if hot => {
                                // Compile once, or cache a bail. A block that touches
                                // guest memory, divides, or raises compiles the same
                                // way; its host callbacks are wired at run time.
                                let compiled = crate::jit::translate_block(&block.pcode)
                                    .and_then(|bytes| self.jit.as_mut()?.compile(&bytes));
                                self.jit_cache.insert(start, compiled);
                                compiled
                            }
                            None => None,
                        };
                        if let Some(handle) = handle {
                            if self.cpu.fuel.remaining >= block.num_instructions as u64 {
                                let outcome = match self.jit.as_mut() {
                                    Some(j) => j.call(handle, &mut self.cpu),
                                    None => crate::jit::JitOutcome::Unavailable,
                                };
                                match outcome {
                                    crate::jit::JitOutcome::Completed => {
                                        // The compiled block ticks no per-instruction
                                        // fuel the way InstructionMarker does; charge
                                        // the whole block here so icount stays exact.
                                        self.cpu.fuel.remaining -= block.num_instructions as u64;
                                        self.jit_dispatches += 1;
                                        jit_ran = true;
                                    }
                                    crate::jit::JitOutcome::Faulted(i) => {
                                        // The block stopped mid-way, at pcode index i.
                                        // The interpreter, running to there, would have
                                        // ticked PC and fuel at each guest instruction's
                                        // marker; reproduce that up to the fault so the
                                        // exception it raised is seen in the same state.
                                        let (pc, guest_insns) =
                                            fault_pc_and_fuel(&block.pcode, i as usize);
                                        if let Some(pc) = pc {
                                            self.cpu.write_pc(pc);
                                        }
                                        self.cpu.fuel.remaining =
                                            self.cpu.fuel.remaining.saturating_sub(guest_insns);
                                        self.jit_dispatches += 1;
                                        self.cpu.block_id = block_id;
                                        self.cpu.block_offset = i as u64;
                                        break;
                                    }
                                    crate::jit::JitOutcome::Unavailable => {}
                                }
                            }
                        }
                    }
                }
            }

            // Safety: every block is validated as part of `lift`.
            if !jit_ran {
                unsafe {
                    if let Some(offset) = self
                        .cpu
                        .interpret_block_unchecked(&block.pcode, offset as usize)
                    {
                        // We exited early due to an exception, so keep track of
                        // the offset where the CPU exited from.
                        self.cpu.block_id = block_id;
                        self.cpu.block_offset = offset as u64;
                        break;
                    }
                }
            }

            match self.cpu.block_exit(block.exit) {
                Target::Internal(id) => {
                    block_id = id as u64;
                    offset = 0;
                }
                Target::External(addr) => {
                    let addr: u64 = self.cpu.read_dynamic(addr).zxt();
                    self.cpu.write_pc(addr);

                    // A block earns the optimizer by being re-entered. This is
                    // counted here because a map lookup happens here anyway;
                    // straight-line chaining inside a group stays untouched.
                    if let Some(threshold) = self.promote_after {
                        if !self.promoted.contains(&addr) {
                            let count = self.entries.entry(addr).or_default();
                            *count += 1;
                            if *count >= threshold {
                                self.promoted.insert(addr);
                                // Drop the cheap version so the next entry
                                // lifts it again, with the optimizer on. Its
                                // group stays in the block arena, which is
                                // append-only: the entries become unreachable
                                // but are not reclaimed. `promoted` bounds
                                // that at one stale copy per address, so the
                                // table converges toward twice the image's hot
                                // blocks rather than growing without limit.
                                let key = self.get_block_key(addr);
                                self.code.map.remove(&key);
                                self.lifted.remove(&(addr, key.isa_mode));
                                self.cpu.block_id = block_id;
                                self.cpu.exception.code = ExceptionCode::CodeNotTranslated as u32;
                                self.cpu.exception.value = addr;
                                break;
                            }
                        }
                    }

                    match self.code.map.get(&self.get_block_key(addr)) {
                        Some(group) => {
                            block_id = group.blocks.0 as u64;
                            offset = 0;
                        }
                        None => {
                            self.cpu.block_id = block_id;
                            self.cpu.exception.code = ExceptionCode::CodeNotTranslated as u32;
                            self.cpu.exception.value = addr;
                            break;
                        }
                    }
                }
                Target::Invalid(e, addr) => {
                    tracing::debug!(
                        "End of block has invalid target: {e:?} @ {addr:#x}, PC: {:#x}",
                        self.cpu.read_pc()
                    );

                    // Synchronize the RIP (this is necessary if an invalid
                    // instruction occurs in the middle of a block).
                    self.cpu.write_pc(addr);

                    // Since the invalid instruction does not have a marker, we
                    // need to check if we ran out of fuel and raise the
                    // appropriate exception first. The next step will raise
                    // the actual exception related to the DecodeError.
                    let code = match self.cpu.fuel.remaining == 0 {
                        true => ExceptionCode::InstructionLimit,
                        false => ExceptionCode::from(e),
                    };
                    self.cpu.exception = Exception::new(code, addr);
                    break;
                }
            }

            block = match self.code.blocks.get(block_id as usize) {
                Some(block) => block,
                None => return self.corrupted_block_map(block_id),
            };
            set_current_block_start(block.start);
            set_current_icount(self.cpu.icount());
        }
    }

    pub fn lift(&mut self, addr: u64) -> Result<lifter::BlockGroup, lifter::DecodeError> {
        self.update_context();
        let isa_mode = self.cpu.isa_mode() as u64;

        // Another address space may have lifted exactly this code here
        // already — the common case when a shell execs the same binary again,
        // or when two processes run the same image. Reuse is only allowed
        // when the bytes still match, so this cannot resurrect the bug the
        // address-space id was added to fix.
        if let Some(group) = self.reuse_lifted(addr, isa_mode) {
            let key = self.get_block_key(addr);
            self.code.map.insert(key, group);
            return Ok(group);
        }

        // Tiered lifting: the optimizer runs only for an address that has
        // proved hot. The setting is restored afterwards so nothing else sees
        // a changed lifter.
        let optimize = self.promote_after.is_none() || self.promoted.contains(&addr);
        let saved = (
            self.lifter.settings.optimize,
            self.lifter.settings.optimize_block,
        );
        if !optimize {
            self.lifter.settings.optimize = false;
            self.lifter.settings.optimize_block = false;
        }
        let mut ctx = lifter::Context::new(&mut *self.cpu, &mut self.code, addr);
        let lifted = self.lifter.lift_block(&mut ctx);
        self.lifter.settings.optimize = saved.0;
        self.lifter.settings.optimize_block = saved.1;
        let group = lifted?;

        // Add breakpoints to the lifted code.
        if !self.code.breakpoints.is_empty() {
            for block in &mut self.code.blocks[group.range()] {
                for inst in &block.pcode.instructions {
                    if matches!(inst.op, pcode::Op::InstructionMarker)
                        && self
                            .code
                            .breakpoints
                            .contains(&inst.inputs.first().as_u64())
                    {
                        block.breakpoints += 1;
                    }
                }
            }
        }

        self.code.modified.extend(group.range());

        // Validate that all modified code is valid before it reaches the
        // unchecked interpreter entry point.
        for id in self.code.modified.drain() {
            let block = &mut self.code.blocks[id];
            for inst in &block.pcode.instructions {
                if !self.cpu.validate(inst) {
                    use pcode::PcodeDisplay;
                    panic!(
                        "block {:#x} contains invalid instruction {} ({:?})",
                        block.start,
                        inst.display(&self.cpu.arch.sleigh),
                        inst,
                    );
                }
            }
        }

        let key = self.get_block_key(addr);
        self.code.map.insert(key, group);
        self.remember_lifted(addr, isa_mode, group);

        Ok(group)
    }

    /// A group already lifted at this address from the bytes now in memory,
    /// under the same context, or None.
    fn reuse_lifted(&mut self, addr: u64, isa_mode: u64) -> Option<lifter::BlockGroup> {
        // Disjoint field borrows: the candidate list is read while guest
        // memory is read through the CPU.
        let InterpVm {
            lifted,
            cpu,
            code,
            lift_context,
            ..
        } = self;
        let candidates = lifted.get(&(addr, isa_mode))?;
        let mut buf = Vec::new();
        for candidate in candidates {
            if candidate.context != *lift_context {
                continue;
            }
            buf.clear();
            buf.resize(candidate.source.len(), 0);
            if cpu
                .mem
                .read_bytes(candidate.group.start, &mut buf, icicle_cpu::mem::perm::NONE)
                .is_err()
            {
                continue;
            }
            if buf != candidate.source {
                continue;
            }
            // The recorded block numbers must still name this group. They
            // would not if the table were flushed behind this index's back.
            let group = candidate.group;
            if code
                .blocks
                .get(group.blocks.0)
                .is_some_and(|block| block.start == group.start)
                && code.blocks.len() >= group.blocks.1
            {
                return Some(group);
            }
        }
        None
    }

    /// Remembers a freshly lifted group so another address space can reuse it.
    fn remember_lifted(&mut self, addr: u64, isa_mode: u64, group: lifter::BlockGroup) {
        let len = group.end.saturating_sub(group.start) as usize;
        if len == 0 || len > MAX_LIFTED_SOURCE {
            return;
        }
        let mut source = vec![0_u8; len];
        if self
            .cpu
            .mem
            .read_bytes(group.start, &mut source, icicle_cpu::mem::perm::NONE)
            .is_err()
        {
            return;
        }
        let context = self.lift_context;
        let entry = self.lifted.entry((addr, isa_mode)).or_default();
        if entry.len() < MAX_LIFTED_CANDIDATES {
            entry.push(LiftedCode {
                group,
                context,
                source,
            });
        }
    }

    fn update_context(&mut self) {
        // Use the context from the last block.
        if let Some(block) = self.code.blocks.get(self.cpu.block_id as usize) {
            self.lift_context = block.context;
            self.lifter.set_context(block.context);
        }

        // Check for ISA mode changes (e.g. long mode vs 32-bit compat mode).
        let isa_mode = self.cpu.isa_mode();
        if self.prev_isa_mode != isa_mode {
            tracing::debug!("ISA mode change {} -> {isa_mode}", self.prev_isa_mode);
            self.prev_isa_mode = isa_mode;
            match self.cpu.arch.isa_mode_context.get(isa_mode as usize) {
                Some(ctx) => {
                    self.lift_context = *ctx;
                    self.lifter.set_context(*ctx);
                }
                None => {
                    tracing::error!("Unknown or unsupported ISA mode: {}", self.prev_isa_mode);
                    self.cpu.exception.code = ExceptionCode::InternalError as u32;
                    self.cpu.exception.value = InternalError::CorruptedBlockMap as u64;
                }
            }
        }
    }
}

/// If `block` is a self-loop — its structured exit branches back to the block's
/// own start — returns how it loops, for [`crate::jit::translate_region`]:
///
/// - `Some(Some(cond))`: a conditional branch that loops while `cond` is taken
///   (and falls through to its other target when the condition goes false).
/// - `Some(None)`: an unconditional jump back to its own start — an infinite
///   loop that a fuel slice bounds (a `hlt`/`jmp $` spin), and whose region
///   simply runs the body up to the iteration budget.
/// - `None`: not a self-loop (a call, a return, or an exit that leaves the
///   block).
///
/// The taken target resolves to this block whether it is an internal target
/// (the same block index) or an external jump back to the block's start address.
fn self_loop_kind(block: &lifter::Block, block_id: u64) -> Option<Option<pcode::Value>> {
    let resolves_to_self = |target: Target| match target {
        Target::Internal(id) => id as u64 == block_id,
        Target::External(pcode::Value::Const(addr, _)) => addr == block.start,
        _ => false,
    };
    match block.exit {
        lifter::BlockExit::Branch { cond, target, .. } if resolves_to_self(target) => {
            Some(Some(cond))
        }
        lifter::BlockExit::Jump { target } if resolves_to_self(target) => Some(None),
        _ => None,
    }
}

/// The PC and the number of guest instructions the interpreter would have
/// retired reaching pcode index `fault_index`. There is one guest instruction
/// per `InstructionMarker` up to and including the faulting instruction's, and
/// that marker's address is the PC. This restores the interpreter's state when
/// a JIT'd block faults partway, since the JIT emits nothing for the markers.
fn fault_pc_and_fuel(block: &pcode::Block, fault_index: usize) -> (Option<u64>, u64) {
    if block.instructions.is_empty() {
        return (None, 0);
    }
    let end = fault_index.min(block.instructions.len() - 1);
    let mut pc = None;
    let mut guest_insns = 0u64;
    for inst in &block.instructions[..=end] {
        if matches!(inst.op, pcode::Op::InstructionMarker) {
            pc = Some(inst.inputs.first().as_u64());
            guest_insns += 1;
        }
    }
    (pc, guest_insns)
}

/// Adjusts the fuel counter when the interpreter is entered mid-block.
///
/// - When we enter the interpreter at the start of a block that has pcode
///   instructions injected before the first instruction marker, the fuel
///   counter must not be decremented before the first marker executes.
/// - When we resume in the middle of a block (e.g. after a fault), the fuel
///   counter must be decremented to account for the missing marker.
fn adjust_cpu_fuel_for_block_reentry(cpu: &mut Cpu, block: &lifter::Block, offset: u64) {
    if block.pcode.address_of(offset as usize).is_none() {
        // The offset is _before_ the first instruction in the block; the
        // executed pcode is not related to any instruction.
        return;
    }

    if let Some(inst) = block.pcode.instructions.get(offset as usize) {
        if !matches!(inst.op, pcode::Op::InstructionMarker) {
            cpu.fuel.remaining = cpu.fuel.remaining.saturating_sub(1);
        }
    }
}
