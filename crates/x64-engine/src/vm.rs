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

/// Bound one compiled loop dispatch independently of the caller's fuel slice.
/// Browser hosts cannot preempt a synchronous WebAssembly call. Giving a hot
/// REP/string loop an entire multi-million-instruction slice can therefore
/// freeze page-in, terminal, timer, and cancellation handling for minutes.
/// Re-dispatch is architecturally invisible and keeps exact fuel accounting.
const JIT_REGION_DISPATCH_BUDGET: u64 = 65_536;

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
    // A demand fault happens after the faulting instruction's marker has
    // already consumed its unit of fuel. Re-entering at that p-code offset
    // must therefore not apply the generic mid-block compensation a second
    // time. This is thread-local for the same reason as the mirrors above: a
    // test process may run independent machines concurrently.
    static PAGE_IN_RETRY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Whether `WEBTOS_JIT_TRACE` diagnostics are on: every JIT dispatch, fault
/// resume, and suspicious branch target prints to stderr. Native-only — env
/// vars read as absent on wasm32, so there the code compiles out entirely.
pub fn jit_trace_enabled() -> bool {
    #[cfg(target_arch = "wasm32")]
    {
        false
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *ON.get_or_init(|| std::env::var_os("WEBTOS_JIT_TRACE").is_some())
    }
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

/// Marks the next mid-block interpreter entry as a retry of a restartable
/// demand fault whose instruction marker has already consumed fuel.
pub fn mark_page_in_retry() {
    PAGE_IN_RETRY.with(|c| c.set(true));
}

fn take_page_in_retry() -> bool {
    PAGE_IN_RETRY.with(|c| c.replace(false))
}

fn clear_page_in_retry() {
    PAGE_IN_RETRY.with(|c| c.set(false));
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
    /// Compiled handles keyed by [`BlockKey`] — the same (vaddr, isa_mode,
    /// asid) identity the block cache uses, not the bare address: a handle
    /// compiled for one image must never be served for a different image that
    /// Compiled per-block handles, keyed by block id — the one identity that
    /// names exactly one p-code body. An address key is not enough: several
    /// blocks can share a start address (a REP-style instruction lifts to a
    /// prologue block chained to a loop block at the same address), and a
    /// re-lift after a code page-in can replace the block behind an address,
    /// either of which would serve one block's compiled code to another.
    /// Block ids are append-only between flushes, so a stale id is simply
    /// never dispatched again. `Some(handle)` once compiled, `None` once the
    /// block is known not to JIT (so it is never retried). Cleared by
    /// [`InterpVm::flush_code`] when bytes change (self-modifying code),
    /// which also empties the arena those ids named.
    jit_cache: std::collections::HashMap<u64, Option<u32>>,
    /// Compiled *region* (self-loop) handles, keyed by block id the same
    /// way: `Some(handle)` once the block compiled as a region, `None` once it
    /// is known not to (not a self-loop, or not region-translatable), so it is
    /// never retried. Separate from `jit_cache` because a region is a different
    /// wasm module (an internal loop) than the per-block function.
    jit_region_cache: std::collections::HashMap<u64, Option<u32>>,
    /// Resume/fault tables for region-cache entries that are multi-block
    /// state-machine traces. Entries are removed with their LRU handle, so
    /// this metadata is bounded by the same code budget as compiled wasm.
    jit_trace_meta: std::collections::HashMap<u64, TraceMeta>,
    /// Per-block-id entry counts, to decide when a block is hot enough to
    /// compile. Separate from `entries`, which counts only external re-entries.
    jit_entries: std::collections::HashMap<u64, u64>,
    /// How many times a compiled block ran in place of the interpreter.
    jit_dispatches: u64,
    /// Dispatch split used by cross-platform gates: single-shot blocks versus
    /// self-loop regions. The aggregate above remains the public compatibility
    /// counter.
    jit_block_dispatches: u64,
    jit_region_dispatches: u64,
    /// Unique guest instruction ranges observed while execution accounting is
    /// enabled. Off by default; large-image gates use it to distinguish bytes
    /// actually executed from whole pages first fetched for execution.
    executed_instructions: Option<std::collections::HashSet<(u64, u64)>>,
    /// Bookkeeping for the compiled-code budget: how much wasm code the backend
    /// is holding, and which block each live handle belongs to, so the least
    /// recently used can be evicted when the budget is exceeded.
    jit_budget: JitBudget,
    /// Wall-clock split across run phases, accumulated only while `Some` (see
    /// [`InterpVm::set_phase_timing`]). Off by default: the `Instant::now` at
    /// each block and exception is only paid when a run is being profiled.
    phase_times: Option<PhaseTimes>,
    /// Synthetic demand-paging prototype: page-aligned guest addresses that are
    /// mapped but not yet resident, each with the bytes and final permission to
    /// fill on first access. A permission fault at one of these fills it and
    /// retries the faulting instruction, exactly as a real chunk fetch would.
    /// Empty in production; populated only by the page-in prototype tests.
    lazy_pages: std::collections::HashMap<u64, (Vec<u8>, u8)>,
    /// How many synthetic page-ins have been served.
    page_ins: u64,
    /// A host-backed page miss may return from `run` mid-block. The next call
    /// must continue the same interpreter turn rather than performing the
    /// normal fresh-run block/timer setup; synchronous prototype page-in never
    /// crossed this boundary, so it did not need this bit.
    resume_page_in: bool,
    /// Lift-churn counters: groups decoded, groups served from reuse, and code
    /// flushes — to size how much lifting a persistent cache could avoid.
    lift_decoded: u64,
    lift_reused: u64,
    flush_count: u64,
}

/// Where a profiled run spends wall-clock time, in nanoseconds. `exec` is
/// interpreting p-code and running compiled blocks; `lift` is translating guest
/// bytes to blocks; `syscall` is the OS layer handling an exception (a syscall
/// and its host I/O); the rest of the run loop is unattributed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PhaseTimes {
    pub exec_ns: u64,
    pub lift_ns: u64,
    pub syscall_ns: u64,
}

/// One live compiled handle's place in the budget: which block cache holds it,
/// how big its wasm is, and when it last ran (for least-recently-used eviction).
struct JitEntry {
    key: u64,
    is_region: bool,
    bytes: u32,
    last_epoch: u64,
}

#[derive(Clone)]
struct TraceMeta {
    resumes: Vec<crate::jit::TraceResume>,
    fault_sites: Vec<(usize, usize)>,
    blocks: Vec<usize>,
}

/// The compiled-code budget and its metrics. `budget == 0` means unlimited (the
/// default, so nothing changes until a host sets a cap). Native runs leave it
/// unlimited; the browser sets a cap so a long session cannot grow the engine's
/// wasm code memory without bound.
#[derive(Default)]
struct JitBudget {
    /// Live handles → their entry. A handle absent here was evicted or never
    /// compiled; the block re-earns compilation.
    meta: std::collections::HashMap<u32, JitEntry>,
    /// Sum of `bytes` over `meta` — the code the backend currently holds.
    total_bytes: usize,
    /// The cap in wasm bytes, or 0 for unlimited.
    budget: usize,
    /// Monotonic clock for recency; the smallest `last_epoch` is the LRU victim.
    epoch: u64,
    compiles: u64,
    evictions: u64,
    hits: u64,
    peak_bytes: usize,
}

/// A snapshot of the compiled-code budget, for tuning and for surfacing to the
/// resource ledger. See [`InterpVm::jit_code_stats`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct JitCodeStats {
    /// Wasm bytes the backend currently holds across all live handles.
    pub total_bytes: usize,
    /// The high-water mark of `total_bytes`.
    pub peak_bytes: usize,
    /// The cap, or 0 for unlimited.
    pub budget: usize,
    /// Live compiled handles.
    pub live: usize,
    /// Compilations performed.
    pub compiles: u64,
    /// Handles evicted under budget pressure or a code flush.
    pub evictions: u64,
    /// Dispatches to a compiled handle (a cache hit that ran).
    pub hits: u64,
}

impl JitBudget {
    fn next_epoch(&mut self) -> u64 {
        self.epoch += 1;
        self.epoch
    }

    /// Evicts least-recently-used handles until `incoming` more bytes fit under
    /// the budget, dropping each from the backend and from whichever block cache
    /// still points at it. A single block larger than the whole budget is left
    /// to run once the rest is cleared.
    fn make_room(
        &mut self,
        incoming: usize,
        jit: &mut dyn crate::jit::JitBackend,
        block_cache: &mut std::collections::HashMap<u64, Option<u32>>,
        region_cache: &mut std::collections::HashMap<u64, Option<u32>>,
        trace_meta: &mut std::collections::HashMap<u64, TraceMeta>,
    ) {
        if self.budget == 0 {
            return;
        }
        while self.total_bytes + incoming > self.budget {
            let Some((&handle, _)) = self.meta.iter().min_by_key(|(_, e)| e.last_epoch) else {
                break;
            };
            let entry = self.meta.remove(&handle).expect("just found");
            jit.evict(handle);
            let cache = if entry.is_region {
                &mut *region_cache
            } else {
                &mut *block_cache
            };
            // Only clear the mapping if it still names this handle; a re-lift may
            // have replaced it already.
            if cache.get(&entry.key).copied().flatten() == Some(handle) {
                cache.remove(&entry.key);
            }
            if entry.is_region {
                trace_meta.remove(&entry.key);
            }
            self.total_bytes = self.total_bytes.saturating_sub(entry.bytes as usize);
            self.evictions += 1;
        }
    }

    /// Records a freshly compiled handle.
    fn record(&mut self, handle: u32, key: u64, is_region: bool, bytes: usize) {
        let last_epoch = self.next_epoch();
        self.meta.insert(
            handle,
            JitEntry {
                key,
                is_region,
                bytes: bytes as u32,
                last_epoch,
            },
        );
        self.total_bytes += bytes;
        self.peak_bytes = self.peak_bytes.max(self.total_bytes);
        self.compiles += 1;
    }

    /// Marks a handle used, so recency tracks execution.
    fn touch(&mut self, handle: u32) {
        let epoch = self.next_epoch();
        if let Some(entry) = self.meta.get_mut(&handle) {
            entry.last_epoch = epoch;
        }
        self.hits += 1;
    }

    /// Drops every live handle from the backend (used when the code cache is
    /// flushed wholesale). Metrics are preserved.
    fn clear(&mut self, jit: &mut dyn crate::jit::JitBackend) {
        for &handle in self.meta.keys() {
            jit.evict(handle);
        }
        self.meta.clear();
        self.total_bytes = 0;
    }

    fn stats(&self) -> JitCodeStats {
        JitCodeStats {
            total_bytes: self.total_bytes,
            peak_bytes: self.peak_bytes,
            budget: self.budget,
            live: self.meta.len(),
            compiles: self.compiles,
            evictions: self.evictions,
            hits: self.hits,
        }
    }
}

/// See [`InterpVm::lift_stats`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiftStats {
    pub blocks: usize,
    pub indexed: usize,
    pub promoted: usize,
    pub counted: usize,
    /// Groups actually decoded (a lift that the cross-address-space reuse cache
    /// missed). This is the work a cross-session persistent cache could avoid —
    /// but only for bytes that recur; code a JIT-in-a-JIT generates fresh each
    /// run is re-decoded here every time and is not cacheable.
    pub decoded: u64,
    /// Groups served from the reuse cache without decoding.
    pub reused: u64,
    /// Times the code cache was flushed wholesale (self-modifying code / execve)
    /// — each flush forces everything live to be decoded again, churn a
    /// persistent cache cannot remove because the bytes changed.
    pub flushes: u64,
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
    /// Of the covered weight, the part in self-loop blocks — the ones region
    /// compilation already runs as one `jit_call` for the whole loop.
    pub covered_self_loop_insns: u64,
    /// Of the covered weight, the part in non-self-loop blocks — dispatched one
    /// block at a time, so the share a multi-block trace could stitch.
    pub covered_chain_insns: u64,
    /// Of the non-self-loop weight, the part in blocks that a looping trace
    /// actually forms over — the reach of the trace selector, and so the share
    /// a multi-block trace could really capture.
    pub covered_trace_insns: u64,
    /// How the non-self-loop covered blocks exit, `"kind" -> weight`, heaviest
    /// first — the control-flow shape of the multi-block opportunity.
    pub chain_exits: Vec<(String, u64)>,
    /// Total per-block JIT dispatches on the non-self-loop path (one per block
    /// entry). `covered_chain_insns / chain_dispatches` is the average guest
    /// instructions each such jit_call amortizes over.
    pub chain_dispatches: u64,
    /// Those dispatches bucketed by block size (guest instructions),
    /// `"bucket" -> dispatch count` — the dispatch-granularity distribution.
    pub chain_dispatch_sizes: Vec<(String, u64)>,
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
            jit_trace_meta: std::collections::HashMap::new(),
            jit_entries: std::collections::HashMap::new(),
            jit_dispatches: 0,
            jit_block_dispatches: 0,
            jit_region_dispatches: 0,
            executed_instructions: None,
            jit_budget: JitBudget::default(),
            phase_times: None,
            lazy_pages: std::collections::HashMap::new(),
            page_ins: 0,
            resume_page_in: false,
            lift_decoded: 0,
            lift_reused: 0,
            flush_count: 0,
        }
    }

    /// Turns on (or off) wall-clock accounting across run phases (exec, lift,
    /// syscall); resets the accumulators when turned on. See [`phase_times`].
    pub fn set_phase_timing(&mut self, on: bool) {
        self.phase_times = on.then(PhaseTimes::default);
    }

    /// The accumulated phase wall-clock, or `None` if timing is off.
    pub fn phase_times(&self) -> Option<PhaseTimes> {
        self.phase_times
    }

    /// Registers a page (address is truncated to the page) as mapped-but-not-
    /// resident: `bytes` (one page) is filled in and `perm` set on the first
    /// access fault, which then retries. The demand-paging prototype's synthetic
    /// backing store.
    pub fn register_lazy_page(&mut self, addr: u64, bytes: Vec<u8>, perm: u8) {
        self.lazy_pages.insert(addr & !0xfff, (bytes, perm));
    }

    /// How many synthetic page-ins have been served.
    pub fn page_in_count(&self) -> u64 {
        self.page_ins
    }

    pub fn suspend_for_page_in(&mut self) {
        self.resume_page_in = true;
    }

    /// A host image replacement discards the faulting process rather than
    /// resuming it. Clear both halves of the retry bookkeeping so the new
    /// image cannot inherit a skipped timer update or fuel compensation from
    /// the process it replaced.
    pub fn cancel_page_in_resume(&mut self) {
        self.resume_page_in = false;
        clear_page_in_retry();
    }

    /// If the exception is an access fault on a registered non-resident page,
    /// fills that page and returns true so the caller retries the faulting
    /// instruction; otherwise false. This is the resumable page-in: the faulting
    /// instruction has committed no architectural state (x86 faults are
    /// restartable), so re-entering the interpreter at the same block offset —
    /// which is where a JIT fault also lands, since the JIT is skipped at a
    /// non-zero offset — re-runs exactly that instruction against the now-
    /// resident page, with icount and PC unchanged.
    fn try_page_in(&mut self) -> bool {
        let code = ExceptionCode::from_u32(self.cpu.exception.code);
        let is_access_fault = matches!(
            code,
            ExceptionCode::ReadUnmapped
                | ExceptionCode::ReadPerm
                | ExceptionCode::ReadUninitialized
                | ExceptionCode::WriteUnmapped
                | ExceptionCode::WritePerm
                | ExceptionCode::ExecViolation
        );
        if !is_access_fault {
            return false;
        }
        let page = self.cpu.exception.value & !0xfff;
        let Some((bytes, perm)) = self.lazy_pages.remove(&page) else {
            return false;
        };
        // Fill the page's bytes (bypassing permission checks) and grant the
        // intended permission, then clear the fault so the retry runs clean.
        if self
            .cpu
            .mem
            .write_bytes(page, &bytes, icicle_cpu::mem::perm::NONE)
            .is_err()
            || self
                .cpu
                .mem
                .update_perm(page, bytes.len() as u64, perm)
                .is_err()
        {
            // Could not resolve it; put it back and let the fault stand.
            self.lazy_pages.insert(page, (bytes, perm));
            return false;
        }
        self.cpu.exception.clear();
        self.page_ins += 1;
        mark_page_in_retry();
        true
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
        self.jit_trace_meta.clear();
        if let Some(jit) = self.jit.as_deref_mut() {
            self.jit_budget.clear(jit);
        }
    }

    /// Caps the wasm code the JIT backend may hold, in bytes; `0` is unlimited.
    /// Over the cap, the least recently used compiled blocks are evicted and fall
    /// back to the interpreter until they grow hot again. Bounds the engine's
    /// native code memory across a long session.
    pub fn set_jit_code_budget(&mut self, bytes: usize) {
        self.jit_budget.budget = bytes;
    }

    /// A snapshot of the compiled-code budget and its metrics.
    pub fn jit_code_stats(&self) -> JitCodeStats {
        self.jit_budget.stats()
    }

    /// How many times a compiled block ran in place of the interpreter.
    pub fn jit_dispatch_count(&self) -> u64 {
        self.jit_dispatches
    }

    pub fn jit_block_dispatch_count(&self) -> u64 {
        self.jit_block_dispatches
    }

    pub fn jit_region_dispatch_count(&self) -> u64 {
        self.jit_region_dispatches
    }

    pub fn track_executed_bytes(&mut self, enabled: bool) {
        self.executed_instructions = enabled.then(std::collections::HashSet::new);
    }

    /// Unique guest source bytes belonging to instructions that reached an
    /// instruction marker. Overlapping ranges are merged before counting.
    pub fn executed_byte_count(&self) -> u64 {
        let Some(instructions) = &self.executed_instructions else {
            return 0;
        };
        let mut ranges = instructions
            .iter()
            .filter_map(|&(start, len)| start.checked_add(len).map(|end| (start, end)))
            .collect::<Vec<_>>();
        ranges.sort_unstable();
        let mut total = 0_u64;
        let mut current: Option<(u64, u64)> = None;
        for (start, end) in ranges {
            match current {
                Some((before, through)) if start <= through => {
                    current = Some((before, through.max(end)));
                }
                Some((before, through)) => {
                    total = total.saturating_add(through - before);
                    current = Some((start, end));
                }
                None => current = Some((start, end)),
            }
        }
        if let Some((start, end)) = current {
            total = total.saturating_add(end - start);
        }
        total
    }

    /// How well the JIT covers the blocks a profiled run actually executed.
    ///
    /// Weighs each profiled block by `entries * instructions` (the guest
    /// instructions it retired), so the answer is about executed work, not the
    /// static op count. Requires [`profile_blocks`] to have been on during the
    /// run. `None` if it was not.
    pub fn jit_coverage(&self) -> Option<JitCoverage> {
        let profile = self.profile.as_ref()?;
        // Latest lifted block at each address (a re-lift replaces an earlier one),
        // with its arena id so self-loop targets can be resolved.
        let mut by_addr: std::collections::HashMap<u64, (u64, &lifter::Block)> =
            std::collections::HashMap::new();
        for (id, block) in self.code.blocks.iter().enumerate() {
            by_addr.insert(block.start, (id as u64, block));
        }
        // Block ids that appear in some looping trace formed from a hot block —
        // the reach of the trace selector.
        let mut in_a_trace: std::collections::HashSet<usize> = std::collections::HashSet::new();
        for &(id, _) in by_addr.values() {
            if let Some(order) = select_trace(&self.code.blocks, id as usize, &|addr| {
                by_addr.get(&addr).map(|(id, _)| *id as usize)
            }) {
                in_a_trace.extend(order);
            }
        }

        let mut hot = 0u64;
        let mut covered = 0u64;
        let mut covered_self_loop = 0u64;
        let mut covered_chain = 0u64;
        let mut covered_trace = 0u64;
        let mut hist: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        // How the non-self-loop covered blocks exit, weighted by executed work —
        // to characterize the shape of the multi-block opportunity.
        let mut exits: std::collections::HashMap<&'static str, u64> =
            std::collections::HashMap::new();
        // Dispatch granularity for the non-self-loop path: how many jit_calls
        // (block entries) land on blocks of each size. A per-block dispatch to a
        // tiny block cannot amortize the call overhead the way a region does, so
        // this predicts whether the JIT can speed the block up at all.
        let mut chain_dispatches = 0u64;
        let mut size_buckets: std::collections::HashMap<&'static str, u64> =
            std::collections::HashMap::new();
        let bucket = |n: u64| -> &'static str {
            match n {
                0..=1 => "1",
                2..=4 => "2-4",
                5..=16 => "5-16",
                17..=64 => "17-64",
                _ => "65+",
            }
        };
        let internal = |t: Target| matches!(t, Target::Internal(_));
        let ext_const = |t: Target| matches!(t, Target::External(pcode::Value::Const(..)));
        let exit_kind = |exit: lifter::BlockExit| -> &'static str {
            match exit {
                lifter::BlockExit::Jump { target } if internal(target) => "jump-internal",
                lifter::BlockExit::Jump { target } if ext_const(target) => "jump-extern-const",
                lifter::BlockExit::Jump { .. } => "jump-indirect",
                lifter::BlockExit::Branch {
                    target,
                    fallthrough,
                    ..
                } => match (internal(target), internal(fallthrough)) {
                    (true, true) => "branch-both-internal",
                    (true, false) | (false, true) => "branch-one-internal",
                    (false, false) => "branch-no-internal",
                },
                lifter::BlockExit::Call { .. } => "call",
                lifter::BlockExit::Return { .. } => "return",
            }
        };
        for (addr, prof) in profile {
            let Some(&(id, block)) = by_addr.get(addr) else {
                continue;
            };
            let weight = prof.entries.saturating_mul(prof.instructions);
            if weight == 0 {
                continue;
            }
            hot = hot.saturating_add(weight);
            match crate::jit::first_bail(&block.pcode) {
                None => {
                    covered = covered.saturating_add(weight);
                    if self_loop_kind(block, id).is_some() {
                        covered_self_loop = covered_self_loop.saturating_add(weight);
                    } else {
                        covered_chain = covered_chain.saturating_add(weight);
                        if in_a_trace.contains(&(id as usize)) {
                            covered_trace = covered_trace.saturating_add(weight);
                        }
                        *exits.entry(exit_kind(block.exit)).or_default() += weight;
                        chain_dispatches = chain_dispatches.saturating_add(prof.entries);
                        *size_buckets.entry(bucket(prof.instructions)).or_default() += prof.entries;
                    }
                }
                Some(b) => {
                    *hist.entry(format!("{}@{}", b.op, b.width)).or_default() += weight;
                }
            }
        }
        let mut bails: Vec<(String, u64)> = hist.into_iter().collect();
        bails.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let mut chain_exits: Vec<(String, u64)> =
            exits.into_iter().map(|(k, v)| (k.to_owned(), v)).collect();
        chain_exits.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let order = ["1", "2-4", "5-16", "17-64", "65+"];
        let chain_dispatch_sizes: Vec<(String, u64)> = order
            .iter()
            .filter_map(|&k| size_buckets.get(k).map(|&v| (k.to_owned(), v)))
            .collect();
        Some(JitCoverage {
            hot_insns: hot,
            covered_insns: covered,
            covered_self_loop_insns: covered_self_loop,
            covered_chain_insns: covered_chain,
            covered_trace_insns: covered_trace,
            chain_exits,
            chain_dispatches,
            chain_dispatch_sizes,
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
        let resume_page_in = std::mem::take(&mut self.resume_page_in);
        if !resume_page_in {
            if self.cpu.block_id == u64::MAX {
                if let Some((block, _)) = self.get_current_block() {
                    self.cpu.block_id = block;
                    self.cpu.block_offset = 0;
                }
            }
            self.update_timer();
        }
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
                let started = self.phase_times.map(|_| std::time::Instant::now());
                self.run_block_interpreter();
                if let (Some(t), Some(pt)) = (started, self.phase_times.as_mut()) {
                    pt.exec_ns += t.elapsed().as_nanos() as u64;
                }
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
            decoded: self.lift_decoded,
            reused: self.lift_reused,
            flushes: self.flush_count,
        }
    }

    /// Drops every lifted block, including the content-addressed index.
    /// Prefer this to `vm.code.flush_code()`: emptying `code.blocks` on its
    /// own leaves the index holding block numbers that no longer mean
    /// anything.
    pub fn flush_code(&mut self) {
        self.flush_count += 1;
        self.code.flush_code();
        self.lifted.clear();
        // Compiled handles were built from bytes that are now gone. A key can
        // survive a flush (self-modifying code rewrites a page without changing
        // the asid), so keying alone is not enough — drop the handles, the bail
        // decisions, and the hotness counts, and let re-lifted blocks earn the
        // JIT again from their new bytes.
        self.jit_cache.clear();
        self.jit_region_cache.clear();
        self.jit_trace_meta.clear();
        self.jit_entries.clear();
        if let Some(jit) = self.jit.as_deref_mut() {
            self.jit_budget.clear(jit);
        }
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

        // Demand paging: a fault on a registered non-resident page is served and
        // the faulting instruction retried, before the OS layer could turn the
        // fault into a signal. `block_id`/`block_offset` are left where the fault
        // left them, so re-entering the run loop retries exactly that pcode.
        if !self.lazy_pages.is_empty() && self.try_page_in() {
            return VmExit::Running;
        }

        let started = self.phase_times.map(|_| std::time::Instant::now());
        let env_exit = self.env.handle_exception(&mut self.cpu);
        if let (Some(t), Some(pt)) = (started, self.phase_times.as_mut()) {
            pt.syscall_ns += t.elapsed().as_nanos() as u64;
        }
        if let Some(exit) = env_exit {
            return exit;
        }

        // Some host-side memory operations (notably Linux MADV_DONTNEED)
        // legitimately replace guest bytes without passing through a p-code
        // store. The MMU clears executable-page marks before that mutation
        // and raises this latch so the corresponding lifted blocks cannot
        // survive into the next dispatch. Do this after the environment has
        // completed its syscall state transition, so the resumed PC is the
        // instruction following the syscall and is re-lifted from its actual
        // current bytes.
        if std::mem::take(&mut self.cpu.mem.invalidate_icache) {
            self.flush_code();
            self.cpu.block_id = u64::MAX;
            self.cpu.block_offset = 0;
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
        if addr < 0x10000 && jit_trace_enabled() {
            let start = self
                .code
                .blocks
                .get(self.cpu.block_id as usize)
                .map(|b| b.start)
                .unwrap_or(u64::MAX);
            eprintln!(
                "[jit] LOW TARGET {addr:#x} from block_id={} start={start:#x} offset={}",
                self.cpu.block_id, self.cpu.block_offset
            );
        }
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

        let started = self.phase_times.map(|_| std::time::Instant::now());
        let lifted = self.lift(pc);
        if let (Some(t), Some(pt)) = (started, self.phase_times.as_mut()) {
            pt.lift_ns += t.elapsed().as_nanos() as u64;
        }
        match lifted {
            Ok(group) => {
                self.cpu.block_id = group.blocks.0 as u64;
                self.cpu.block_offset = 0;
                VmExit::Running
            }
            Err(e) => {
                tracing::trace!("DecodeError at {pc:#x}: {e:?}");
                let fault_address = match e {
                    lifter::DecodeError::NonExecutableMemory(address) => address,
                    _ => pc,
                };
                self.cpu.exception = Exception::new(ExceptionCode::from(e), fault_address);
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
        adjust_cpu_fuel_for_block_reentry(&mut self.cpu, block, offset, take_page_in_retry());

        'blocks: loop {
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
            let jit_trace = jit_trace_enabled();
            // A zero-instruction block retires nothing: dispatching it would advance
            // register state under an icount that never moves, and its handle would
            // be reused by a real block that shares the address. Keep it out of the
            // JIT entirely (the region path already required `num > 0`); the
            // interpreter runs it.
            if offset == 0 && !block.has_breakpoint() && block.num_instructions > 0 {
                if let Some(after) = self.jit_after {
                    // Key the JIT caches by block id — the only identity that
                    // names exactly one p-code body. Blocks can share a start
                    // address (REP-style lifts, re-lifts after a code page-in),
                    // and `execve` lifts fresh blocks with fresh ids, so an id
                    // never serves one block's compiled code to another.
                    let key = block_id;
                    let count = self.jit_entries.entry(key).or_insert(0);
                    *count += 1;
                    let hot = *count >= after;

                    // Multi-block region path. The selector only admits a
                    // bounded, closed trace with static side exits; all edges
                    // inside that trace stay in one wasm invocation. The
                    // packed return value contains both the exact retired
                    // instruction count and the block/address at which Rust
                    // must resume.
                    if hot {
                        if let Some(order) =
                            select_trace(&self.code.blocks, block_id as usize, &|addr| {
                                resolve_trace_external(&self.code, self.get_block_key(addr))
                            })
                        {
                            let handle = match self.jit_region_cache.get(&key).copied() {
                                Some(decided) => decided,
                                None => match crate::jit::translate_trace(
                                    &self.code.blocks,
                                    &order,
                                    self.cpu.arch.reg_pc,
                                ) {
                                    None => {
                                        self.jit_region_cache.insert(key, None);
                                        None
                                    }
                                    Some(translation) => {
                                        self.jit_budget.make_room(
                                            translation.bytes.len(),
                                            self.jit
                                                .as_deref_mut()
                                                .expect("jit installed when hot"),
                                            &mut self.jit_cache,
                                            &mut self.jit_region_cache,
                                            &mut self.jit_trace_meta,
                                        );
                                        match self
                                            .jit
                                            .as_deref_mut()
                                            .and_then(|j| j.compile(&translation.bytes))
                                        {
                                            Some(h) => {
                                                self.jit_region_cache.insert(key, Some(h));
                                                self.jit_trace_meta.insert(
                                                    key,
                                                    TraceMeta {
                                                        resumes: translation.resumes,
                                                        fault_sites: translation.fault_sites,
                                                        blocks: order,
                                                    },
                                                );
                                                self.jit_budget.record(
                                                    h,
                                                    key,
                                                    true,
                                                    translation.bytes.len(),
                                                );
                                                Some(h)
                                            }
                                            None => None,
                                        }
                                    }
                                },
                            };
                            if let (Some(handle), Some(meta)) =
                                (handle, self.jit_trace_meta.get(&key).cloned())
                            {
                                let fuel_before = self.cpu.fuel.remaining;
                                let outcome = if fuel_before < block.num_instructions as u64 {
                                    // The trace ABI cannot retire a fractional
                                    // block. Fall through to the ordinary path,
                                    // which stops at the exact instruction
                                    // boundary instead of treating a zero-work
                                    // trace return as corrupted metadata.
                                    crate::jit::RegionOutcome::Unavailable
                                } else {
                                    match self.jit.as_mut() {
                                        Some(j) => j.call_region(
                                            handle,
                                            &mut self.cpu,
                                            fuel_before.min(JIT_REGION_DISPATCH_BUDGET),
                                        ),
                                        None => crate::jit::RegionOutcome::Unavailable,
                                    }
                                };
                                match outcome {
                                    crate::jit::RegionOutcome::Ran(packed) => {
                                        let retired = packed >> crate::jit::TRACE_RESUME_BITS;
                                        let resume_index = (packed
                                            & ((1 << crate::jit::TRACE_RESUME_BITS) - 1))
                                            as usize;
                                        let Some(resume) = meta.resumes.get(resume_index).copied()
                                        else {
                                            self.cpu.exception.code =
                                                ExceptionCode::InternalError as u32;
                                            self.cpu.exception.value =
                                                InternalError::CorruptedBlockMap as u64;
                                            break 'blocks;
                                        };
                                        if retired == 0 || retired > fuel_before {
                                            self.cpu.exception.code =
                                                ExceptionCode::InternalError as u32;
                                            self.cpu.exception.value =
                                                InternalError::CorruptedBlockMap as u64;
                                            break 'blocks;
                                        }
                                        self.cpu.fuel.remaining -= retired;
                                        self.jit_dispatches += 1;
                                        self.jit_region_dispatches += 1;
                                        record_trace_instruction_ranges(
                                            &mut self.executed_instructions,
                                            &self.code.blocks,
                                            &meta.blocks,
                                            retired,
                                            None,
                                        );
                                        self.jit_budget.touch(handle);
                                        if jit_trace {
                                            eprintln!(
                                                "[jit] trace {:#x} blocks={} retired={retired} resume={:#x}",
                                                block.start,
                                                meta.blocks.len(),
                                                resume.addr
                                            );
                                        }
                                        if resume.block_id != usize::MAX {
                                            block_id = resume.block_id as u64;
                                            offset = 0;
                                            self.cpu.block_id = block_id;
                                            self.cpu.block_offset = 0;
                                            block = match self.code.blocks.get(resume.block_id) {
                                                Some(block) => block,
                                                None => {
                                                    self.corrupted_block_map(block_id);
                                                    break 'blocks;
                                                }
                                            };
                                            set_current_block_start(block.start);
                                            set_current_icount(self.cpu.icount());
                                            continue 'blocks;
                                        }

                                        self.cpu.write_pc(resume.addr);
                                        match self.code.map.get(&self.get_block_key(resume.addr)) {
                                            Some(group) => {
                                                block_id = group.blocks.0 as u64;
                                                offset = 0;
                                                self.cpu.block_id = block_id;
                                                self.cpu.block_offset = 0;
                                                block =
                                                    match self.code.blocks.get(block_id as usize) {
                                                        Some(block) => block,
                                                        None => {
                                                            self.corrupted_block_map(block_id);
                                                            break 'blocks;
                                                        }
                                                    };
                                                set_current_block_start(block.start);
                                                set_current_icount(self.cpu.icount());
                                                continue 'blocks;
                                            }
                                            None => {
                                                self.cpu.block_id = block_id;
                                                self.cpu.exception.code =
                                                    ExceptionCode::CodeNotTranslated as u32;
                                                self.cpu.exception.value = resume.addr;
                                                break 'blocks;
                                            }
                                        }
                                    }
                                    crate::jit::RegionOutcome::Faulted(retired, index) => {
                                        let Some(&(fault_block, local_index)) =
                                            meta.fault_sites.get(index as usize)
                                        else {
                                            self.cpu.exception.code =
                                                ExceptionCode::InternalError as u32;
                                            self.cpu.exception.value =
                                                InternalError::CorruptedBlockMap as u64;
                                            break 'blocks;
                                        };
                                        if retired > fuel_before {
                                            self.cpu.exception.code =
                                                ExceptionCode::InternalError as u32;
                                            self.cpu.exception.value =
                                                InternalError::CorruptedBlockMap as u64;
                                            break 'blocks;
                                        }
                                        self.cpu.fuel.remaining -= retired;
                                        let faulted = &self.code.blocks[fault_block];
                                        let (pc, guest_insns) =
                                            fault_pc_and_fuel(&faulted.pcode, local_index);
                                        if let Some(pc) = pc {
                                            self.cpu.write_pc(pc);
                                        }
                                        self.cpu.fuel.remaining =
                                            self.cpu.fuel.remaining.saturating_sub(guest_insns);
                                        self.jit_dispatches += 1;
                                        self.jit_region_dispatches += 1;
                                        record_trace_instruction_ranges(
                                            &mut self.executed_instructions,
                                            &self.code.blocks,
                                            &meta.blocks,
                                            retired,
                                            Some((fault_block, local_index)),
                                        );
                                        self.jit_budget.touch(handle);
                                        self.cpu.block_id = fault_block as u64;
                                        self.cpu.block_offset = local_index as u64;
                                        break 'blocks;
                                    }
                                    crate::jit::RegionOutcome::Unavailable => {}
                                }
                            }
                        }
                    }

                    // Region (self-loop) path. A register-only self-loop runs its
                    // whole loop in one call; a self-loop that needs the host
                    // caches a bail here and takes the per-block path below.
                    if let Some(cond) = self_loop_kind(block, block_id) {
                        let handle = match self.jit_region_cache.get(&key).copied() {
                            Some(decided) => decided,
                            None if hot => match crate::jit::translate_region(&block.pcode, cond) {
                                // Not a region we can build: a permanent bail.
                                None => {
                                    self.jit_region_cache.insert(key, None);
                                    None
                                }
                                Some(bytes) => {
                                    self.jit_budget.make_room(
                                        bytes.len(),
                                        self.jit.as_deref_mut().expect("jit installed when hot"),
                                        &mut self.jit_cache,
                                        &mut self.jit_region_cache,
                                        &mut self.jit_trace_meta,
                                    );
                                    match self.jit.as_deref_mut().and_then(|j| j.compile(&bytes)) {
                                        Some(h) => {
                                            self.jit_region_cache.insert(key, Some(h));
                                            self.jit_budget.record(h, key, true, bytes.len());
                                            Some(h)
                                        }
                                        // A transient decline (over budget, runtime
                                        // refused): leave the cache absent so it retries
                                        // once room frees, not a permanent bail.
                                        None => None,
                                    }
                                }
                            },
                            None => None,
                        };
                        if let Some(handle) = handle {
                            let num = block.num_instructions as u64;
                            if num > 0 && self.cpu.fuel.remaining >= num {
                                // Bound the region to the fuel budget so it never
                                // retires more than the interpreter would in this
                                // slice; at least one iteration by the guard above.
                                let max_iters =
                                    (self.cpu.fuel.remaining / num).min(JIT_REGION_DISPATCH_BUDGET);
                                let outcome = match self.jit.as_mut() {
                                    Some(j) => j.call_region(handle, &mut self.cpu, max_iters),
                                    None => crate::jit::RegionOutcome::Unavailable,
                                };
                                match outcome {
                                    crate::jit::RegionOutcome::Ran(iters) => {
                                        if jit_trace {
                                            eprintln!(
                                                "[jit] region {:#x} n={num} iters={iters} fuel={}",
                                                block.start, self.cpu.fuel.remaining
                                            );
                                        }
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
                                        self.jit_region_dispatches += 1;
                                        if iters > 0 {
                                            record_instruction_ranges(
                                                &mut self.executed_instructions,
                                                &block.pcode,
                                                0,
                                                None,
                                            );
                                        }
                                        self.jit_budget.touch(handle);
                                        jit_ran = true;
                                    }
                                    crate::jit::RegionOutcome::Faulted(iters, index) => {
                                        if jit_trace {
                                            eprintln!(
                                                "[jit] region-fault {:#x} iters={iters} index={index} fuel={}",
                                                block.start, self.cpu.fuel.remaining
                                            );
                                        }
                                        // A host op faulted mid-loop. Charge the fully
                                        // completed iterations first (each retired the
                                        // whole block), then reproduce the interpreter's
                                        // partial faulting iteration exactly as the
                                        // per-block Faulted arm does: tick PC and fuel up
                                        // to the fault so the exception the import raised
                                        // is seen in the same state, and resume the
                                        // interpreter at the faulting pcode index.
                                        self.cpu.fuel.remaining = self
                                            .cpu
                                            .fuel
                                            .remaining
                                            .saturating_sub(iters.saturating_mul(num));
                                        let (pc, guest_insns) =
                                            fault_pc_and_fuel(&block.pcode, index as usize);
                                        if let Some(pc) = pc {
                                            self.cpu.write_pc(pc);
                                        }
                                        self.cpu.fuel.remaining =
                                            self.cpu.fuel.remaining.saturating_sub(guest_insns);
                                        self.jit_dispatches += 1;
                                        self.jit_region_dispatches += 1;
                                        record_instruction_ranges(
                                            &mut self.executed_instructions,
                                            &block.pcode,
                                            0,
                                            (iters == 0).then_some(index as usize),
                                        );
                                        self.jit_budget.touch(handle);
                                        self.cpu.block_id = block_id;
                                        self.cpu.block_offset = index as u64;
                                        break;
                                    }
                                    crate::jit::RegionOutcome::Unavailable => {}
                                }
                            }
                        }
                    }

                    // Per-block (single-shot) path, when the region did not run.
                    if !jit_ran {
                        let handle = match self.jit_cache.get(&key).copied() {
                            Some(decided) => decided,
                            None if hot => match crate::jit::translate_block(&block.pcode) {
                                // Not translatable: a permanent bail. A block that
                                // touches guest memory, divides, or raises translates
                                // the same way; its host callbacks are wired at run time.
                                None => {
                                    self.jit_cache.insert(key, None);
                                    None
                                }
                                Some(bytes) => {
                                    self.jit_budget.make_room(
                                        bytes.len(),
                                        self.jit.as_deref_mut().expect("jit installed when hot"),
                                        &mut self.jit_cache,
                                        &mut self.jit_region_cache,
                                        &mut self.jit_trace_meta,
                                    );
                                    match self.jit.as_deref_mut().and_then(|j| j.compile(&bytes)) {
                                        Some(h) => {
                                            self.jit_cache.insert(key, Some(h));
                                            self.jit_budget.record(h, key, false, bytes.len());
                                            Some(h)
                                        }
                                        // Transient decline: leave the cache absent to
                                        // retry once room frees, not a permanent bail.
                                        None => None,
                                    }
                                }
                            },
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
                                        if jit_trace {
                                            eprintln!(
                                                "[jit] block {:#x} n={} fuel={}",
                                                block.start,
                                                block.num_instructions,
                                                self.cpu.fuel.remaining
                                            );
                                        }
                                        // The compiled block ticks no per-instruction
                                        // fuel the way InstructionMarker does; charge
                                        // the whole block here so icount stays exact.
                                        self.cpu.fuel.remaining -= block.num_instructions as u64;
                                        self.jit_dispatches += 1;
                                        self.jit_block_dispatches += 1;
                                        record_instruction_ranges(
                                            &mut self.executed_instructions,
                                            &block.pcode,
                                            0,
                                            None,
                                        );
                                        self.jit_budget.touch(handle);
                                        jit_ran = true;
                                    }
                                    crate::jit::JitOutcome::Faulted(i) => {
                                        if jit_trace {
                                            eprintln!(
                                                "[jit] block-fault {:#x} index={i} fuel={} exc={:#x}@{:#x}",
                                                block.start,
                                                self.cpu.fuel.remaining,
                                                self.cpu.exception.code,
                                                self.cpu.exception.value
                                            );
                                            for (n, inst) in
                                                block.pcode.instructions.iter().enumerate()
                                            {
                                                eprintln!("[jit]   pcode[{n}] {inst:?}");
                                            }
                                        }
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
                                        self.jit_block_dispatches += 1;
                                        record_instruction_ranges(
                                            &mut self.executed_instructions,
                                            &block.pcode,
                                            0,
                                            Some(i as usize),
                                        );
                                        self.jit_budget.touch(handle);
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
                let start_offset = offset as usize;
                unsafe {
                    let stopped = self
                        .cpu
                        .interpret_block_unchecked(&block.pcode, start_offset);
                    record_instruction_ranges(
                        &mut self.executed_instructions,
                        &block.pcode,
                        start_offset,
                        stopped,
                    );
                    if let Some(offset) = stopped {
                        // We exited early due to an exception, so keep track of
                        // the offset where the CPU exited from.
                        self.cpu.block_id = block_id;
                        self.cpu.block_offset = offset as u64;
                        break;
                    }
                }
            }

            let exit_target = self.cpu.block_exit(block.exit);
            if jit_trace && jit_ran {
                eprintln!("[jit]   -> {exit_target:?} pc={:#x}", self.cpu.read_pc());
            }
            match exit_target {
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
            self.lift_reused += 1;
            let key = self.get_block_key(addr);
            self.code.map.insert(key, group);
            return Ok(group);
        }
        self.lift_decoded += 1;

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

/// The block ids, in execution order, of a linear looping trace anchored at
/// `header`, or `None` if no clean trace forms. A trace is a chain of blocks
/// joined by in-group edges that closes with an edge back to the header; a
/// conditional branch's non-followed direction becomes a side exit to a static
/// address. Bounded in length, and never a single self-loop block (that is the
/// region's job). Correctness never depends on which direction is followed — a
/// wrong guess just fails to close, so no trace forms.
fn select_trace(
    blocks: &[lifter::Block],
    header: usize,
    resolve_external: &impl Fn(u64) -> Option<usize>,
) -> Option<Vec<usize>> {
    const MAX_BLOCKS: usize = 8;
    // In-group block id of a target, and whether a target has a static resume
    // address (an in-group block's start, or an external constant) so a side
    // exit to it can write a constant PC.
    let in_group = |t: Target| -> Option<usize> {
        match t {
            Target::Internal(b) if b < blocks.len() => Some(b),
            // A jump across lift groups is represented as an external constant.
            // Resolve it through the caller's current BlockKey (address, ISA,
            // and address-space id), never by scanning the global append-only
            // arena where another process can own the newest block at that VA.
            Target::External(pcode::Value::Const(addr, _)) => resolve_external(addr),
            _ => None,
        }
    };
    let has_static_addr = |t: Target| -> bool {
        match t {
            Target::Internal(b) => b < blocks.len(),
            Target::External(pcode::Value::Const(..)) => true,
            _ => false,
        }
    };

    let mut order = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut cur = header;
    loop {
        if order.len() >= MAX_BLOCKS {
            return None;
        }
        if !seen.insert(cur) {
            return None; // revisited a non-header block: not a clean linear loop
        }
        order.push(cur);
        let block = blocks.get(cur)?;
        // A block whose body cannot fully translate can never be a trace member.
        if crate::jit::first_bail(&block.pcode).is_some() {
            return None;
        }
        match block.exit {
            lifter::BlockExit::Jump { target } => match in_group(target) {
                Some(n) if n == header => return (order.len() >= 2).then_some(order),
                Some(n) if !seen.contains(&n) => cur = n,
                _ => return None,
            },
            lifter::BlockExit::Branch {
                target,
                fallthrough,
                ..
            } => {
                let (t_id, f_id) = (in_group(target), in_group(fallthrough));
                // Close the loop if either direction returns to the header and
                // the other side-exits to a static address.
                if t_id == Some(header) && has_static_addr(fallthrough) && order.len() >= 2 {
                    return Some(order);
                }
                if f_id == Some(header) && has_static_addr(target) && order.len() >= 2 {
                    return Some(order);
                }
                // Otherwise follow one in-group, unvisited successor whose
                // sibling is a static side exit; prefer the fallthrough.
                if let Some(n) = f_id.filter(|&n| n != header && !seen.contains(&n)) {
                    if has_static_addr(target) {
                        cur = n;
                        continue;
                    }
                }
                if let Some(n) = t_id.filter(|&n| n != header && !seen.contains(&n)) {
                    if has_static_addr(fallthrough) {
                        cur = n;
                        continue;
                    }
                }
                return None;
            }
            _ => return None, // Call / Return / indirect: not traceable
        }
    }
}

fn resolve_trace_external(code: &BlockTable, key: BlockKey) -> Option<usize> {
    code.map.get(&key).map(|group| group.blocks.0)
}

/// Records exactly the unique guest instructions a linear trace reached.
/// `retired` counts whole blocks before a normal side exit/budget return or
/// before `fault`, and the trace always starts at `order[0]`. Once a complete
/// cycle retired, every member was visited; otherwise only the retired prefix
/// was. This avoids both over-counting untaken side blocks and under-counting
/// blocks completed before a later block faulted.
fn record_trace_instruction_ranges(
    tracking: &mut Option<std::collections::HashSet<(u64, u64)>>,
    blocks: &[lifter::Block],
    order: &[usize],
    retired: u64,
    fault: Option<(usize, usize)>,
) {
    if tracking.is_none() {
        return;
    }
    let cycle = order.iter().fold(0_u64, |total, &id| {
        total.saturating_add(
            blocks
                .get(id)
                .map_or(0, |block| block.num_instructions as u64),
        )
    });
    let mut remaining = retired;
    for &id in order {
        let Some(block) = blocks.get(id) else {
            continue;
        };
        let instructions = block.num_instructions as u64;
        if retired >= cycle || remaining >= instructions {
            record_instruction_ranges(tracking, &block.pcode, 0, None);
            remaining = remaining.saturating_sub(instructions);
        } else {
            break;
        }
    }
    if let Some((id, through)) =
        fault.and_then(|(id, through)| order.contains(&id).then_some((id, through)))
    {
        if let Some(block) = blocks.get(id) {
            record_instruction_ranges(tracking, &block.pcode, 0, Some(through));
        }
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

/// Records guest instruction source ranges whose markers ran in one p-code
/// slice. `through` is the inclusive p-code offset where execution stopped;
/// `None` means the slice completed. Keeping `(address, length)` pairs makes
/// the hot path one hash insertion per distinct instruction, while
/// [`InterpVm::executed_byte_count`] performs the rarer interval union.
fn record_instruction_ranges(
    tracking: &mut Option<std::collections::HashSet<(u64, u64)>>,
    block: &pcode::Block,
    start: usize,
    through: Option<usize>,
) {
    let Some(tracking) = tracking.as_mut() else {
        return;
    };
    let end = through
        .map(|offset| offset.saturating_add(1))
        .unwrap_or(block.instructions.len())
        .min(block.instructions.len());
    if start >= end {
        return;
    }
    for instruction in &block.instructions[start..end] {
        if matches!(instruction.op, pcode::Op::InstructionMarker) {
            tracking.insert((
                instruction.inputs.first().as_u64(),
                instruction.inputs.second().as_u64(),
            ));
        }
    }
}

/// Adjusts the fuel counter when the interpreter is entered mid-block.
///
/// - When we enter the interpreter at the start of a block that has pcode
///   instructions injected before the first instruction marker, the fuel
///   counter must not be decremented before the first marker executes.
/// - When we resume in the middle of a block (e.g. after a fault), the fuel
///   counter must be decremented to account for the missing marker.
fn adjust_cpu_fuel_for_block_reentry(
    cpu: &mut Cpu,
    block: &lifter::Block,
    offset: u64,
    page_in_retry: bool,
) {
    if page_in_retry {
        return;
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_external_targets_are_resolved_by_the_full_address_space_key() {
        let mut code = BlockTable::default();
        let group = |block, start| lifter::BlockGroup {
            blocks: (block, block + 1),
            start,
            end: start + 1,
        };
        let at = 0x40_0000;
        code.map.insert(
            BlockKey {
                vaddr: at,
                isa_mode: 1,
                asid: 7,
            },
            group(3, at),
        );
        code.map.insert(
            BlockKey {
                vaddr: at,
                isa_mode: 1,
                asid: 8,
            },
            group(9, at),
        );

        assert_eq!(
            resolve_trace_external(
                &code,
                BlockKey {
                    vaddr: at,
                    isa_mode: 1,
                    asid: 7,
                }
            ),
            Some(3)
        );
        assert_eq!(
            resolve_trace_external(
                &code,
                BlockKey {
                    vaddr: at,
                    isa_mode: 1,
                    asid: 8,
                }
            ),
            Some(9)
        );
        assert_eq!(
            resolve_trace_external(
                &code,
                BlockKey {
                    vaddr: at,
                    isa_mode: 2,
                    asid: 8,
                }
            ),
            None
        );
    }
}
