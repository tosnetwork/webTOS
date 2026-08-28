//! Browser execution host boundary for the webTOS Linux runtime.
//!
//! Exposes a small C ABI over one Linux machine (x64-engine interpreter +
//! linux-compat environment) so the wasm module needs no JS binding
//! generator. All pointers are offsets into the module's linear memory;
//! lengths are u32 so no BigInt support is required. The wasm module is
//! single-threaded, so the thread-local state is effectively global.
//!
//! Call sequence per process: `wtw_init` once; then `wtw_add_file` for the
//! guest image and root filesystem (or `wtw_file_create` +
//! `wtw_file_append` to stream a large one in), `wtw_arg`/`wtw_env` to stage argv and
//! envp, `wtw_load` with the guest path, and `wtw_run` in fuel slices,
//! draining output with `wtw_output_*` after each slice. The filesystem
//! persists across `wtw_load` calls. Any `-1` return leaves a message
//! readable via `wtw_error_*`.
//!
//! For an interactive workload, call `wtw_pty_install` between `wtw_load` and
//! the first `wtw_run`: stdin/stdout/stderr then sit on a pty whose master the
//! host holds, so the guest takes its terminal path. `wtw_run` reports
//! `STATUS_AWAITING_INPUT` when the guest blocks on a read the host has not
//! answered; the host yields to the event loop, delivers keystrokes with
//! `wtw_pty_input`, and calls `wtw_run` again. `wtw_pty_resize` reports a new
//! window size and raises SIGWINCH so a full-screen program redraws.

use std::cell::RefCell;

use linux_compat::{net::HostBroker, Machine};
use pcode::{Op, VarNode};
use x64_engine::jit::{translate_block, var_offset, REG_SPACE_BYTES};
use x64_engine::{CpuExit, EngineConfig};

mod spec {
    include!(concat!(env!("OUT_DIR"), "/spec_files.rs"));
}

/// Guest exit classes reported by [`wtw_run`].
pub const STATUS_RUNNING: i32 = 0;
pub const STATUS_HALT: i32 = 1;
pub const STATUS_PAGE_FAULT: i32 = 2;
pub const STATUS_ILLEGAL_INSTRUCTION: i32 = 3;
pub const STATUS_INTERRUPTED: i32 = 4;
pub const STATUS_OUT_OF_MEMORY: i32 = 5;
pub const STATUS_UNHANDLED: i32 = 6;
/// The guest is blocked reading the terminal and the host owes it input.
/// Not an error: feed `wtw_pty_input` and call `wtw_run` again.
pub const STATUS_AWAITING_INPUT: i32 = 7;
/// The guest is blocked on the network and the host owes it socket activity.
/// Not an error: carry out the pending commands, deliver results, run again.
pub const STATUS_AWAITING_NETWORK: i32 = 8;
/// The workload has spent the instructions `wtw_set_cpu_budget_kinsn` allowed
/// it. Not a failure: raise the budget and call `wtw_run` again to continue
/// where it stopped, or stop. Distinct from `STATUS_RUNNING`, which means the
/// turn is over and the host should call again — a host that confuses the two
/// spins forever on a workload with no allowance left.
pub const STATUS_OUT_OF_CPU: i32 = 9;
/// `wtw_net_budget_ms` when the guest armed no timer: the host may wait as
/// long as it wants.
pub const NET_BUDGET_UNBOUNDED: u32 = u32::MAX;

struct HostState {
    machine: Option<Machine>,
    argv: Vec<Vec<u8>>,
    envp: Vec<Vec<u8>>,
    /// Last exported filesystem snapshot; kept alive for the reader.
    fs_image: Vec<u8>,
    /// Paths the next export writes as empty; see `wtw_fs_exclude`.
    fs_excluded: Vec<Vec<u8>>,
    /// Credentials awaiting `wtw_secrets_apply`, as (name, value, scope).
    secrets: Vec<(String, String, Vec<Vec<u8>>)>,
    /// Last drained guest output; kept alive so the pointer handed to JS
    /// stays valid until the next drain.
    output: Vec<u8>,
    /// Whether stdio is a host-driven pty, which changes where `wtw_run`
    /// collects guest output from.
    pty: bool,
    /// Last rendered architectural trace; kept alive for the reader.
    trace_text: String,
    /// The host-driven network broker, once `wtw_net_enable` attached one.
    net: Option<std::rc::Rc<std::cell::RefCell<HostBroker>>>,
    /// Last drained broker command stream; kept alive for the reader.
    net_commands: Vec<u8>,
    error: String,
    allocations: Vec<Box<[u8]>>,
    /// Staging buffer for bytes the host hands in repeatedly. See
    /// [`wtw_scratch`].
    scratch: Vec<u8>,
    /// A register buffer the JIT self-test runs a compiled block against, and
    /// the block's translated bytes. Both live in this linear memory so a
    /// compiled block can share the register buffer by importing this memory
    /// (see `wtw_jit_selftest`).
    jit_regs: Vec<u8>,
    jit_block: Vec<u8>,
}

thread_local! {
    static STATE: RefCell<HostState> = const {
        RefCell::new(HostState {
            machine: None,
            argv: Vec::new(),
            envp: Vec::new(),
            fs_image: Vec::new(),
            fs_excluded: Vec::new(),
            secrets: Vec::new(),
            output: Vec::new(),
            pty: false,
            trace_text: String::new(),
            net: None,
            net_commands: Vec::new(),
            error: String::new(),
            allocations: Vec::new(),
            scratch: Vec::new(),
            jit_regs: Vec::new(),
            jit_block: Vec::new(),
        })
    };
}

fn with_state<R>(f: impl FnOnce(&mut HostState) -> R) -> R {
    STATE.with(|state| f(&mut state.borrow_mut()))
}

fn fail(state: &mut HostState, message: impl Into<String>) -> i32 {
    state.error = message.into();
    -1
}

/// The largest single message the host can send.
///
/// Being inside linear memory is not enough to be a plausible message: a
/// length can be inside it and still be most of it, and a copy of most of a
/// 32-bit address space cannot be served — the allocator aborts, which is a
/// dead tab rather than an error the page can handle. Serving a few of them
/// in a row exhausts the space even when each one on its own would fit.
///
/// The largest message the host actually sends is a 4 MiB image chunk
/// (`IMAGE_CHUNK` in `web/worker.js`), and the largest staged file is an
/// agent image of about 52 MB. This is thirty-two times the chunk, above any
/// image the browser gates carry, and a thirty-second of the address space,
/// so no single call can take a meaningful bite out of it.
const MAX_MESSAGE_BYTES: u64 = 128 << 20;

/// How much staging memory the host may hold at once.
///
/// A `wtw_alloc` buffer lives until `wtw_reset`, so a host that keeps asking
/// for them keeps the module growing. Each request can be a perfectly
/// reasonable size and the total still reach the end of a 32-bit address
/// space, where the next allocation aborts — a dead tab, from a sequence of
/// calls none of which was individually wrong.
///
/// The host stages one image chunk at a time and a handful of small files, an
/// agent image among them: about 53 MB in the browser gates. This leaves room
/// for several times that before saying no.
const MAX_STAGED_BYTES: u64 = 256 << 20;

/// The longest path the host can name.
///
/// A path is not a message. It has a maximum length, the guest's `PATH_MAX`,
/// and a "path" of a hundred megabytes is not a long path — it is a length
/// that was never a path, which the filesystem then holds on to for as long
/// as the session lasts. Sweeping the boundary drove the module past two
/// gigabytes this way, one accepted call at a time.
const MAX_PATH_BYTES: u64 = 4096;

/// How many bytes of linear memory the module actually has.
///
/// A native build has no linear memory to speak of, so it answers with the
/// whole address space and the bound below never fires; the boundary this
/// guards only exists in wasm.
fn linear_memory_bytes() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        const WASM_PAGE: u64 = 65_536;
        core::arch::wasm32::memory_size(0) as u64 * WASM_PAGE
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        u64::MAX
    }
}

/// Copies `[ptr, ptr+len)` out of linear memory, or `None` if that range is
/// not inside it.
///
/// The old version of this documented a safety contract — that `ptr` came
/// from `wtw_alloc` — which the caller breaks by passing a different number.
/// On this boundary the caller's numbers are exactly the input whose
/// correctness is not ours to assume: a page can call these functions with
/// anything, and a length it made up turned into a read past the end of
/// memory, which is a trap, which is a dead tab.
fn slice_arg(ptr: u32, len: u32) -> Option<Vec<u8>> {
    bounded_arg(ptr, len, MAX_MESSAGE_BYTES)
}

/// The same, for an argument that names a path rather than carrying content.
fn path_arg(ptr: u32, len: u32) -> Option<Vec<u8>> {
    bounded_arg(ptr, len, MAX_PATH_BYTES)
}

fn bounded_arg(ptr: u32, len: u32, max: u64) -> Option<Vec<u8>> {
    if len as u64 > max {
        return None;
    }
    let end = (ptr as u64).checked_add(len as u64)?;
    if end > linear_memory_bytes() {
        return None;
    }
    // Inside memory the module owns — but a length can be inside it and still
    // be most of it, and a copy that cannot be allocated aborts rather than
    // failing. Ask for the room first.
    let mut out = Vec::new();
    out.try_reserve_exact(len as usize).ok()?;
    out.extend_from_slice(unsafe { std::slice::from_raw_parts(ptr as *const u8, len as usize) });
    Some(out)
}

/// Allocates `len` bytes inside the module and returns the offset, so the
/// host can copy input into wasm memory. Buffers live until `wtw_reset`.
#[no_mangle]
pub extern "C" fn wtw_alloc(len: u32) -> u32 {
    with_state(|state| {
        // The caller picks this number. One it cannot be served — four
        // gigabytes in a 32-bit address space — must come back as a refusal,
        // because a failed allocation inside wasm is an abort, and an abort
        // is a dead tab rather than an error the page can handle. Offset zero
        // is never a live allocation, so it is the refusal.
        let staged: u64 = state.allocations.iter().map(|b| b.len() as u64).sum();
        let mut buf = Vec::<u8>::new();
        if len as u64 > MAX_MESSAGE_BYTES
            || staged.saturating_add(len as u64) > MAX_STAGED_BYTES
            || buf.try_reserve_exact(len as usize).is_err()
        {
            state.error = format!(
                "wtw_alloc: cannot serve {len} bytes ({staged} already staged; \
                 wtw_reset releases them)"
            );
            return 0;
        }
        buf.resize(len as usize, 0);
        let buf = buf.into_boxed_slice();
        let ptr = buf.as_ptr() as u32;
        state.allocations.push(buf);
        ptr
    })
}

/// Returns the offset of a single staging buffer of at least `len` bytes.
///
/// Unlike [`wtw_alloc`], whose buffers live until `wtw_reset`, this one is
/// reused: every call may overwrite it, and growing it moves it, so the host
/// must call this immediately before writing and pass the result straight to
/// one call. Every API that takes bytes copies them, so nothing outlives the
/// call. This is the path for input that repeats without bound — keystrokes
/// and received packets — where per-call allocations would grow the module's
/// memory for as long as the session lasts.
#[no_mangle]
pub extern "C" fn wtw_scratch(len: u32) -> u32 {
    with_state(|state| {
        let len = len as usize;
        if state.scratch.len() < len {
            // Same refusal as `wtw_alloc`: a size that cannot be served is an
            // answer, not an abort.
            if len as u64 > MAX_MESSAGE_BYTES
                || state
                    .scratch
                    .try_reserve(len - state.scratch.len())
                    .is_err()
            {
                state.error = format!("wtw_scratch: cannot serve {len} bytes");
                return 0;
            }
            state.scratch.resize(len, 0);
        }
        state.scratch.as_ptr() as u32
    })
}

// ---- JIT self-test ----
//
// Proves, end to end and from JS, that the browser can compile a block this
// engine emits and run it against the engine's own memory. `wtw_jit_selftest`
// seeds a register buffer in this linear memory and translates a block that
// adds two of its registers; JS then compiles that block with `env.regs` bound
// to this memory and `env.regs_base` set to the buffer's offset, runs it, and
// `wtw_jit_check` confirms the sum landed in the buffer. No copy: the compiled
// block writes the very bytes this module reads. This is the browser wiring's
// shared-memory round trip, provable in Node before it reaches the run loop.

const JIT_TEST_OUT: i16 = 1;
const JIT_TEST_A: i16 = 2;
const JIT_TEST_B: i16 = 3;
const JIT_TEST_AV: u64 = 1000;
const JIT_TEST_BV: u64 = 337;

/// Seeds the register buffer and translates the self-test block (out = a + b),
/// leaving its bytes for `wtw_jit_block_ptr`/`_len`. Returns 0 on success, -1
/// if the block did not translate.
#[no_mangle]
pub extern "C" fn wtw_jit_selftest() -> i32 {
    with_state(|state| {
        state.jit_regs.clear();
        state.jit_regs.resize(REG_SPACE_BYTES as usize, 0);
        let put = |regs: &mut [u8], id: i16, value: u64| {
            let off = var_offset(VarNode::new(id, 8)) as usize;
            regs[off..off + 8].copy_from_slice(&value.to_le_bytes());
        };
        put(&mut state.jit_regs, JIT_TEST_A, JIT_TEST_AV);
        put(&mut state.jit_regs, JIT_TEST_B, JIT_TEST_BV);

        let (out, a, b) = (
            VarNode::new(JIT_TEST_OUT, 8),
            VarNode::new(JIT_TEST_A, 8),
            VarNode::new(JIT_TEST_B, 8),
        );
        let mut block = pcode::Block::new();
        block.push((out, Op::IntAdd, a, b));
        match translate_block(&block) {
            Some(bytes) => {
                state.jit_block = bytes;
                0
            }
            None => fail(state, "wtw_jit_selftest: block did not translate"),
        }
    })
}

/// Offset of the translated self-test block's bytes in this linear memory.
#[no_mangle]
pub extern "C" fn wtw_jit_block_ptr() -> u32 {
    with_state(|state| state.jit_block.as_ptr() as u32)
}

/// Length of the translated self-test block's bytes.
#[no_mangle]
pub extern "C" fn wtw_jit_block_len() -> u32 {
    with_state(|state| state.jit_block.len() as u32)
}

/// Offset of the register buffer — the value JS supplies as `env.regs_base`.
#[no_mangle]
pub extern "C" fn wtw_jit_regs_ptr() -> u32 {
    with_state(|state| state.jit_regs.as_ptr() as u32)
}

/// Length of the register buffer.
#[no_mangle]
pub extern "C" fn wtw_jit_regs_len() -> u32 {
    with_state(|state| state.jit_regs.len() as u32)
}

/// Returns 1 if the self-test's output register holds the expected sum — proof
/// the compiled block ran and wrote through the shared memory — else 0.
#[no_mangle]
pub extern "C" fn wtw_jit_check() -> i32 {
    with_state(|state| {
        let off = var_offset(VarNode::new(JIT_TEST_OUT, 8)) as usize;
        if state.jit_regs.len() < off + 8 {
            return 0;
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&state.jit_regs[off..off + 8]);
        i32::from(u64::from_le_bytes(bytes) == JIT_TEST_AV + JIT_TEST_BV)
    })
}

/// Builds the machine from the embedded SLEIGH specification. Returns 0 on
/// success.
#[no_mangle]
pub extern "C" fn wtw_init() -> i32 {
    with_state(|state| {
        let files = spec::SPEC_FILES
            .iter()
            .map(|&(name, content)| (name.to_owned(), content.to_owned()))
            .collect();
        match Machine::from_spec_files(files, &EngineConfig::default()) {
            Ok(machine) => {
                state.machine = Some(machine);
                0
            }
            Err(e) => fail(state, format!("machine build failed: {e}")),
        }
    })
}

/// Adds a file to the guest filesystem (parent directories are created).
#[no_mangle]
pub extern "C" fn wtw_add_file(path_ptr: u32, path_len: u32, data_ptr: u32, data_len: u32) -> i32 {
    with_state(|state| {
        let Some(machine) = state.machine.as_mut() else {
            return fail(state, "wtw_add_file called before wtw_init");
        };
        let Some(path) = path_arg(path_ptr, path_len) else {
            return fail(state, "path is not inside the module's memory");
        };
        let Some(data) = slice_arg(data_ptr, data_len) else {
            return fail(state, "data is not inside the module's memory");
        };
        match machine.add_file(&path, data, 0o755) {
            Ok(()) => 0,
            Err(e) => fail(state, e),
        }
    })
}

/// Starts a file the host will deliver in pieces, reserving `capacity` bytes.
/// An agent image runs to hundreds of megabytes, so it arrives as a stream:
/// `wtw_file_create` once, `wtw_file_append` per piece. Passing the whole
/// image through `wtw_alloc` instead would hold a second copy of it for the
/// module's lifetime, which on wasm32 is the difference between fitting and
/// not.
#[no_mangle]
pub extern "C" fn wtw_file_create(path_ptr: u32, path_len: u32, capacity: u32, mode: u32) -> i32 {
    with_state(|state| {
        let Some(machine) = state.machine.as_mut() else {
            return fail(state, "wtw_file_create called before wtw_init");
        };
        let Some(path) = path_arg(path_ptr, path_len) else {
            return fail(state, "path is not inside the module's memory");
        };
        match machine.create_file(&path, capacity as usize, mode) {
            Ok(()) => 0,
            Err(e) => fail(state, e),
        }
    })
}

/// Appends one piece to a file started with `wtw_file_create`. The bytes are
/// copied, so the host may stage them in the scratch buffer.
#[no_mangle]
pub extern "C" fn wtw_file_append(
    path_ptr: u32,
    path_len: u32,
    data_ptr: u32,
    data_len: u32,
) -> i32 {
    with_state(|state| {
        let Some(machine) = state.machine.as_mut() else {
            return fail(state, "wtw_file_append called before wtw_init");
        };
        let Some(path) = path_arg(path_ptr, path_len) else {
            return fail(state, "path is not inside the module's memory");
        };
        let Some(data) = slice_arg(data_ptr, data_len) else {
            return fail(state, "data is not inside the module's memory");
        };
        match machine.append_file(&path, &data) {
            Ok(()) => 0,
            Err(e) => fail(state, e),
        }
    })
}

/// Adds a symlink to the guest filesystem, so one multi-call image (BusyBox
/// and friends) can appear on `PATH` under each of its command names.
#[no_mangle]
pub extern "C" fn wtw_add_symlink(
    path_ptr: u32,
    path_len: u32,
    target_ptr: u32,
    target_len: u32,
) -> i32 {
    with_state(|state| {
        let Some(machine) = state.machine.as_mut() else {
            return fail(state, "wtw_add_symlink called before wtw_init");
        };
        let Some(path) = path_arg(path_ptr, path_len) else {
            return fail(state, "path is not inside the module's memory");
        };
        let Some(target) = path_arg(target_ptr, target_len) else {
            return fail(state, "target is not inside the module's memory");
        };
        match machine.add_symlink(&path, &target) {
            Ok(()) => 0,
            Err(e) => fail(state, e),
        }
    })
}

/// Appends one argv entry for the next `wtw_load`.
#[no_mangle]
pub extern "C" fn wtw_arg(ptr: u32, len: u32) -> i32 {
    with_state(|state| {
        let Some(arg) = slice_arg(ptr, len) else {
            return fail(state, "argument is not inside the module's memory");
        };
        state.argv.push(arg);
        0
    })
}

/// Appends one envp entry (`KEY=value`) for the next `wtw_load`.
#[no_mangle]
pub extern "C" fn wtw_env(ptr: u32, len: u32) -> i32 {
    with_state(|state| {
        let Some(var) = slice_arg(ptr, len) else {
            return fail(state, "environment entry is not inside the module's memory");
        };
        state.envp.push(var);
        0
    })
}

/// Loads the static ELF at `path` in the guest filesystem, consuming the
/// staged argv/envp. The filesystem persists from any previous process.
#[no_mangle]
pub extern "C" fn wtw_load(path_ptr: u32, path_len: u32) -> i32 {
    with_state(|state| {
        let argv = std::mem::take(&mut state.argv);
        let envp = std::mem::take(&mut state.envp);
        let Some(machine) = state.machine.as_mut() else {
            return fail(state, "wtw_load called before wtw_init");
        };
        let Some(path) = path_arg(path_ptr, path_len) else {
            return fail(state, "path is not inside the module's memory");
        };
        machine.set_args(argv, envp);
        match machine.load(&path) {
            Ok(()) => 0,
            Err(e) => fail(state, format!("ELF load failed: {e}")),
        }
    })
}

/// Runs up to `fuel` guest instructions. Returns a `STATUS_*` class;
/// `STATUS_RUNNING` means the fuel ran out and the caller should drain
/// output and call again.
#[no_mangle]
pub extern "C" fn wtw_run(fuel: u32) -> i32 {
    with_state(|state| {
        let Some(machine) = state.machine.as_mut() else {
            return fail(state, "wtw_run called before wtw_init");
        };
        machine.vm_mut().icount_limit = machine.icount().saturating_add(fuel as u64);
        let exit = machine.run();
        // With stdio on a pty the guest's writes land in the pty, not the
        // plain output buffer; exactly one of the two is ever non-empty.
        state.output = machine.take_output();
        if state.pty {
            state.output.extend(machine.drain_terminal_output());
        }
        classify(state, exit)
    })
}

/// Maps an engine exit to the status class the host sees, recording a
/// diagnostic for the ones that carry one.
fn classify(state: &mut HostState, exit: CpuExit) -> i32 {
    let machine = match state.machine.as_mut() {
        Some(machine) => machine,
        None => return STATUS_UNHANDLED,
    };
    match exit {
        CpuExit::InstructionLimit => STATUS_RUNNING,
        CpuExit::Halt { .. } => STATUS_HALT,
        CpuExit::Breakpoint { .. } => STATUS_RUNNING,
        CpuExit::Interrupted => {
            if machine.awaiting_network() {
                STATUS_AWAITING_NETWORK
            } else if machine.awaiting_terminal_input() {
                STATUS_AWAITING_INPUT
            } else {
                STATUS_INTERRUPTED
            }
        }
        CpuExit::OutOfMemory => STATUS_OUT_OF_MEMORY,
        CpuExit::OutOfCpu => STATUS_OUT_OF_CPU,
        CpuExit::PageFault { address, access } => {
            state.error = format!("page fault: {access:?} at {address:#x}");
            STATUS_PAGE_FAULT
        }
        CpuExit::IllegalInstruction { rip } => {
            state.error = format!("illegal instruction at {rip:#x}");
            STATUS_ILLEGAL_INSTRUCTION
        }
        CpuExit::Unhandled { code, value } => {
            state.error = format!("unhandled exception {code:?} ({value:#x})");
            STATUS_UNHANDLED
        }
    }
}

/// Puts the loaded process's stdin/stdout/stderr on a host-driven pty of
/// `rows` x `cols`, so `isatty` is true and the guest runs its interactive
/// terminal path. Call after `wtw_load`, before the first `wtw_run`.
#[no_mangle]
pub extern "C" fn wtw_pty_install(rows: u32, cols: u32) -> i32 {
    with_state(|state| {
        let Some(machine) = state.machine.as_mut() else {
            return fail(state, "wtw_pty_install called before wtw_init");
        };
        if rows == 0 || cols == 0 {
            return fail(state, "terminal size must be non-zero");
        }
        machine.install_pty_stdio(
            rows.min(u16::MAX as u32) as u16,
            cols.min(u16::MAX as u32) as u16,
        );
        state.pty = true;
        0
    })
}

/// Queues keystrokes for the terminal. They reach the guest when it next
/// blocks reading, so this may be called between `wtw_run` slices.
#[no_mangle]
pub extern "C" fn wtw_pty_input(ptr: u32, len: u32) -> i32 {
    with_state(|state| {
        let Some(machine) = state.machine.as_mut() else {
            return fail(state, "wtw_pty_input called before wtw_init");
        };
        let Some(bytes) = slice_arg(ptr, len) else {
            return fail(state, "bytes is not inside the module's memory");
        };
        machine.feed_terminal_input(&bytes);
        0
    })
}

/// Reports a new terminal size and raises SIGWINCH on the foreground group.
#[no_mangle]
pub extern "C" fn wtw_pty_resize(rows: u32, cols: u32) -> i32 {
    with_state(|state| {
        let Some(machine) = state.machine.as_mut() else {
            return fail(state, "wtw_pty_resize called before wtw_init");
        };
        if rows == 0 || cols == 0 {
            return fail(state, "terminal size must be non-zero");
        }
        machine.resize_terminal(
            rows.min(u16::MAX as u32) as u16,
            cols.min(u16::MAX as u32) as u16,
        );
        0
    })
}

// ------------------------------------------------------------------- trace

/// Starts recording an architectural trace, sampling registers and flags
/// every `sample_every` retired instructions (0 records events only). Call
/// after `wtw_load`, then drive the run with `wtw_run_traced`.
///
/// The point of exporting this is that the trace a browser records can be
/// compared against a reference recorded natively. Instruction counts already
/// match across engines; a trace says the architectural state does too.
#[no_mangle]
pub extern "C" fn wtw_trace_start(sample_every: u32) -> i32 {
    with_state(|state| {
        let Some(machine) = state.machine.as_mut() else {
            return fail(state, "wtw_trace_start called before wtw_init");
        };
        machine.record_trace(sample_every as u64);
        0
    })
}

/// Names the image the trace is of, so the recording identifies its subject
/// exactly as the native recorder does.
#[no_mangle]
pub extern "C" fn wtw_trace_image(
    path_ptr: u32,
    path_len: u32,
    data_ptr: u32,
    data_len: u32,
) -> i32 {
    with_state(|state| {
        let Some(machine) = state.machine.as_mut() else {
            return fail(state, "wtw_trace_image called before wtw_init");
        };
        let Some(path) = path_arg(path_ptr, path_len) else {
            return fail(state, "path is not inside the module's memory");
        };
        let Some(data) = slice_arg(data_ptr, data_len) else {
            return fail(state, "data is not inside the module's memory");
        };
        machine.describe_trace_image(&path, &data);
        0
    })
}

/// Runs up to `fuel` instructions, breaking at exact counts to sample state.
/// Returns the same `STATUS_*` classes as `wtw_run`.
#[no_mangle]
pub extern "C" fn wtw_run_traced(fuel: u32) -> i32 {
    with_state(|state| {
        let Some(machine) = state.machine.as_mut() else {
            return fail(state, "wtw_run_traced called before wtw_init");
        };
        let exit = machine.run_traced(fuel as u64);
        state.output = machine.take_output();
        if state.pty {
            state.output.extend(machine.drain_terminal_output());
        }
        classify(state, exit)
    })
}

/// Renders the recorded trace and returns its length; read it at
/// `wtw_trace_ptr`. Taking it ends the recording.
#[no_mangle]
pub extern "C" fn wtw_trace_take() -> i32 {
    with_state(|state| {
        let Some(machine) = state.machine.as_mut() else {
            return fail(state, "wtw_trace_take called before wtw_init");
        };
        match machine.take_trace() {
            Some(trace) => {
                state.trace_text = trace.to_text();
                state.trace_text.len() as i32
            }
            None => fail(state, "no trace was being recorded"),
        }
    })
}

#[no_mangle]
pub extern "C" fn wtw_trace_ptr() -> u32 {
    with_state(|state| state.trace_text.as_ptr() as u32)
}

/// Sets the guest's physical-memory cap, in mebibytes (default 1 GiB). A tab
/// has less to give than a workstation, and wasm32 caps the module's whole
/// linear memory at 4 GiB, so a host that knows its budget should say so:
/// the guest then fails an allocation cleanly instead of the module dying
/// when the browser refuses to grow. Returns -1 when the guest has already
/// allocated past the requested cap.
#[no_mangle]
pub extern "C" fn wtw_set_guest_memory_mb(mb: u32) -> i32 {
    with_state(|state| {
        let Some(machine) = state.machine.as_mut() else {
            return fail(state, "wtw_set_guest_memory_mb called before wtw_init");
        };
        if machine.set_guest_memory_mb(mb as usize) {
            0
        } else {
            fail(
                state,
                "cannot shrink below what the guest already allocated",
            )
        }
    })
}

/// Mebibytes of guest physical memory allocated so far.
#[no_mangle]
pub extern "C" fn wtw_guest_memory_used_mb() -> u32 {
    with_state(|state| {
        state
            .machine
            .as_ref()
            .map_or(0, |machine| machine.guest_memory_mb().0 as u32)
    })
}

/// The guest's physical-memory cap, in mebibytes.
#[no_mangle]
pub extern "C" fn wtw_guest_memory_cap_mb() -> u32 {
    with_state(|state| {
        state
            .machine
            .as_ref()
            .map_or(0, |machine| machine.guest_memory_mb().1 as u32)
    })
}

// ----------------------------------------------------------------- network

/// Attaches the host-driven network broker. Until this is called the guest
/// has no network at all: `socket(2)` fails with `EAFNOSUPPORT`. The module
/// still opens nothing itself — every connection is a command for the host,
/// which enforces its own policy on what may be reached.
#[no_mangle]
pub extern "C" fn wtw_net_enable() -> i32 {
    with_state(|state| {
        let Some(machine) = state.machine.as_mut() else {
            return fail(state, "wtw_net_enable called before wtw_init");
        };
        let broker = std::rc::Rc::new(std::cell::RefCell::new(HostBroker::new()));
        machine.set_network(broker.clone());
        state.net = Some(broker);
        0
    })
}

fn with_broker(state: &mut HostState, f: impl FnOnce(&mut HostBroker)) -> i32 {
    match state.net.clone() {
        Some(broker) => {
            f(&mut broker.borrow_mut());
            0
        }
        None => fail(state, "network is not enabled"),
    }
}

/// Moves the pending broker commands into the module's read buffer and
/// returns their length; read them at `wtw_net_cmd_ptr`. See
/// `linux_compat::net::HostBroker::take_commands` for the encoding.
#[no_mangle]
pub extern "C" fn wtw_net_take() -> i32 {
    with_state(|state| match state.net.clone() {
        Some(broker) => {
            state.net_commands = broker.borrow_mut().take_commands();
            state.net_commands.len() as i32
        }
        None => fail(state, "network is not enabled"),
    })
}

#[no_mangle]
pub extern "C" fn wtw_net_cmd_ptr() -> u32 {
    with_state(|state| state.net_commands.as_ptr() as u32)
}

/// Reports a connection open. `ip`/`port` carry the local address the host
/// assigned, or zero when it has none to report.
#[no_mangle]
pub extern "C" fn wtw_net_connected(handle: u32, ip: u32, port: u32) -> i32 {
    with_state(|state| {
        with_broker(state, |broker| {
            broker.deliver_connected(handle as u64, socket_addr(ip, port));
        })
    })
}

/// Delivers stream bytes received from the peer.
#[no_mangle]
pub extern "C" fn wtw_net_data(handle: u32, ptr: u32, len: u32) -> i32 {
    with_state(|state| {
        let Some(bytes) = slice_arg(ptr, len) else {
            return fail(state, "bytes is not inside the module's memory");
        };
        with_broker(state, |broker| {
            broker.deliver_data(handle as u64, &bytes);
        })
    })
}

/// Delivers one datagram and the address it came from.
#[no_mangle]
pub extern "C" fn wtw_net_datagram(handle: u32, ip: u32, port: u32, ptr: u32, len: u32) -> i32 {
    with_state(|state| {
        let Some(bytes) = slice_arg(ptr, len) else {
            return fail(state, "bytes is not inside the module's memory");
        };
        let from = socket_addr(ip, port)
            .unwrap_or_else(|| std::net::SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0));
        with_broker(state, |broker| {
            broker.deliver_datagram(handle as u64, from, &bytes);
        })
    })
}

/// Reports that the peer closed the stream.
#[no_mangle]
pub extern "C" fn wtw_net_closed(handle: u32) -> i32 {
    with_state(|state| {
        with_broker(state, |broker| {
            broker.deliver_closed(handle as u64);
        })
    })
}

/// Reports a transport failure the guest should see, as a Linux errno. A
/// destination the host refuses is reported here, typically `ENETUNREACH`.
#[no_mangle]
pub extern "C" fn wtw_net_error(handle: u32, errno: u32) -> i32 {
    with_state(|state| {
        with_broker(state, |broker| {
            broker.deliver_error(handle as u64, errno as u64);
        })
    })
}

/// Tells the machine the host waited for network activity and none arrived,
/// so the next stall may advance guest time and let socket timeouts fire.
#[no_mangle]
pub extern "C" fn wtw_net_expire() -> i32 {
    with_state(|state| {
        let Some(machine) = state.machine.as_mut() else {
            return fail(state, "wtw_net_expire called before wtw_init");
        };
        machine.expire_network_wait();
        0
    })
}

/// How long the host may wait for network activity before the guest's own
/// earliest timer fires, in milliseconds, or `NET_BUDGET_UNBOUNDED` when the
/// guest armed no timer.
#[no_mangle]
pub extern "C" fn wtw_net_budget_ms() -> u32 {
    with_state(|state| {
        state
            .machine
            .as_mut()
            .and_then(|machine| machine.network_wait_budget_ms())
            .map_or(NET_BUDGET_UNBOUNDED, |ms| {
                ms.min(NET_BUDGET_UNBOUNDED as u64 - 1) as u32
            })
    })
}

/// A zero address means "the host did not report one".
fn socket_addr(ip: u32, port: u32) -> Option<std::net::SocketAddrV4> {
    if ip == 0 && port == 0 {
        return None;
    }
    Some(std::net::SocketAddrV4::new(
        std::net::Ipv4Addr::from(ip),
        port as u16,
    ))
}

/// Serializes the guest filesystem for persistence; read the image via
/// `wtw_fs_ptr`/`wtw_fs_len`. Snapshot between processes, not mid-run.
/// One part of the machine's footprint, in kibibytes: 0 guest pages, 1
/// lifted code, 2 guest files, 3 the total. Kibibytes rather than bytes
/// because the total passes 4 GiB before a `u32` would.
#[no_mangle]
pub extern "C" fn wtw_footprint_kib(part: u32) -> u32 {
    with_state(|state| {
        let Some(machine) = state.machine.as_mut() else {
            return 0;
        };
        let f = machine.footprint();
        let bytes = match part {
            0 => f.guest_bytes,
            1 => f.code_bytes,
            2 => f.files_bytes,
            _ => f.total_bytes,
        };
        (bytes / 1024) as u32
    })
}

/// Caps the total footprint, in kibibytes; 0 removes the cap. A host that
/// knows its tab's ceiling sets this, and an image that would not fit is
/// then refused at the request rather than part-way through the download.
#[no_mangle]
pub extern "C" fn wtw_set_memory_budget_kib(kib: u32) -> i32 {
    with_state(|state| {
        let Some(machine) = state.machine.as_mut() else {
            return fail(state, "wtw_set_memory_budget_kib called before wtw_init");
        };
        machine.set_memory_budget(match kib {
            0 => None,
            kib => Some(kib as usize * 1024),
        });
        0
    })
}

/// Kibibytes left in the budget, or -1 when none is set.
#[no_mangle]
pub extern "C" fn wtw_memory_headroom_kib() -> i32 {
    with_state(|state| {
        let Some(machine) = state.machine.as_mut() else {
            return -1;
        };
        match machine.memory_headroom() {
            Some(left) => (left / 1024).min(i32::MAX as usize) as i32,
            None => -1,
        }
    })
}

/// Caps the guest filesystem, in kibibytes; 0 removes the cap. Memory's
/// budget refuses what the host asks for; this one refuses what the guest
/// writes — past the cap a guest write fails with `ENOSPC` instead of
/// growing the tab's memory until it dies. The cap covers the whole
/// filesystem, images included, so set it above what was loaded.
/// Installs the manifest the host has committed to; a zero length clears it.
///
/// The signature over the manifest is the host's to check, before this call,
/// with the platform's verifier — `crypto.subtle` in a browser, `node:crypto`
/// outside one. Hand-rolling a signature verifier here would be the wrong
/// trade: a wrong one fails open, accepting what it should not while nothing
/// says so, and the platform already ships an audited one. What this layer
/// owes is the other half, which a known-answer test can settle: that the
/// bytes delivered are the bytes the manifest names.
///
/// With a manifest installed, an image is checked before the guest runs it —
/// not when it arrives, so a host that forgets to say a stream finished
/// cannot skip the check that way — and an image the manifest does not name
/// is refused, because a manifest is a list of what may be delivered.
#[no_mangle]
pub extern "C" fn wtw_set_manifest(ptr: u32, len: u32) -> i32 {
    with_state(|state| {
        let Some(machine) = state.machine.as_mut() else {
            return fail(state, "wtw_set_manifest called before wtw_init");
        };
        if len == 0 {
            let _ = machine.set_manifest(None);
            return 0;
        }
        let Some(text) = slice_arg(ptr, len) else {
            return fail(state, "manifest is not inside the module's memory");
        };
        match machine.set_manifest(Some(&text)) {
            Ok(()) => 0,
            Err(why) => fail(state, why),
        }
    })
}

/// How many images the installed manifest names; zero when none is
/// installed, so a host can tell "nothing to check" from "nothing named".
#[no_mangle]
pub extern "C" fn wtw_manifest_len() -> u32 {
    with_state(|state| {
        state
            .machine
            .as_mut()
            .map_or(0, |machine| machine.manifest_paths().len() as u32)
    })
}

/// Writes the 32-byte digest of the SLEIGH specification this engine lifts
/// under into the scratch buffer, and returns its offset.
///
/// A host stores this beside any artifact it persists from the lift cache. A
/// cache built under a different spec is not merely stale — p-code lifted
/// under one spec, run under another, is silent wrong execution — so the
/// fingerprint is what a host checks before trusting a cache it saved.
#[no_mangle]
pub extern "C" fn wtw_spec_fingerprint() -> u32 {
    with_state(|state| {
        let fingerprint = state
            .machine
            .as_ref()
            .map(Machine::spec_fingerprint)
            .unwrap_or([0; 32]);
        if state.scratch.len() < 32 {
            state.scratch.resize(32, 0);
        }
        state.scratch[..32].copy_from_slice(&fingerprint);
        state.scratch.as_ptr() as u32
    })
}

/// Records that `ms` of real time passed while nothing ran.
///
/// A browser stops scheduling a background tab. This machine's clock is
/// retired instructions plus an idle warp, and neither moves while the host
/// is not calling `wtw_run` — so without this a resumed guest believes no
/// time passed, with its timers still pending and its idea of now
/// disagreeing with every peer it talks to.
#[no_mangle]
pub extern "C" fn wtw_skip_time_ms(ms: u32) -> i32 {
    with_state(|state| {
        let Some(machine) = state.machine.as_mut() else {
            return fail(state, "wtw_skip_time_ms called before wtw_init");
        };
        machine.skip_time((ms as u64).saturating_mul(1_000_000));
        0
    })
}

/// Caps the instructions the workload may retire, in thousands; 0 clears it.
///
/// Thousands because a `u32` of instructions is about two seconds of guest
/// time, which is too short a leash to be useful, and the boundary carries
/// 32-bit numbers.
#[no_mangle]
pub extern "C" fn wtw_set_cpu_budget_kinsn(kinsn: u32) -> i32 {
    with_state(|state| {
        let Some(machine) = state.machine.as_mut() else {
            return fail(state, "wtw_set_cpu_budget_kinsn called before wtw_init");
        };
        machine.set_cpu_budget((kinsn != 0).then(|| kinsn as u64 * 1_000));
        0
    })
}

/// Instructions the workload may still retire, in thousands, or -1 when no
/// budget is set.
#[no_mangle]
pub extern "C" fn wtw_cpu_headroom_kinsn() -> i32 {
    with_state(|state| {
        state
            .machine
            .as_ref()
            .and_then(Machine::cpu_headroom)
            .map_or(-1, |left| (left / 1_000).min(i32::MAX as u64) as i32)
    })
}

/// Caps the events the trace may record; 0 clears it. Past the cap the
/// workload keeps running and the log stops growing, which is why this is not
/// reported through `wtw_run`.
#[no_mangle]
pub extern "C" fn wtw_set_event_log_budget(events: u32) -> i32 {
    with_state(|state| {
        let Some(machine) = state.machine.as_mut() else {
            return fail(state, "wtw_set_event_log_budget called before wtw_init");
        };
        machine.set_event_log_budget((events != 0).then_some(events as usize));
        0
    })
}

/// Events that happened past the cap and were not recorded.
#[no_mangle]
pub extern "C" fn wtw_event_log_dropped() -> u32 {
    with_state(|state| {
        state.machine.as_mut().map_or(0, |machine| {
            machine.event_log_dropped().min(u32::MAX as u64) as u32
        })
    })
}

#[no_mangle]
pub extern "C" fn wtw_set_storage_budget_kib(kib: u32) -> i32 {
    with_state(|state| {
        let Some(machine) = state.machine.as_mut() else {
            return fail(state, "wtw_set_storage_budget_kib called before wtw_init");
        };
        machine.set_storage_budget(match kib {
            0 => None,
            kib => Some(kib as usize * 1024),
        });
        0
    })
}

/// Kibibytes the guest may still write, or -1 when no storage cap is set.
#[no_mangle]
pub extern "C" fn wtw_storage_headroom_kib() -> i32 {
    with_state(|state| {
        let Some(machine) = state.machine.as_mut() else {
            return -1;
        };
        match machine.storage_headroom() {
            Some(left) => (left / 1024).min(i32::MAX as usize) as i32,
            None => -1,
        }
    })
}

/// Caps the bytes the guest may relay through the host broker, in kibibytes;
/// 0 removes the cap. Past the cap the guest's sends and receives fail with
/// `EPERM`, so a workload cannot stream without end through somebody else's
/// tab.
#[no_mangle]
pub extern "C" fn wtw_set_network_budget_kib(kib: u32) -> i32 {
    with_state(|state| {
        let Some(machine) = state.machine.as_mut() else {
            return fail(state, "wtw_set_network_budget_kib called before wtw_init");
        };
        machine.set_network_budget(match kib {
            0 => None,
            kib => Some(kib as usize * 1024),
        });
        0
    })
}

/// One part of what the guest has relayed, in kibibytes: 0 sent, 1 received,
/// 2 the total. Counted whether or not a cap is set.
#[no_mangle]
pub extern "C" fn wtw_network_usage_kib(part: u32) -> u32 {
    with_state(|state| {
        let Some(machine) = state.machine.as_mut() else {
            return 0;
        };
        let usage = machine.network_usage();
        let bytes = match part {
            0 => usage.sent_bytes,
            1 => usage.received_bytes,
            _ => usage.total_bytes,
        };
        (bytes / 1024) as u32
    })
}

/// Kibibytes the guest may still relay, or -1 when no network cap is set.
#[no_mangle]
pub extern "C" fn wtw_network_headroom_kib() -> i32 {
    with_state(|state| {
        let Some(machine) = state.machine.as_mut() else {
            return -1;
        };
        match machine.network_headroom() {
            Some(left) => (left / 1024).min(i32::MAX as usize) as i32,
            None => -1,
        }
    })
}

/// Registers a credential the guest receives by placeholder rather than by
/// having it baked into an image. `${name}` is expanded in the files named by
/// `wtw_secret_scope` — or in every file when none are named — at
/// `wtw_secrets_apply`, and redacted back to the placeholder whenever the
/// filesystem is serialized, so a value never reaches browser storage.
///
/// The value is not echoed anywhere: no status message, no log line, no
/// error text carries it.
#[no_mangle]
pub extern "C" fn wtw_secret(name_ptr: u32, name_len: u32, value_ptr: u32, value_len: u32) -> i32 {
    with_state(|state| {
        let (Some(name), Some(value)) = (
            slice_arg(name_ptr, name_len),
            slice_arg(value_ptr, value_len),
        ) else {
            return fail(state, "secret is not inside the module's memory");
        };
        let name = String::from_utf8_lossy(&name).into_owned();
        let value = String::from_utf8_lossy(&value).into_owned();
        state.secrets.push((name, value, Vec::new()));
        0
    })
}

/// Restricts the most recently registered secret to one more guest path.
/// Called once per file the credential belongs in; with no call, the secret
/// reaches every file.
#[no_mangle]
pub extern "C" fn wtw_secret_scope(ptr: u32, len: u32) -> i32 {
    with_state(|state| {
        let Some(path) = path_arg(ptr, len) else {
            return fail(state, "path is not inside the module's memory");
        };
        match state.secrets.last_mut() {
            Some((_, _, paths)) => {
                paths.push(path);
                0
            }
            None => fail(state, "wtw_secret_scope called before wtw_secret"),
        }
    })
}

/// Applies every registered secret to the guest filesystem. Call after the
/// files that reference the placeholders exist and before `wtw_load`.
#[no_mangle]
pub extern "C" fn wtw_secrets_apply() -> i32 {
    with_state(|state| {
        let secrets = std::mem::take(&mut state.secrets);
        let Some(machine) = state.machine.as_mut() else {
            return fail(state, "wtw_secrets_apply called before wtw_init");
        };
        for (name, value, paths) in &secrets {
            let refs: Vec<&[u8]> = paths.iter().map(|p| p.as_slice()).collect();
            if refs.is_empty() {
                machine.set_secret(name, value);
            } else {
                machine.set_scoped_secret(name, value, &refs);
            }
        }
        machine.expand_secrets();
        0
    })
}

/// Names a file the next `wtw_fs_export` writes as empty. A host that streams
/// large images into the guest and caches them itself would otherwise carry
/// them in every snapshot too; it excludes them here and re-injects them after
/// the matching import. The list is consumed by the export.
#[no_mangle]
pub extern "C" fn wtw_fs_exclude(ptr: u32, len: u32) -> i32 {
    with_state(|state| {
        let Some(path) = path_arg(ptr, len) else {
            return fail(state, "path is not inside the module's memory");
        };
        state.fs_excluded.push(path);
        0
    })
}

#[no_mangle]
pub extern "C" fn wtw_fs_export() -> i32 {
    with_state(|state| {
        let excluded = std::mem::take(&mut state.fs_excluded);
        let Some(machine) = state.machine.as_mut() else {
            return fail(state, "wtw_fs_export called before wtw_init");
        };
        state.fs_image = machine.export_fs_excluding(&excluded);
        0
    })
}

#[no_mangle]
pub extern "C" fn wtw_fs_ptr() -> u32 {
    with_state(|state| state.fs_image.as_ptr() as u32)
}

#[no_mangle]
pub extern "C" fn wtw_fs_len() -> u32 {
    with_state(|state| state.fs_image.len() as u32)
}

/// Replaces the guest filesystem with a snapshot previously produced by
/// `wtw_fs_export` (typically loaded from browser storage after a reload).
#[no_mangle]
pub extern "C" fn wtw_fs_import(ptr: u32, len: u32) -> i32 {
    with_state(|state| {
        let Some(machine) = state.machine.as_mut() else {
            return fail(state, "wtw_fs_import called before wtw_init");
        };
        let Some(bytes) = slice_arg(ptr, len) else {
            return fail(state, "bytes is not inside the module's memory");
        };
        match machine.import_fs(&bytes) {
            Ok(()) => 0,
            Err(e) => fail(state, format!("filesystem import failed: {e}")),
        }
    })
}

/// Offset of the output drained by the last `wtw_run`.
#[no_mangle]
pub extern "C" fn wtw_output_ptr() -> u32 {
    with_state(|state| state.output.as_ptr() as u32)
}

/// Length of the output drained by the last `wtw_run`.
#[no_mangle]
pub extern "C" fn wtw_output_len() -> u32 {
    with_state(|state| state.output.len() as u32)
}

/// Offset of the last error message (UTF-8).
#[no_mangle]
pub extern "C" fn wtw_error_ptr() -> u32 {
    with_state(|state| state.error.as_ptr() as u32)
}

/// Length of the last error message.
#[no_mangle]
pub extern "C" fn wtw_error_len() -> u32 {
    with_state(|state| state.error.len() as u32)
}

/// Guest exit code recorded by `exit`/`exit_group`, or -1 if the guest has
/// not exited.
#[no_mangle]
pub extern "C" fn wtw_exit_code() -> i32 {
    with_state(|state| {
        state
            .machine
            .as_mut()
            .and_then(|machine| machine.exit_code())
            .unwrap_or(-1)
    })
}

/// Retired guest instruction count, low 32 bits.
#[no_mangle]
pub extern "C" fn wtw_icount_lo() -> u32 {
    with_state(|state| state.machine.as_ref().map_or(0, |m| m.icount() as u32))
}

/// Retired guest instruction count, high 32 bits.
#[no_mangle]
pub extern "C" fn wtw_icount_hi() -> u32 {
    with_state(|state| {
        state
            .machine
            .as_ref()
            .map_or(0, |m| (m.icount() >> 32) as u32)
    })
}

/// Drops the machine and all host-visible buffers.
#[no_mangle]
pub extern "C" fn wtw_reset() {
    with_state(|state| {
        state.machine = None;
        state.argv.clear();
        state.envp.clear();
        state.fs_image.clear();
        state.output.clear();
        state.pty = false;
        state.trace_text = String::new();
        state.net = None;
        state.net_commands.clear();
        state.error.clear();
        state.allocations.clear();
        state.scratch = Vec::new();
    });
}
