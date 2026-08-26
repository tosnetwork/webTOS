//! Browser execution host boundary for the webTOS Linux runtime.
//!
//! Exposes a small C ABI over one Linux machine (x64-engine interpreter +
//! linux-compat environment) so the wasm module needs no JS binding
//! generator. All pointers are offsets into the module's linear memory;
//! lengths are u32 so no BigInt support is required. The wasm module is
//! single-threaded, so the thread-local state is effectively global.
//!
//! Call sequence per process: `wtw_init` once; then `wtw_add_file` for the
//! guest image and root filesystem, `wtw_arg`/`wtw_env` to stage argv and
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

use linux_compat::Machine;
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

struct HostState {
    machine: Option<Machine>,
    argv: Vec<Vec<u8>>,
    envp: Vec<Vec<u8>>,
    /// Last exported filesystem snapshot; kept alive for the reader.
    fs_image: Vec<u8>,
    /// Last drained guest output; kept alive so the pointer handed to JS
    /// stays valid until the next drain.
    output: Vec<u8>,
    /// Whether stdio is a host-driven pty, which changes where `wtw_run`
    /// collects guest output from.
    pty: bool,
    error: String,
    allocations: Vec<Box<[u8]>>,
}

thread_local! {
    static STATE: RefCell<HostState> = const {
        RefCell::new(HostState {
            machine: None,
            argv: Vec::new(),
            envp: Vec::new(),
            fs_image: Vec::new(),
            output: Vec::new(),
            pty: false,
            error: String::new(),
            allocations: Vec::new(),
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

/// Copies `[ptr, ptr+len)` out of linear memory.
///
/// Safety contract: `ptr` must come from `wtw_alloc` (module-owned memory).
unsafe fn slice_arg(ptr: u32, len: u32) -> Vec<u8> {
    unsafe { std::slice::from_raw_parts(ptr as *const u8, len as usize) }.to_vec()
}

/// Allocates `len` bytes inside the module and returns the offset, so the
/// host can copy input into wasm memory. Buffers live until `wtw_reset`.
#[no_mangle]
pub extern "C" fn wtw_alloc(len: u32) -> u32 {
    with_state(|state| {
        let buf = vec![0_u8; len as usize].into_boxed_slice();
        let ptr = buf.as_ptr() as u32;
        state.allocations.push(buf);
        ptr
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
        let path = unsafe { slice_arg(path_ptr, path_len) };
        let data = unsafe { slice_arg(data_ptr, data_len) };
        match machine.add_file(&path, data, 0o755) {
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
        let path = unsafe { slice_arg(path_ptr, path_len) };
        let target = unsafe { slice_arg(target_ptr, target_len) };
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
        state.argv.push(unsafe { slice_arg(ptr, len) });
        0
    })
}

/// Appends one envp entry (`KEY=value`) for the next `wtw_load`.
#[no_mangle]
pub extern "C" fn wtw_env(ptr: u32, len: u32) -> i32 {
    with_state(|state| {
        state.envp.push(unsafe { slice_arg(ptr, len) });
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
        let path = unsafe { slice_arg(path_ptr, path_len) };
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
        match exit {
            CpuExit::InstructionLimit => STATUS_RUNNING,
            CpuExit::Halt { .. } => STATUS_HALT,
            CpuExit::Breakpoint { .. } => STATUS_RUNNING,
            CpuExit::Interrupted => {
                if machine.awaiting_terminal_input() {
                    STATUS_AWAITING_INPUT
                } else {
                    STATUS_INTERRUPTED
                }
            }
            CpuExit::OutOfMemory => STATUS_OUT_OF_MEMORY,
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
    })
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
        let bytes = unsafe { slice_arg(ptr, len) };
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

/// Serializes the guest filesystem for persistence; read the image via
/// `wtw_fs_ptr`/`wtw_fs_len`. Snapshot between processes, not mid-run.
#[no_mangle]
pub extern "C" fn wtw_fs_export() -> i32 {
    with_state(|state| {
        let Some(machine) = state.machine.as_mut() else {
            return fail(state, "wtw_fs_export called before wtw_init");
        };
        state.fs_image = machine.export_fs();
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
        let bytes = unsafe { slice_arg(ptr, len) };
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
        state.error.clear();
        state.allocations.clear();
    });
}
