//! Browser execution host boundary for the webTOS x64-engine.
//!
//! Exposes a small C ABI over one engine instance so the wasm module needs no
//! JS binding generator. All pointers are offsets into the module's linear
//! memory; lengths are u32 so no BigInt support is required. The wasm module
//! is single-threaded, so the thread-local state is effectively global.
//!
//! Call sequence: `wtw_init` -> (`wtw_alloc` + copy + `wtw_load`) ->
//! `wtw_run` in fuel slices, draining output with `wtw_output_*` after each
//! slice. Any `-1` return leaves a message readable via `wtw_error_*`.

use std::cell::RefCell;

use x64_engine::{CpuExit, Engine, EngineConfig};

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

const GUEST_PATH: &[u8] = b"guest.elf";

struct HostState {
    engine: Option<Engine>,
    /// Last drained guest output; kept alive so the pointer handed to JS
    /// stays valid until the next drain.
    output: Vec<u8>,
    error: String,
    allocations: Vec<Box<[u8]>>,
}

thread_local! {
    static STATE: RefCell<HostState> = RefCell::new(HostState {
        engine: None,
        output: Vec::new(),
        error: String::new(),
        allocations: Vec::new(),
    });
}

fn with_state<R>(f: impl FnOnce(&mut HostState) -> R) -> R {
    STATE.with(|state| f(&mut state.borrow_mut()))
}

fn fail(state: &mut HostState, message: impl Into<String>) -> i32 {
    state.error = message.into();
    -1
}

/// Allocates `len` bytes inside the module and returns the offset, so the
/// host can copy input (e.g. an ELF image) into wasm memory. Buffers live
/// until `wtw_reset`.
#[no_mangle]
pub extern "C" fn wtw_alloc(len: u32) -> u32 {
    with_state(|state| {
        let buf = vec![0_u8; len as usize].into_boxed_slice();
        let ptr = buf.as_ptr() as u32;
        state.allocations.push(buf);
        ptr
    })
}

/// Builds the engine from the embedded SLEIGH specification. Returns 0 on
/// success.
#[no_mangle]
pub extern "C" fn wtw_init() -> i32 {
    with_state(|state| {
        let files = spec::SPEC_FILES
            .iter()
            .map(|&(name, content)| (name.to_owned(), content.to_owned()))
            .collect();
        match Engine::new_linux_minimal_from_files(files, &EngineConfig::default()) {
            Ok(engine) => {
                state.engine = Some(engine);
                0
            }
            Err(e) => fail(state, format!("engine build failed: {e}")),
        }
    })
}

/// Loads the static ELF image at `[ptr, ptr+len)` in wasm memory. Returns 0
/// on success.
#[no_mangle]
pub extern "C" fn wtw_load(ptr: u32, len: u32) -> i32 {
    with_state(|state| {
        let Some(engine) = state.engine.as_mut() else {
            return fail(state, "wtw_load called before wtw_init");
        };
        // Safety: `ptr` must come from `wtw_alloc` (module-owned memory).
        let bytes =
            unsafe { std::slice::from_raw_parts(ptr as *const u8, len as usize) }.to_vec();
        engine.preload_file(GUEST_PATH, bytes);
        match engine.load(GUEST_PATH) {
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
        let Some(engine) = state.engine.as_mut() else {
            return fail(state, "wtw_run called before wtw_init");
        };
        engine.vm_mut().icount_limit = engine.icount().saturating_add(fuel as u64);
        let exit = engine.run();
        state.output = engine.take_output();
        match exit {
            CpuExit::InstructionLimit => STATUS_RUNNING,
            CpuExit::Halt { .. } => STATUS_HALT,
            CpuExit::Breakpoint { .. } => STATUS_RUNNING,
            CpuExit::Interrupted => STATUS_INTERRUPTED,
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
            .engine
            .as_mut()
            .and_then(|engine| engine.exit_code())
            .unwrap_or(-1)
    })
}

/// Retired guest instruction count, low 32 bits.
#[no_mangle]
pub extern "C" fn wtw_icount_lo() -> u32 {
    with_state(|state| state.engine.as_ref().map_or(0, |e| e.icount() as u32))
}

/// Retired guest instruction count, high 32 bits.
#[no_mangle]
pub extern "C" fn wtw_icount_hi() -> u32 {
    with_state(|state| state.engine.as_ref().map_or(0, |e| (e.icount() >> 32) as u32))
}

/// Drops the engine and all host-visible buffers.
#[no_mangle]
pub extern "C" fn wtw_reset() {
    with_state(|state| {
        state.engine = None;
        state.output.clear();
        state.error.clear();
        state.allocations.clear();
    });
}
