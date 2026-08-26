// webTOS execution worker: hosts the wasm Linux runtime off the UI thread.
// Messages in:  { type: "boot", files: [{path, bytes: ArrayBuffer}],
//                                links: [{path, target}] }
//               { type: "exec", path, argv: [..], envp: [..] }
//               { type: "spawn", path, argv, envp, rows, cols }
//                                     -- like exec, but stdin/stdout/stderr
//                                        are a terminal and the run yields
//                                        to this worker's message queue
//               { type: "input", data: string }  -- keystrokes for the terminal
//               { type: "resize", rows, cols }   -- terminal size (SIGWINCH)
//               { type: "persist" }   -- snapshot the guest FS into OPFS
//               { type: "forget" }    -- delete the OPFS snapshot
// Messages out: { type: "status", text }, { type: "ready", restored, storage },
//               { type: "output", text },
//               { type: "waiting" }   -- the guest is blocked on the terminal
//               { type: "done", status, error, exitCode, icount },
//               { type: "persisted", bytes }, { type: "error", text }

const SNAPSHOT_FILE = "webtos-fs.bin";
/// Guest instructions per slice. Bounds how long the worker goes without
/// draining output or reading its own message queue.
const FUEL = 5_000_000;
/// `wtw_run` status classes shared with crates/webtos-web.
const STATUS_RUNNING = 0;
const STATUS_HALT = 1;
const STATUS_AWAITING_INPUT = 7;

// Whether this browsing context may use the origin-private filesystem at all.
// WebKit refuses it outright when the profile has no on-disk storage (a
// private window), so the host reports the capability up front instead of
// failing at the first "Save".
let storageReady = false;

async function opfsProbe() {
  try {
    if (typeof navigator === "undefined" || !navigator.storage) return false;
    await navigator.storage.getDirectory();
    return true;
  } catch {
    return false;
  }
}

async function opfsRead(name) {
  try {
    const root = await navigator.storage.getDirectory();
    const handle = await root.getFileHandle(name);
    const file = await handle.getFile();
    return new Uint8Array(await file.arrayBuffer());
  } catch {
    return null;
  }
}

async function opfsWrite(name, bytes) {
  const root = await navigator.storage.getDirectory();
  const handle = await root.getFileHandle(name, { create: true });
  const writable = await handle.createWritable();
  await writable.write(bytes);
  await writable.close();
}

async function opfsDelete(name) {
  try {
    const root = await navigator.storage.getDirectory();
    await root.removeEntry(name);
  } catch {
    // Nothing to delete.
  }
}

let exports = null;

const mem = () => new Uint8Array(exports.memory.buffer);
const text = (ptr, len) => new TextDecoder().decode(mem().slice(ptr, ptr + len));
const lastError = () => text(exports.wtw_error_ptr(), exports.wtw_error_len());
const put = (value) => {
  const data = typeof value === "string" ? new TextEncoder().encode(value) : new Uint8Array(value);
  const ptr = exports.wtw_alloc(data.length);
  mem().set(data, ptr);
  return [ptr, data.length];
};

async function boot(files, links = []) {
  postMessage({ type: "status", text: "loading wasm module…" });
  const url = new URL("./webtos_web.wasm", self.location.href);
  const { instance } = await WebAssembly.instantiateStreaming(fetch(url), {});
  exports = instance.exports;

  postMessage({ type: "status", text: "compiling SLEIGH specification…" });
  const t0 = performance.now();
  if (exports.wtw_init() !== 0) throw new Error(`machine init failed: ${lastError()}`);

  // Restore the filesystem persisted before the last reload, if any.
  storageReady = await opfsProbe();
  let restored = false;
  const snapshot = storageReady ? await opfsRead(SNAPSHOT_FILE) : null;
  if (snapshot && snapshot.length > 0) {
    if (exports.wtw_fs_import(...put(snapshot)) === 0) {
      restored = true;
    } else {
      postMessage({ type: "status", text: `snapshot ignored: ${lastError()}` });
    }
  }

  // Seed images are (re-)injected on top of whatever was restored.
  for (const file of files) {
    if (exports.wtw_add_file(...put(file.path), ...put(file.bytes)) !== 0) {
      throw new Error(`add_file ${file.path}: ${lastError()}`);
    }
  }
  for (const link of links) {
    if (exports.wtw_add_symlink(...put(link.path), ...put(link.target)) !== 0) {
      throw new Error(`add_symlink ${link.path}: ${lastError()}`);
    }
  }
  postMessage({
    type: "status",
    text: `machine ready in ${(performance.now() - t0).toFixed(0)} ms` +
      (restored ? " — filesystem restored from the previous session" : ""),
  });
  postMessage({ type: "ready", restored, storage: storageReady });
}

async function persist() {
  if (!storageReady) {
    throw new Error("browser storage is unavailable here (private window or blocked storage)");
  }
  if (exports.wtw_fs_export() !== 0) throw new Error(`export failed: ${lastError()}`);
  const bytes = mem().slice(
    exports.wtw_fs_ptr(),
    exports.wtw_fs_ptr() + exports.wtw_fs_len(),
  );
  await opfsWrite(SNAPSHOT_FILE, bytes);
  postMessage({ type: "persisted", bytes: bytes.length });
}

function load(path, argv, envp) {
  for (const arg of argv) exports.wtw_arg(...put(arg));
  for (const env of envp) exports.wtw_env(...put(env));
  if (exports.wtw_load(...put(path)) !== 0) {
    throw new Error(`load failed: ${lastError()}`);
  }
}

function drain() {
  const out = text(exports.wtw_output_ptr(), exports.wtw_output_len());
  if (out.length > 0) postMessage({ type: "output", text: out });
}

function finish(status) {
  postMessage({
    type: "done",
    status,
    error: status === STATUS_HALT ? "" : lastError(),
    exitCode: exports.wtw_exit_code(),
    icount: exports.wtw_icount_hi() * 2 ** 32 + exports.wtw_icount_lo(),
  });
}

function exec(path, argv, envp) {
  load(path, argv, envp);
  // Run to completion in fuel slices, draining guest output after each.
  let status;
  do {
    status = exports.wtw_run(FUEL);
    drain();
  } while (status === STATUS_RUNNING);
  finish(status);
}

// ---------------------------------------------------------------- terminal

// An interactive process is not a single call: it runs, blocks for a
// keystroke, and continues. `running` says a pump is in flight, `waiting`
// says the guest is parked on the terminal until input or a resize arrives.
let running = false;
let waiting = false;

// A macrotask yield that the browser does not clamp to 4 ms the way nested
// setTimeout is. Letting the worker reach its message queue between slices is
// what makes typing and resizing land mid-run.
const channel = new MessageChannel();
const yieldToQueue = () =>
  new Promise((resolve) => {
    channel.port1.onmessage = () => resolve();
    channel.port2.postMessage(0);
  });

async function pump() {
  if (running) return;
  running = true;
  try {
    for (;;) {
      const status = exports.wtw_run(FUEL);
      drain();
      if (status === STATUS_AWAITING_INPUT) {
        waiting = true;
        postMessage({ type: "waiting" });
        return;
      }
      if (status !== STATUS_RUNNING) {
        finish(status);
        return;
      }
      await yieldToQueue();
    }
  } finally {
    running = false;
  }
}

function spawn(path, argv, envp, rows, cols) {
  load(path, argv, envp);
  if (exports.wtw_pty_install(rows, cols) !== 0) {
    throw new Error(`terminal setup failed: ${lastError()}`);
  }
  waiting = false;
  pump();
}

/// Delivers host keystrokes and restarts the pump if the guest was parked.
function input(data) {
  if (exports.wtw_pty_input(...put(data)) !== 0) {
    throw new Error(`terminal input failed: ${lastError()}`);
  }
  if (waiting) {
    waiting = false;
    pump();
  }
}

/// Reports a new window size. SIGWINCH can wake a parked guest, so a resize
/// resumes the pump too — that is how a full-screen program repaints without
/// the user typing.
function resize(rows, cols) {
  if (exports.wtw_pty_resize(rows, cols) !== 0) {
    throw new Error(`terminal resize failed: ${lastError()}`);
  }
  if (waiting) {
    waiting = false;
    pump();
  }
}

self.onmessage = async (event) => {
  const msg = event.data;
  try {
    if (msg.type === "boot") await boot(msg.files, msg.links);
    if (msg.type === "exec") exec(msg.path, msg.argv, msg.envp);
    if (msg.type === "spawn") {
      spawn(msg.path, msg.argv, msg.envp, msg.rows, msg.cols);
    }
    if (msg.type === "input") input(msg.data);
    if (msg.type === "resize") resize(msg.rows, msg.cols);
    if (msg.type === "persist") await persist();
    if (msg.type === "forget") {
      if (!storageReady) throw new Error("browser storage is unavailable here");
      await opfsDelete(SNAPSHOT_FILE);
      postMessage({ type: "status", text: "saved filesystem deleted" });
    }
  } catch (e) {
    postMessage({ type: "error", text: String(e) });
  }
};
