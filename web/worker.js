// webTOS execution worker: hosts the wasm Linux runtime off the UI thread.
// Messages in:  { type: "boot", files: [{path, bytes: ArrayBuffer}] }
//               { type: "exec", path, argv: [..], envp: [..] }
//               { type: "persist" }   -- snapshot the guest FS into OPFS
//               { type: "forget" }    -- delete the OPFS snapshot
// Messages out: { type: "status", text }, { type: "ready", restored },
//               { type: "output", text },
//               { type: "done", status, error, exitCode, icount },
//               { type: "persisted", bytes }, { type: "error", text }

const SNAPSHOT_FILE = "webtos-fs.bin";

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

async function boot(files) {
  postMessage({ type: "status", text: "loading wasm module…" });
  const url = new URL("./webtos_web.wasm", self.location.href);
  const { instance } = await WebAssembly.instantiateStreaming(fetch(url), {});
  exports = instance.exports;

  postMessage({ type: "status", text: "compiling SLEIGH specification…" });
  const t0 = performance.now();
  if (exports.wtw_init() !== 0) throw new Error(`machine init failed: ${lastError()}`);

  // Restore the filesystem persisted before the last reload, if any.
  let restored = false;
  const snapshot = typeof navigator !== "undefined" && navigator.storage
    ? await opfsRead(SNAPSHOT_FILE)
    : null;
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
  postMessage({
    type: "status",
    text: `machine ready in ${(performance.now() - t0).toFixed(0)} ms` +
      (restored ? " — filesystem restored from the previous session" : ""),
  });
  postMessage({ type: "ready", restored });
}

async function persist() {
  if (exports.wtw_fs_export() !== 0) throw new Error(`export failed: ${lastError()}`);
  const bytes = mem().slice(
    exports.wtw_fs_ptr(),
    exports.wtw_fs_ptr() + exports.wtw_fs_len(),
  );
  await opfsWrite(SNAPSHOT_FILE, bytes);
  postMessage({ type: "persisted", bytes: bytes.length });
}

function exec(path, argv, envp) {
  for (const arg of argv) exports.wtw_arg(...put(arg));
  for (const env of envp) exports.wtw_env(...put(env));
  if (exports.wtw_load(...put(path)) !== 0) {
    throw new Error(`load failed: ${lastError()}`);
  }

  // Run in fuel slices so the worker stays responsive; drain guest output
  // after every slice.
  let status;
  do {
    status = exports.wtw_run(5_000_000);
    const out = text(exports.wtw_output_ptr(), exports.wtw_output_len());
    if (out.length > 0) postMessage({ type: "output", text: out });
  } while (status === 0);

  const icount = exports.wtw_icount_hi() * 2 ** 32 + exports.wtw_icount_lo();
  postMessage({
    type: "done",
    status,
    error: status === 1 ? "" : lastError(),
    exitCode: exports.wtw_exit_code(),
    icount,
  });
}

self.onmessage = async (event) => {
  const msg = event.data;
  try {
    if (msg.type === "boot") await boot(msg.files);
    if (msg.type === "exec") exec(msg.path, msg.argv, msg.envp);
    if (msg.type === "persist") await persist();
    if (msg.type === "forget") {
      await opfsDelete(SNAPSHOT_FILE);
      postMessage({ type: "status", text: "saved filesystem deleted" });
    }
  } catch (e) {
    postMessage({ type: "error", text: String(e) });
  }
};
