// webTOS execution worker: hosts the wasm engine off the UI thread.
// Messages in:  { type: "start", elf: ArrayBuffer }
// Messages out: { type: "status", text }, { type: "output", text },
//               { type: "done", status, exitCode, icount }, { type: "error", text }

let exports = null;

const mem = () => new Uint8Array(exports.memory.buffer);
const text = (ptr, len) => new TextDecoder().decode(mem().slice(ptr, ptr + len));
const lastError = () => text(exports.wtw_error_ptr(), exports.wtw_error_len());

async function ensureEngine() {
  if (exports) return;
  postMessage({ type: "status", text: "loading wasm module…" });
  const url = new URL("./webtos_web.wasm", self.location.href);
  const { instance } = await WebAssembly.instantiateStreaming(fetch(url), {});
  exports = instance.exports;

  postMessage({ type: "status", text: "compiling SLEIGH specification…" });
  const t0 = performance.now();
  if (exports.wtw_init() !== 0) throw new Error(`engine init failed: ${lastError()}`);
  postMessage({
    type: "status",
    text: `engine ready in ${(performance.now() - t0).toFixed(0)} ms`,
  });
}

function runElf(elfBytes) {
  const elf = new Uint8Array(elfBytes);
  const ptr = exports.wtw_alloc(elf.length);
  mem().set(elf, ptr);
  if (exports.wtw_load(ptr, elf.length) !== 0) {
    throw new Error(`ELF load failed: ${lastError()}`);
  }

  // Run in fuel slices so the worker stays responsive to future control
  // messages; drain guest output after every slice.
  let status;
  do {
    status = exports.wtw_run(1_000_000);
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
    if (msg.type === "start") {
      await ensureEngine();
      runElf(msg.elf);
    }
  } catch (e) {
    postMessage({ type: "error", text: String(e) });
  }
};
