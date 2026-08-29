// Probe: does the Claude Code TUI paint under the engine when the JIT is on?
// Drives the wasm module directly (Node's V8 compiles the engine ~30x faster
// than the native interpreter), delivers claude + loader + glibc by manifest,
// installs a pty, and pumps until the alternate screen appears or a budget
// runs out. Usage: node web/probe_claude_tui.mjs [minutes]
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { makeJitHost } from "./jit_host.mjs";

const wasmPath = new URL("./webtos_web.wasm", import.meta.url).pathname;
const minutes = Number(process.argv[2] ?? 10);

const claude = await readFile(new URL("./claude", import.meta.url));
const libDir = new URL("./claude-libs/", import.meta.url);
const lib = async (name) => ({
  path: name === "ld-linux-x86-64.so.2" ? "/lib64/ld-linux-x86-64.so.2" : `/lib/x86_64-linux-gnu/${name}`,
  bytes: await readFile(new URL(name, libDir)),
});
const files = [
  { path: "/bin/claude", bytes: claude },
  await lib("ld-linux-x86-64.so.2"),
  await lib("libc.so.6"),
  await lib("libm.so.6"),
  await lib("libdl.so.2"),
  await lib("libpthread.so.0"),
  await lib("librt.so.1"),
];

const chunkSize = 64 * 1024;
const chunks = new Map();
const dirs = new Set();
const records = [];
for (const { path, bytes } of files) {
  let at = 1;
  for (;;) {
    const next = path.indexOf("/", at);
    if (next < 0) break;
    dirs.add(path.slice(0, next));
    at = next + 1;
  }
  const hashes = [];
  for (let off = 0; off < bytes.length; off += chunkSize) {
    const chunk = bytes.subarray(off, Math.min(off + chunkSize, bytes.length));
    const hash = createHash("sha256").update(chunk).digest("hex");
    hashes.push(hash);
    chunks.set(hash, chunk);
  }
  records.push({
    path,
    line: `f 755 0 ${Buffer.from(path).toString("hex")} ${bytes.length} ${chunkSize} ${"0".repeat(16)} ${hashes.join(",")}`,
  });
}
for (const d of dirs) records.push({ path: d, line: `d 755 0 ${Buffer.from(d).toString("hex")}` });
records.sort((a, b) => (a.path < b.path ? -1 : 1));
const manifest = `webtos-chunk-manifest 1\n${records.map((r) => r.line).join("\n")}\n`;

const jit = makeJitHost();
const { instance } = await WebAssembly.instantiate(await readFile(wasmPath), { env: jit.imports });
const e = instance.exports;
jit.bind(e);
const mem = () => new Uint8Array(e.memory.buffer);
const put = (v) => {
  const d = typeof v === "string" ? new TextEncoder().encode(v) : v;
  const p = e.wtw_alloc(d.length);
  mem().set(d, p);
  return [p, d.length];
};
const err = () => new TextDecoder().decode(mem().slice(e.wtw_error_ptr(), e.wtw_error_ptr() + e.wtw_error_len()));

const useJit = process.env.PROBE_JIT !== "0";
const usePty = process.env.PROBE_PTY !== "0";
if (e.wtw_init() !== 0) throw new Error(`init: ${err()}`);
if (e.wtw_set_guest_memory_mb(2048) !== 0) throw new Error(`guestmem: ${err()}`);
if (useJit && e.wtw_jit_enable(10) !== 0) throw new Error(`jit: ${err()}`);
if (e.wtw_install_chunk_manifest(...put(manifest)) !== 0) throw new Error(`manifest: ${err()}`);
e.wtw_arg(...put("claude"));
e.wtw_env(...put("PATH=/bin"));
e.wtw_env(...put("HOME=/root"));
e.wtw_env(...put("TERM=xterm-256color"));

const deliver = (ctx) => {
  const len = e.wtw_page_request_take();
  if (len !== 65) throw new Error(`${ctx}: request len ${len}: ${err()}`);
  const req = mem().slice(e.wtw_page_request_ptr(), e.wtw_page_request_ptr() + len);
  const hash = Buffer.from(req.slice(32, 64)).toString("hex");
  const view = new DataView(req.buffer, req.byteOffset, req.byteLength);
  const bytes = chunks.get(hash);
  if (!bytes) throw new Error(`${ctx}: unknown chunk ${hash}`);
  if (e.wtw_page_deliver(view.getUint32(0, true), view.getUint32(4, true), ...put(bytes)) !== 0) {
    throw new Error(`${ctx}: deliver: ${err()}`);
  }
};

for (;;) {
  const s = e.wtw_load(...put("/bin/claude"));
  if (s === 0) break;
  if (s !== 10) throw new Error(`load: status ${s}: ${err()}`);
  deliver("metadata");
}
if (usePty && e.wtw_pty_install(40, 120) !== 0) throw new Error(`pty: ${err()}`);

const deadline = Date.now() + minutes * 60_000;
let rendered = "";
let status = 0;
let slices = 0;
const drain = () => {
  const n = e.wtw_output_len();
  if (n > 0) rendered += new TextDecoder().decode(mem().slice(e.wtw_output_ptr(), e.wtw_output_ptr() + n));
};
while (Date.now() < deadline) {
  const t0 = Date.now();
  status = e.wtw_run(50_000_000);
  slices += 1;
  if (slices <= 20 || slices % 50 === 0) {
    const ic = (e.wtw_icount_hi() >>> 0) * 2 ** 32 + (e.wtw_icount_lo() >>> 0);
    console.error(
      `[slice ${slices}] status=${status} icount=${ic.toLocaleString()} ms=${Date.now() - t0} rendered=${rendered.length}`,
    );
  }
  drain();
  if (rendered.includes("\x1b[?1049h")) break;
  if (status === 10) { deliver("run"); continue; }
  if (status === 7) continue; // awaiting input: the TUI may idle-wait; keep pumping
  if (status !== 0) break;
}
drain();

const icount = (e.wtw_icount_hi() >>> 0) * 2 ** 32 + (e.wtw_icount_lo() >>> 0);
const alt = rendered.includes("\x1b[?1049h");
console.log(`jit=${useJit} pty=${usePty} status=${status} slices=${slices} icount=${icount.toLocaleString()}`);
if (status !== 0 && status !== 1 && status !== 7) console.log(`engine error: ${err()}`);
console.log(`alt_screen=${alt} rendered_bytes=${rendered.length}`);
const printable = rendered.replace(/\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07|\x1b[=>]/g, "").trim();
console.log(`visible text (first 400): ${JSON.stringify(printable.slice(0, 400))}`);
process.exit(alt ? 0 : 2);
