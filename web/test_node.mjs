// Node harness for the webtos-web wasm module: proves the engine runs a
// static ELF end-to-end outside a browser renderer. Usage:
//   node web/test_node.mjs [path/to/module.wasm] [path/to/guest.elf]
import { readFile } from "node:fs/promises";

const wasmPath = process.argv[2] ?? new URL("./webtos_web.wasm", import.meta.url).pathname;
const elfPath = process.argv[3] ?? new URL("../test_data/hello_linux.elf", import.meta.url).pathname;

const { instance } = await WebAssembly.instantiate(await readFile(wasmPath), {});
const e = instance.exports;
const mem = () => new Uint8Array(e.memory.buffer);
const text = (ptr, len) => new TextDecoder().decode(mem().slice(ptr, ptr + len));
const err = () => text(e.wtw_error_ptr(), e.wtw_error_len());

const t0 = performance.now();
if (e.wtw_init() !== 0) throw new Error(`init: ${err()}`);
console.log(`[node] engine ready in ${(performance.now() - t0).toFixed(0)} ms (spec compiled in-memory)`);

const elf = await readFile(elfPath);
const ptr = e.wtw_alloc(elf.length);
mem().set(elf, ptr);
if (e.wtw_load(ptr, elf.length) !== 0) throw new Error(`load: ${err()}`);

let status;
let output = "";
do {
  status = e.wtw_run(1_000_000);
  output += text(e.wtw_output_ptr(), e.wtw_output_len());
} while (status === 0);

const icount = e.wtw_icount_hi() * 2 ** 32 + e.wtw_icount_lo();
console.log(`[node] guest output: ${JSON.stringify(output)}`);
console.log(`[node] status=${status} exit_code=${e.wtw_exit_code()} icount=${icount}`);
if (status !== 1 || e.wtw_exit_code() !== 0 || !output.includes("Hello")) {
  console.error(`[node] FAILED: ${err()}`);
  process.exit(1);
}
console.log("[node] PASS");
