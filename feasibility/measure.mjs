// Measures the ceiling a hot-block JIT-to-wasm approaches for compute-bound
// work: md5 compiled to wasm, run in the same wasm engine the browser uses,
// versus the p-code interpreter's measured rate on the same md5sum workload.
import { readFile } from "node:fs/promises";

const wasm = await readFile(new URL("./md5wasm/target/wasm32-unknown-unknown/release/md5wasm.wasm", import.meta.url));
const memory = new WebAssembly.Memory({ initial: 4 }); // 256 KiB
const { instance } = await WebAssembly.instantiate(wasm, { env: { memory } });
// The module has its own memory (no import); use its exported memory.
const mem = instance.exports.memory ?? memory;
const { md5_bench } = instance.exports;

const SIZE = 4 * 1024 * 1024; // 4 MiB, matching the interpreter bench
// The wasm module's own linear memory; grow it to hold 4 MiB + slack.
const need = Math.ceil((SIZE + 65536) / 65536);
if (mem.buffer.byteLength < need * 65536) mem.grow(need - mem.buffer.byteLength / 65536);
const view = new Uint8Array(mem.buffer);
for (let i = 0; i < SIZE; i++) view[i] = (i * 2654435761) & 0xff;

// Warm up, then time enough md5 work to be steady-state.
md5_bench(0, SIZE, 1);
const ROUNDS = 21; // 20 x 4 MiB = 80 MiB of md5
const t0 = performance.now();
const r = md5_bench(0, SIZE, ROUNDS);
const secs = (performance.now() - t0) / 1000;
const mib = (SIZE * ROUNDS) / (1024 * 1024);
const wasmRate = mib / secs;

// The interpreter's measured rate on the same md5sum workload, from
// crates/linux-compat/tests/bench.rs on the Linux host: 4 MiB in 4.66 s.
const interpMiB = 4, interpSecs = 4.66;
const interpRate = interpMiB / interpSecs;

console.log(`[feasibility] result guard: ${r >>> 0}`);
console.log(`[feasibility] md5 compiled to wasm:  ${wasmRate.toFixed(1)} MiB/s  (${mib.toFixed(0)} MiB in ${secs.toFixed(2)} s)`);
console.log(`[feasibility] md5 interpreted (p-code): ${interpRate.toFixed(2)} MiB/s  (measured: 4 MiB in 4.66 s)`);
console.log(`[feasibility] ceiling ratio: ${(wasmRate / interpRate).toFixed(0)}x`);
