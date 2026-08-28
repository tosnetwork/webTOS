// The engine (wasm) emits a wasm module at runtime; the JS host instantiates
// it and calls it. Proves the full path: wasm-encoder inside wasm -> bytes ->
// runtime instantiate -> call.
import { readFile } from "node:fs/promises";
const probe = await readFile(new URL("./target/wasm32-unknown-unknown/release/encoder_probe.wasm", import.meta.url));
const { instance } = await WebAssembly.instantiate(probe, {});
const { memory, emit_add_module } = instance.exports;

// Ask the wasm engine to emit an "add" module into its own memory.
const OUT = 1024, CAP = 4096;
const len = emit_add_module(OUT, CAP);
const bytes = new Uint8Array(memory.buffer.slice(OUT, OUT + len));
console.log(`[encoder] emitted ${len} bytes at runtime from inside wasm`);

// Validate and run the runtime-generated module.
if (!WebAssembly.validate(bytes)) { console.error("[encoder] FAILED: emitted bytes are not valid wasm"); process.exit(1); }
const gen = await WebAssembly.instantiate(bytes, {});
const r = gen.instance.exports.add(40, 2);
console.log(`[encoder] runtime-generated add(40,2) = ${r}`);
if (r !== 42) { console.error("[encoder] FAILED: wrong result"); process.exit(1); }
console.log("[encoder] PASS — wasm-encoder emits valid, runnable wasm from inside a wasm module");
