// JIT shared-memory round trip, driven from Node.
//
// Proves the browser wiring's core mechanism before it reaches the run loop:
// the engine emits a p-code block as wasm, the JS host has the WebAssembly
// engine compile it, and it runs against the engine's OWN linear memory — no
// copy — writing a register the engine then reads back.
//
// Usage: node web/test_jit.mjs [path/to/module.wasm]
import { readFile } from "node:fs/promises";

const wasmPath = process.argv[2] ?? new URL("./webtos_web.wasm", import.meta.url).pathname;

const { instance } = await WebAssembly.instantiate(await readFile(wasmPath), {});
const e = instance.exports;
const mem = () => new Uint8Array(e.memory.buffer);
const text = (ptr, len) => new TextDecoder().decode(mem().slice(ptr, ptr + len));
const err = () => text(e.wtw_error_ptr(), e.wtw_error_len());

const fail = (msg) => {
  console.error(`[jit] FAILED: ${msg}`);
  process.exit(1);
};

// 1. The engine seeds a register buffer in its memory and translates a block
//    that adds two of those registers.
if (e.wtw_jit_selftest() !== 0) fail(`selftest prepare: ${err()}`);

// 2. Read the emitted block bytes and the register buffer's base offset.
const blockPtr = e.wtw_jit_block_ptr();
const blockLen = e.wtw_jit_block_len();
const regsBase = e.wtw_jit_regs_ptr();
if (blockLen === 0) fail("engine produced no block bytes");
const blockBytes = mem().slice(blockPtr, blockPtr + blockLen);

// 3. Compile the block and instantiate it bound to the engine's own memory,
//    with regs_base pointing at the register buffer inside it.
let blockInstance;
try {
  const module = new WebAssembly.Module(blockBytes);
  const regsBaseGlobal = new WebAssembly.Global({ value: "i32", mutable: false }, regsBase);
  blockInstance = new WebAssembly.Instance(module, {
    env: { regs: e.memory, regs_base: regsBaseGlobal },
  });
} catch (ex) {
  fail(`browser could not compile/instantiate the emitted block: ${ex}`);
}

// 4. Run it. It reads a and b and writes their sum, all through the shared
//    memory the engine also sees.
blockInstance.exports.run();

// 5. The engine reads its register buffer and confirms the sum landed.
if (e.wtw_jit_check() !== 1) fail("compiled block did not write the expected sum into shared memory");

console.log("[jit] OK: browser-compiled block ran against the engine's shared memory (1000 + 337 = 1337)");
