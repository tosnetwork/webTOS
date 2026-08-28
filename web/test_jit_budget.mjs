// The compiled-code budget in the browser path: with a cap smaller than the
// code a workload compiles, the engine evicts least-recently-used blocks (the
// `jit_evict` host import drops the module and instance) and keeps running
// correctly, holding its wasm code memory under the cap. Run once unlimited to
// learn the code size, then again capped below it.
//
// Usage: node web/test_jit_budget.mjs [path/to/module.wasm]
import { readFile } from "node:fs/promises";
import { makeJitHost } from "./jit_host.mjs";

const wasmPath = process.argv[2] ?? new URL("./webtos_web.wasm", import.meta.url).pathname;
const wasmBytes = await readFile(wasmPath);

// Two distinct hot self-loops, so two regions compile — enough that a budget
// smaller than both must evict one. rax ends at 3*count + 5*count.
// xor eax,eax; mov ebx,3; mov ecx,5; mov edx,COUNT; mov esi,COUNT;
// loop1: add rax,rbx; dec rdx; jnz loop1;
// loop2: add rax,rcx; dec rsi; jnz loop2;
// mov edi,eax; mov eax,60; syscall.
function loopElf(count) {
  const c = [count & 0xff, (count >> 8) & 0xff, (count >> 16) & 0xff, (count >> 24) & 0xff];
  const code = [
    0x31, 0xc0, 0xbb, 3, 0, 0, 0, 0xb9, 5, 0, 0, 0,
    0xba, ...c, 0xbe, ...c,
    0x48, 0x01, 0xd8, 0x48, 0xff, 0xca, 0x75, 0xf8, // loop1: add rax,rbx; dec rdx; jnz
    0x48, 0x01, 0xc8, 0x48, 0xff, 0xce, 0x75, 0xf8, // loop2: add rax,rcx; dec rsi; jnz
    0x89, 0xc7, 0xb8, 0x3c, 0, 0, 0, 0x0f, 0x05,
  ];
  const codeOff = 120, vaddr = 0x400000n, total = codeOff + code.length;
  const buf = new Uint8Array(total), dv = new DataView(buf.buffer);
  buf.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0], 0);
  dv.setUint16(16, 2, true); dv.setUint16(18, 0x3e, true); dv.setUint32(20, 1, true);
  dv.setBigUint64(24, vaddr + BigInt(codeOff), true); dv.setBigUint64(32, 64n, true);
  dv.setUint16(52, 64, true); dv.setUint16(54, 56, true); dv.setUint16(56, 1, true);
  dv.setUint32(64, 1, true); dv.setUint32(68, 5, true);
  dv.setBigUint64(80, vaddr, true); dv.setBigUint64(88, vaddr, true);
  dv.setBigUint64(96, BigInt(total), true); dv.setBigUint64(104, BigInt(total), true);
  dv.setBigUint64(112, 0x1000n, true);
  buf.set(code, codeOff);
  return buf;
}

async function run(elf, budget) {
  const jit = makeJitHost();
  const { instance } = await WebAssembly.instantiate(wasmBytes, { env: jit.imports });
  const e = instance.exports;
  jit.bind(e);
  const mem = () => new Uint8Array(e.memory.buffer);
  const put = (bytes) => {
    const d = typeof bytes === "string" ? new TextEncoder().encode(bytes) : bytes;
    const p = e.wtw_alloc(d.length);
    mem().set(d, p);
    return [p, d.length];
  };
  if (e.wtw_init() !== 0) throw new Error("init");
  if (e.wtw_add_file(...put("/loop"), ...put(elf)) !== 0) throw new Error("add_file");
  if (e.wtw_jit_enable(10) !== 0) throw new Error("jit_enable");
  if (budget !== undefined && e.wtw_jit_set_code_budget(budget) !== 0) throw new Error("set_budget");
  e.wtw_arg(...put("/loop"));
  if (e.wtw_load(...put("/loop")) !== 0) throw new Error("load");
  let status;
  do {
    status = e.wtw_run(5_000_000);
  } while (status === 0);
  return {
    exitCode: e.wtw_exit_code(),
    dispatches: Number(e.wtw_jit_dispatch_count()),
    codeBytes: Number(e.wtw_jit_code_bytes()),
    evictions: Number(e.wtw_jit_evictions()),
  };
}

const fail = (m) => {
  console.error(`[jit-budget] FAILED: ${m}`);
  process.exit(1);
};

const elf = loopElf(2000);

// Unlimited: learn the exit and the code the workload holds.
const full = await run(elf);
if (full.dispatches === 0) fail("unlimited run never dispatched — proves nothing");
if (full.evictions !== 0) fail(`unlimited run evicted ${full.evictions} with no budget`);
if (full.codeBytes === 0) fail("unlimited run reports zero code bytes");

// Cap below what the workload holds, so at least one block must be evicted.
const budget = Math.max(1, full.codeBytes - 1);
const capped = await run(elf, budget);
if (capped.exitCode !== full.exitCode) {
  fail(`capped run diverged: exit ${capped.exitCode} vs ${full.exitCode}`);
}
if (capped.evictions === 0) fail(`budget ${budget} < ${full.codeBytes} held but evicted nothing`);
if (capped.codeBytes > budget) fail(`held ${capped.codeBytes} bytes over the ${budget} budget`);

console.log(
  `[jit-budget] OK: unlimited held ${full.codeBytes} B (exit ${full.exitCode}); ` +
    `capped at ${budget} B held ${capped.codeBytes} B with ${capped.evictions} evictions, same exit`
);
