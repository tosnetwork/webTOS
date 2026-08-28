// Measures the browser JIT against the interpreter on a compute loop.
//
// The loop body is a single tiny basic block that branches back to itself — a
// self-loop. It is now region-compiled: the whole loop, back-edge included, is
// one wasm function with an internal `loop`, so N iterations are ONE jit_call
// instead of one per iteration. That removes the per-dispatch overhead this
// bench used to be dominated by.
//
// Before region compilation this same loop measured ~2.76x over the interpreter
// (one jit_call per iteration paid the run-loop bookkeeping plus the
// wasm/JS/wasm boundary every time); the `dispatches` line below — a handful of
// fuel slices for tens of millions of iterations, not one per iteration — is
// what the region bought. See feasibility/jit_browser_measurement.md.
//
// Usage: node web/bench_jit.mjs [iterations]
import { readFile } from "node:fs/promises";
import { makeJitHost } from "./jit_host.mjs";

const wasmBytes = await readFile(new URL("./webtos_web.wasm", import.meta.url).pathname);
const iters = Number(process.argv[2] ?? 20_000_000);

// xor eax,eax; mov ebx,3; mov ecx,5; mov edx,iters;
// loop: add rax,rbx; add rax,rcx; dec rdx; jnz loop; mov edi,eax; mov eax,60; syscall
function loopElf(count) {
  const code = [
    0x31, 0xc0, 0xbb, 3, 0, 0, 0, 0xb9, 5, 0, 0, 0,
    0xba, count & 0xff, (count >> 8) & 0xff, (count >> 16) & 0xff, (count >>> 24) & 0xff,
    0x48, 0x01, 0xd8, 0x48, 0x01, 0xc8, 0x48, 0xff, 0xca, 0x75, 0xf5,
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

async function timeRun(elf, enableJit) {
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
  e.wtw_init();
  e.wtw_add_file(...put("/loop"), ...put(elf));
  if (enableJit) e.wtw_jit_enable(10);
  e.wtw_arg(...put("/loop"));
  e.wtw_load(...put("/loop"));
  const start = process.hrtime.bigint();
  let icount = 0n;
  let status;
  do {
    status = e.wtw_run(50_000_000);
  } while (status === 0);
  const ns = Number(process.hrtime.bigint() - start);
  return { ns, exit: e.wtw_exit_code(), dispatches: Number(e.wtw_jit_dispatch_count()) };
}

const elf = loopElf(iters);
const guestInsns = iters * 4; // add, add, dec, jnz
// Warm up.
await timeRun(loopElf(100000), false);
await timeRun(loopElf(100000), true);

const interp = await timeRun(elf, false);
const jit = await timeRun(elf, true);
const rate = (r) => (guestInsns / (r.ns / 1e9) / 1e6).toFixed(1);

console.log(`compute loop, ${guestInsns.toLocaleString()} guest instructions`);
console.log(`  interpreter: ${(interp.ns / 1e6).toFixed(0)} ms  (${rate(interp)} M-insn/s)  exit ${interp.exit}`);
console.log(`  browser JIT: ${(jit.ns / 1e6).toFixed(0)} ms  (${rate(jit)} M-insn/s)  exit ${jit.exit}  ${jit.dispatches.toLocaleString()} dispatches (region)`);
console.log(`  speedup:     ${(interp.ns / jit.ns).toFixed(2)}x  vs interpreter  (was ~2.76x per-block, one jit_call per iteration)  ${jit.exit === interp.exit ? "" : "*** EXIT MISMATCH ***"}`);
console.log(`  per-iter dispatches: ${(jit.dispatches / iters).toExponential(1)}  (per-block would be ~1.0)`);
