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
    0x31, 0xff, 0xb8, 0x3c, 0, 0, 0, 0x0f, 0x05,
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

// A two-block loop. A condition in block A side-exits to `done`; block B
// decrements the counter and jumps back to A. Neither block is a self-loop, so
// a low dispatch count proves the multi-block state-machine region is active.
function multiBlockElf(count) {
  const code = [
    0x31, 0xc0, // xor eax,eax
    0xb9, count & 0xff, (count >> 8) & 0xff, (count >> 16) & 0xff, (count >>> 24) & 0xff,
    0x48, 0x83, 0xc0, 0x01, // A: add rax,1
    0x48, 0x85, 0xc9, // test rcx,rcx
    0x74, 0x05, // jz done
    0x48, 0xff, 0xc9, // B: dec rcx
    0xeb, 0xf2, // jmp A
    0x31, 0xff, 0xb8, 0x3c, 0, 0, 0, 0x0f, 0x05,
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

// xor eax,eax; mov esi,dataAddr; mov ecx,count;
// loop: movzx edx,[rsi]; add rax,rdx; inc rsi; dec rcx; jnz loop;
// mov edi,eax; mov eax,60; syscall.
//
// A HOST self-loop: the byte load takes the softmmu callback every iteration.
// It now region-compiles too — the whole loop, load included, is one wasm
// function that faults back to the interpreter only if a load ever faults — so
// the scan is a handful of dispatches, not one per byte.
function memScanElf(count) {
  const codeOff = 120;
  const vaddr = 0x400000n;
  const dataAddr = Number(vaddr) + codeOff + 35; // after the 35-byte code
  const code = [
    0x31, 0xc0, // xor eax, eax
    0xbe, dataAddr & 0xff, (dataAddr >> 8) & 0xff, (dataAddr >> 16) & 0xff, (dataAddr >>> 24) & 0xff,
    0xb9, count & 0xff, (count >> 8) & 0xff, (count >> 16) & 0xff, (count >>> 24) & 0xff,
    0x0f, 0xb6, 0x16, // loop: movzx edx, byte [rsi]
    0x48, 0x01, 0xd0, //       add rax, rdx
    0x48, 0xff, 0xc6, //       inc rsi
    0x48, 0xff, 0xc9, //       dec rcx
    0x75, 0xf2, //             jnz loop
    0x89, 0xc7, 0xb8, 0x3c, 0, 0, 0, 0x0f, 0x05,
  ];
  const data = Array.from({ length: count }, (_, i) => i & 0xff);
  const body = code.concat(data);
  const total = codeOff + body.length;
  const buf = new Uint8Array(total), dv = new DataView(buf.buffer);
  buf.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0], 0);
  dv.setUint16(16, 2, true); dv.setUint16(18, 0x3e, true); dv.setUint32(20, 1, true);
  dv.setBigUint64(24, vaddr + BigInt(codeOff), true); dv.setBigUint64(32, 64n, true);
  dv.setUint16(52, 64, true); dv.setUint16(54, 56, true); dv.setUint16(56, 1, true);
  dv.setUint32(64, 1, true); dv.setUint32(68, 7, true); // R+W+X (the loop reads the data area)
  dv.setBigUint64(80, vaddr, true); dv.setBigUint64(88, vaddr, true);
  dv.setBigUint64(96, BigInt(total), true); dv.setBigUint64(104, BigInt(total), true);
  dv.setBigUint64(112, 0x1000n, true);
  buf.set(body, codeOff);
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
  return {
    ns,
    exit: e.wtw_exit_code(),
    dispatches: Number(e.wtw_jit_dispatch_count()),
    blocks: Number(e.wtw_jit_block_dispatch_count()),
    regions: Number(e.wtw_jit_region_dispatch_count()),
  };
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

await timeRun(multiBlockElf(100000), true); // warm up
const multiInterp = await timeRun(multiBlockElf(iters), false);
const multiJit = await timeRun(multiBlockElf(iters), true);
if (multiJit.regions === 0 || multiJit.dispatches / iters >= 0.001) {
  throw new Error(
    `multi-block region did not amortize dispatch: ${multiJit.regions} regions, ${multiJit.dispatches} total for ${iters} iterations`,
  );
}
console.log(`\ntwo-block loop, ${(iters * 5).toLocaleString()} approximate guest instructions`);
console.log(`  interpreter: ${(multiInterp.ns / 1e6).toFixed(0)} ms  exit ${multiInterp.exit}`);
console.log(`  browser JIT: ${(multiJit.ns / 1e6).toFixed(0)} ms  exit ${multiJit.exit}  ${multiJit.dispatches.toLocaleString()} dispatches (${multiJit.regions} region, ${multiJit.blocks} block)`);
console.log(`  speedup:     ${(multiInterp.ns / multiJit.ns).toFixed(2)}x  vs interpreter`);
console.log(`  per-iter dispatches: ${(multiJit.dispatches / iters).toExponential(1)}  (two per iteration without trace regions)`);

// A HOST self-loop: the byte-scan loop now region-compiles as well, so the
// softmmu load rides inside one region call instead of forcing a per-block
// dispatch every iteration.
const scanCount = 4_000_000;
await timeRun(memScanElf(100000), true); // warm up
const scanInterp = await timeRun(memScanElf(scanCount), false);
const scanJit = await timeRun(memScanElf(scanCount), true);
const scanInsns = scanCount * 4; // movzx, add, inc, dec, jnz counted as the body
const scanRate = (r) => (scanInsns / (r.ns / 1e9) / 1e6).toFixed(1);
console.log(`\nmemory scan (HOST self-loop), ${scanCount.toLocaleString()} byte loads`);
console.log(`  interpreter: ${(scanInterp.ns / 1e6).toFixed(0)} ms  (${scanRate(scanInterp)} M-insn/s)  exit ${scanInterp.exit}`);
console.log(`  browser JIT: ${(scanJit.ns / 1e6).toFixed(0)} ms  (${scanRate(scanJit)} M-insn/s)  exit ${scanJit.exit}  ${scanJit.dispatches.toLocaleString()} dispatches (region)`);
console.log(`  speedup:     ${(scanInterp.ns / scanJit.ns).toFixed(2)}x  vs interpreter  ${scanJit.exit === scanInterp.exit ? "" : "*** EXIT MISMATCH ***"}`);
console.log(`  per-iter dispatches: ${(scanJit.dispatches / scanCount).toExponential(1)}  (per-block would be ~1.0)`);
