// End-to-end JIT run: a guest with a hot loop, run through the full engine loop
// once interpreted and once with the JIT enabled, must produce the same result,
// and the JIT must actually dispatch compiled blocks.
//
// The guest is a hand-built static ELF whose loop body (add/add/dec) is a
// register-only block the translator handles; the loop runs enough times to go
// hot. It exits with the low byte of the accumulator, so a wrong JIT result
// would change the exit code.
//
// Usage: node web/test_jit_run.mjs [path/to/module.wasm]
import { readFile } from "node:fs/promises";
import { makeJitHost } from "./jit_host.mjs";

const wasmPath = process.argv[2] ?? new URL("./webtos_web.wasm", import.meta.url).pathname;
const wasmBytes = await readFile(wasmPath);

// A minimal static x86-64 ELF: xor eax,eax; mov ebx,3; mov ecx,5; mov edx,COUNT;
// loop: add rax,rbx; add rax,rcx; dec rdx; jnz loop; mov edi,eax; mov eax,60; syscall.
function loopElf(count) {
  const code = [
    0x31, 0xc0, // xor eax, eax
    0xbb, 0x03, 0x00, 0x00, 0x00, // mov ebx, 3
    0xb9, 0x05, 0x00, 0x00, 0x00, // mov ecx, 5
    0xba, count & 0xff, (count >> 8) & 0xff, (count >> 16) & 0xff, (count >> 24) & 0xff, // mov edx, count
    0x48, 0x01, 0xd8, // loop: add rax, rbx
    0x48, 0x01, 0xc8, //       add rax, rcx
    0x48, 0xff, 0xca, //       dec rdx
    0x75, 0xf5, //             jnz loop
    0x89, 0xc7, // mov edi, eax
    0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 60 (exit)
    0x0f, 0x05, // syscall
  ];
  const codeOff = 120; // 64 (ELF header) + 56 (one program header)
  const vaddr = 0x400000n;
  const total = codeOff + code.length;
  const buf = new Uint8Array(total);
  const dv = new DataView(buf.buffer);
  // ELF header
  buf.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0], 0);
  dv.setUint16(16, 2, true); // ET_EXEC
  dv.setUint16(18, 0x3e, true); // x86-64
  dv.setUint32(20, 1, true);
  dv.setBigUint64(24, vaddr + BigInt(codeOff), true); // e_entry
  dv.setBigUint64(32, 64n, true); // e_phoff
  dv.setUint16(52, 64, true); // e_ehsize
  dv.setUint16(54, 56, true); // e_phentsize
  dv.setUint16(56, 1, true); // e_phnum
  // Program header at 64
  dv.setUint32(64, 1, true); // PT_LOAD
  dv.setUint32(68, 5, true); // R+X
  dv.setBigUint64(72, 0n, true); // p_offset
  dv.setBigUint64(80, vaddr, true); // p_vaddr
  dv.setBigUint64(88, vaddr, true); // p_paddr
  dv.setBigUint64(96, BigInt(total), true); // p_filesz
  dv.setBigUint64(104, BigInt(total), true); // p_memsz
  dv.setBigUint64(112, 0x1000n, true); // p_align
  buf.set(code, codeOff);
  return buf;
}

// A static ELF that sums `count` bytes from a data area (a host block: the
// byte load takes the softmmu callback), then exits with the low byte of the
// sum. The single RWX segment holds code then data.
function memElf(count) {
  const data = Array.from({ length: count }, (_, i) => i & 0xff);
  const codeOff = 120;
  const vaddr = 0x400000n;
  const dataAddr = Number(vaddr) + codeOff + 35; // after the 35-byte code
  const code = [
    0x31, 0xc0, // xor eax, eax
    0xbe, dataAddr & 0xff, (dataAddr >> 8) & 0xff, (dataAddr >> 16) & 0xff, (dataAddr >> 24) & 0xff, // mov esi, dataAddr
    0xb9, count & 0xff, (count >> 8) & 0xff, (count >> 16) & 0xff, (count >> 24) & 0xff, // mov ecx, count
    0x0f, 0xb6, 0x16, // loop: movzx edx, byte [rsi]
    0x48, 0x01, 0xd0, //       add rax, rdx
    0x48, 0xff, 0xc6, //       inc rsi
    0x48, 0xff, 0xc9, //       dec rcx
    0x75, 0xf2, //             jnz loop
    0x89, 0xc7, // mov edi, eax
    0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 60
    0x0f, 0x05, // syscall
  ];
  const body = code.concat(data);
  const total = codeOff + body.length;
  const buf = new Uint8Array(total);
  const dv = new DataView(buf.buffer);
  buf.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0], 0);
  dv.setUint16(16, 2, true);
  dv.setUint16(18, 0x3e, true);
  dv.setUint32(20, 1, true);
  dv.setBigUint64(24, vaddr + BigInt(codeOff), true);
  dv.setBigUint64(32, 64n, true);
  dv.setUint16(52, 64, true);
  dv.setUint16(54, 56, true);
  dv.setUint16(56, 1, true);
  dv.setUint32(64, 1, true); // PT_LOAD
  dv.setUint32(68, 7, true); // R+W+X (the loop reads the data area)
  dv.setBigUint64(72, 0n, true);
  dv.setBigUint64(80, vaddr, true);
  dv.setBigUint64(88, vaddr, true);
  dv.setBigUint64(96, BigInt(total), true);
  dv.setBigUint64(104, BigInt(total), true);
  dv.setBigUint64(112, 0x1000n, true);
  buf.set(body, codeOff);
  return buf;
}

async function run(elf, enableJit) {
  const jit = makeJitHost();
  const { instance } = await WebAssembly.instantiate(wasmBytes, { env: jit.imports });
  const e = instance.exports;
  jit.bind(e);
  const mem = () => new Uint8Array(e.memory.buffer);
  const text = (p, l) => new TextDecoder().decode(mem().slice(p, p + l));
  const err = () => text(e.wtw_error_ptr(), e.wtw_error_len());
  const put = (bytes) => {
    const data = typeof bytes === "string" ? new TextEncoder().encode(bytes) : bytes;
    const ptr = e.wtw_alloc(data.length);
    mem().set(data, ptr);
    return [ptr, data.length];
  };

  if (e.wtw_init() !== 0) throw new Error(`init: ${err()}`);
  if (e.wtw_add_file(...put("/loop"), ...put(elf)) !== 0) throw new Error(`add_file: ${err()}`);
  if (enableJit && e.wtw_jit_enable(10) !== 0) throw new Error(`jit_enable: ${err()}`);
  e.wtw_arg(...put("/loop"));
  if (e.wtw_load(...put("/loop")) !== 0) throw new Error(`load: ${err()}`);

  let status;
  do {
    status = e.wtw_run(5_000_000);
  } while (status === 0);
  return {
    status,
    exitCode: e.wtw_exit_code(),
    dispatches: Number(e.wtw_jit_dispatch_count()),
  };
}

const fail = (m) => {
  console.error(`[jit-run] FAILED: ${m}`);
  process.exit(1);
};

async function check(label, elf) {
  const interp = await run(elf, false);
  const jit = await run(elf, true);
  if (interp.dispatches !== 0) fail(`${label}: the interpreter run dispatched ${interp.dispatches} blocks`);
  if (jit.dispatches === 0) fail(`${label}: the JIT run never dispatched — proves nothing`);
  if (interp.status !== jit.status || interp.exitCode !== jit.exitCode) {
    fail(
      `${label}: diverged: interp (status ${interp.status}, exit ${interp.exitCode}), ` +
        `jit (status ${jit.status}, exit ${jit.exitCode})`
    );
  }
  console.log(
    `[jit-run] OK ${label}: identical interpreted and JIT'd ` +
      `(exit ${jit.exitCode}, ${jit.dispatches} dispatches)`
  );
}

// A register-only hot loop, and a memory-scan loop whose byte load exercises the
// softmmu callback (wtw_jit_load) through the browser path.
await check("register loop", loopElf(1000));
await check("memory scan", memElf(256));
