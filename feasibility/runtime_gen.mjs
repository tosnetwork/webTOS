// The feasibility risk the AOT measurement did not cover: can we GENERATE wasm
// at runtime for a hot block, instantiate it sharing the guest's memory, and
// dispatch to it cheaply? This hand-encodes a minimal wasm module at runtime —
// a function that reduces a shared-memory buffer with a rotate-add loop, the
// shape of a hot block's arithmetic — and measures it against a JS interpreter
// loop that dispatches per operation, the shape of the p-code interpreter.

// --- A tiny wasm encoder: just enough for one function over imported memory.
const U = (...b) => b;
const leb = (n) => { const o = []; do { let x = n & 0x7f; n >>>= 7; if (n) x |= 0x80; o.push(x); } while (n); return o; };
const vec = (items) => [...leb(items.length), ...items.flat()];
const str = (s) => [...leb(s.length), ...[...s].map(c => c.charCodeAt(0))];

// module: import memory; export "run"(ptr:i32, len:i32)->i32 that does
//   acc=0; for i in 0..len step 4: acc = rotl(acc + mem[ptr+i], 7); return acc
// opcodes
const OP = { block:0x02, loop:0x03, br_if:0x0d, end:0x0b, local_get:0x20, local_set:0x21,
  local_tee:0x22, i32_load:0x28, i32_const:0x41, i32_add:0x6a, i32_sub:0x6b, i32_mul:0x6c,
  i32_and:0x71, i32_shl:0x74, i32_shru:0x76, i32_rotl:0x77, i32_ge_u:0x4f, i32_lt_u:0x49, drop:0x1a };

function buildRunModule() {
  // locals: 0=ptr(param),1=len(param),2=acc,3=i
  const body = [
    OP.i32_const, 0, OP.local_set, 2,          // acc = 0
    OP.i32_const, 0, OP.local_set, 3,          // i = 0
    OP.block, 0x40,
      OP.loop, 0x40,
        OP.local_get, 3, OP.local_get, 1, OP.i32_ge_u, OP.br_if, 1,   // if i>=len break
        // acc = rotl(acc + mem[ptr+i], 7)
        OP.local_get, 2,
        OP.local_get, 0, OP.local_get, 3, OP.i32_add, OP.i32_load, 0x02, 0x00, // mem[ptr+i], align=2 off=0
        OP.i32_add,
        OP.i32_const, 7, OP.i32_rotl, OP.local_set, 2,
        OP.local_get, 3, OP.i32_const, 4, OP.i32_add, OP.local_set, 3,          // i += 4
        OP.br_if, 0, ...[], // unconditional continue via br 0 -- use br
      OP.end,
    OP.end,
    OP.local_get, 2, OP.end,
  ];
  // fix: the loop needs an unconditional br 0 to continue; replace the trailing br_if,0 with br 0
  // (br opcode 0x0c)
  const idx = body.lastIndexOf(OP.br_if);
  body.splice(idx, 2, 0x0c, 0); // br 0

  const localDecls = vec([[2, 0x7f]]); // 2 extra i32 locals (acc,i)
  const funcBody = vec([...localDecls, ...body]);

  const typeSec   = [0x01, ...vec([[0x60, ...vec([0x7f,0x7f]), ...vec([0x7f])]])];
  const importSec = [0x02, ...vec([[...str("env"), ...str("mem"), 0x02, 0x00, 0x01]])]; // import memory min 1
  const funcSec   = [0x03, ...vec([[0x00]])];
  const exportSec = [0x07, ...vec([[...str("run"), 0x00, 0x00]])];
  const codeSec   = [0x0a, ...vec([funcBody])];

  const withLen = (sec) => [sec[0], ...leb(sec.length - 1), ...sec.slice(1)];
  return new Uint8Array([
    0x00,0x61,0x73,0x6d, 0x01,0x00,0x00,0x00,
    ...withLen(typeSec), ...withLen(importSec), ...withLen(funcSec),
    ...withLen(exportSec), ...withLen(codeSec),
  ]);
}

const SIZE = 4 * 1024 * 1024;
const memory = new WebAssembly.Memory({ initial: Math.ceil((SIZE + 65536) / 65536) });
const view = new Uint8Array(memory.buffer);
for (let i = 0; i < SIZE; i++) view[i] = (i * 2654435761) & 0xff;

// Generate + instantiate the module at RUNTIME.
const t_gen = performance.now();
const bytes = buildRunModule();
const mod = new WebAssembly.Module(bytes);
const inst = new WebAssembly.Instance(mod, { env: { mem: memory } });
const genMs = performance.now() - t_gen;

const run = inst.exports.run;
// Correctness: the runtime-generated wasm and the JS interpreter below must
// compute the identical reduction, or the comparison measures different work.
run(0, SIZE); // warm
const REPS = 50;
const t0 = performance.now();
let guard = 0;
for (let r = 0; r < REPS; r++) guard = (guard + run(0, SIZE))|0;
const wasmSecs = (performance.now() - t0) / 1000;
const wasmRate = (SIZE * REPS) / (1024*1024) / wasmSecs;

// JS "interpreter": the same reduction, but dispatching per op through an
// op array, reading a typed "register file" — the shape of the p-code loop.
const rf = new Int32Array(4);
const ops = [ "load", "add", "rotl", "step" ];
function interp(ptr, len) {
  rf[0]=0; rf[1]=ptr;
  for (let i=0;i<len;i+=4){
    for (const op of ops){
      switch(op){
        case "load": rf[2] = view[ptr+i] | (view[ptr+i+1]<<8) | (view[ptr+i+2]<<16) | (view[ptr+i+3]<<24); break;
        case "add": rf[0] = (rf[0] + rf[2])|0; break;
        case "rotl": rf[0] = ((rf[0]<<7)|(rf[0]>>>25))|0; break;
        case "step": break;
      }
    }
  }
  return rf[0];
}
const wasmResult = run(0, SIZE) >>> 0;
const interpResult = interp(0, SIZE) >>> 0;
if (wasmResult !== interpResult) {
  console.error(`[runtime-gen] MISMATCH: wasm ${wasmResult} vs interp ${interpResult} — comparing different work`);
  process.exit(1);
}
console.log(`[runtime-gen] correctness: both reduce to ${wasmResult} — same work`);
const REPS2 = 10;
const t1 = performance.now();
let guard2 = 0;
for (let r=0;r<REPS2;r++) guard2 = (guard2 + interp(0, SIZE))|0;
const interpSecs = (performance.now() - t1) / 1000;
const interpRate = (SIZE * REPS2) / (1024*1024) / interpSecs;

console.log(`[runtime-gen] module generated at runtime: ${bytes.length} bytes, gen+instantiate ${genMs.toFixed(2)} ms`);
console.log(`[runtime-gen] guards: ${guard>>>0} / ${guard2>>>0}`);
console.log(`[runtime-gen] runtime-generated wasm: ${wasmRate.toFixed(0)} MiB/s`);
console.log(`[runtime-gen] per-op-dispatch JS loop: ${interpRate.toFixed(0)} MiB/s`);
console.log(`[runtime-gen] dispatch-elimination win: ${(wasmRate/interpRate).toFixed(1)}x`);
