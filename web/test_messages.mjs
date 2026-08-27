// The host's half of the boundary. Everything the page can say to the engine
// arrives through these exported functions as plain 32-bit numbers: pointers
// into the module's own linear memory, lengths, handles, budgets. A number
// that does not mean what the engine assumed must come back as an error, not
// as a trap — a trapped module is a dead tab, and a length the engine trusts
// is a read of memory the caller never wrote.
//
// This is the sixth of the seven input surfaces the roadmap names, and the
// only one on the host side of the wall.
//
// Usage: node web/test_messages.mjs [path/to/module.wasm]
import { readFile } from "node:fs/promises";

const wasmPath = process.argv[2] ?? new URL("./webtos_web.wasm", import.meta.url).pathname;
const bytes = await readFile(wasmPath);

// A trapped module cannot be trusted to answer the next question, so each
// trap is followed by a new one. Instantiating costs little next to what a
// stale instance would hide.
// A host that means to survive sets a ceiling; `web/worker.js` forwards one
// on request. The sweep sets one too, because without it the module has no
// answer to "no memory left" other than the allocator's, which is an abort.
// That distinction is the point rather than a workaround: with a ceiling the
// same calls come back refused, and the sweep below proves it by leaving the
// ceiling in place for every case.
const BUDGET_MIB = 512;

const fresh = async () => {
  const { instance } = await WebAssembly.instantiate(bytes, {});
  instance.exports.wtw_init();
  instance.exports.wtw_set_memory_budget_kib(BUDGET_MIB * 1024);
  return instance.exports;
};

let e = await fresh();

// The exports, and how many arguments each takes. Read from the module
// rather than listed here: a function added tomorrow is swept tomorrow,
// without anyone remembering to add it.
const exported = Object.entries(e)
  .filter(([name, value]) => name.startsWith("wtw_") && typeof value === "function")
  .map(([name, fn]) => ({ name, arity: fn.length }))
  .sort((a, b) => a.name.localeCompare(b.name));

const values = (memBytes, valid) => [
  [0, "zero"],
  [1, "one"],
  [0xffffffff, "u32::MAX"],
  [0x80000000, "the sign bit"],
  [0x7fffffff, "i32::MAX"],
  [memBytes, "one past the end of memory"],
  [memBytes - 1, "the last byte of memory"],
  [memBytes + 0x1000, "beyond memory"],
  [valid, "a pointer the caller allocated"],
  [valid + 0x10000, "past what the caller allocated"],
  [0xdead0000, "unmapped"],
  [0xfff, "unaligned and low"],
];

// Arguments that get past a length check of zero, so a call reaches the code
// behind it rather than returning early.
const plausible = [4, 4, 4, 4];

const results = { calls: 0, ok: 0, refused: 0, traps: [] };
const seenTrap = new Set();

// A trap can depend on what the earlier calls left behind, and a report that
// names only the call that trapped cannot be reproduced. Keep the run-up.
const recent = [];
const growth = [];
const RECENT = 6;

const call = async (fn, name, args, label) => {
  results.calls += 1;
  const record = `${name}(${args.join(", ")})`;
  const memAtTrap = e.memory.buffer.byteLength;
  try {
    const ret = e[name](...args);
    if (ret === 0 || ret === undefined) results.ok += 1;
    else results.refused += 1;
    // Which calls make the module grow, and by how much: a boundary that
    // lets one call take a bite out of a 32-bit address space is a boundary
    // a page can starve, and the sweep should be able to name the call.
    const grew = e.memory.buffer.byteLength - memAtTrap;
    if (grew > 0) growth.push([grew, record]);
    recent.push(record);
    if (recent.length > RECENT) recent.shift();
  } catch (error) {
    const key = `${name}: ${error.message}`;
    if (!seenTrap.has(key)) {
      seenTrap.add(key);
      results.traps.push(
        `${name}(${label}): ${error.message}\n` +
          `      module memory at the trap: ${(memAtTrap / (1 << 20)).toFixed(0)} MiB\n` +
          `      after: ${recent.join(" ; ") || "nothing"}\n` +
          `      trapping call: ${record}`,
      );
    }
    // A trapped module cannot answer the next question. The run-up died with
    // it, so the next case starts from a state nothing has touched.
    recent.length = 0;
    e = await fresh();
  }
};

for (const { name, arity } of exported) {
  if (arity === 0) {
    await call(null, name, [], "no arguments");
    continue;
  }
  // A pointer the caller really owns, re-taken each round: a trap resets the
  // instance, and an offset from the old one means nothing in the new one.
  for (let slot = 0; slot < arity; slot += 1) {
    const memBytes = e.memory.buffer.byteLength;
    const valid = e.wtw_alloc(64);
    for (const [value, vname] of values(memBytes, valid)) {
      const args = plausible.slice(0, arity);
      args[slot] = value;
      await call(null, name, args, `arg${slot}=${vname}`);
    }
  }
  // Two at a time over the pointer/length pairs these functions are built
  // from: a pointer the caller owns with a length that runs off the end of it
  // is the pair no single-argument case can express.
  for (let a = 0; a + 1 < arity; a += 1) {
    const memBytes = e.memory.buffer.byteLength;
    const valid = e.wtw_alloc(64);
    for (const [first, fname] of values(memBytes, valid)) {
      for (const [second, sname] of values(memBytes, valid)) {
        const args = plausible.slice(0, arity);
        args[a] = first;
        args[a + 1] = second;
        await call(null, name, args, `arg${a}=${fname} arg${a + 1}=${sname}`);
      }
    }
  }
}

console.log(
  `[messages] budget ${BUDGET_MIB} MiB; module memory ended at ${(e.memory.buffer.byteLength / (1 << 20)).toFixed(0)} MiB`,
);
growth.sort((a, b) => b[0] - a[0]);
for (const [grew, record] of growth.slice(0, 8)) {
  console.log(`[messages]   grew ${(grew / (1 << 20)).toFixed(0)} MiB: ${record}`);
}
console.log(
  `[messages] swept ${results.calls} calls across ${exported.length} exported functions; ` +
    `${results.ok} returned success, ${results.refused} refused`,
);

// A sweep where nothing succeeds has bounced off the first argument check and
// would report "no traps" whether or not the code behind it was sound.
if (results.ok < exported.length) {
  console.error(
    `[messages] FAILED: only ${results.ok} calls succeeded across ${exported.length} functions; ` +
      `the sweep is not reaching the code it is aiming at`,
  );
  process.exit(1);
}

if (results.traps.length > 0) {
  console.error(`[messages] FAILED: ${results.traps.length} distinct traps`);
  for (const trap of results.traps.slice(0, 40)) console.error(`[messages]   ${trap}`);
  process.exit(1);
}

console.log("[messages] PASS");
