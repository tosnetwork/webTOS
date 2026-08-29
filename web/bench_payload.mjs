// Exact browser counterpart of `crates/linux-compat/tests/bench.rs::payload`.
// Keep this shared by the browser benchmark and its digest test: instruction
// counts do not depend on md5sum's input bytes, so comparing icount alone
// cannot detect a workload-generator drift.
export function benchmarkPayload(length) {
  const out = new Uint8Array(length);
  let hi = 0x2545f491 >>> 0;
  let lo = 0x4f6cdd1d >>> 0;
  for (let i = 0; i < length; i += 1) {
    const beforeLo13 = lo;
    const beforeHi13 = hi;
    lo = (beforeLo13 ^ (beforeLo13 << 13)) >>> 0;
    hi = (beforeHi13 ^ (beforeHi13 << 13) ^ (beforeLo13 >>> 19)) >>> 0;

    const beforeLo7 = lo;
    const beforeHi7 = hi;
    lo = (beforeLo7 ^ (beforeLo7 >>> 7) ^ (beforeHi7 << 25)) >>> 0;
    hi = (beforeHi7 ^ (beforeHi7 >>> 7)) >>> 0;

    const beforeLo17 = lo;
    const beforeHi17 = hi;
    lo = (beforeLo17 ^ (beforeLo17 << 17)) >>> 0;
    hi = (beforeHi17 ^ (beforeHi17 << 17) ^ (beforeLo17 >>> 15)) >>> 0;
    out[i] = (lo >>> 24) & 0xff;
  }
  return out;
}
