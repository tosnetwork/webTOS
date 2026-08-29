import { createHash } from "node:crypto";

import { benchmarkPayload } from "./bench_payload.mjs";

const expected = new Map([
  [1, "1bc78ba35cac54fe318a6bd7e2acdf69a1eaf7c47c9597b0f6cc10e026aec5a1"],
  [4, "0bf23c3f806176c4a7e2e0169ac721515120732ec16cf2d9a7f4b44844b0d649"],
]);

for (const [mib, want] of expected) {
  const payload = benchmarkPayload(mib * 1024 * 1024);
  const got = createHash("sha256").update(payload).digest("hex");
  if (got !== want) {
    throw new Error(`${mib} MiB browser benchmark payload drifted: ${got} != ${want}`);
  }
  console.log(`[bench-payload] ok: ${mib} MiB ${got}`);
}
