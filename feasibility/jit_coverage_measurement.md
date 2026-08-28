# Bail-cause histogram: what the JIT actually covers

`crates/linux-compat/examples/jit_coverage` runs a guest, profiles the blocks
it executes, and reports what fraction of that executed work (weighted by
`entries * instructions`) translates whole, and — for what does not — which op
and width bailed. This is the number that matters: `translate_block` is
all-or-nothing, so one unhandled op bails a whole hot block, and the honest
metric is executed coverage, not the 60/72 static op count.

Measured on the x86-64 Linux host against `test_data/busybox-musl` (static
musl), `GUEST_ARGV0=busybox`:

| workload | executed insns | translate whole | heaviest bail |
|---|---|---|---|
| sha256sum /bin/guest | 78.8M | **100.0%** | Load@16 0.0% |
| sha1sum /bin/guest | 64.6M | **100.0%** | Load@16 0.0% |
| md5sum /bin/guest | 15.6M | **100.0%** | Load@16 0.0% |
| gzip -c /bin/guest | 279.0M | **100.0%** | ZeroExtend@16 0.0% |
| sort /etc/passwd | 5.8K | 99.2% | SignExtend@16 0.5% |

**The finding.** For real scalar-integer workloads the JIT covers ~100% of the
hot path. Every bail is a 16-byte op (SIMD `Load@16`, an i128 sign/zero
extend), and together they are a rounding error — musl's hot loops (hashing,
compression) are scalar, so the wide-op wall the memory note warned about is
present but does not bite here.

**What this changes.** The earlier guess — including this session's — that
16-byte SIMD / i128 dominates real bails is **not true for static musl
workloads**. Coverage there is already ~100%, so the thing capping the speedup
is not coverage but the per-dispatch overhead the browser measurement isolated
(2.76x on a micro-loop). **Region/trace compilation is the lever**, not more
op coverage: fold a hot loop's back-edge into one wasm function so 279M
instructions are a handful of `jit_call`s, not one per iteration.

**The caveat this cannot see.** BusyBox-musl is scalar and static. A glibc
workload (its string/memory routines are heavily SSE/AVX) or a JIT-in-a-JIT
like Node would shift the histogram toward `@16`, and those need the dynamic
loader and libraries mounted to measure (`GUEST_MOUNT`). So: region compilation
first for the workloads measured; re-run this histogram against a mounted glibc
/ Node before deciding wide-op coverage is worth it there. Measure, per
workload class, before adding ops.
