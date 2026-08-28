# Bail-cause histogram, part 2: dynamic glibc and SIMD-heavy workloads

`crates/linux-compat/examples/jit_coverage` now imports a host runtime the way
`run_guest` does (`GUEST_MOUNT` / `GUEST_COPY` / `GUEST_EXE` / `GUEST_ENV` /
`GUEST_MEM_MB`), so it can profile a dynamically linked glibc binary and Node,
not just a static musl one. `jit_coverage_measurement.md` left that class
UNMEASURED and flagged it as the case that could move the histogram toward the
16-byte (`@16`) wall. This note measures it.

All runs are on the x86-64 Linux host (`100.91.25.120`), from a detached
worktree of commit `c11e89a`, against the gitignored real workloads. The metric
is unchanged: executed work weighted by `entries * instructions`, and
`translate_block` is all-or-nothing, so one unhandled op bails a whole hot
block. `Op@width` names the *first* op that bails a block; width is in bytes, so
`@16` is a 128-bit SSE/i128 operation, `@10` an 80-bit x87 long double.

## What was measured

| workload | kind | executed insns | translate whole | Σ `@16` bails |
|---|---|---|---|---|
| busybox `sha256sum` (baseline) | static musl | 78.78M | **100.0%** | ~0.0% |
| `codex --version` | static-pie (Rust) | 5.98M | **95.9%** | ~3.2% |
| `node --version` | glibc dynamic (C++) | 7.13M | **89.9%** | ~9.2% |
| `node -e` float compute loop | glibc dynamic + V8 JIT | _see below_ | | |

The baseline reproduces the prior note's number exactly (same 78,781,929
weighted insns, 100.0%), confirming the tool is unchanged for static ELFs.

### `codex --version` (static-pie, no mount)

```
$ jit_coverage ~/.codex/packages/standalone/current/bin/codex --version
profiled hot blocks:          10093
weighted executed insns:      5979940
translate whole (JIT-able):   95.9%  (5735290 of 5979940)
bail causes (op@width, share of executed insns):
  SignExtend@16                1.3%
  Load@16                      1.2%
  PcodeOp@0                    0.8%
  Copy@16                      0.4%
  ZeroExtend@16                0.3%
  IntXor@16                    0.0%
  IntRight@16                  0.0%
```

Static-pie, so no runtime is mounted — a clean dynamic-free comparison to musl.
Even here coverage drops from musl's 100% to 95.9%: a Rust/LLVM binary's
start-up touches SSE (`SignExtend@16`, `Load@16`, `Copy@16`, `ZeroExtend@16`),
which musl's hand-written scalar loops did not. `PcodeOp@0` (0.8%) is a
non-width bail — a CALLOTHER/intrinsic p-code op the lifter does not model —
not something wide-op coverage would fix.

### `node --version` (glibc dynamic, loader + libs mounted)

```
$ GUEST_MEM_MB=2048 \
  GUEST_MOUNT="/lib/x86_64-linux-gnu:/lib/x86_64-linux-gnu,/lib64:/lib64" \
  GUEST_EXE=/bin/node \
  jit_coverage ~/.nvm/versions/node/v24.13.0/bin/node --version
profiled hot blocks:          13880
weighted executed insns:      7127493
translate whole (JIT-able):   89.9%  (6409580 of 7127493)
bail causes (op@width, share of executed insns):
  ZeroExtend@16                3.4%
  SignExtend@16                2.3%
  Load@16                      1.6%
  IntXor@16                    1.4%
  PcodeOp@0                    0.8%
  Copy@16                      0.2%
  Store@16                     0.1%
  IntOr@16                     0.1%
  IntRight@16                  0.1%
  Store@10                     0.0%
  Load@10                      0.0%
  PcodeOp@8                    0.0%
```

Node runs through the mounted glibc loader. Even just starting V8 (`--version`
does no real user compute) drops coverage to 89.9%, and the top six bails are
all `@16` SSE ops totalling ~9%: glibc's `memcpy`/`memset`/`strlen` and V8's
own runtime are vectorised, exactly the wall the memory note predicted. `@10`
(x87 long double) and non-width `PcodeOp` bails are rounding error by
comparison.

### `node -e` float compute loop (V8 JIT-in-JIT)

```
$ GUEST_MEM_MB=3072 \
  GUEST_MOUNT="/lib/x86_64-linux-gnu:/lib/x86_64-linux-gnu,/lib64:/lib64" \
  GUEST_EXE=/bin/node \
  jit_coverage ~/.nvm/versions/node/v24.13.0/bin/node \
    -e "let s=0; for(let i=0;i<1000000;i++){ s+=Math.sqrt(i)+i*1.5; } console.log(s);"
profiled hot blocks:          ...
weighted executed insns:      859149808
translate whole (JIT-able):   96.8%  (831503282 of 859149808)
bail causes (op@width, share of executed insns):
  ZeroExtend@16                2.8%
  SignExtend@16                0.1%
  IntXor@16                    0.1%
  Load@16                      0.1%
  PcodeOp@0                    0.1%
```

Under sustained user compute (859M executed insns) coverage is HIGHER than at
startup — 96.8% vs 89.9% — because once V8 JIT-compiles the float loop the hot
path is float arithmetic the translator already handles (FloatAdd/FloatSqrt/…).
But `@16` is still the dominant bail class, `ZeroExtend@16` alone 2.8% (V8's
SSE value tagging), and those blocks stay interpreted no matter what. So even
the JIT-in-JIT compute case confirms the trend: the 16-byte move/widen quartet
is the wide-op slice worth implementing for glibc/Node.

## Verdict

Wide-op (`@16` SIMD / i128) coverage is **a rounding error for static musl,
a few percent for a static-pie Rust binary, and the dominant bail class for
glibc/Node.** The `@16` share tracks how vectorised the code is:

- static musl scalar loops: ~0%
- Rust static-pie start-up: ~3%
- glibc + V8 start-up: ~9%, and it is the *entire* top of the histogram

So the earlier finding — "coverage is already ~100%, region compilation is the
only lever" — holds **only for the scalar static-musl class it was measured on.**
For the glibc/SIMD class the histogram does shift to `@16`, and there wide-op
coverage is worth implementing: at ~9% of executed work bailed on `@16` before
any user compute, those blocks stay interpreted forever no matter how good
region compilation gets, because a region still cannot form across an
untranslatable block.

### Top 3 bail ops to implement first (by executed weight, glibc/Node)

1. **`ZeroExtend@16`** — 128-bit zero-extend (SSE unpack / movd-zero-upper).
2. **`SignExtend@16`** — 128-bit sign-extend (i128 / SSE widening).
3. **`Load@16`** — 128-bit vector load (`movdqa`/`movups`, the workhorse of
   glibc `memcpy`/`memset`).

`IntXor@16` (SSE `pxor`, common as a zeroing idiom) is a close fourth. These are
the 128-bit-move-and-widen core, not the full SSE/AVX arithmetic surface — a
narrow, high-yield first slice.

### Recommendation

- **For the musl/scalar workload class:** unchanged — coverage is ~100%, spend
  on region/trace compilation, not op coverage.
- **For the glibc / SIMD / Node class:** wide-op coverage IS worth it. Start
  with the 128-bit move/widen/load quartet above; they alone recover most of
  the ~9% that bails before any user code runs, and they are prerequisites for
  region compilation to reach the vectorised hot loops at all.
