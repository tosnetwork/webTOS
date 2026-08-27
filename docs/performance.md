# Performance and memory: what is measured

Milestone 8 is where the interpreter becomes a supportable runtime. Deciding
what to optimize needs numbers rather than impressions, so this records what
the current build actually costs and what a browser tab actually grants.

Two harnesses produce these figures, running the same guest workloads with the
same inputs so the results are comparable:

```bash
# native reference
cargo test -p linux-compat --release --test bench -- --ignored --nocapture

# per browser engine
node web/bench.mjs
```

Both hash a file with BusyBox `md5sum` at two sizes and report the difference
between them. That subtraction is the point: each run pays once to start a
process and once to lift the blocks it touches, and those fixed costs cancel,
leaving what the interpreter sustains once warm — the number that decides how
an interactive session feels.

The browser harness also runs a control: `crates/bench-control`, a few hundred
bytes containing one hot loop. The reason is in the next section.

## Measured, 2026-08-27

Apple M-series laptop; `crates` built `--release` (wasm32 pinned to
`opt-level = 2`). Instruction counts are identical everywhere, which is the
determinism gate doing its job — only the time differs.

**Read the ratios, not the absolutes.** The machine was not quiet (other
applications, load average 6–9), and that moves the absolute times by about
3x between runs. Two runs, hours apart:

| | Machine build | md5sum 4 MiB | Sustained | Control | Ceiling |
|---|---|---|---|---|---|
| Native, quieter | 150 ms | 3.10 s | 21.3 M inst/s | — | n/a |
| Chromium, quieter | 124 ms | 5.19 s | 10.9 M inst/s | — | 3892 MiB |
| WebKit, quieter | 129 ms | 4.70 s | 11.9 M inst/s | — | 3892 MiB |
| Firefox, quieter | 1048 ms | 39.30 s | 1.4 M inst/s | — | 3892 MiB |
| Native, loaded | 120 ms | 4.31 s | 15.4 M inst/s | — | n/a |
| Chromium, loaded | 303 ms | 14.26 s | 3.5 M inst/s | 219 M iter/s | 3892 MiB |
| WebKit, loaded | 193 ms | 6.96 s | 8.3 M inst/s | 338 M iter/s | 3892 MiB |
| Firefox, loaded | 1573 ms | 55.76 s | 1.2 M inst/s | 46 M iter/s | 3892 MiB |

"Machine build" is compiling the embedded SLEIGH specification, which every
session pays once before the first instruction runs. "Control" is
`crates/bench-control`, and only the second run had it.

What survives both runs: the ordering (WebKit ≥ Chromium ≫ Firefox), the
browser landing within a small factor of native on the fast engines, and an
identical 3892 MiB ceiling. Run the harnesses on the machine you care about
rather than trusting the numbers here.

### Half of native — and one engine's column is not about webTOS at all

Chromium and WebKit run the interpreter at roughly half native throughput.
That is a far smaller gap than the architecture suggests, and it means the
browser is not the reason a workload feels slow: the interpreter is.

Firefox measures at about an eighth of the other two. The tempting explanation
is the interpreter's shape — `icicle_cpu::exec::interpreter::interpret` is a
single 61.8 KiB function, 4.7% of the whole code section and three times the
next largest, which is exactly what an optimizing compiler might decline to
handle. That explanation is wrong, and three measurements say so:

- Forcing Chromium to its baseline tier (`--js-flags=--liftoff-only`) costs
  2.7x: 10.1 to 3.8 M inst/s, measured back to back. So tier matters, and a
  declined function would look roughly like that.
- Turning Firefox's optimizing tier *off* changes nothing (1.3 to 1.6 M inst/s,
  within noise), and turning its baseline tier off leaves "no WebAssembly
  compiler available". Its optimizing tier is contributing nothing here.
- The control module settles it. At a few hundred bytes, no size heuristic can
  reach it, and the spread is there anyway: 219, 338 and 46 M iterations per
  second for Chromium, WebKit and Firefox, on identical work with identical
  results.

The control also points the other way from the hypothesis. If the 61.8 KiB
function were being declined, webTOS would look *worse* than the control in
Firefox. It looks better: Firefox runs the control at 0.21x Chromium and the
interpreter at 0.34x. Whatever is slow, it is slower on a tiny loop than on
ours.

So the Firefox column measures the browser build the test harness downloads,
which compiles wasm with its baseline compiler only. It is not a statement
about Firefox as shipped, and it is not a webTOS problem to fix. The control
stays in the harness so this does not have to be rediscovered.

What survives from the scare is a real risk, just not a demonstrated one: a
60 KB function is a large thing to hand an optimizing compiler, and Chromium's
own baseline-versus-optimized gap shows what it would cost if an engine ever
did decline it. Splitting the cold half of the interpreter — the float and
80-bit paths, about a third of the match arms — would remove the risk cheaply.

### The 4 GiB ceiling is real but not the near-term limit

All three engines grew the module's linear memory to 3892 MiB, which is
effectively the whole wasm32 address space. So the ceiling is not "browsers
give you a few hundred megabytes" — it is the architectural 4 GiB, and the
constraint that matters is what has to fit inside it *together*: the guest's
physical pages, the guest filesystem holding the image, the translated-block
cache, and the module's own heap.

For scale, a BusyBox shell touches 1 MiB of guest physical memory against the
1 GiB default cap, and hashing 4 MiB leaves the module at a 52 MiB heap. The
agent images are what press on this: a 52 MB image is 52 MB in the filesystem
plus its mapped segments once it runs. A workload that natively wants a 4 GiB
guest does not fit beside everything else, and `wtw_set_guest_memory_mb` exists
so a host can say what its budget is and have the guest fail an allocation
cleanly rather than have the module die when the browser refuses to grow.

### Process startup was a translation problem

`busybox true` retires 2,713 instructions and takes 20 ms; a five-stage shell
pipeline retires 124k instructions and takes over a second. Almost none of that
time was spent executing guest code.

`bench_execve_relift_cost` measured it. A BusyBox shell runs `/bin/true` —
which is the same BusyBox image — 1 or 16 times, so by the time the first one
starts, every block of its startup path has already been lifted by the shell
itself. It was re-lifted anyway:

| Per extra `execve` | Instructions | Wall time | Rate |
|---|---|---|---|
| Before | 22,272 | 48.8 ms | 0.5 M inst/s |
| After | 22,272 | 1.8–2.3 ms | 10–12 M inst/s |

The five-stage shell pipeline moved with it, 1.06 s to 0.28 s.

Blocks are keyed by `(virtual address, isa mode, address-space id)`, and
`fork` and `execve` each take a fresh address-space id — necessary, because
two images put different code at the same address, and reusing one for the
other was a real bug. But it made identity *which process is looking*, when
what matters is *what the memory contains*: about 98% of an `execve` was
re-lifting blocks lifted moments earlier for another process.

The engine now keeps a second index of lifted groups, keyed by address and ISA
mode but not by address space, and reuses one only when the guest bytes at
that address still match the ones it was lifted from. Lifting is a pure
function of the bytes, the address and the context, so identical input gives
an identical block, and a different image at the same address can never match.
The hot path is untouched: the index is consulted only when the
per-address-space map misses, which is exactly when a lift was about to
happen. **About 20x**, with identical instruction counts — the guest does the
same work; the engine stops repeating itself. What remains per exec is genuine
setup: address-space teardown, ELF loading, stack construction.

The change also let a real bug be fixed rather than worked around. The
root-process load path reset every image to address-space id 0, so a second
image loaded into a live machine keyed its blocks identically to the first —
and the two static fixtures in this repository share a load address, so
`guest_ps` printed `hello`'s output. Each load now takes its own address
space. Without the content-addressed index that would have cost 18 ms of
re-lifting per load; with it, a repeated load still runs in 0.1 ms.

### The workload that matters has no hot path

The plan for milestone 8 says "profile executed blocks and translate only
proven hot paths". `bench_block_hotness` and `bench_agent_startup_is_lifting`
did the profiling half, and it does not support the second half.

How concentrated execution is, weighted by retired instructions:

| Workload | Blocks executed | Cover 50% | Cover 90% | Hottest block |
|---|---|---|---|---|
| `md5sum` 1 MiB | 696 | 4 | 8 | 16% |
| `busybox ls /bin` | 1,056 | 68 | 445 | 3% |
| shell loop, 100 iterations | 1,701 | 55 | 478 | 7% |
| **agent `--help`** | **29,347** | **212** | **1,879** | **1.5%** |

Compute is the textbook case: thirteen blocks cover 99% of a megabyte of
hashing, and a translator aimed at them would pay for itself immediately.
A real agent starting up is the opposite. It executes twenty-nine thousand
distinct blocks, the hottest accounts for one and a half percent, and covering
ninety percent means translating nearly two thousand of them. There is no hot
path to find.

And the time is not going where a translator would look. The same invocation,
three times in one machine, the first paying to lift what the others find
already lifted:

| Run | Instructions | Wall time | Rate |
|---|---|---|---|
| Cold | 18,528,799 | 5.27 s | 3.5 M inst/s |
| Warm | 18,488,726 | 0.86 s | 21.4 M inst/s |
| Warm | 18,506,097 | 0.85 s | 21.9 M inst/s |

**84% of a cold agent start is lifting, not executing** — and the warm rate is
the interpreter's own sustained rate, so once the blocks exist the interpreter
is not the bottleneck at all. A hot-block translator would attack the
remaining 16%, spread across a distribution with no peak, and would add
translation work to a run already dominated by it.

### Almost all of that lifting was the optimizer

Splitting the lifting cost said where it went. The same agent start, with the
p-code optimizer configured three ways:

| Optimizer | Cold | Lifting | Warm rate |
|---|---|---|---|
| Instruction and block (the default) | 5.09 s | 4.35 s (86%) | 25.1 M inst/s |
| Instruction only | 3.35 s | 2.61 s (78%) | 25.0 M inst/s |
| Off | 1.10 s | 0.24 s (22%) | 21.5 M inst/s |

**94% of lifting was optimization, not decoding.** And what it buys is small:
hashing 4 MiB runs at 17.1 M inst/s optimized against 15.3 unoptimized, about
12%. Optimizing every block to gain 12% on the few that are hot, while paying
four seconds for the 29,000 that are not, is the wrong trade for anything but
a compute loop.

So blocks are now lifted without the optimizer and re-lifted with it once they
have been entered enough times to have earned it. Counting happens where the
interpreter already does a lookup, so straight-line chaining inside a block
group costs nothing extra.

| Threshold | Agent cold start | md5sum 4 MiB |
|---|---|---|
| Optimize everything | 5.07 s | 3.11 s (17.2 M inst/s) |
| 200 | 1.42 s | 3.07 s (17.4 M inst/s) |
| 1000 (the default) | 1.20 s | 3.06 s (17.5 M inst/s) |
| 5000 | 1.13 s | 3.08 s (17.4 M inst/s) |

There is no trade-off to make. Compute is unaffected — its inner blocks are
entered millions of times and promote immediately at any of these thresholds —
and startup improves by more than three times. The default is 1000, where the
startup curve has flattened and merely warm code can still earn optimization.

The reference traces did not have to be regenerated, which is the point of
having them: a change that rewrites how every block is lifted turned out to be
architecturally invisible, and the baselines said so rather than a person
asserting it.

Measured after, against the same workloads:

| | Before | After |
|---|---|---|
| Agent `--help`, cold | 5.27 s | 1.44 s |
| — of which lifting | 84% | 31% |
| Five-stage shell pipeline | 1.06 s | 0.04 s |
| Reloading the same image | 21.9 ms | 1.2 ms |
| `execve`, marginal | ~2 ms | 1.3 ms |
| md5sum sustained | 17.3 M inst/s | 17.3 M inst/s |

The shell pipeline moving twenty-six-fold is the two changes compounding: the
content-addressed cache stopped re-lifting the same image per process, and
tiering stopped optimizing what a short-lived process never repeats.

#### The cost tiering does have: one stale copy per promoted block

Promotion re-lifts an address with the optimizer and drops the cheap version
from the block map, but the block arena is append-only, so the retired group's
entries stay allocated and unreachable. The soak test found this by asserting
the block table was flat across repeated runs of the same image, which it is
not.

Eighty rounds of the agent, measured:

| Round | 0 | 9 | 19 | 39 | 59 | 79 |
|---|---|---|---|---|---|---|
| Lifted blocks | 32,440 | 35,362 | 36,730 | 38,308 | 39,108 | 39,672 |

Growth per ten rounds falls from 2,922 to about 250: addresses cross the
threshold at different rates, and each can only ever be promoted once. The
bound is twice the image's distinct blocks, and 22% over eighty rounds is well
inside it. Guest memory and the filesystem stay flat over the same run.

The soak therefore asserts convergence rather than flatness — the last
quarter's growth must be a small fraction of the first quarter's — which still
catches a genuinely linear leak. Reclaiming the retired groups would need
index reuse in the arena, and stale `Target::Internal` references make that a
larger change than the memory it returns is worth today.

## What this says about milestone 8

In priority order, on the evidence above:

1. ~~**Attack translation cost.**~~ Done: a content-addressed lift cache took
   `execve` from 48.8 ms to about 2 ms. What is left per exec is address-space
   teardown and ELF loading — a different problem, and a smaller one.
2. ~~**Stop optimizing blocks that are never repeated.**~~ Done: tiered
   lifting took a cold agent start from 5.3 s to 1.4 s and cost compute
   nothing.
3. **Persist the lift cache across sessions.** Still worth doing — 31% of a
   cold start remains lifting — but the prize shrank from four seconds to
   about half of one, so it now ranks below its own risk. Revisit after the
   items below.
4. **Hot-block translation, scoped to compute.** Still the floor for
   long-running arithmetic, where thirteen blocks cover 99% of the work. Not
   the answer for startup, which is where the complaint actually is — the
   profile above is why that sentence changed.
5. **Split the interpreter's cold half.** Not urgent — no engine has been shown
   to decline the 61.8 KiB function — but the cost if one did is known, and the
   fix is mechanical.
6. **Budget memory as a whole.** Guest RAM, image bytes, and block cache share
   one 4 GiB address space; quotas need to account for all three together.

Not on the list: chasing the Firefox column. It measures a baseline-only
browser build, and the control in the harness is what proves it.

## Keeping the numbers honest

Both harnesses print rather than assert. A benchmark that fails because a
laptop was busy teaches nothing — and this laptop was busy, which is exactly
why the table above carries two runs instead of one tidy set of figures. A
threshold picked from one machine becomes a lie on another. Re-run them when
the interpreter changes, record the conditions, and keep the control column:
it is what turns "one engine is slow" into a statement about which engine.
