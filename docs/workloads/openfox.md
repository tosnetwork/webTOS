# Workload profile: OpenFox

**Status: version, help, and configuration-persistence gates pass natively.**

OpenFox is the first real agent workload (roadmap milestone 6): a static Go
binary (~97 MB with embedded assets) exercising the whole Go runtime on the
webTOS Linux layer.

## Fixture

Built by [`tools/build_openfox_fixture.sh`](../../tools/build_openfox_fixture.sh)
from a local OpenFox checkout (`OPENFOX_SRC`, default `~/openfox`):

```
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -tags goolm,stdjson ./cmd/openfox
```

The source commit is recorded next to the binary (`test_data/openfox.commit`).
Static + pure-Go olm means the guest needs no shared libraries.

## What the Go runtime demanded (all implemented)

- **Timed futex waits** returning `-ETIMEDOUT` (the scheduler patches the
  return value when the deadline fires without a wake; restart semantics
  cannot express timeouts — re-execution would re-arm them forever).
- The same fix for **timed `epoll_wait`/`poll`/`select`**: timed waits park
  once and return 0 on wake; only infinite waits use restart semantics.
- **`nanosleep` as a scheduling point**: the sleeper parks until its
  deadline (Go's sysmon micro-sleeps in a loop; returning immediately
  starved every other thread).
- **Per-thread-group address spaces**: an `mmap` by any thread is visible
  to its siblings (maps swap only on cross-group switches). This replaces
  the per-task map clone inherited from upstream, which lost post-clone
  mappings.
- **Signal dispositions**: default-ignore signals and signals with a
  registered handler are dropped, not fatal (Go's SIGURG preemption).
- `sched_getaffinity` (one-CPU mask), `prctl(PR_SET_NAME)`, and
  best-effort debug info (Go's compressed DWARF no longer fails the load).

## Gates (crates/linux-compat/tests/openfox.rs)

- `openfox version` exits 0 and reports the Go toolchain.
- `openfox --help` exits 0 and lists subcommands.
- `openfox status` runs on a clean profile (reports missing config), and
  after seeding `~/.openfox/config.json` + workspace, a filesystem
  snapshot restored into a brand-new machine still shows both present —
  the reload-persistence semantics of the milestone gate.

Each invocation retires ~60 M instructions (a few seconds native).

## Not yet covered

- The scripted network-backed agent task (needs an LLM endpoint mock
  behind the broker), secret injection, crash bundles, the 60-minute
  soak, and browser delivery of the 97 MB image (interpreter throughput
  makes this a post-M8 concern).
