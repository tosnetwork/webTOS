# Content-addressed chunk store + demand paging for the guest filesystem

Status: **Phase 2 complete (2026-08-29).** Phase 0's prerequisite was proven at
`29f3975`; the implementation now passes the x86-64 no-skip release suite, the
overflow-checking syscall sweep, Node boundary gates, and Chromium, Firefox,
and WebKit at 39/39 each. A real 268 MB Codex image also closes the large-image
measurement gate. The result is that an agent image can be installed by
manifest and fetched only where execution touches it, with OPFS caching and
the same architectural trace boundary as eager execution.

This revision incorporates an adversarial code review (Codex, gpt-5.6). The
first draft overclaimed how much of the fault/wait machinery already existed;
the review found ten concrete problems, all folded in below. It correctly made
the async fault inside a JIT region a prototype-first blocker and required a
VMA model, host ABI, and deterministic completion rule. The prototype then
showed that the feared parked state and new VM outcome were unnecessary:
`block_offset` already preserves the retry point and the retry runs through the
interpreter after the page is filled.

## Why

The big workloads are large and mostly cold. Claude Code is 239 MB, Codex 256
MB, Node 121 MB. A run executes and reads a fraction of that. Today the whole
image is downloaded (streamed in 4 MiB transfer chunks by `web/worker.js`,
`IMAGE_CHUNK`), cached in OPFS, and staged into the VFS before the guest starts.
Time-to-prompt and peak memory both pay for bytes that are never touched.

The goal is demand paging: a byte of the image is fetched the first time the
guest reaches it, from an OPFS cache when warm and the network when cold, and
never otherwise. The base image is immutable and content-addressed, so it is
CDN-cacheable and shared across agents (Node, Claude, Codex share libc, the
loader, and much of their runtime).

## Baseline at the scope decision (the anchor)

- `vfs.rs`: `NodeKind::File(Vec<u8>)` — a file's **entire** contents are an
  owned `Vec<u8>` resident in host memory. `Vfs::bytes()` sums
  `data.capacity()`; the storage budget is enforced against that.
- `read`/`pread` (`syscall.rs` ~715, ~766, ~837): match `NodeKind::File(data)`
  and copy `data[start..end]` into guest memory. Always assumes the bytes are
  present.
- **mmap is eager** (`sys_mmap`, `syscall.rs:2169–2203`): for a file-backed
  `MAP_PRIVATE`, it does `data[start..end].to_vec()` then `write_mem(cpu,
  target, &bytes)` — the whole mapped range is copied into guest memory at
  mmap-time. `MAP_SHARED` file mappings are `ENOSYS`. Final page permissions are
  `prot_to_perm(prot)` (`syscall.rs:2204`), which **includes `EXEC`** when
  `PROT_EXEC` was requested.
- **The initial executable is not loaded through guest mmap at all.** The host
  loader `load_elf`/`load` (`lib.rs:669`, `:845`) reaches the image through
  `ElfLoader::read_file`, which **clones the whole file** (`lib.rs:838`,
  `data.clone()`) to parse headers and lay `PT_LOAD` segments into guest memory.
  Guest `mmap(2)` is used later, by ld.so, for the shared libraries. So there
  are two eager consumers, not one: the host loader (first process) and guest
  mmap (subsequent libraries).
- Snapshots (`Vfs::serialize`/`deserialize`) write every file's full contents;
  `web/worker.js` persists that blob into OPFS for reload.
- The softmmu perm-fault does **not** currently produce a resumable host
  callback. In the browser JIT a perm miss becomes a **guest CPU exception**:
  the fast path branches to `IMPORT_LOAD`/`IMPORT_STORE`, the shim raises an
  exception (`webtos-web/src/lib.rs:486`, `:504`), and the block returns through
  `wtw_jit_fault` (`:551`). The interpreter faults equivalently. `HostWait` has
  only `Terminal` and `Network` (`syscall.rs:2820`), and `Machine::run` resumes
  only for those (`lib.rs:1618`); the worker pump recognizes only input/network
  statuses (`worker.js:777`). **A missing permission is a terminal guest fault
  today, not a resumable wait.**
- Task parking is **syscall-restart machinery**: `block_and_switch` calls
  `prepare_resume` (`syscall.rs:2839`), which rewrites PC to *after / retry the
  syscall* (`:2515`); the scheduler only switches at syscall boundaries
  (`proc.rs:3`). It cannot be reused verbatim for a mid-instruction fault.
- OPFS access today is **async** (`getFileHandle`/`arrayBuffer`,
  `worker.js:90`). There is no synchronous chunk API.
- The trace header identifies an image by **length + FNV of the full byte
  array** (`trace.rs:146`); blocked events in the trace are syscall results only
  (`trace.rs:91`).

## The two layers of laziness

Laziness can enter at two independent points, and they are not equally
valuable:

1. **read()-path (host-side file contents).** Make `NodeKind::File` chunk-backed
   so a `read`/`pread` materializes only the touched chunks. Simple, no MMU
   involvement, and a warm chunk can complete synchronously. But it does **not**
   help binaries: the host loader reaches the executable through a full-file
   clone, and ld.so reaches libraries through mmap — neither is a `read`.

2. **fault-path (demand paging of mapped/loaded code).** Map a file-backed
   region **without copying**, leave its pages non-resident, and fault a page in
   on first access. This is where the agent-binary win is. It **shares the
   softmmu perm-fault as the detection mechanism** — a non-resident page is a
   page without `READ|INIT`, so any access, interpreter or JIT, already traps —
   **but the resumable handling downstream of that trap is entirely new** (see
   the next two sections). The host loader's full-file clone (layer for the
   first process) must be converted separately to ranged reads or file-backed
   segment mappings; converting guest `mmap(2)` alone leaves the initial
   executable eager.

Both consume one shared foundation (chunk store + manifest). But the fault path
is gated on a hard prerequisite, addressed first.

## Prerequisite (prototype-first blocker): a resumable page-in fault — PROVEN

**Status: the synthetic prototype passes.** A data page is mapped non-resident
(no `READ`) with its bytes registered to fill on first access
(`InterpVm::register_lazy_page`); `handle_exception` serves the fault before the
OS layer turns it into a signal (`try_page_in`), fills the page, and returns
`Running` so the run loop re-enters at the untouched `block_offset` and re-runs
exactly that pcode. The gate `a_page_in_retries_identically_to_an_eager_run`
(`tests/jit_dispatch.rs`) runs a memory scan as a **region** self-loop and as a
**per-block** two-block loop, each interpreted and JIT'd, and asserts the lazy
run matches the eager run's result and retired-instruction count with **exactly
one page-in**. All four combinations pass. By the go/no-go rule (if region JIT
cannot meet this, ship only read-path laziness), region JIT **meets** it, so the
mmap-demand-paging design below is viable.

The mechanism turned out simpler than the three items below feared: a JIT fault
already lands at `block_offset` with the JIT skipped at a non-zero offset, so the
**retry after a page-in automatically runs through the interpreter** at the
faulting offset — no separate parked state, no new VM outcome, and x86 fault
restartability means the instruction committed nothing to redo. Original
analysis (superseded by the working prototype, kept for the record):

Before any filesystem work, the engine must be able to **take a fault mid-block,
park only the faulting task, fetch, and resume the *same* pcode instruction**
with identical `icount` and trace. Today it cannot; three things are missing:

1. **A page-in exception distinct from a guest fault.** The current perm miss is
   converted straight to a CPU exception and returned as a terminal guest fault.
   A non-resident-page access must instead raise a *page-in* condition carrying
   `{asid, vma_generation, fault_addr, access_kind (read/write/exec), resume
   point}`, consumed in `LinuxEnv::handle_exception`, not in generic MMU error
   handling. (Codex finding 1.)

2. **A page-fault parked state that does not rewrite PC.** `prepare_resume`
   rewrites PC as if a syscall were retried; a load/store/instruction-fetch fault
   can land anywhere, including mid-translated-block. Parking a page fault needs
   a state that preserves the exact interpreter/JIT resume point
   (`block_id`, `block_offset`, `icount`, fuel) unchanged — a new park operation,
   not `block_and_switch(..., restart)`. (Codex finding 2.)

3. **A "retry this pcode instruction after page-in" outcome in the VM.** The
   JIT's fault path undoes the failed pcode op and returns fault PC + fuel
   (`jit.rs:438`, `vm.rs:746`), and the region path returns completed-iteration
   count (`vm.rs:684`) — both built for a *terminal* guest exception the
   interpreter then raises. Page-in needs a third outcome: clear the condition,
   and re-enter at the saved offset to re-execute the faulting op against
   now-resident memory. Interpreter, JIT-block, and JIT-region each need it, and
   each needs a test asserting identical `icount`/trace versus the eager run.
   (Codex finding 3.)

**Historical go/no-go, now closed.** This isolated synthetic-page test was the
first deliverable because every later layer depends on it. `29f3975` supplies
the required region-JIT evidence; Phase 2's risks are now image authority,
VMA lifecycle, deterministic completion, and loader coverage.

## Phase 2 scope decision: immutable file-backed mmap demand paging

The blocker is closed. The next implementation is deliberately **not** “make
the VFS lazy everywhere,” nor “add a generic pager.” It is one vertical slice
whose product question is falsifiable: *can a pinned agent image map its
executable and shared-library files without eagerly materializing their cold
bytes, while preserving Linux `MAP_PRIVATE` and webTOS trace semantics?*

### In scope

1. **A pinned immutable base image.** An offline manifest names file metadata,
   fixed-size content-addressed chunks, a manifest root, and the legacy image
   identity needed by existing traces. Every chunk is verified before it is
   exposed. This is the authority for bytes; OPFS and the network are only
   transports and caches.
2. **A bounded chunk store.** It fetches an already-known chunk by hash from
   warm OPFS or the existing host delivery path, accounts resident bytes and
   overlay bytes to the storage budget, and never treats a logical file length
   as resident memory. The initial implementation may retain fetched chunks
   for the session; eviction and cross-image deduplication are later work.
3. **Non-resident private file mappings.** `MAP_PRIVATE` mappings of immutable
   base files create VMA metadata and page permissions, but do not copy file
   bytes into guest memory. First read, write, or instruction fetch asks the
   pager for the corresponding chunk/page; a successful fill restores the
   VMA's final permissions, including `EXEC`.
4. **Initial executable and loader coverage.** The host ELF loader must stop
   cloning the full executable. It may parse only the bounded ELF metadata
   eagerly, but its `PT_LOAD` ranges and the dynamic loader's later `mmap`s use
   the same VMA/page-in mechanism. Guest `mmap` alone is not success: it leaves
   the first 256 MB executable eager.
5. **Correct invalidation and private identity.** A mapping binds an immutable
   file/overlay version at `mmap` time. Page-in tickets carry address-space and
   VMA generation; `munmap`, `MAP_FIXED`, `mremap`, `mprotect`, `execve`, and
   fork must make a late completion harmless rather than filling a reused
   address.
6. **Deterministic completion.** A page miss is a whole-machine deterministic
   barrier: no guest task runs until that exact ticket is verified and the
   faulting instruction can retry. Fetch latency therefore changes host wall
   time only; it cannot choose another guest task or alter trace order. This is
   intentionally stricter than task-local parking and fits the existing
   syscall-boundary scheduler without inventing a mid-instruction task state.

### Explicitly out of scope

- `MAP_SHARED`, writable shared files, and a general page cache;
- eviction, prefetching, compression, background download, and cross-agent
  chunk deduplication;
- making arbitrary `read`/`pread`, mutation, snapshot, or sendfile callers
  fully lazy beyond the adapters required by the vertical slice;
- changing guest-visible ELF, mmap, fault, scheduler, trace, or errno
  semantics to obtain a time-to-prompt result;
- claiming browser delivery for Codex or Claude Code before their image profile
  passes the gates below.

### Non-negotiable invariants

- A successful lazy execution has the same exit state, guest bytes, retired
  instruction count, and architectural trace as the eager image.
- A failed hash, unavailable chunk, malformed manifest, stale ticket, or quota
  overage fails closed and cannot expose substituted bytes or silently run an
  eager fallback.
- The failed p-code operation commits no architectural state. The proven
  `block_offset` retry rule remains the only retry mechanism; Phase 2 does not
  add a second parked-state or JIT-outcome model.
- `PROT_EXEC` remains executable after first fill, and `MAP_PRIVATE` observes
  the version that existed when it was mapped, not later VFS mutations.

### Definition of done and current evidence

The vertical slice is complete only when all of the following are gated. Local
unit checks and Linux fixture checks are implementation evidence, not a
substitute for the final three-browser matrix:

1. A manifest-backed executable and a dynamic shared library both map with no
   eager payload copy; an access to each causes exactly the expected page-ins.
2. The eager and lazy versions reproduce the same trace, result, and retired
   `icount` for interpreter, per-block JIT, and region JIT, on the x86-64 Linux
   fixture host and in Chromium, Firefox, and WebKit.
3. Tests cover `EXEC` first fetch, a cross-page access, syscall
   `copy_from_user`/`copy_to_user`, a hash mismatch,
   storage-budget refusal, private-file mutation after `mmap`, and every stale
   completion path (`munmap`, `MAP_FIXED`, `mprotect`, `mremap`, `execve`, fork).
4. A measured Codex/Claude-sized image demonstrates that untouched payload is
   not materialized. The report separates bytes delivered, bytes resident,
   bytes executed, and latency; “the prompt appeared” is not sufficient.

Only after that gate may Phase 3 add deduplication, eviction, or prefetch.

All four gates are closed by the 2026-08-29 matrix:

| Gate | Evidence |
|---|---|
| Loader and mmap coverage | `lazy_paging.rs` demand-maps the initial static ELF and a dynamic ELF plus its exact manifest-bound musl interpreter; guest `execve` prefetches bounded ELF metadata before its point of no return; `MAP_PRIVATE` pins the mmap-time version and syscall copies page in user buffers |
| Interpreter/JIT determinism | The eager/lazy BusyBox gate compares output, exit, retired `icount`, and architectural events in interpreter and JIT modes; `a_page_in_retries_identically_to_an_eager_run` separately covers per-block and region JIT retry; the browser lazy gate asserts both block and region dispatch counters, and the three engines all report the same 4,821 instructions |
| Adversarial lifecycle | Unit/integration gates cover bad hashes, quota refusal, cross-page execute/read/write, cold-lift invalidation, scoped-secret materialization, canonical parent directories, atomic manifest installation, snapshot re-binding without losing resident overlays, executable-authority preservation, trailing snapshot bytes, `munmap`, `MAP_FIXED`, `mprotect`, growing `mremap`, `execve`, and fork |
| Platform matrix | `test_node.mjs`, 9,943 exported-boundary calls, manifest enforcement, and Chromium/Firefox/WebKit 39/39 all pass against a fresh wasm build |

The explicit large-image command used the x86-64 host's stock
`codex-cli 0.150.1` binary with `--version`:

```text
logical bytes                 268,330,432
delivered bytes                21,849,536  (8.14%)
resident filesystem bytes      21,849,576  (8.14%)
demand-filled page bytes       14,340,096
execute-first page bytes        1,347,584
executed bytes                    471,227
retired instructions            5,650,191
instrumented run latency            2,317 ms
exit/output                    0 / codex-cli 0.150.1
```

`execute-first page bytes` counts pages whose first materializing access was
instruction fetch; it is deliberately reported separately from all
demand-filled pages. `executed bytes` is the union of guest instruction-source
ranges actually reached by interpreter or JIT instruction markers, counted
once even when a loop executes them repeatedly. That is the exact code-byte
metric; `execute-first page bytes` remains the page-granularity transport
metric. Tracking those ranges adds instrumentation overhead, so the latency is
labelled instrumented rather than presented as a clean performance baseline.
The run left 91.86% of the logical image undelivered. The gate also found two
scale-only defects before passing: a lift built against a cold cross-page
target had to be invalidated after fill, and unaligned cross-page reads/writes
report the resident starting page rather than the adjacent cold page. Both now
have small regression gates in addition to this explicit large measurement.

## Core abstractions

### Chunk and manifest (the immutable, content-addressed base)

- **Chunk**: a fixed-size 64 KiB slice of a file's bytes (a multiple
  of the 4 KiB guest page). Identified by `Hash` = SHA-256 of its bytes.
- **ChunkedFile**: `{ size: u64, chunk_size: u32, chunks: Vec<Hash> }`. The last
  chunk is short.
- **Manifest**: `path -> ChunkedFile` for every base-image file, plus metadata
  (mode, mtime, symlink targets, directory structure). The manifest is itself
  serialized and hashed; its root hash **is the image identity** and also
  supplies the **precomputed full-image identity the trace header needs** (see
  determinism). A Merkle image: the root pins every byte without reading them.

Built offline at image-build time; not guest-visible; never changes during a run.

The canonical builder is:

```bash
SOURCE_DATE_EPOCH=0 python3 tools/build_chunk_manifest.py \
  <rootfs> <output-dir> --guest-prefix /
```

It writes `manifest.txt` plus `chunks/<sha256>`, prints the manifest root, and
sorts byte paths before serialization. The explicit source epoch fixes every
manifest mtime rather than inheriting host filesystem metadata. The manifest
encodes paths and symlink
targets as lowercase hex, so whitespace and non-UTF-8 Unix names cannot create
an ambiguous signed form. The VM rejects noncanonical paths, unsorted or
duplicate entries, malformed layouts, and any chunk whose delivered SHA-256
does not match its entry.

### ChunkStore and the new host ABI (this is new protocol, not reuse)

There is no completion message, ticket registry, page-delivery API, or page-in
wait status today (Codex finding 9). They must be defined:

```
trait ChunkStore {
    /// Warm path: bytes already in OPFS, read synchronously. None on miss.
    fn get(&self, hash: Hash) -> Option<Bytes>;
    /// Cold path: begin a network fetch; returns a ticket that completes later.
    fn fetch(&self, hash: Hash) -> Ticket;
}
```

New `wtw_*` boundary, mirroring but distinct from the push-all-up-front image
streaming:

- engine → host: a **page-request dequeue** (ticket, hash, and the VMA
  coordinates the completion must be validated against).
- host → engine: **deliver verified bytes by ticket**, and a
  `STATUS_AWAITING_PAGEIN` the worker pump learns to recognize alongside
  input/network.
- Every returned chunk is **hash-verified before use**; wrong bytes are a hard
  error, never used.
- **Warm cache path:** the worker uses OPFS `createSyncAccessHandle` when the
  engine supplies it and `File.arrayBuffer()` otherwise. Both occur behind the
  same deterministic VM barrier; support and behavior are gated in Chromium,
  Firefox, and WebKit rather than assumed.

### FileData: typed accessors, not one transparent `&[u8]`

An accessor that can asynchronously page in **cannot** return `&[u8]`, yet
several callers need owned full contents or `&mut Vec<u8>` (Codex finding 8).
The type carries the state; three distinct APIs carry the three needs:

```
enum FileData {
    Resident(Vec<u8>),                 // created/written/fully-resident
    Chunked(ChunkedFile),              // immutable descriptor; shared store
}
// read path (may park):   read_range(off, len) -> Ready(Vec<u8>) | Pending(Ticket)
// mutate path (forces residency): materialize_file() -> &mut Vec<u8>
// snapshot path:          descriptor + manifest root, not cached base bytes
```

Every current `NodeKind::File(data)` site must be classified and migrated — the
draft's "~15 match sites" was an undercount. The real surface (Codex finding 8):
`read_backing` (`syscall.rs:715`), write (`:764`/`:781`/`:791`), truncate
(`:837`/`:845`), `O_TRUNC` (`:1251`), mmap (`:2178`), exec ELF validation
(`:3736`), sendfile (`:5462`), loader clone (`lib.rs:838`), plus VFS `size`
(`vfs.rs:77`), budget `data_len` (`:39`), snapshot `serialize` (`:779`),
`rewrite_file` (`:737`), `take_file_contents`/`put_file_contents` (`:695`/`:708`),
and `append_file` (`:331`). Mutating and whole-file-owning sites route through
`materialize_file` (correctness first, laziness only where it pays); only
`read`/`pread`, the loader, mmap, and sendfile take the lazy path.

### VMA metadata (required for any async completion)

`sys_mmap` stores no mapping metadata beyond raw MMU pages; `MAP_FIXED` unmaps
first (`:2143`), `munmap` removes memory (`:374`), fork snapshots virtual
mappings (`:3612`). An async fetch can complete after its address was unmapped,
`MAP_FIXED`-reused, mremapped, mprotected, or forked — filling `{addr, hash}`
blindly writes stale bytes into the wrong mapping or address space (Codex
finding 6). So a per-address-space **VMA table** is required:

- Each file-backed VMA records `{range, node, file_offset, final_perm
  (prot_to_perm, EXEC included), generation}`.
- Cloned with the virtual mappings on fork; bumped/removed on
  unmap/MAP_FIXED/mremap/mprotect.
- A page-in ticket carries `{asid, vma_generation, page_index, access_kind}` and
  is **validated atomically before completion**; a stale ticket is dropped, not
  applied.
- On completion the page is filled and its permission set to the VMA's recorded
  `final_perm` for that page — **restoring `EXEC` for code**, not a generic
  `READ|INIT` (Codex finding 7). Instruction-fetch/lift reads
  (`vm.rs:1000` reads source bytes through the MMU) are themselves page-in
  candidates, so an `EXEC`-only page must page in on fetch and must not be
  silently downgraded to readable data.

### MAP_PRIVATE must snapshot the file at mmap time, not at fault time

Today the private copy is taken at mmap-time (`:2183`). If a deferred fault
re-reads mutable `FileData`, a `write`/`pwrite`/`O_TRUNC`/overlay update between
mmap and first fault would change the bytes the mapping exposes, moving
execution and traces (Codex finding 5). Each private mapping must therefore bind
to an **immutable file version/overlay snapshot captured at mmap time**; the
fault resolves against that pinned version, never against the live node.

## Determinism and the trace-replay boundary (the heart of this)

The trace gate (`test_data/traces/*.trace`) records what the CPU does. Demand
paging must change **when** bytes arrive, never **which** bytes the CPU sees,
and never the **order** in which tasks run.

1. **Bytes are a pure function of the image.** Page contents come from a
   content-addressed chunk; the manifest pins the hash; the hash pins the bytes,
   independent of source (OPFS/network) and arrival time. So guest-visible memory
   is identical to today's eager load, and a correct implementation regenerates
   **no** trace — the invariant the design exists to protect, checked by the gate.

2. **The page-in set and order are deterministic.** A page-in is triggered by a
   deterministic event — the guest touches address X at instruction N — so the
   sequence of page-in *requests* is a function of the run, not of network
   timing.

3. **Arrival latency is nondeterministic but cannot decide scheduling.** The
   subtle hole remains real: content hashing fixes bytes, not task order. The
   implemented rule is a global page-in barrier. The CPU keeps the original
   exception and p-code offset, and no guest task runs while its ticket is
   outstanding. Delivery first re-submits that exception to the pager, fills
   the authoritative page, and only then retries execution. Because there is
   no scheduling choice during the wait, completion needs no new architectural
   trace event; network latency changes wall time only.

4. **The trace header needs an identity a lazy image can supply.** The header is
   length + FNV over the whole byte array (`trace.rs:146`); a lazy image has not
   read the whole array. Version the header to carry the **manifest root**, and,
   if byte-for-byte-identical *old* traces must still validate, a **precomputed
   legacy FNV** emitted by the manifest builder. (Codex finding 10.)

Corollary — **snapshots shrink and become shareable.** A snapshot records the
manifest root, immutable descriptors, and any files promoted to resident by
mutation, then re-fetches unchanged base chunks by hash on restore. Cached
immutable chunks are never serialized per session.

### Where determinism could still break (guards)

- Chunk hash-verification failure → hard error, never used (guards silent
  wrong-bytes that would move a trace unseen).
- `read`/mmap past EOF must zero-fill exactly as today
  (`offset_into`/`.min(data.len())` semantics preserved in `read_range`).
- Storage budget must count resident chunk bytes + overlay, not the file's
  logical size, or a large image reads as free and blows the cap while paging in
  (`Vfs::bytes` accounting changes with residency).
- A mutated file is promoted atomically to resident storage before the write;
  an existing `MAP_PRIVATE` retains the immutable descriptor captured at mmap.

## Phasing

0. **Resumable page-in fault (prerequisite blocker).** ✅ Proven at `29f3975`.
   The synthetic non-resident-page gate covers interpreter, per-block JIT, and
   region JIT without a new parked state or VM outcome. Everything below
   depends on this evidence.
1. **Foundation + read-path.** Implemented: chunk store, canonical manifest,
   `NodeKind::ChunkedFile`,
   `read_range`, the new host ABI + `STATUS_AWAITING_PAGEIN`, OPFS-sync warm
   path with async fallback. Convert `read`/`pread`/sendfile. Win: large data
   files. Trace gate untouched.
2. **Demand-faulted code.** Implemented and matrix-gated: VMA table (with fork/unmap/MAP_FIXED/mprotect
   lifecycle and EXEC-preserving perms), mmap-time private-version binding,
   demand-faulted guest mmap, **and** a ranged/file-backed rewrite of the host
   ELF loader so the first executable is lazy too. Win: the agent binaries.
3. **Shared immutable base.** Session-wide and OPFS hash dedupe plus
   descriptor-only snapshots are implemented. Eviction and measured
   cross-agent policy remain post-gate work.

## Remaining risks / open questions

- **VMA lifecycle regressions** — generation checks now gate
  unmap/MAP_FIXED/mremap/mprotect/exec and fork preserves address-space
  identity, but the release suite and browser matrix remain the continuing
  guard.
- **64 KiB chunk vs 4 KiB page** — page in the whole chunk (fewer round-trips) or
  just the page (less waste); start chunk-granular, measure.
- **Mutation granularity** — the scoped implementation promotes a chunked file
  to `Resident` before a legacy whole-file mutation. A measured per-byte COW
  overlay is later work, not part of this correctness slice.
- **`MAP_SHARED` file mappings** remain `ENOSYS`; demand paging does not change
  that.
- **OPFS API differences** — `createSyncAccessHandle` is used where available;
  the asynchronous verified barrier is the portable fallback and is included
  in the three-engine matrix.
- **Manifest build reproducibility** — closed for the locked M8 workload
  images. `tools/build_workload_image.py` fixes manifest and archive metadata,
  verifies every input against `workloads/LOCK.json`, and emits a bound
  in-toto statement; two-root/different-mtime tests and real BusyBox, OpenFox,
  Codex, and Claude Code builds compare byte for byte. Detached signing is
  implemented, while production key custody and publication remain explicit
  maintainer operations.

## What this is not

Not a block device and not Ext2. The VFS stays file-level; laziness enters
beneath typed file accessors and beneath mmap, backed by a content-addressed
chunk store in OPFS. The technique (demand paging from a content store, COW
overlay, lazy-loading image) is broad prior art (qcow2 overlays, NBD, Docker
layer pulls, git partial clone); this is a clean-room design against our own VFS
and softmmu, not a port of anyone's engine.
