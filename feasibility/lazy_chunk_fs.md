# Content-addressed chunk store + demand paging for the guest filesystem

Status: design / feasibility. No code yet. The question this answers: can we
stop materializing a whole agent image before it runs — fetch only the bytes a
run actually touches, cache them in OPFS, and keep the execution bit-for-bit
replayable against the trace gate?

This revision incorporates an adversarial code review (Codex, gpt-5.6). The
first draft overclaimed how much of the fault/wait machinery already exists; the
review found ten concrete problems, all folded in below. The short version of
what changed: the softmmu fault is shared only for *detection* — the resumable
page-in (a mid-instruction parked state, a retry-same-instruction outcome, a VMA
model, a new host ABI, and a deterministic multi-task fault scheduler) is **new
work**, and the async-fault-in-a-JIT-region is a **prototype-first blocker**, not
a "confirm it works" footnote.

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

## What exists today (the anchor)

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

## Prerequisite (prototype-first blocker): a resumable page-in fault

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

**This is the highest-risk item and the first deliverable.** It is provable in
isolation (a synthetic non-resident page, no chunk store yet) and everything
below depends on it. If the region path cannot carry a mid-iteration retry
cleanly, the whole mmap layer is blocked and only the read() layer is viable.

## Core abstractions

### Chunk and manifest (the immutable, content-addressed base)

- **Chunk**: a fixed-size slice of a file's bytes (proposed 64 KiB, a multiple
  of the 4 KiB guest page). Identified by `Hash` = SHA-256 of its bytes.
- **ChunkedFile**: `{ size: u64, chunk_size: u32, chunks: Vec<Hash> }`. The last
  chunk is short.
- **Manifest**: `path -> ChunkedFile` for every base-image file, plus metadata
  (mode, mtime, symlink targets, directory structure). The manifest is itself
  serialized and hashed; its root hash **is the image identity** and also
  supplies the **precomputed full-image identity the trace header needs** (see
  determinism). A Merkle image: the root pins every byte without reading them.

Built offline at image-build time; not guest-visible; never changes during a run.

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
- **Warm sync path:** OPFS `createSyncAccessHandle` gives synchronous reads
  inside a Worker, so a warm chunk pages in without parking. This is **proposed,
  not present**, and its availability across Chromium/Firefox/WebKit must be
  verified; where it is absent, the async park is the fallback and the warm path
  simply degrades to it.

### FileData: typed accessors, not one transparent `&[u8]`

An accessor that can asynchronously page in **cannot** return `&[u8]`, yet
several callers need owned full contents or `&mut Vec<u8>` (Codex finding 8).
The type carries the state; three distinct APIs carry the three needs:

```
enum FileData {
    Resident(Vec<u8>),                 // created/written/fully-resident; today
    Chunked { file: ChunkedFile, resident: ChunkMap, overlay: Overlay },
}
// read path (may park):   read_range(off, len) -> Ready(Vec<u8>) | Pending(Ticket)
// mutate path (forces residency): materialize_mut() -> &mut Vec<u8>
// snapshot path:          snapshot_encoding() -> resident set + overlay, not bytes
```

Every current `NodeKind::File(data)` site must be classified and migrated — the
draft's "~15 match sites" was an undercount. The real surface (Codex finding 8):
`read_backing` (`syscall.rs:715`), write (`:764`/`:781`/`:791`), truncate
(`:837`/`:845`), `O_TRUNC` (`:1251`), mmap (`:2178`), exec ELF validation
(`:3736`), sendfile (`:5462`), loader clone (`lib.rs:838`), plus VFS `size`
(`vfs.rs:77`), budget `data_len` (`:39`), snapshot `serialize` (`:779`),
`rewrite_file` (`:737`), `take_file_contents`/`put_file_contents` (`:695`/`:708`),
and `append_file` (`:331`). Mutating and whole-file-owning sites route through
`materialize_mut` (correctness first, laziness only where it pays); only
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

3. **Arrival latency is nondeterministic but must not decide scheduling.** This
   is the subtle hole the first draft missed (Codex finding 10): with more than
   one task, *when* a cold fetch completes could otherwise decide which ready
   task the scheduler picks, reordering instructions, random draws, signals,
   syscalls, and trace events. Content hashing fixes bytes, **not scheduling**.
   So the fault scheduler must be deterministic by construction:
   - a page fault blocks **only** the faulting task;
   - ready tasks are selected by a **stable queue order**, never by fetch
     arrival;
   - page-in completion is applied at a deterministic point (e.g. the faulting
     task becomes runnable in stable order once its bytes are present), and the
     completion order is **recorded in the trace and replayed**, so a replay
     does not depend on live network timing at all.
   Without this rule the single-task argument does not extend to the multi-task
   case, and this is a first-class requirement, not a footnote.

4. **The trace header needs an identity a lazy image can supply.** The header is
   length + FNV over the whole byte array (`trace.rs:146`); a lazy image has not
   read the whole array. Version the header to carry the **manifest root**, and,
   if byte-for-byte-identical *old* traces must still validate, a **precomputed
   legacy FNV** emitted by the manifest builder. (Codex finding 10.)

Corollary — **snapshots shrink and become shareable.** A snapshot records the
manifest root plus resident/overlay state (what was written), and re-fetches
base chunks by hash on restore. The immutable base is never serialized per
session.

### Where determinism could still break (guards)

- Chunk hash-verification failure → hard error, never used (guards silent
  wrong-bytes that would move a trace unseen).
- `read`/mmap past EOF must zero-fill exactly as today
  (`offset_into`/`.min(data.len())` semantics preserved in `read_range`).
- Storage budget must count resident chunk bytes + overlay, not the file's
  logical size, or a large image reads as free and blows the cap while paging in
  (`Vfs::bytes` accounting changes with residency).
- Overlay-vs-base resolution is **per-byte**, overlay wins, not per-chunk.

## Phasing

0. **Resumable page-in fault (prerequisite blocker).** The page-in exception,
   the no-`prepare_resume` parked state, and the retry-same-pcode outcome for
   interpreter/JIT-block/JIT-region, each trace-gated against the eager run. No
   chunk store yet — a synthetic non-resident page. Everything below depends on
   this proving out.
1. **Foundation + read-path.** Chunk store, manifest, `FileData::Chunked`,
   `read_range`, the new host ABI + `STATUS_AWAITING_PAGEIN`, OPFS-sync warm
   path with async fallback. Convert `read`/`pread`/sendfile. Win: large data
   files. Trace gate untouched.
2. **Demand-faulted code.** VMA table (with fork/unmap/MAP_FIXED/mprotect
   lifecycle and EXEC-preserving perms), mmap-time private-version binding,
   demand-faulted guest mmap, **and** a ranged/file-backed rewrite of the host
   ELF loader so the first executable is lazy too. Win: the agent binaries.
3. **Shared immutable base.** Dedupe the base across agents by chunk hash so
   Node/Claude/Codex share libc/loader/runtime in one OPFS cache; snapshots stop
   storing base bytes.

## Risks / open questions

- **Async fault inside a JIT region** is the top risk and Phase 0's crux; if a
  mid-iteration retry cannot be made bit-exact, the mmap layer is blocked.
- **VMA lifecycle correctness under fork/MAP_FIXED/mremap/mprotect** with fetches
  in flight — the ticket-generation validation must be airtight.
- **64 KiB chunk vs 4 KiB page** — page in the whole chunk (fewer round-trips) or
  just the page (less waste); start chunk-granular, measure.
- **Overlay growth / promote-to-`Resident` threshold** under a workload that
  rewrites a large mapped region — needs a measured rule like the JIT block-table
  ceiling.
- **`MAP_SHARED` file mappings** remain `ENOSYS`; demand paging does not change
  that.
- **OPFS `createSyncAccessHandle` support** across the three engines — verify;
  async park is the fallback.
- **Manifest build tool** is new offline surface, trust-rooted by the manifest
  hash, so a bad build is a detected mismatch, not silent.

## What this is not

Not a block device and not Ext2. The VFS stays file-level; laziness enters
beneath typed file accessors and beneath mmap, backed by a content-addressed
chunk store in OPFS. The technique (demand paging from a content store, COW
overlay, lazy-loading image) is broad prior art (qcow2 overlays, NBD, Docker
layer pulls, git partial clone); this is a clean-room design against our own VFS
and softmmu, not a port of anyone's engine.
