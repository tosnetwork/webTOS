# Security

webTOS runs an x86-64 Linux binary that nobody vouched for, in a browser tab,
and the tab survives. That sentence is the product; everything below is what
it costs to mean it.

## What is trusted, and what is not

**The guest is the adversary.** That is not a worst case, it is the design:
the point of running a binary here is that you did not have to trust it. So
every instruction byte it executes, every syscall argument it passes, every
address it computes, and every file it writes is attacker-controlled input to
this codebase.

**The host page is trusted with its own data and not with the module's
integrity.** A page can already do anything to its own memory. What it must
not be able to do is take the tab down or read something back that a boundary
released — so the exported `wtw_*` functions treat their arguments as input
rather than as a contract.

**The network is not trusted.** Bytes from a relay reach the guest; a manifest
commits to the images that do.

## The seven input surfaces

The roadmap names them, and six are swept exhaustively rather than sampled.
The count next to each is defects found by that sweep.

| Surface | How it is swept | Found |
|---|---|---|
| ELF loading | every truncation, every single-bit flip | 5 |
| Snapshot restore | the same | 2 |
| Syscall arguments | every argument position of every syscall number against a corpus of the ways a number breaks code that trusts it, singly and paired, against four page contents — 7,128,576 cases | 5 |
| Instruction decoding | every opcode in all four maps under seventeen prefix combinations against six ModRM forms, then again truncated against a mapping boundary — 365,568 sequences | 0 |
| Instruction execution and memory translation | the same corpus run under nine register patterns — 940,032 executions | 3 |
| Host messages | every argument position of every exported function, singly and paired — `web/test_messages.mjs` | 32 traps, one cause |
| Image parsing | no parser: an image is bytes into a file, and what reads it is the ELF loader or the snapshot importer, both above. The delivery protocol is gated instead | 1 |

Four of the syscall defects were wrapped arithmetic, invisible in the release
profile. Anything about arithmetic is run under `--profile relcheck`, and the
sweeps say in their own output which profile they ran in — a pass in the wrong
one is not a pass.

## Ceilings

A guest that does nothing wrong can still take a tab down by asking for too
much. Five things have ceilings, and the fifth is the one with nothing else
behind it:

- **Memory** — refused at the request rather than part-way through.
- **Storage** — the guest sees `ENOSPC`.
- **Network** — the guest sees `EPERM`.
- **Event log** — recording stops, the workload does not, and the trace says
  how much it dropped. A log that stops without saying so reads as a workload
  that stopped doing anything.
- **CPU** — a workload that computes in a loop and issues no syscalls is
  outside every other mechanism here: no kernel entry to interrupt it at, and
  the instruction limit only ends a turn that the host's loop begins another
  of. Spent, `run` returns `OutOfCpu` before executing anything further, and
  raising the allowance resumes it where it stopped.

With no memory budget set, a host that keeps sending well-formed messages can
still exhaust the address space. That is the budget's job and it is optional;
a host that means to survive sets one.

## Images

An image arrives in pieces over a network and is cached in browser storage
between sessions. TLS says something about the server that sent it and nothing
about a copy that has been in OPFS since last week.

A manifest names each image with its size and SHA-256. Delivery refuses bytes
that disagree, an image the manifest does not name is refused as well — a
manifest is a list of what may be delivered — and the check happens before the
guest runs the image rather than when it arrives, so a host that forgets to
say a stream finished cannot skip it.

**The signature over the manifest is verified by the host, not by the module,
and that is deliberate.** A wrong signature verifier fails open: it accepts
what it should not and nothing says so. Hand-rolling an unaudited one inside a
security boundary is worse than having none. The platform ships an audited
verifier — `crypto.subtle` in a browser, `node:crypto` outside — and the host
uses it before installing. The module owes the other half, which a
known-answer test can settle: that the bytes delivered are the bytes the
manifest names. `web/test_manifest.mjs` shows the two composing.

## Credentials

A credential is injected at runtime and scoped: it reaches only the files the
host named, and a program outside that scope reads the placeholder rather than
an empty value that would read as "no key configured". It is redacted out of
snapshots, and out of crash bundles — for real, in every build, because a
bundle is a diagnostic that leaves the machine and the executable path in it
is whatever the guest asked to run.

What has been checked, and what has not: a process cannot find another's
credential in memory it is handed, and a snapshot does not carry a file that
was deleted, rewritten shorter, or renamed over. Both of the last two were
defects, found by asking the question rather than by assuming the answer.

## Reporting

Open an issue at <https://github.com/tosnetwork/webTOS/issues>. If the finding
is a way for a guest to reach the host — memory outside the guest's own,
execution outside the module, or a way to make the module abort rather than
refuse — say so in the title and leave the exploit out of the description;
a maintainer will ask for it privately.

There is no published release yet and so no supported-version table. The
repository has a reproducible release-candidate builder and gate documented in
`docs/RELEASE.md`; its workflow creates GitHub OIDC provenance and SBOM
attestations, but a workflow artifact is evidence for review, not a supported
release. Workload statements can carry detached Ed25519 signatures as described
in `workloads/README.md`. Production private keys and trust-root changes are
maintainer-controlled and never generated implicitly by a build. When a
maintainer publishes a release, this section gets its version and support
window.

## What would change this document

A defect found in a swept surface means the sweep's corpus was missing a way a
number or a byte can be wrong, and the corpus gets that case rather than the
one instance being patched. A defect found in an unswept one means the surface
was named wrongly, and this table gets a row.
