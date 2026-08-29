# Release process

webTOS release candidates are browser-runtime artifacts, not snapshots of a
developer's `web/` directory. The latter changes shape depending on which
large, gitignored workload fixtures happen to be staged. A candidate contains:

- `webtos_web.wasm`, the Linux x86-64 userspace runtime;
- `worker.js`, the browser worker and host-message boundary;
- `jit_host.mjs`, the direct JavaScript JIT host adapter;
- the exact Cargo lockfile, an artifact-specific SPDX SBOM, dependency-license
  metadata, and provenance for both vendored source sets;
- deterministic build metadata and a SHA-256 manifest covering every payload.

Guest programs are intentionally separate. In particular, the BusyBox demo is
GPL-2.0 software fetched from a pinned upstream binary, while agent images are
large third-party workloads with their own redistribution terms. Neither
silently enters the MIT runtime artifact.

## Reproducibility inputs

The Rust nightly is pinned by date in `rust-toolchain.toml`, and
`crates/Cargo.lock` is committed. Dependency fetching is separated from two
frozen builds. Each build runs with a clean environment, incremental
compilation disabled, a fixed locale, timezone, source epoch, and
`CONST_RANDOM_SEED`, plus path remapping for the checkout, Cargo registry, and
Rust toolchain. Caller-supplied Cargo profile and Rust flags do not reach the
compiler.

The canonical builder is Ubuntu 24.04 on `x86_64-unknown-linux-gnu`, the image
used by the release workflow. The same target toolchain does not promise
identical wasm across host operating systems or architectures, so the builder
records both the OS and triple in `BUILDINFO.json` and refuses another host.
It also isolates Cargo configuration from the caller while reusing only the
frozen registry and Git caches. A developer can set
`WEBTOS_RELEASE_ALLOW_NONCANONICAL_HOST=1` for local validation, but that output
is not a release candidate.

The uncompressed POSIX ustar writer fixes timestamps, ownership, modes, and
ordering. Avoiding compression also avoids making zlib version an undeclared
reproducibility input. `SHA256SUMS` covers every payload file, while the
adjacent `.sha256` file covers the tar itself.

## Gates

From a clean checkout:

```bash
tools/check_release_reproducible.sh
```

The gate performs two complete builds in separate Cargo target directories.
The first is deliberately invoked with hostile `RUSTFLAGS`, Cargo target, and
release-profile overrides; the build wrapper discards them. The two wasm
modules, canonical archives, and sidecars must compare byte for byte, and each
archive is verified again against its fixed member allowlist.

Packaging mechanics have a fast independent regression suite:

```bash
python3 tools/test_package_release.py
```

The manual `reproducible release candidate` workflow runs the license gate and
the two-build comparison. It then uses GitHub OIDC to produce separate GitHub
artifact-attestation bundles for build provenance and for the SPDX SBOM. The
workflow has only read access to repository contents; its additional
`id-token`, `attestations`, and `artifact-metadata` permissions exist solely for
those attestations. The action is pinned by full commit ID.

Uploading a workflow artifact or recording an attestation is not publication:
creating a GitHub release and declaring supported versions remain explicit
maintainer actions. The workflow must run from the exact commit being released,
and a reviewer must verify both attestations against the candidate digest
before publication. Signatures stay outside the canonical tar because signing
identities and signature metadata are not reproducible build inputs.

## Boundary of the claim

This gate proves that the core runtime can be rebuilt byte for byte from the
same committed inputs on the pinned Linux builder. It does not claim that a
third-party guest binary is reproducible from source. The independent workload
image, licensing, and detached-signature contract is documented in
`workloads/README.md`; proprietary workloads remain evidence inputs rather
than redistributable artifacts.
