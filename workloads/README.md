# Workload release contract

`LOCK.json` is the source of truth for the workload bytes tested by webTOS.
Every entry pins the guest path, mode, size, SHA-256, version, source material,
license decision, redistribution decision, and expected canonical manifest
root. A version label without matching bytes is rejected.

Build an image from an already-staged filesystem tree:

```bash
python3 -B tools/build_workload_image.py \
  --spec workloads/LOCK.json --workload-id busybox \
  --source /path/to/root --output /tmp/busybox-image \
  --archive /tmp/webtos-workload-busybox-1.35.0.tar --source-epoch 0
python3 -B tools/verify_workload_image.py \
  /tmp/webtos-workload-busybox-1.35.0.tar
```

The builder rejects undeclared, missing, wrong-mode, wrong-size, or
wrong-hash files. It emits content-addressed 64 KiB chunks, a canonical
manifest, the locked spec, a license inventory, a workload descriptor, an
in-toto/SLSA statement, and a canonical tar. Host paths and input mtimes do
not affect the result. The verifier recomputes the archive manifest, internal
bindings, and every chunk hash.

For OpenFox, first run `tools/check_openfox_reproducible.sh`. It builds the
clean pinned source twice with Go 1.25.13, changes the timezone between builds,
and requires both binaries to equal the locked SHA-256. BusyBox is a pinned
upstream binary. Codex and Claude Code are opaque upstream installations:
webTOS can reproduce an image from the same locked bytes, but does not claim
those binaries are reproducible from source.

## Signing and redistribution

The canonical tar is unsigned by design. A maintainer signs the extracted
`ATTESTATION.intoto.json` as a detached object so key material and signing
metadata cannot perturb reproducible bytes:

```bash
node tools/workload_signature.mjs sign \
  ATTESTATION.intoto.json private-ed25519.pem signature.json
node tools/workload_signature.mjs verify \
  ATTESTATION.intoto.json trusted-public-ed25519.pem signature.json
```

The verifier checks the Ed25519 algorithm, the SHA-256 identity of the trusted
public key, the exact statement digest, and the signature. Private keys must
not be stored in this repository and must be inaccessible to group/other users.
Key generation, custody, rotation, revocation, and the production public-key
trust list are maintainer operations; this repository does not silently create
a production trust root.

`redistribution` is an enforcement decision, not informational prose. In
particular, the locked Codex and Claude Code bytes are evidence inputs only and
are not authorized for publication by webTOS. Compatibility reports publish
their identities and results, never the binaries.
