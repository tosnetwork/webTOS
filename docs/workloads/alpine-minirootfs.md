# Alpine minirootfs license inventory

The test rootfs is Alpine 3.20.3 for x86-64, pinned by the tarball SHA-256 in
[`tools/fetch_alpine_rootfs.sh`](../../tools/fetch_alpine_rootfs.sh). The
rootfs itself remains outside Git, but its package database is converted into
the committed, package-level [`LICENSES.json`](alpine-minirootfs-LICENSES.json).

Every record identifies the package, version, Alpine binary-package source,
upstream source, declared SPDX expression, redistribution decision, and the
obligations that decision carries. The builder fails closed when a package
has an unknown license expression, and `--check` rejects a stale inventory:

```bash
python3 tools/build_alpine_license_inventory.py \
  test_data/alpine-minirootfs/lib/apk/db/installed \
  docs/workloads/alpine-minirootfs-LICENSES.json --check
```

This inventory records release policy; it is not legal advice and does not
replace the license texts or corresponding-source duties of the packages.
