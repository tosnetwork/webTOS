#!/usr/bin/env bash
# Build the canonical webTOS browser-runtime release artifact.
set -euo pipefail
umask 022

ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
OUT_DIR="$ROOT/dist"
TARGET_DIR="$ROOT/crates/target/release-artifact"
VERSION=""
SOURCE_COMMIT=""
SOURCE_EPOCH=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        --target-dir) TARGET_DIR="$2"; shift 2 ;;
        --version) VERSION="$2"; shift 2 ;;
        --source-commit) SOURCE_COMMIT="$2"; shift 2 ;;
        --source-epoch) SOURCE_EPOCH="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

if [ ! -f "$ROOT/crates/Cargo.lock" ]; then
    echo "crates/Cargo.lock is required for a release build" >&2
    exit 1
fi
toml_section_value() {
    awk -v section="$1" -v key="$2" '
        $0 == "[" section "]" { in_section = 1; next }
        /^\[/ { in_section = 0 }
        in_section && $1 == key && $2 == "=" {
            value = $0
            sub(/^[^=]*=[[:space:]]*"/, "", value)
            sub(/"[[:space:]]*(#.*)?$/, "", value)
            print value
            exit
        }
    ' "$3"
}

CARGO_VERSION="$(toml_section_value package version "$ROOT/crates/webtos-web/Cargo.toml")"
if [ -z "$CARGO_VERSION" ]; then
    echo "cannot read package.version from crates/webtos-web/Cargo.toml" >&2
    exit 1
fi
VERSION="${VERSION:-$CARGO_VERSION}"
if [ "$VERSION" != "$CARGO_VERSION" ]; then
    echo "release version $VERSION does not match webtos-web $CARGO_VERSION" >&2
    exit 1
fi
case "$VERSION" in
    *[!A-Za-z0-9._-]*|'') echo "invalid release version: $VERSION" >&2; exit 1 ;;
esac

TREE_STATE="clean"
if git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    SOURCE_COMMIT="${SOURCE_COMMIT:-$(git -C "$ROOT" rev-parse HEAD)}"
    if ! git -C "$ROOT" cat-file -e "$SOURCE_COMMIT^{commit}" 2>/dev/null; then
        echo "source commit is not present in this repository: $SOURCE_COMMIT" >&2
        exit 1
    fi
    SOURCE_EPOCH="${SOURCE_EPOCH:-$(
        git -C "$ROOT" show -s --format=%ct "$SOURCE_COMMIT"
    )}"
    if [ -n "$(git -C "$ROOT" status --porcelain --untracked-files=all)" ]; then
        TREE_STATE="dirty"
        if [ "${WEBTOS_RELEASE_ALLOW_DIRTY:-0}" != "1" ]; then
            echo "release builds require a clean worktree (WEBTOS_RELEASE_ALLOW_DIRTY=1 is local validation only)" >&2
            exit 1
        fi
    fi
elif [ -z "$SOURCE_COMMIT" ] || [ -z "$SOURCE_EPOCH" ]; then
    echo "--source-commit and --source-epoch are required outside a Git checkout" >&2
    exit 1
fi
if ! printf '%s' "$SOURCE_COMMIT" | grep -Eq '^[0-9a-f]{40}$'; then
    echo "source commit must be a 40-character lowercase Git object id" >&2
    exit 1
fi
if ! printf '%s' "$SOURCE_EPOCH" | grep -Eq '^[0-9]+$'; then
    echo "source epoch must be a nonnegative integer" >&2
    exit 1
fi

TOOLCHAIN="$(toml_section_value toolchain channel "$ROOT/rust-toolchain.toml")"
if ! printf '%s' "$TOOLCHAIN" | grep -Eq '^nightly-[0-9]{4}-[0-9]{2}-[0-9]{2}$'; then
    echo "rust-toolchain.toml must pin a dated nightly, found: $TOOLCHAIN" >&2
    exit 1
fi
BUILDER_HOST="$(cd "$ROOT" && rustc --version --verbose | awk '/^host:/ { print $2 }')"
if [ "$BUILDER_HOST" != "x86_64-unknown-linux-gnu" ] && \
   [ "${WEBTOS_RELEASE_ALLOW_NONCANONICAL_HOST:-0}" != "1" ]; then
    echo "canonical releases require x86_64-unknown-linux-gnu, found: $BUILDER_HOST" >&2
    echo "WEBTOS_RELEASE_ALLOW_NONCANONICAL_HOST=1 is local validation only" >&2
    exit 1
fi

CARGO_HOME_REAL="${CARGO_HOME:-$HOME/.cargo}"
RUSTUP_HOME_REAL="${RUSTUP_HOME:-$HOME/.rustup}"
REMAP_FLAGS="--remap-path-prefix=$ROOT=/usr/src/webtos --remap-path-prefix=$CARGO_HOME_REAL=/usr/local/cargo --remap-path-prefix=$RUSTUP_HOME_REAL=/usr/local/rustup"
METADATA="$(mktemp)"
STAGE="$(mktemp -d)"
trap 'rm -f "$METADATA"; rm -rf "$STAGE"' EXIT
mkdir -p "$OUT_DIR" "$TARGET_DIR"

controlled_cargo() {
    (
        cd "$ROOT/crates"
        env -i \
            HOME="$HOME" \
            PATH="$PATH" \
            CARGO_HOME="$CARGO_HOME_REAL" \
            RUSTUP_HOME="$RUSTUP_HOME_REAL" \
            LC_ALL=C \
            TZ=UTC \
            SOURCE_DATE_EPOCH="$SOURCE_EPOCH" \
            CONST_RANDOM_SEED=webtos-release-v1 \
            CARGO_INCREMENTAL=0 \
            RUSTFLAGS="$REMAP_FLAGS" \
            cargo "$@"
    )
}

controlled_cargo build --frozen --release --target wasm32-unknown-unknown \
    --target-dir "$TARGET_DIR" -p webtos-web
controlled_cargo metadata --frozen --filter-platform wasm32-unknown-unknown \
    --format-version 1 > "$METADATA"

WASM="$TARGET_DIR/wasm32-unknown-unknown/release/webtos_web.wasm"
if [ ! -f "$WASM" ]; then
    echo "release build did not produce $WASM" >&2
    exit 1
fi
if strings "$WASM" | grep -Fq "$ROOT"; then
    echo "release wasm contains the checkout path" >&2
    exit 1
fi
if strings "$WASM" | grep -Fq "$HOME"; then
    echo "release wasm contains the builder home path" >&2
    exit 1
fi
node -e 'const fs=require("fs");if(!WebAssembly.validate(fs.readFileSync(process.argv[1])))process.exit(1)' "$WASM"

cp "$WASM" "$STAGE/webtos_web.wasm"
cp "$ROOT/web/worker.js" "$STAGE/worker.js"
cp "$ROOT/web/jit_host.mjs" "$STAGE/jit_host.mjs"
cp "$ROOT/README.md" "$STAGE/README.md"
cp "$ROOT/docs/RELEASE.md" "$STAGE/RELEASE.md"
cp "$ROOT/SECURITY.md" "$STAGE/SECURITY.md"
cp "$ROOT/LICENSE" "$STAGE/LICENSE"
cp "$ROOT/LICENSES.tsv" "$STAGE/LICENSES.tsv"
cp "$ROOT/crates/Cargo.lock" "$STAGE/Cargo.lock"
cp "$ROOT/rust-toolchain.toml" "$STAGE/rust-toolchain.toml"
mkdir "$STAGE/provenance"
cp "$ROOT/third_party/icicle/PROVENANCE.md" "$STAGE/provenance/icicle-PROVENANCE.md"
cp "$ROOT/third_party/icicle/LICENCE-MIT" "$STAGE/provenance/icicle-LICENCE-MIT"
cp "$ROOT/third_party/icicle/LICENCE-APACHE" "$STAGE/provenance/icicle-LICENCE-APACHE"
cp "$ROOT/third_party/ghidra-x86/PROVENANCE.md" "$STAGE/provenance/ghidra-x86-PROVENANCE.md"
cp "$ROOT/third_party/ghidra-x86/LICENSE" "$STAGE/provenance/ghidra-x86-LICENSE"

python3 "$ROOT/tools/build_sbom.py" \
    --metadata "$METADATA" \
    --lock "$ROOT/crates/Cargo.lock" \
    --wasm "$WASM" \
    --version "$VERSION" \
    --source-commit "$SOURCE_COMMIT" \
    --source-epoch "$SOURCE_EPOCH" \
    --output "$STAGE/SBOM.spdx.json"

WASM_SHA="$(sha256sum "$WASM" | awk '{print $1}')"
LOCK_SHA="$(sha256sum "$ROOT/crates/Cargo.lock" | awk '{print $1}')"
LICENSE_SHA="$(sha256sum "$ROOT/LICENSES.tsv" | awk '{print $1}')"
SBOM_SHA="$(sha256sum "$STAGE/SBOM.spdx.json" | awk '{print $1}')"
python3 - "$STAGE/BUILDINFO.json" "$VERSION" "$SOURCE_COMMIT" "$TREE_STATE" \
    "$SOURCE_EPOCH" "$TOOLCHAIN" "$BUILDER_HOST" "$WASM_SHA" "$LOCK_SHA" \
    "$LICENSE_SHA" "$SBOM_SHA" <<'PY'
import json
import pathlib
import sys

(
    output,
    version,
    commit,
    state,
    epoch,
    toolchain,
    builder_host,
    wasm,
    lock,
    licenses,
    sbom,
) = sys.argv[1:]
document = {
    "builder_host": builder_host,
    "cargo_lock_sha256": lock,
    "licenses_sha256": licenses,
    "profile": "release",
    "release_format": 1,
    "sbom_sha256": sbom,
    "source_commit": commit,
    "source_epoch": int(epoch),
    "source_tree": state,
    "target": "wasm32-unknown-unknown",
    "toolchain": toolchain,
    "version": version,
    "webtos_web_wasm_sha256": wasm,
}
pathlib.Path(output).write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
PY

ARCHIVE="$OUT_DIR/webtos-runtime-$VERSION.tar"
python3 "$ROOT/tools/package_release.py" create "$STAGE" "$ARCHIVE" \
    --root "webtos-runtime-$VERSION"
python3 "$ROOT/tools/package_release.py" verify "$ARCHIVE"
echo "Built $ARCHIVE"
