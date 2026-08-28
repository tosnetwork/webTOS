//! The dependency license manifest, and the gate that keeps it honest.
//!
//! Every crate in a build carries a license, and a supportable release has to
//! know what they are — a dependency with an unclear or disallowed license is
//! a legal defect that surfaces at the worst time. The licenses are recorded
//! in `LICENSES.tsv`, one line per package, and this checks two things: that
//! every license is one the project has decided it can ship, and that the
//! manifest still matches what the tree actually pulls in.
//!
//! The tree is read with `cargo tree -f "{p}|{l}"`, which prints the license
//! per package directly, so there is no JSON to hand-parse — the fragile path
//! that a first attempt at this took and got wrong. A change in dependencies
//! moves the manifest, the way a change in behavior moves the traces;
//! regenerate deliberately:
//!
//!   cargo test -p linux-compat --test licenses -- --ignored rewrite
//!
//! The drift check needs cargo on the path, so it is skipped — loudly — where
//! cargo is absent; the manifest in the tree is the artifact, regenerated and
//! reviewed where cargo is present. The allowed-license check needs only the
//! recorded manifest and runs everywhere.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;

fn manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../LICENSES.tsv")
}

fn workspace_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// The licenses the project has decided it can ship. Permissive only. A
/// license not on this list is not rejected as bad — it is rejected as
/// *undecided*, so adding it is a deliberate edit here, not a silent pass.
const ALLOWED: &[&str] = &[
    "MIT",
    "Apache-2.0",
    "Apache-2.0 WITH LLVM-exception",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "Zlib",
    "0BSD",
    "CC0-1.0",
    "Unlicense",
    "Unicode-3.0",
    "MPL-2.0",
];

/// Whether an SPDX expression is satisfiable from the allowed set.
///
/// `A OR B` passes if either alternative does; `A AND B` requires both. The
/// `WITH` exception clause is dropped — the base license decides. Slashes are
/// the old `MIT/Apache-2.0` spelling of OR.
fn is_allowed(expr: &str) -> bool {
    let expr = expr.replace('/', " OR ").replace(['(', ')'], " ");
    expr.split(" OR ").any(|alternative| {
        alternative.split(" AND ").all(|term| {
            let base = term.split(" WITH ").next().unwrap_or(term).trim();
            ALLOWED.contains(&base)
        })
    })
}

/// `(name, version, license)` for every normal dependency edge, from
/// `cargo tree`. None when cargo is not on the path.
fn tree_licenses() -> Option<BTreeSet<(String, String, String)>> {
    let output = Command::new("cargo")
        .args(["tree", "-e", "normal", "--prefix", "none", "-f", "{p}|{l}"])
        .current_dir(workspace_dir())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut rows = BTreeSet::new();
    for line in text.lines() {
        // Strip the ` (*)` duplicate marker and any stray ANSI.
        let line = strip_ansi(line);
        let line = line
            .split(" (*)")
            .next()
            .unwrap_or(&line)
            .trim()
            .to_string();
        let Some((pv, license)) = line.rsplit_once('|') else {
            continue;
        };
        let pv = pv.trim();
        // `name vX.Y.Z` — the version starts at the last ` v` before a digit.
        let Some((name, version)) = split_name_version(pv) else {
            continue;
        };
        let license = if license.trim().is_empty() {
            "UNKNOWN".to_string()
        } else {
            license.trim().to_string()
        };
        rows.insert((name, version, license));
    }
    Some(rows)
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Skip until the terminating 'm' of a CSI sequence.
            for n in chars.by_ref() {
                if n == 'm' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn split_name_version(pv: &str) -> Option<(String, String)> {
    let idx = pv.rfind(" v")?;
    let name = pv[..idx].trim().to_string();
    // `cargo tree` appends a source in parentheses for local and proc-macro
    // crates — `0.1.0 (/path)`, `1.0 (proc-macro)`. The version is just the
    // number before it, so a local crate reads the same as a registry one.
    let version = pv[idx + 2..]
        .split(" (")
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name, version))
}

fn read_manifest() -> BTreeSet<(String, String, String)> {
    let text = std::fs::read_to_string(manifest_path()).expect("LICENSES.tsv");
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| {
            let mut f = l.split('\t');
            Some((
                f.next()?.to_string(),
                f.next()?.to_string(),
                f.next()?.to_string(),
            ))
        })
        .collect()
}

#[test]
fn every_dependency_license_is_one_we_can_ship() {
    let manifest = read_manifest();
    assert!(!manifest.is_empty(), "the license manifest is empty");
    let mut undecided = Vec::new();
    for (name, version, license) in &manifest {
        if !is_allowed(license) {
            undecided.push(format!("{name} {version}: {license}"));
        }
    }
    assert!(
        undecided.is_empty(),
        "the manifest lists licenses the project has not decided it can ship; \
         add the license to ALLOWED if it is acceptable, or drop the \
         dependency:\n  {}",
        undecided.join("\n  ")
    );
}

#[test]
fn the_manifest_matches_what_the_tree_pulls_in() {
    let Some(actual) = tree_licenses() else {
        println!("[licenses] cargo unavailable; manifest not re-derived from the tree");
        return;
    };
    let recorded = read_manifest();

    let mut drift = Vec::new();
    for row in &actual {
        if !recorded.contains(row) {
            drift.push(format!("tree has {row:?}, manifest does not"));
        }
    }
    for row in &recorded {
        if !actual.contains(row) {
            drift.push(format!("manifest has {row:?}, tree does not"));
        }
    }
    assert!(
        drift.is_empty(),
        "the license manifest has drifted from the dependency tree; regenerate \
         with `--ignored rewrite`:\n  {}",
        drift.join("\n  ")
    );
}

#[test]
#[ignore = "regenerates LICENSES.tsv; run deliberately"]
fn rewrite() {
    let rows = tree_licenses().expect("cargo tree for rewrite");
    let mut out = String::from(
        "# webTOS dependency license manifest (normal dependency edges; run/build, not dev)\n\
         # Regenerate: cargo test -p linux-compat --test licenses -- --ignored rewrite\n\
         # name\tversion\tlicense\n",
    );
    for (name, version, license) in rows {
        out.push_str(&format!("{name}\t{version}\t{license}\n"));
    }
    std::fs::write(manifest_path(), out).expect("write LICENSES.tsv");
    println!("[licenses] wrote the manifest");
}
