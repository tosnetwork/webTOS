//! Milestone-7 workload: the host `git` binary (a glibc dynamic executable)
//! running real repository operations inside the guest. Git is a host-path
//! dependency rather than a vendored fixture, so every test skips cleanly
//! when git, its shared libraries, or the glibc loader are unavailable.

use std::path::{Path, PathBuf};
use std::process::Command;

use linux_compat::Machine;
use x64_engine::{CpuExit, EngineConfig};

fn ldef_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

const GIT: &str = "/usr/bin/git";
const LIBS: &[&str] = &[
    "/lib64/ld-linux-x86-64.so.2",
    "/lib/x86_64-linux-gnu/libc.so.6",
    "/lib/x86_64-linux-gnu/libz.so.1",
    "/lib/x86_64-linux-gnu/libpcre2-8.so.0",
];

/// Builds a machine with the host git binary, its shared libraries, a HOME
/// carrying a git identity, and `repo_dir` mounted at /repo. Returns None
/// (skip) when any host prerequisite is missing.
fn git_machine(repo_dir: &Path, home_dir: &Path) -> Option<Machine> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .try_init();
    if !Path::new(GIT).exists() {
        eprintln!("skipping: host git not found at {GIT}");
        return None;
    }
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    let git_bytes = std::fs::read(GIT).ok()?;
    machine.add_file(GIT.as_bytes(), git_bytes, 0o755).ok()?;
    for lib in LIBS {
        match std::fs::read(lib) {
            Ok(bytes) => machine.add_file(lib.as_bytes(), bytes, 0o755).ok()?,
            Err(_) => {
                eprintln!("skipping: host library {lib} not found");
                return None;
            }
        }
    }
    machine.add_host_tree(repo_dir, "/repo").ok()?;
    machine.add_host_tree(home_dir, "/root").ok()?;
    Some(machine)
}

/// Runs `git -C /repo <args>` in the guest and returns (exit, combined stdout).
fn run_git(machine: &mut Machine, args: &[&str]) -> (CpuExit, String) {
    let mut argv: Vec<Vec<u8>> = vec![b"git".to_vec(), b"-C".to_vec(), b"/repo".to_vec()];
    argv.extend(args.iter().map(|a| a.as_bytes().to_vec()));
    machine.set_args(
        argv,
        vec![
            b"HOME=/root".to_vec(),
            b"PATH=/usr/bin:/bin".to_vec(),
            b"GIT_CONFIG_NOSYSTEM=1".to_vec(),
            b"TERM=dumb".to_vec(),
        ],
    );
    machine.load(GIT.as_bytes()).expect("git ELF load failed");
    machine.vm_mut().icount_limit = machine.icount() + 4_000_000_000;
    let exit = machine.run();
    let output = String::from_utf8_lossy(&machine.take_output()).into_owned();
    (exit, output)
}

/// Prepares a host git repo with one commit and a dirty modification, plus a
/// HOME with a git identity. Returns None when host git cannot build it.
fn seed_repo(root: &Path) -> Option<(PathBuf, PathBuf)> {
    let repo = root.join("repo");
    let home = root.join("home");
    std::fs::create_dir_all(&repo).ok()?;
    std::fs::create_dir_all(&home).ok()?;
    std::fs::write(
        home.join(".gitconfig"),
        "[user]\n\temail = t@example.com\n\tname = Tester\n[commit]\n\tgpgsign = false\n[core]\n\tpager = cat\n",
    )
    .ok()?;
    let git = |args: &[&str]| -> bool {
        Command::new(GIT)
            .args(args)
            .current_dir(&repo)
            .env("HOME", &home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };
    if !git(&["init", "-q"]) {
        eprintln!("skipping: host git init failed");
        return None;
    }
    std::fs::write(repo.join("a.txt"), "line one\nline two\n").ok()?;
    git(&["add", "a.txt"]);
    git(&["commit", "-q", "-m", "first commit"]);
    std::fs::write(
        repo.join("a.txt"),
        "line one\nline two changed\nline three\n",
    )
    .ok()?;
    Some((repo, home))
}

#[test]
fn git_status_reports_a_dirty_file() {
    let dir = std::env::temp_dir().join("webtos-git-status");
    let _ = std::fs::remove_dir_all(&dir);
    let Some((repo, home)) = seed_repo(&dir) else {
        return;
    };
    let Some(mut machine) = git_machine(&repo, &home) else {
        return;
    };
    let (exit, out) = run_git(&mut machine, &["status", "--short"]);
    assert_eq!(exit, CpuExit::Halt { code: Some(0) }, "git status: {out:?}");
    assert!(out.contains("M a.txt"), "git status output: {out:?}");
}

#[test]
fn git_diff_shows_the_change() {
    let dir = std::env::temp_dir().join("webtos-git-diff");
    let _ = std::fs::remove_dir_all(&dir);
    let Some((repo, home)) = seed_repo(&dir) else {
        return;
    };
    let Some(mut machine) = git_machine(&repo, &home) else {
        return;
    };
    let (exit, out) = run_git(&mut machine, &["diff"]);
    assert_eq!(exit, CpuExit::Halt { code: Some(0) }, "git diff: {out:?}");
    assert!(
        out.contains("+line two changed") && out.contains("+line three"),
        "git diff output: {out:?}"
    );
}

#[test]
fn git_commit_writes_an_object_and_updates_the_ref() {
    let dir = std::env::temp_dir().join("webtos-git-commit");
    let _ = std::fs::remove_dir_all(&dir);
    let Some((repo, home)) = seed_repo(&dir) else {
        return;
    };
    let Some(mut machine) = git_machine(&repo, &home) else {
        return;
    };
    // `commit -a` stages the tracked modification and commits in one run
    // (guest filesystem changes do not persist across separate runs).
    let (exit, out) = run_git(
        &mut machine,
        &["commit", "-a", "-m", "second commit from webTOS"],
    );
    assert_eq!(exit, CpuExit::Halt { code: Some(0) }, "git commit: {out:?}");
    assert!(
        out.contains("second commit from webTOS") && out.contains("1 file changed"),
        "git commit output: {out:?}"
    );
}
