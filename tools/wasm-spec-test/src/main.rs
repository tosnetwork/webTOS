extern crate alloc;

mod runner;
pub mod wasm;

use runner::{collect_wast_files, FileReport, FileStatus, WastRunner};
use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::mpsc;
use std::thread;

fn max_parallel() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get() / 2)
        .unwrap_or(1)
        .max(1)
}

fn print_usage(binary: &str) {
    println!("Usage: {binary} [--verbose] [PATH ...]");
    println!();
    println!("Examples:");
    println!("  {binary}");
    println!("  {binary} tests/spec/i32.wast");
    println!("  {binary} tests/spec/");
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn print_report(report: &FileReport) {
    let label = display_path(&report.path);
    match report.status() {
        FileStatus::Pass => {
            if report.skipped_assertions == 0 {
                println!(
                    "[PASS] {label} ({}/{}) assertions",
                    report.passed_assertions,
                    report.total_assertions
                );
            } else {
                println!(
                    "[PASS] {label} ({}/{}) assertions, {} skipped",
                    report.passed_assertions,
                    report.total_assertions,
                    report.skipped_assertions
                );
            }
        }
        FileStatus::Skip => {
            println!(
                "[SKIP] {label} ({} skipped assertions)",
                report.skipped_assertions
            );
            for reason in report.skipped_reasons.iter().take(5) {
                println!("  {reason}");
            }
        }
        FileStatus::Fail => {
            println!(
                "[FAIL] {label} ({}/{}) assertions",
                report.passed_assertions,
                report.total_assertions
            );
            for failure in report.failures.iter().take(100) {
                println!("  line {} [{}] {}", failure.line, failure.kind, failure.message);
            }
            if report.failures.len() > 100 {
                println!("  ... {} more failures", report.failures.len() - 100);
            }
        }
    }
}

enum FileOutcome {
    Report(FileReport),
    Error(PathBuf, String),
    Panic(PathBuf),
}

fn main() -> ExitCode {
    let mut verbose = false;
    let mut inputs: Vec<PathBuf> = Vec::new();
    let binary = env::args().next().unwrap_or_else(|| "wasm-spec-test".to_string());

    for arg in env::args().skip(1) {
        match arg.as_str() {
            "-h" | "--help" => {
                print_usage(&binary);
                return ExitCode::SUCCESS;
            }
            "-v" | "--verbose" => verbose = true,
            _ => inputs.push(PathBuf::from(arg)),
        }
    }

    if inputs.is_empty() {
        inputs.push(PathBuf::from("tests/spec"));
    }

    let mut files = Vec::new();
    for input in &inputs {
        match collect_wast_files(input) {
            Ok(mut found) => files.append(&mut found),
            Err(error) => {
                eprintln!("[ERROR] {}: {error}", display_path(input));
                return ExitCode::FAILURE;
            }
        }
    }

    if files.is_empty() {
        eprintln!("[ERROR] no .wast files found");
        return ExitCode::FAILURE;
    }

    files.sort();
    files.dedup();

    // Run files in parallel using a thread pool with bounded concurrency.
    let (tx, rx) = mpsc::channel::<FileOutcome>();
    let file_count = files.len();
    let parallelism = max_parallel().min(file_count);

    // Shared work queue: each thread grabs the next file atomically.
    let work = std::sync::Arc::new(std::sync::Mutex::new(files.into_iter()));

    for _ in 0..parallelism {
        let tx = tx.clone();
        let work = work.clone();
        thread::spawn(move || {
            loop {
                let file = {
                    let mut iter = work.lock().unwrap();
                    iter.next()
                };
                let Some(file) = file else { break };
                let file_clone = file.clone();
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    WastRunner::run_file(&file_clone, verbose)
                }));
                let outcome = match result {
                    Ok(Ok(report)) => FileOutcome::Report(report),
                    Ok(Err(error)) => FileOutcome::Error(file, format!("{error:#}")),
                    Err(_panic) => FileOutcome::Panic(file),
                };
                let _ = tx.send(outcome);
            }
        });
    }
    drop(tx); // Close sender so rx iterator ends when all threads finish.

    let mut pass_files = 0usize;
    let mut fail_files = 0usize;
    let mut skip_files = 0usize;
    let mut total_assertions = 0usize;
    let mut passed_assertions = 0usize;
    let mut skipped_assertions = 0usize;

    // Collect results and buffer for sorted output.
    let mut outcomes: Vec<FileOutcome> = rx.into_iter().collect();

    // Sort by path for deterministic output.
    outcomes.sort_by(|a, b| {
        let path_a = match a {
            FileOutcome::Report(r) => &r.path,
            FileOutcome::Error(p, _) => p,
            FileOutcome::Panic(p) => p,
        };
        let path_b = match b {
            FileOutcome::Report(r) => &r.path,
            FileOutcome::Error(p, _) => p,
            FileOutcome::Panic(p) => p,
        };
        path_a.cmp(path_b)
    });

    for outcome in outcomes {
        match outcome {
            FileOutcome::Report(report) => {
                total_assertions += report.total_assertions;
                passed_assertions += report.passed_assertions;
                skipped_assertions += report.skipped_assertions;
                match report.status() {
                    FileStatus::Pass => pass_files += 1,
                    FileStatus::Fail => fail_files += 1,
                    FileStatus::Skip => skip_files += 1,
                }
                print_report(&report);
            }
            FileOutcome::Error(file, error) => {
                fail_files += 1;
                eprintln!("[FAIL] {} ({error})", display_path(&file));
            }
            FileOutcome::Panic(file) => {
                fail_files += 1;
                eprintln!("[PANIC] {} (internal panic)", display_path(&file));
            }
        }
    }

    println!();
    println!(
        "Summary: {} passed, {} failed, {} skipped files | {}/{} assertions passed, {} skipped",
        pass_files,
        fail_files,
        skip_files,
        passed_assertions,
        total_assertions,
        skipped_assertions
    );

    if fail_files == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
