extern crate alloc;

mod runner;
pub mod wasm;

use runner::{collect_wast_files, FileReport, FileStatus, WastRunner};
use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

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

    let mut pass_files = 0usize;
    let mut fail_files = 0usize;
    let mut skip_files = 0usize;
    let mut total_assertions = 0usize;
    let mut passed_assertions = 0usize;
    let mut skipped_assertions = 0usize;

    for file in files {
        let file_clone = file.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            WastRunner::run_file(&file_clone, verbose)
        }));
        match result {
            Ok(Ok(report)) => {
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
            Ok(Err(error)) => {
                fail_files += 1;
                eprintln!("[FAIL] {} ({error:#})", display_path(&file));
            }
            Err(_panic) => {
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
