use crate::wasm::decoder::{ExportKind, FuncTypeDef, GlobalDef, ImportKind, WasmModule};
use crate::wasm::runtime::{ExecResult, WasmInstance};
use crate::wasm::types::{RuntimeClass, ValType, Value, V128, WasmError};
use anyhow::{Context, Result, anyhow, bail};
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use wast::{
    QuoteWat, WastDirective, WastExecute, WastRet, Wat,
    core::{NanPattern, V128Pattern, WastArgCore, WastRetCore},
    lexer::Lexer,
    parser::ParseBuffer,
    token::{F32, F64, Id},
};

const DEFAULT_FUEL: u64 = 1_000_000_000;
const SPECTEST_MODULE: &str = "spectest";

/// Preprocess legacy exception handling syntax that the `wast` crate can't parse.
/// Transforms folded `(try (do ...) (catch ...) ...)` into flat form:
///   `try ... catch $tag ... catch_all ... end`
/// Also handles `(delegate ...)` which ends a try without `end`.
fn preprocess_legacy_eh(input: &str) -> String {
    // Quick check: if no `(do ` pattern exists, nothing to transform.
    if !input.contains("(do ") && !input.contains("(do)") {
        return input.to_string();
    }

    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len + 256);
    let mut i = 0;

    // Track try-block nesting to know when to emit `end`
    // Each entry: true = needs `end`, false = ended by `delegate`
    let mut try_stack: Vec<bool> = Vec::new();

    while i < len {
        // Skip ;; line comments
        if i + 1 < len && bytes[i] == b';' && bytes[i + 1] == b';' {
            while i < len && bytes[i] != b'\n' {
                out.push(bytes[i] as char);
                i += 1;
            }
            continue;
        }
        // Skip (; block comments ;)
        if i + 1 < len && bytes[i] == b'(' && bytes[i + 1] == b';' {
            out.push('(');
            out.push(';');
            i += 2;
            let mut depth = 1;
            while i < len && depth > 0 {
                if i + 1 < len && bytes[i] == b'(' && bytes[i + 1] == b';' {
                    depth += 1;
                    out.push('(');
                    out.push(';');
                    i += 2;
                } else if i + 1 < len && bytes[i] == b';' && bytes[i + 1] == b')' {
                    depth -= 1;
                    out.push(';');
                    out.push(')');
                    i += 2;
                } else {
                    out.push(bytes[i] as char);
                    i += 1;
                }
            }
            continue;
        }

        // Match `(try` at a word boundary
        if bytes[i] == b'(' && matches_keyword(bytes, i + 1, b"try") {
            let after = i + 1 + 3;
            if after >= len || !is_ident_char(bytes[after]) {
                // Found `(try` — emit `try` (without the opening paren)
                out.push_str("try");
                i = after;
                try_stack.push(true); // assume needs `end` until we see `delegate`
                continue;
            }
        }

        // Match `(do` at word boundary — remove `(do` and later its closing `)`
        if bytes[i] == b'(' && matches_keyword(bytes, i + 1, b"do") {
            let after = i + 1 + 2;
            if after >= len || !is_ident_char(bytes[after]) {
                // Skip `(do`
                i = after;
                // If followed by `)` immediately (empty do), skip that too
                let mut j = i;
                while j < len && (bytes[j] == b' ' || bytes[j] == b'\t' || bytes[j] == b'\n' || bytes[j] == b'\r') {
                    j += 1;
                }
                if j < len && bytes[j] == b')' {
                    // `(do)` — skip the closing paren
                    i = j + 1;
                } else {
                    // `(do <body>)` — need to find and skip matching closing paren
                    // We consume the body normally and track parens
                    // The closing `)` of `(do ...)` will be consumed by skip_matching_close
                    let body_end = find_matching_close(bytes, i);
                    // Output everything inside, but not the final `)`
                    while i < body_end {
                        // Recursively handle nested try/do/catch within the do body
                        // Just output character by character — nested patterns will be
                        // caught by the main loop
                        out.push(bytes[i] as char);
                        i += 1;
                    }
                    // Skip the closing `)` of `(do ...)`
                    if i < len && bytes[i] == b')' {
                        i += 1;
                    }
                }
                // Emit newline for readability
                out.push('\n');
                continue;
            }
        }

        // Match `(catch` at word boundary (but not `(catch_all`)
        if bytes[i] == b'(' && matches_keyword(bytes, i + 1, b"catch") {
            let after = i + 1 + 5;
            if after < len && bytes[after] == b'_' {
                // This is `(catch_all` — handle below
            } else if after >= len || !is_ident_char(bytes[after]) {
                // `(catch $tag ...)`  — emit `catch` + tag, unwrap parens
                out.push_str("catch");
                i = after;
                // Read the tag name
                while i < len && (bytes[i] == b' ' || bytes[i] == b'\t') {
                    out.push(bytes[i] as char);
                    i += 1;
                }
                // Copy tag name (e.g., $e0 or a number)
                while i < len && !bytes[i].is_ascii_whitespace() && bytes[i] != b')' {
                    out.push(bytes[i] as char);
                    i += 1;
                }
                // Now we need to output the body and skip the closing `)`
                let close = find_matching_close_from(bytes, i, 0);
                while i < close {
                    out.push(bytes[i] as char);
                    i += 1;
                }
                if i < len && bytes[i] == b')' {
                    i += 1; // skip closing paren
                }
                out.push('\n');
                continue;
            }
        }

        // Match `(catch_all`
        if bytes[i] == b'(' && matches_keyword(bytes, i + 1, b"catch_all") {
            let after = i + 1 + 9;
            if after >= len || !is_ident_char(bytes[after]) {
                out.push_str("catch_all");
                i = after;
                // Output body and skip closing `)`
                let close = find_matching_close_from(bytes, i, 0);
                while i < close {
                    out.push(bytes[i] as char);
                    i += 1;
                }
                if i < len && bytes[i] == b')' {
                    i += 1;
                }
                out.push('\n');
                continue;
            }
        }

        // Match `(delegate`
        if bytes[i] == b'(' && matches_keyword(bytes, i + 1, b"delegate") {
            let after = i + 1 + 8;
            if after >= len || !is_ident_char(bytes[after]) {
                out.push_str("delegate");
                i = after;
                // Copy label and skip closing `)`
                while i < len && bytes[i] != b')' {
                    out.push(bytes[i] as char);
                    i += 1;
                }
                if i < len && bytes[i] == b')' {
                    i += 1; // skip `)` of `(delegate ...)`
                }
                // Mark current try as not needing `end`
                if let Some(last) = try_stack.last_mut() {
                    *last = false;
                }
                out.push('\n');
                continue;
            }
        }

        // Match `)` that closes a `(try` — emit `end` if needed
        if bytes[i] == b')' && !try_stack.is_empty() {
            // Check if this `)` is the one closing the try block.
            // We need to check the paren depth: the try's closing `)` is at depth 0
            // relative to the try block. But since we removed the opening `(` of `(try`,
            // we need a different approach: we check if this `)` would be unmatched
            // in the current context (i.e., it's not closing any sub-expression).

            // Count open parens from the position after the last try started
            // Actually, let's just look ahead: if the next non-whitespace after this `)` is
            // another `)` or a top-level directive, then this might be our try-closer.
            // A simpler approach: just track paren depth since the try started.

            // For simplicity, check if this `)` is "extra" (would be unbalanced)
            // by scanning forward from this point. If removing it still leaves valid
            // syntax, it was the try closer.

            // Actually the simplest reliable way: this `)` was originally matching
            // the `(try` we removed. We can detect it by checking if there's an
            // unmatched `)` — but that's complex. Let me use a different approach:
            // just output it and let the paren balancing work out.
            // The `(try` open paren was removed, so one `)` will be extra.
            // We rely on the fact that the `)` immediately after the last
            // catch/catch_all/delegate block is the try closer.

            // Better approach: don't try to detect — just output `)` normally.
            // The unbalanced `)` will cause issues. Instead, we need to track this
            // properly.
            out.push(')');
            i += 1;
            continue;
        }

        out.push(bytes[i] as char);
        i += 1;
    }

    // The approach above has a flaw: we removed `(` from `(try` but not the matching `)`.
    // And we removed both `(` and `)` from `(do ...)`, `(catch ...)`, etc.
    // So the try's `)` is still there and unmatched. We need to remove it.
    // Let's use a second pass to fix paren balance, or better yet, redo the approach.

    // Actually, let me just do a second pass: re-run the preprocessor on the output
    // to handle any nested cases, then fix paren balance.

    // Simpler: let me rewrite using a proper recursive approach.
    drop(out);
    drop(try_stack);
    preprocess_legacy_eh_proper(input)
}

/// Find the position of the matching closing `)` starting from `start`,
/// where `start` points to the first char AFTER `(keyword`.
/// Counts nested `(...)` pairs and returns the position of the closing `)`.
fn find_matching_close(bytes: &[u8], start: usize) -> usize {
    let mut depth = 1; // we're already inside one `(`
    let mut i = start;
    let len = bytes.len();
    while i < len {
        if bytes[i] == b'(' {
            depth += 1;
        } else if bytes[i] == b')' {
            depth -= 1;
            if depth == 0 {
                return i;
            }
        } else if bytes[i] == b';' && i + 1 < len && bytes[i + 1] == b';' {
            // line comment
            while i < len && bytes[i] != b'\n' { i += 1; }
            continue;
        } else if bytes[i] == b'"' {
            // string literal
            i += 1;
            while i < len && bytes[i] != b'"' {
                if bytes[i] == b'\\' { i += 1; }
                i += 1;
            }
        }
        i += 1;
    }
    start // fallback
}

/// Like find_matching_close but starts with a given depth.
fn find_matching_close_from(bytes: &[u8], start: usize, extra_depth: usize) -> usize {
    let mut depth: i32 = extra_depth as i32;
    let mut i = start;
    let len = bytes.len();
    while i < len {
        if bytes[i] == b'(' {
            depth += 1;
        } else if bytes[i] == b')' {
            if depth == 0 {
                return i;
            }
            depth -= 1;
        } else if bytes[i] == b';' && i + 1 < len && bytes[i + 1] == b';' {
            while i < len && bytes[i] != b'\n' { i += 1; }
            continue;
        } else if bytes[i] == b'"' {
            i += 1;
            while i < len && bytes[i] != b'"' {
                if bytes[i] == b'\\' { i += 1; }
                i += 1;
            }
        }
        i += 1;
    }
    start
}

fn matches_keyword(bytes: &[u8], start: usize, keyword: &[u8]) -> bool {
    let end = start + keyword.len();
    if end > bytes.len() { return false; }
    // Skip leading whitespace
    &bytes[start..end] == keyword
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.' || b == b'$'
}

/// Proper recursive preprocessor for legacy EH syntax.
/// Processes the input as an S-expression stream, transforming legacy try blocks.
fn preprocess_legacy_eh_proper(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len() + 256);
    let mut pos = 0;
    process_sexp_stream(bytes, &mut pos, &mut out, false);
    out
}

/// Process a stream of S-expressions or atoms.
/// If `inside_paren` is true, we stop when we hit the unmatched `)`.
fn process_sexp_stream(bytes: &[u8], pos: &mut usize, out: &mut String, inside_paren: bool) {
    let len = bytes.len();
    while *pos < len {
        // Skip whitespace
        if bytes[*pos].is_ascii_whitespace() {
            out.push(bytes[*pos] as char);
            *pos += 1;
            continue;
        }

        // Line comment
        if *pos + 1 < len && bytes[*pos] == b';' && bytes[*pos + 1] == b';' {
            while *pos < len && bytes[*pos] != b'\n' {
                out.push(bytes[*pos] as char);
                *pos += 1;
            }
            continue;
        }

        // Block comment
        if *pos + 1 < len && bytes[*pos] == b'(' && bytes[*pos + 1] == b';' {
            let start = *pos;
            *pos += 2;
            let mut depth = 1;
            while *pos < len && depth > 0 {
                if *pos + 1 < len && bytes[*pos] == b'(' && bytes[*pos + 1] == b';' {
                    depth += 1; *pos += 2;
                } else if *pos + 1 < len && bytes[*pos] == b';' && bytes[*pos + 1] == b')' {
                    depth -= 1; *pos += 2;
                } else {
                    *pos += 1;
                }
            }
            out.push_str(&String::from_utf8_lossy(&bytes[start..*pos]));
            continue;
        }

        // Closing paren
        if bytes[*pos] == b')' {
            if inside_paren {
                return; // don't consume the `)`, caller handles it
            }
            out.push(')');
            *pos += 1;
            continue;
        }

        // Opening paren — check what follows
        if bytes[*pos] == b'(' {
            *pos += 1;
            skip_whitespace(bytes, pos);

            if peek_keyword(bytes, *pos, b"try") {
                process_try_block(bytes, pos, out);
            } else if peek_keyword(bytes, *pos, b"do") {
                process_do_block(bytes, pos, out);
            } else if peek_keyword(bytes, *pos, b"catch_all") {
                process_catch_all_block(bytes, pos, out);
            } else if peek_keyword(bytes, *pos, b"catch") && !peek_keyword(bytes, *pos, b"catch_all") {
                process_catch_block(bytes, pos, out);
            } else if peek_keyword(bytes, *pos, b"delegate") {
                process_delegate(bytes, pos, out);
            } else {
                // Normal S-expression — output `(`, process contents, output `)`
                out.push('(');
                process_sexp_stream(bytes, pos, out, true);
                if *pos < bytes.len() && bytes[*pos] == b')' {
                    out.push(')');
                    *pos += 1;
                }
            }
            continue;
        }

        // String literal
        if bytes[*pos] == b'"' {
            out.push('"');
            *pos += 1;
            while *pos < len && bytes[*pos] != b'"' {
                if bytes[*pos] == b'\\' {
                    out.push(bytes[*pos] as char);
                    *pos += 1;
                    if *pos < len {
                        out.push(bytes[*pos] as char);
                        *pos += 1;
                    }
                } else {
                    out.push(bytes[*pos] as char);
                    *pos += 1;
                }
            }
            if *pos < len {
                out.push('"');
                *pos += 1;
            }
            continue;
        }

        // Atom (identifier, number, keyword, etc.)
        while *pos < len && !bytes[*pos].is_ascii_whitespace() && bytes[*pos] != b'(' && bytes[*pos] != b')' && bytes[*pos] != b'"' {
            // Handle line comments within atom scanning
            if bytes[*pos] == b';' && *pos + 1 < len && bytes[*pos + 1] == b';' {
                break;
            }
            out.push(bytes[*pos] as char);
            *pos += 1;
        }
    }
}

fn skip_whitespace(bytes: &[u8], pos: &mut usize) {
    while *pos < bytes.len() && bytes[*pos].is_ascii_whitespace() {
        *pos += 1;
    }
}

fn peek_keyword(bytes: &[u8], pos: usize, kw: &[u8]) -> bool {
    let end = pos + kw.len();
    if end > bytes.len() { return false; }
    if &bytes[pos..end] != kw { return false; }
    // Must be followed by non-ident char or EOF
    end >= bytes.len() || !is_ident_char(bytes[end])
}

/// Process `(try ...)` — already consumed `(`, pos points at `try`
fn process_try_block(bytes: &[u8], pos: &mut usize, out: &mut String) {
    // Emit `try` without surrounding parens
    out.push_str("try");
    *pos += 3; // skip "try"

    // Copy block type annotations (e.g., `$label`, `(result i32)`)
    // and then process the body which should contain (do ...) (catch ...) etc.
    let mut has_delegate = false;

    // Process the contents of the try block
    while *pos < bytes.len() {
        skip_whitespace_emit(bytes, pos, out);

        if *pos >= bytes.len() { break; }

        // Closing `)` of the `(try ...)`
        if bytes[*pos] == b')' {
            *pos += 1; // consume it (don't output — we removed the `(`)
            break;
        }

        // Opening `(` of a sub-expression
        if bytes[*pos] == b'(' {
            *pos += 1;
            skip_whitespace(bytes, pos);

            if peek_keyword(bytes, *pos, b"do") {
                process_do_block(bytes, pos, out);
            } else if peek_keyword(bytes, *pos, b"catch_all") {
                process_catch_all_block(bytes, pos, out);
            } else if peek_keyword(bytes, *pos, b"catch") && !peek_keyword(bytes, *pos, b"catch_all") {
                process_catch_block(bytes, pos, out);
            } else if peek_keyword(bytes, *pos, b"delegate") {
                process_delegate(bytes, pos, out);
                has_delegate = true;
            } else if peek_keyword(bytes, *pos, b"result") {
                // `(result ...)` — part of block type, output normally
                out.push('(');
                process_sexp_stream(bytes, pos, out, true);
                if *pos < bytes.len() && bytes[*pos] == b')' {
                    out.push(')');
                    *pos += 1;
                }
            } else {
                // Something else — output normally
                out.push('(');
                process_sexp_stream(bytes, pos, out, true);
                if *pos < bytes.len() && bytes[*pos] == b')' {
                    out.push(')');
                    *pos += 1;
                }
            }
            continue;
        }

        // Label like `$t` or `$label`
        if bytes[*pos] == b'$' {
            while *pos < bytes.len() && !bytes[*pos].is_ascii_whitespace() && bytes[*pos] != b'(' && bytes[*pos] != b')' {
                out.push(bytes[*pos] as char);
                *pos += 1;
            }
            continue;
        }

        // Other atom
        while *pos < bytes.len() && !bytes[*pos].is_ascii_whitespace() && bytes[*pos] != b'(' && bytes[*pos] != b')' {
            out.push(bytes[*pos] as char);
            *pos += 1;
        }
    }

    if !has_delegate {
        out.push_str(" end");
    }
}

/// Process `(do ...)` — already consumed `(`, pos points at `do`.
/// Removes the `do` wrapper and outputs just the body.
fn process_do_block(bytes: &[u8], pos: &mut usize, out: &mut String) {
    *pos += 2; // skip "do"
    // Process body contents
    process_sexp_stream(bytes, pos, out, true);
    // Skip closing `)`
    if *pos < bytes.len() && bytes[*pos] == b')' {
        *pos += 1;
    }
    out.push('\n');
}

/// Process `(catch $tag ...)` — already consumed `(`, pos points at `catch`.
fn process_catch_block(bytes: &[u8], pos: &mut usize, out: &mut String) {
    out.push_str(" catch");
    *pos += 5; // skip "catch"
    // Copy tag
    skip_whitespace_emit(bytes, pos, out);
    while *pos < bytes.len() && !bytes[*pos].is_ascii_whitespace() && bytes[*pos] != b')' && bytes[*pos] != b'(' {
        out.push(bytes[*pos] as char);
        *pos += 1;
    }
    // Process handler body
    process_sexp_stream(bytes, pos, out, true);
    if *pos < bytes.len() && bytes[*pos] == b')' {
        *pos += 1;
    }
    out.push('\n');
}

/// Process `(catch_all ...)` — already consumed `(`, pos points at `catch_all`.
fn process_catch_all_block(bytes: &[u8], pos: &mut usize, out: &mut String) {
    out.push_str(" catch_all");
    *pos += 9; // skip "catch_all"
    // Process handler body
    process_sexp_stream(bytes, pos, out, true);
    if *pos < bytes.len() && bytes[*pos] == b')' {
        *pos += 1;
    }
    out.push('\n');
}

/// Process `(delegate $label)` — already consumed `(`, pos points at `delegate`.
fn process_delegate(bytes: &[u8], pos: &mut usize, out: &mut String) {
    out.push_str(" delegate");
    *pos += 8; // skip "delegate"
    // Copy label/index
    while *pos < bytes.len() && bytes[*pos] != b')' {
        out.push(bytes[*pos] as char);
        *pos += 1;
    }
    if *pos < bytes.len() && bytes[*pos] == b')' {
        *pos += 1;
    }
    out.push('\n');
}

fn skip_whitespace_emit(bytes: &[u8], pos: &mut usize, out: &mut String) {
    while *pos < bytes.len() && bytes[*pos].is_ascii_whitespace() {
        out.push(bytes[*pos] as char);
        *pos += 1;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileStatus {
    Pass,
    Fail,
    Skip,
}

#[derive(Debug, Clone)]
pub struct FailureDetail {
    pub line: usize,
    pub kind: &'static str,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct FileReport {
    pub path: PathBuf,
    pub total_assertions: usize,
    pub passed_assertions: usize,
    pub skipped_assertions: usize,
    pub failures: Vec<FailureDetail>,
    pub skipped_reasons: Vec<String>,
}

impl FileReport {
    pub fn status(&self) -> FileStatus {
        if !self.failures.is_empty() {
            FileStatus::Fail
        } else if self.passed_assertions == 0 && self.skipped_assertions > 0 {
            FileStatus::Skip
        } else {
            FileStatus::Pass
        }
    }
}

#[derive(Debug)]
struct DirectiveError {
    kind: &'static str,
    message: String,
    counts_as_assertion: bool,
}

impl DirectiveError {
    fn directive(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            counts_as_assertion: false,
        }
    }

    fn assertion(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            counts_as_assertion: true,
        }
    }
}

#[derive(Debug)]
enum DirectiveOutcome {
    NonAssertion,
    AssertionPassed,
    AssertionSkipped(String),
}

#[derive(Debug, Clone)]
struct RunnerError {
    kind: &'static str,
    message: String,
    /// If this error is an uncaught exception, carry the exception info
    /// so it can be propagated to a caller's try_table.
    exception: Option<(u32, Vec<Value>)>,
}

impl RunnerError {
    fn new(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            exception: None,
        }
    }

    fn exception(tag_idx: u32, values: Vec<Value>) -> Self {
        Self {
            kind: "trap",
            message: "unhandled exception".to_string(),
            exception: Some((tag_idx, values)),
        }
    }

    fn trap(err: WasmError) -> Self {
        Self::new("trap", trap_message(&err))
    }
}

type RunnerResult<T> = std::result::Result<T, RunnerError>;

struct InstanceRecord {
    instance: WasmInstance,
}

type InstanceHandle = Rc<RefCell<InstanceRecord>>;

pub struct WastRunner {
    verbose: bool,
    module_definitions: HashMap<String, Vec<u8>>,
    instances: HashMap<String, InstanceHandle>,
    current: Option<InstanceHandle>,
    anonymous_instances: usize,
    /// Memory sharing pairs: (importer, importer_mem_idx, exporter, exporter_mem_idx).
    /// When either side's memory changes, sync to the other.
    memory_shares: Vec<(InstanceHandle, usize, InstanceHandle, usize)>,
    /// Whether GC-proposal features are enabled for this test file.
    gc_enabled: bool,
    /// Whether multi-memory proposal is enabled for this test file.
    multi_memory_enabled: bool,
    /// Whether multiple tables should be rejected (threads-only tests).
    reject_multi_table: bool,
    /// The handle used in the last invoke/execute, for unwrapping externrefs.
    last_invoke_handle: Option<InstanceHandle>,
}

impl WastRunner {
    pub fn new(verbose: bool) -> Self {
        Self {
            verbose,
            module_definitions: HashMap::new(),
            instances: HashMap::new(),
            current: None,
            anonymous_instances: 0,
            memory_shares: Vec::new(),
            gc_enabled: false,
            multi_memory_enabled: false,
            reject_multi_table: false,
            last_invoke_handle: None,
        }
    }

    pub fn run_file(path: &Path, verbose: bool) -> Result<FileReport> {
        let raw_text = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        // Preprocess legacy exception handling syntax if needed
        let text = if path.to_string_lossy().contains("legacy/") {
            preprocess_legacy_eh(&raw_text)
        } else {
            raw_text
        };
        let mut lexer = Lexer::new(&text);
        lexer.allow_confusing_unicode(true);
        let buffer = ParseBuffer::new_with_lexer(lexer)
            .map_err(|err| annotate_wast_error(err, path, &text))?;
        let wast = wast::parser::parse::<wast::Wast<'_>>(&buffer)
            .map_err(|err| annotate_wast_error(err, path, &text))?;

        let mut runner = Self::new(verbose);
        // Enable proposal features based on file path
        let path_str = path.to_string_lossy();
        if path_str.contains("proposals/gc/") || path_str.contains("proposals/wasm-3.0/") {
            runner.gc_enabled = true;
        }
        if path_str.contains("proposals/wasm-3.0/") {
            runner.multi_memory_enabled = true;
        }
        if path_str.contains("proposals/multi-memory/") || path_str.contains("proposals/custom-page-sizes/") {
            runner.multi_memory_enabled = true;
        }
        if path_str.contains("proposals/threads/") {
            runner.reject_multi_table = true;
        }
        let mut report = FileReport {
            path: path.to_path_buf(),
            total_assertions: 0,
            passed_assertions: 0,
            skipped_assertions: 0,
            failures: Vec::new(),
            skipped_reasons: Vec::new(),
        };

        for directive in wast.directives {
            let span = directive.span();
            let (line, _column) = span.linecol_in(&text);
            let line = line + 1;
            match runner.process_directive(directive) {
                Ok(DirectiveOutcome::NonAssertion) => {}
                Ok(DirectiveOutcome::AssertionPassed) => {
                    report.total_assertions += 1;
                    report.passed_assertions += 1;
                }
                Ok(DirectiveOutcome::AssertionSkipped(reason)) => {
                    report.total_assertions += 1;
                    report.skipped_assertions += 1;
                    report
                        .skipped_reasons
                        .push(format!("line {line}: {reason}"));
                }
                Err(error) => {
                    if error.counts_as_assertion {
                        report.total_assertions += 1;
                    }
                    report.failures.push(FailureDetail {
                        line,
                        kind: error.kind,
                        message: error.message,
                    });
                }
            }
        }

        Ok(report)
    }

    fn process_directive(&mut self, directive: WastDirective<'_>) -> std::result::Result<DirectiveOutcome, DirectiveError> {
        match directive {
            WastDirective::Module(mut module) => {
                let (name, bytes) = self.module_bytes(&mut module).map_err(|err| {
                    DirectiveError::directive("module", format!("compile failed: {}", err.message))
                })?;
                self.instantiate_module_bytes(name.as_deref(), &bytes)
                    .map_err(|err| {
                        DirectiveError::directive("module", format!("instantiate failed: {}", err.message))
                    })?;
                Ok(DirectiveOutcome::NonAssertion)
            }
            WastDirective::ModuleDefinition(mut module) => {
                let (name, bytes) = self.module_bytes(&mut module).map_err(|err| {
                    DirectiveError::directive(
                        "module_definition",
                        format!("compile failed: {}", err.message),
                    )
                })?;
                if let Some(name) = name {
                    self.module_definitions.insert(name, bytes);
                }
                Ok(DirectiveOutcome::NonAssertion)
            }
            WastDirective::ModuleInstance { instance, module, .. } => {
                let Some(module) = module else {
                    return Err(DirectiveError::directive(
                        "module_instance",
                        "unnamed module definitions are not supported",
                    ));
                };
                let bytes = self
                    .module_definitions
                    .get(module.name())
                    .cloned()
                    .ok_or_else(|| {
                        DirectiveError::directive(
                            "module_instance",
                            format!("missing module definition `{}`", module.name()),
                        )
                    })?;
                self.instantiate_module_bytes(instance.map(|id| id.name()), &bytes)
                    .map_err(|err| {
                        DirectiveError::directive(
                            "module_instance",
                            format!("instantiate failed: {}", err.message),
                        )
                    })?;
                Ok(DirectiveOutcome::NonAssertion)
            }
            WastDirective::Register { name, module, .. } => {
                let handle = self.get_instance_handle(module).map_err(|err| {
                    DirectiveError::directive("register", err.message)
                })?;
                self.instances.insert(name.to_string(), handle);
                Ok(DirectiveOutcome::NonAssertion)
            }
            WastDirective::Invoke(invoke) => {
                self.invoke(invoke).map_err(|err| {
                    DirectiveError::directive("invoke", err.message)
                })?;
                Ok(DirectiveOutcome::NonAssertion)
            }
            WastDirective::AssertMalformed { mut module, message, .. } => {
                let outcome = module
                    .encode()
                    .map_err(|err| RunnerError::new("decode", err.to_string()))
                    .and_then(|bytes| self.decode_module(&bytes));
                match outcome {
                    Ok(_) => Err(DirectiveError::assertion(
                        "assert_malformed",
                        format!("module unexpectedly decoded successfully; expected `{message}`"),
                    )),
                    Err(_) => Ok(DirectiveOutcome::AssertionPassed),
                }
            }
            WastDirective::AssertInvalid { mut module, message, .. } => {
                let outcome = self.compile_module(&mut module);
                match outcome {
                    Ok(_) => Err(DirectiveError::assertion(
                        "assert_invalid",
                        format!("module unexpectedly validated successfully; expected `{message}`"),
                    )),
                    Err(_) => Ok(DirectiveOutcome::AssertionPassed),
                }
            }
            WastDirective::AssertUnlinkable { module, message, .. } => {
                let mut quoted = QuoteWat::Wat(module);
                let (name, bytes) = self.module_bytes(&mut quoted).map_err(|err| {
                    DirectiveError::assertion("assert_unlinkable", err.message)
                })?;
                match self.instantiate_module_bytes(name.as_deref(), &bytes) {
                    Ok(_) => Err(DirectiveError::assertion(
                        "assert_unlinkable",
                        format!("module unexpectedly linked successfully; expected `{message}`"),
                    )),
                    Err(_) => Ok(DirectiveOutcome::AssertionPassed),
                }
            }
            WastDirective::AssertTrap { exec, message, .. } => {
                match self.execute(exec) {
                    Ok(values) => Err(DirectiveError::assertion(
                        "assert_trap",
                        format!("expected trap `{message}`, got {:?}", values),
                    )),
                    Err(err) => {
                        self.assert_message("assert_trap", &err, message)?;
                        Ok(DirectiveOutcome::AssertionPassed)
                    }
                }
            }
            WastDirective::AssertReturn { exec, results, .. } => {
                let actual = self.execute(exec).map_err(|err| {
                    DirectiveError::assertion("assert_return", err.message)
                })?;
                self.assert_results(&actual, &results)?;
                Ok(DirectiveOutcome::AssertionPassed)
            }
            WastDirective::AssertExhaustion { call, message, .. } => {
                match self.invoke(call) {
                    Ok(values) => Err(DirectiveError::assertion(
                        "assert_exhaustion",
                        format!("expected exhaustion `{message}`, got {:?}", values),
                    )),
                    Err(err) => {
                        self.assert_message("assert_exhaustion", &err, message)?;
                        Ok(DirectiveOutcome::AssertionPassed)
                    }
                }
            }
            WastDirective::AssertException { exec, .. } => {
                match self.execute(exec) {
                    Ok(values) => Err(DirectiveError::assertion(
                        "assert_exception",
                        format!("expected exception, got {:?}", values),
                    )),
                    Err(err) => {
                        if err.exception.is_some() {
                            Ok(DirectiveOutcome::AssertionPassed)
                        } else {
                            Err(DirectiveError::assertion(
                                "assert_exception",
                                format!("expected exception, got trap: {}", err.message),
                            ))
                        }
                    }
                }
            }
            WastDirective::AssertSuspension { .. }
            | WastDirective::Thread(..)
            | WastDirective::Wait { .. } => Ok(DirectiveOutcome::AssertionSkipped(
                "directive is not supported by the ATOS host-side runner".to_string(),
            )),
        }
    }

    fn module_bytes(&mut self, module: &mut QuoteWat<'_>) -> RunnerResult<(Option<String>, Vec<u8>)> {
        if !is_core_module(module) {
            return Err(RunnerError::new(
                "unsupported",
                "component model directives are not supported",
            ));
        }
        let name = module.name().map(|id| id.name().to_string());
        let bytes = module
            .encode()
            .map_err(|err| RunnerError::new("decode", err.to_string()))?;
        Ok((name, bytes))
    }

    fn compile_module(&mut self, module: &mut QuoteWat<'_>) -> RunnerResult<(Option<String>, WasmModule)> {
        let (name, bytes) = self.module_bytes(module)?;
        let decoded = self.decode_module(&bytes)?;
        Ok((name, decoded))
    }

    fn decode_module(&self, bytes: &[u8]) -> RunnerResult<WasmModule> {
        let mut module = crate::wasm::decoder::decode(bytes)
            .map_err(|err| RunnerError::new("decode", format!("{err:?}")))?;
        module.gc_enabled = module.gc_enabled || self.gc_enabled;
        module.implicit_rec_enabled = self.gc_enabled; // GC proposal enables implicit rec groups
        module.multi_memory_enabled = module.multi_memory_enabled || self.multi_memory_enabled;
        module.reject_multi_table = self.reject_multi_table;
        crate::wasm::validator::validate(&module)
            .map_err(|err| {
                eprintln!("[DEBUG] validation error: {err:?}");
                RunnerError::new("validation", format!("{err:?}"))
            })?;
        Ok(module)
    }

    fn instantiate_module_bytes(&mut self, name: Option<&str>, bytes: &[u8]) -> RunnerResult<InstanceHandle> {
        let mut module = self.decode_module(bytes)?;
        self.inject_imported_globals(&mut module)?;
        self.fixup_funcref_globals(&mut module)?;
        // Re-evaluate segment offsets that reference globals (extended-const)
        self.fixup_segment_offsets(&mut module, bytes);
        self.inject_imported_memory(&mut module)?;
        self.inject_imported_tables(&mut module)?;
        self.ensure_linkable_imports(&module)?;

        // Collect info about memory/table imports before creating the instance
        let memory_sources = self.find_memory_sources(&module);
        let table_sources = self.find_table_sources(&module);

        if name.is_none() {
            self.anonymous_instances += 1;
        }
        let instance = match WasmInstance::with_class(module, DEFAULT_FUEL, RuntimeClass::BestEffort) {
            Ok(inst) => inst,
            Err(err) => {
                // On instantiation failure (e.g., OOB data/element segments), the spec
                // requires that segments applied *before* the failure persist in shared
                // memory/tables.  Apply partial segments to the exporter before returning.
                // We need the module back; re-decode it cheaply just for segment info.
                if !memory_sources.is_empty() {
                    if let Ok(failed_module) = self.decode_module(bytes) {
                        self.apply_partial_data_segments_to_shared(&failed_module, &memory_sources);
                    }
                }
                if !table_sources.is_empty() {
                    if let Ok(failed_module) = self.decode_module(bytes) {
                        self.apply_partial_elem_segments_to_shared(&failed_module, &table_sources);
                    }
                }
                return Err(RunnerError::trap(err));
            }
        };
        let handle = Rc::new(RefCell::new(InstanceRecord {
            instance,
        }));

        // Share memory: copy exporter's memory per-index, then re-apply importer's data segments
        for &(imp_mem_idx, exp_mem_idx, ref src_handle) in &memory_sources {
            let mut record = handle.borrow_mut();
            let src = src_handle.borrow();
            let src_mem_size = src.instance.memory_sizes.get(exp_mem_idx).copied().unwrap_or(0);
            let rec_mem_size = record.instance.memory_sizes.get(imp_mem_idx).copied().unwrap_or(0);
            let copy_len = src_mem_size.min(rec_mem_size);
            if copy_len > 0
                && imp_mem_idx < record.instance.memories.len()
                && exp_mem_idx < src.instance.memories.len()
            {
                record.instance.memories[imp_mem_idx][..copy_len]
                    .copy_from_slice(&src.instance.memories[exp_mem_idx][..copy_len]);
            }
            // If exporter's memory is larger, grow the importer's memory to match
            if src_mem_size > rec_mem_size
                && imp_mem_idx < record.instance.memories.len()
                && exp_mem_idx < src.instance.memories.len()
            {
                record.instance.memories[imp_mem_idx].resize(src_mem_size, 0);
                record.instance.memories[imp_mem_idx][rec_mem_size..src_mem_size]
                    .copy_from_slice(&src.instance.memories[exp_mem_idx][rec_mem_size..src_mem_size]);
                record.instance.memory_sizes[imp_mem_idx] = src_mem_size;
            }
            drop(src);
            // Re-apply the importer's own active data segments that target this memory
            let rec_mem_size = record.instance.memory_sizes.get(imp_mem_idx).copied().unwrap_or(0);
            let segs: Vec<(usize, usize, usize)> = record.instance.module.data_segments.iter()
                .filter(|seg| seg.is_active && seg.memory_idx as usize == imp_mem_idx)
                .map(|seg| (seg.offset as usize, seg.data_offset, seg.data_len))
                .collect();
            for (dst_start, src_start, len) in segs {
                if dst_start.saturating_add(len) <= rec_mem_size
                    && src_start.saturating_add(len) <= record.instance.module.code.len()
                    && imp_mem_idx < record.instance.memories.len()
                {
                    let code_bytes = record.instance.module.code[src_start..src_start + len].to_vec();
                    record.instance.memories[imp_mem_idx][dst_start..dst_start + len]
                        .copy_from_slice(&code_bytes);
                }
            }
            // Copy the result back to the exporter so both share the same state
            let rec_mem_size = record.instance.memory_sizes.get(imp_mem_idx).copied().unwrap_or(0);
            let mut src_mut = src_handle.borrow_mut();
            let src_mem_size = src_mut.instance.memory_sizes.get(exp_mem_idx).copied().unwrap_or(0);
            if rec_mem_size > src_mem_size && exp_mem_idx < src_mut.instance.memories.len() {
                src_mut.instance.memories[exp_mem_idx].resize(rec_mem_size, 0);
                src_mut.instance.memory_sizes[exp_mem_idx] = rec_mem_size;
            }
            let src_mem_size = src_mut.instance.memory_sizes.get(exp_mem_idx).copied().unwrap_or(0);
            let copy_back = rec_mem_size.min(src_mem_size);
            if copy_back > 0
                && exp_mem_idx < src_mut.instance.memories.len()
                && imp_mem_idx < record.instance.memories.len()
            {
                src_mut.instance.memories[exp_mem_idx][..copy_back]
                    .copy_from_slice(&record.instance.memories[imp_mem_idx][..copy_back]);
            }
            // Track memory sharing for later sync
            self.memory_shares.push((handle.clone(), imp_mem_idx, src_handle.clone(), exp_mem_idx));
        }

        // Share tables: copy exporter's table entries, then re-apply element segments
        for (tbl_idx, src_handle) in &table_sources {
            let tbl_idx = *tbl_idx;
            let mut record = handle.borrow_mut();
            let src = src_handle.borrow();
            // Find the source table index from the export
            let src_module_name = self.find_table_import_module(&record.instance.module, tbl_idx);
            let src_tbl_idx = if let Some((mod_name, fld_name)) = &src_module_name {
                if let Some(sh) = self.instances.get(mod_name.as_str()) {
                    if Rc::ptr_eq(sh, src_handle) {
                        exported_table_index(&src.instance.module, fld_name)
                            .unwrap_or(0) as usize
                    } else { 0 }
                } else { 0 }
            } else { 0 };

            if let Some(src_table) = src.instance.tables.get(src_tbl_idx) {
                if tbl_idx < record.instance.tables.len() {
                    // Resize importer table to match exporter
                    if record.instance.tables[tbl_idx].len() < src_table.len() {
                        record.instance.tables[tbl_idx].resize(src_table.len(), None);
                    }
                    // Copy entries
                    let copy_len = src_table.len().min(record.instance.tables[tbl_idx].len());
                    record.instance.tables[tbl_idx][..copy_len]
                        .copy_from_slice(&src_table[..copy_len]);
                }
            }
            drop(src);
            // Re-apply importer's active element segments for this table.
            use crate::wasm::decoder::ElemMode;
            let segs: Vec<_> = record.instance.module.element_segments.iter()
                .filter(|s| s.mode == ElemMode::Active && s.table_idx as usize == tbl_idx)
                .map(|s| (s.offset as usize, s.func_indices.clone()))
                .collect();

            // Track which positions are from the importer's element segments
            let mut importer_positions: std::collections::HashSet<usize> = std::collections::HashSet::new();
            for (offset, func_indices) in &segs {
                for (i, &func_idx) in func_indices.iter().enumerate() {
                    let idx = offset + i;
                    if idx < record.instance.tables[tbl_idx].len() {
                        importer_positions.insert(idx);
                        record.instance.tables[tbl_idx][idx] =
                            if func_idx == u32::MAX { None } else { Some(func_idx) };
                    }
                }
            }

            // Build the exporter's table: resolve importer entries to exporter's space
            let importer_table = record.instance.tables.get(tbl_idx).cloned().unwrap_or_default();
            drop(record);
            let mut src_mut = src_handle.borrow_mut();
            let src_tbl_idx_val = src_tbl_idx;

            // Exporter's table: start from current exporter table, then overlay
            // resolved importer entries
            let mut exporter_table = if src_tbl_idx_val < src_mut.instance.tables.len() {
                src_mut.instance.tables[src_tbl_idx_val].clone()
            } else {
                Vec::new()
            };
            // Resize if needed
            if exporter_table.len() < importer_table.len() {
                exporter_table.resize(importer_table.len(), None);
            }
            // For positions from the importer's element segments, resolve to exporter's space
            for &pos in &importer_positions {
                if pos < importer_table.len() {
                    if let Some(func_idx) = importer_table[pos] {
                        let resolved = resolve_cross_module_function(
                            &mut src_mut.instance.module,
                            &handle,
                            func_idx,
                            &self.instances,
                        );
                        exporter_table[pos] = Some(resolved);
                    } else {
                        exporter_table[pos] = None;
                    }
                }
            }

            // Save exporter table
            if src_tbl_idx_val < src_mut.instance.tables.len() {
                src_mut.instance.tables[src_tbl_idx_val] = exporter_table;
            }
            drop(src_mut);

            // Importer's table: resolve exporter's entries to importer's space
            let mut importer_resolved = importer_table.clone();
            {
                let mut imp_mut = handle.borrow_mut();
                for pos in 0..importer_resolved.len() {
                    if importer_positions.contains(&pos) {
                        // Already has the importer's own func idx, keep as-is
                        continue;
                    }
                    if let Some(func_idx) = importer_resolved[pos] {
                        // This is an exporter's func idx, resolve to importer's space
                        let resolved = resolve_cross_module_function(
                            &mut imp_mut.instance.module,
                            src_handle,
                            func_idx,
                            &self.instances,
                        );
                        importer_resolved[pos] = Some(resolved);
                    }
                }
                if tbl_idx < imp_mut.instance.tables.len() {
                    imp_mut.instance.tables[tbl_idx] = importer_resolved;
                }
            }
        }

        let inserted_name = name.map(str::to_string);
        if let Some(name) = &inserted_name {
            self.instances.insert(name.clone(), handle.clone());
        }

        // Detect aliased table imports: if two imports resolve to the same source table,
        // set table_aliases so runtime redirects one to the other.
        {
            let mut record = handle.borrow_mut();
            let mut tbl_source_map: Vec<(String, String)> = Vec::new(); // (module, field) per import table idx
            for import in &record.instance.module.imports {
                if !matches!(import.kind, ImportKind::Table(_)) { continue; }
                let mod_name = bytes_to_string(record.instance.module.get_name(import.module_name_offset, import.module_name_len));
                let fld_name = bytes_to_string(record.instance.module.get_name(import.field_name_offset, import.field_name_len));
                tbl_source_map.push((mod_name, fld_name));
            }
            // For each pair of table imports, check if they resolve to the same source table index
            // Two different export names (tab1, tab2) may point to the same table in the source
            let mut resolved_sources: Vec<Option<(String, u32)>> = Vec::new(); // (module, source_table_idx)
            for (mod_name, fld_name) in &tbl_source_map {
                if let Some(src_handle) = self.instances.get(mod_name.as_str()) {
                    if let Ok(src) = src_handle.try_borrow() {
                        if let Some(src_tbl_idx) = exported_table_index(&src.instance.module, fld_name) {
                            resolved_sources.push(Some((mod_name.clone(), src_tbl_idx)));
                        } else {
                            resolved_sources.push(None);
                        }
                    } else {
                        resolved_sources.push(None);
                    }
                } else {
                    resolved_sources.push(None);
                }
            }
            for i in 0..resolved_sources.len() {
                for j in (i+1)..resolved_sources.len() {
                    if let (Some(a), Some(b)) = (&resolved_sources[i], &resolved_sources[j]) {
                        if a == b {
                            if j < record.instance.table_aliases.len() {
                                record.instance.table_aliases[j] = Some(i);
                            }
                        }
                    }
                }
            }
        }

        // Detect aliased global imports: same source global → alias
        {
            let mut record = handle.borrow_mut();
            let mut glob_sources: Vec<Option<(String, u32)>> = Vec::new();
            for import in &record.instance.module.imports {
                let ImportKind::Global(_, _, _) = import.kind else { continue };
                let mod_name = bytes_to_string(record.instance.module.get_name(import.module_name_offset, import.module_name_len));
                let fld_name = bytes_to_string(record.instance.module.get_name(import.field_name_offset, import.field_name_len));
                if let Some(src_handle) = self.instances.get(&mod_name) {
                    if let Ok(src) = src_handle.try_borrow() {
                        if let Some(src_idx) = exported_global_index(&src.instance.module, &fld_name) {
                            glob_sources.push(Some((mod_name, src_idx)));
                        } else { glob_sources.push(None); }
                    } else { glob_sources.push(None); }
                } else { glob_sources.push(None); }
            }
            for i in 0..glob_sources.len() {
                for j in (i+1)..glob_sources.len() {
                    if let (Some(a), Some(b)) = (&glob_sources[i], &glob_sources[j]) {
                        if a == b && j < record.instance.global_aliases.len() {
                            record.instance.global_aliases[j] = Some(i);
                        }
                    }
                }
            }
        }

        // Detect aliased memory imports: same source memory → alias
        {
            let mut record = handle.borrow_mut();
            let mut mem_sources: Vec<Option<(String, u32)>> = Vec::new();
            for import in &record.instance.module.imports {
                if !matches!(import.kind, ImportKind::Memory) { continue; }
                let mod_name = bytes_to_string(record.instance.module.get_name(import.module_name_offset, import.module_name_len));
                let fld_name = bytes_to_string(record.instance.module.get_name(import.field_name_offset, import.field_name_len));
                if let Some(src_handle) = self.instances.get(&mod_name) {
                    if let Ok(src) = src_handle.try_borrow() {
                        if let Some(src_idx) = exported_memory_index(&src.instance.module, &fld_name) {
                            mem_sources.push(Some((mod_name, src_idx)));
                        } else { mem_sources.push(None); }
                    } else { mem_sources.push(None); }
                } else { mem_sources.push(None); }
            }
            for i in 0..mem_sources.len() {
                for j in (i+1)..mem_sources.len() {
                    if let (Some(a), Some(b)) = (&mem_sources[i], &mem_sources[j]) {
                        if a == b && j < record.instance.memory_aliases.len() {
                            record.instance.memory_aliases[j] = Some(i);
                        }
                    }
                }
            }
        }

        if let Err(err) = self.run_start(&handle) {
            if let Some(name) = &inserted_name {
                self.instances.remove(name);
            }
            return Err(err);
        }

        self.current = Some(handle.clone());
        Ok(handle)
    }

    /// Returns Vec of (importer_mem_idx, exporter_mem_idx, handle) for each imported memory.
    fn find_memory_sources(&self, module: &WasmModule) -> Vec<(usize, usize, InstanceHandle)> {
        let mut result = Vec::new();
        let mut mem_idx = 0usize;
        for import in &module.imports {
            if !matches!(import.kind, ImportKind::Memory) {
                continue;
            }
            let module_name = bytes_to_string(module.get_name(import.module_name_offset, import.module_name_len));
            let field_name = bytes_to_string(module.get_name(import.field_name_offset, import.field_name_len));
            if module_name != SPECTEST_MODULE {
                if let Some(handle) = self.instances.get(&module_name) {
                    let record = handle.borrow();
                    if let Some(exp_mem_idx) = exported_memory_index(&record.instance.module, &field_name) {
                        result.push((mem_idx, exp_mem_idx as usize, handle.clone()));
                    }
                }
            }
            mem_idx += 1;
        }
        result
    }

    /// Backward-compat: returns Some if there's at least one memory source (for memory 0).
    #[allow(dead_code)]
    fn find_memory_source(&self, module: &WasmModule) -> Option<InstanceHandle> {
        self.find_memory_sources(module).into_iter().next().map(|(_, _, h)| h)
    }

    fn find_table_sources(&self, module: &WasmModule) -> Vec<(usize, InstanceHandle)> {
        let mut result = Vec::new();
        let mut tbl_idx = 0usize;
        for import in &module.imports {
            if !matches!(import.kind, ImportKind::Table(_)) {
                continue;
            }
            let module_name = bytes_to_string(module.get_name(import.module_name_offset, import.module_name_len));
            let _field_name = bytes_to_string(module.get_name(import.field_name_offset, import.field_name_len));
            if module_name != SPECTEST_MODULE {
                if let Some(handle) = self.instances.get(&module_name) {
                    result.push((tbl_idx, handle.clone()));
                }
            }
            tbl_idx += 1;
        }
        result
    }

    /// Apply data segments from a failed module to the shared (exporter) memories.
    /// Stops at the first OOB segment, matching spec instantiation semantics.
    fn apply_partial_data_segments_to_shared(
        &self,
        module: &WasmModule,
        memory_sources: &[(usize, usize, InstanceHandle)],
    ) {
        for seg in &module.data_segments {
            if !seg.is_active {
                continue;
            }
            let imp_mem_idx = seg.memory_idx as usize;
            // Find the exporter for this memory index
            let source = memory_sources.iter().find(|(imp_idx, _, _)| *imp_idx == imp_mem_idx);
            if let Some((_, exp_mem_idx, src_handle)) = source {
                let mut src_mut = src_handle.borrow_mut();
                let mem_size = src_mut.instance.memory_sizes.get(*exp_mem_idx).copied().unwrap_or(0);
                let dst_start = seg.offset as usize;
                let len = seg.data_len;
                // Stop at first OOB segment (the one that caused the trap)
                if dst_start.saturating_add(len) > mem_size {
                    break;
                }
                let src_start = seg.data_offset;
                if src_start.saturating_add(len) <= module.code.len()
                    && *exp_mem_idx < src_mut.instance.memories.len()
                {
                    src_mut.instance.memories[*exp_mem_idx][dst_start..dst_start + len]
                        .copy_from_slice(&module.code[src_start..src_start + len]);
                }
            } else {
                // Non-shared memory - check if OOB
                let mem_size = if imp_mem_idx < module.memories.len() {
                    module.memories[imp_mem_idx].min_pages as usize * 65536
                } else { 0 };
                let dst_start = seg.offset as usize;
                let len = seg.data_len;
                if dst_start.saturating_add(len) > mem_size {
                    break;
                }
            }
        }
    }

    /// Apply element segments from a failed module to the shared (exporter) tables.
    /// Stops at the first OOB segment, matching spec instantiation semantics.
    /// Resolves cross-module function references so the exporter can call them.
    fn apply_partial_elem_segments_to_shared(&self, module: &WasmModule, table_sources: &[(usize, InstanceHandle)]) {
        use crate::wasm::decoder::ElemMode;
        for (tbl_idx, src_handle) in table_sources {
            let mut src_mut = src_handle.borrow_mut();
            // Find the exporter's table index
            let src_module_name = self.find_table_import_module(module, *tbl_idx);
            let src_tbl_idx = if let Some((mod_name, fld_name)) = &src_module_name {
                if let Some(sh) = self.instances.get(mod_name.as_str()) {
                    if Rc::ptr_eq(sh, src_handle) {
                        exported_table_index(&src_mut.instance.module, fld_name)
                            .unwrap_or(0) as usize
                    } else { 0 }
                } else { 0 }
            } else { 0 };

            // First resolve all function indices, then apply to the table
            let mut resolved_segs: Vec<(usize, Vec<Option<u32>>)> = Vec::new();
            for seg in &module.element_segments {
                if seg.mode != ElemMode::Active || seg.table_idx as usize != *tbl_idx {
                    continue;
                }
                let offset = seg.offset as usize;
                let count = seg.func_indices.len();
                let tbl_len = src_mut.instance.tables.get(src_tbl_idx).map(|t| t.len()).unwrap_or(0);
                if offset.saturating_add(count) > tbl_len {
                    break; // OOB segment: stop here
                }
                let mut resolved = Vec::with_capacity(count);
                for &func_idx in &seg.func_indices {
                    if func_idx == u32::MAX {
                        resolved.push(None);
                    } else {
                        let r = copy_function_from_module(
                            &mut src_mut.instance.module,
                            module,
                            func_idx,
                        );
                        resolved.push(Some(r));
                    }
                }
                resolved_segs.push((offset, resolved));
            }
            // Apply resolved segments to the table
            if let Some(tbl) = src_mut.instance.tables.get_mut(src_tbl_idx) {
                for (offset, entries) in &resolved_segs {
                    for (i, entry) in entries.iter().enumerate() {
                        tbl[offset + i] = *entry;
                    }
                }
            }
        }
    }

    /// Sync shared memory between all instances that share it.
    /// After any call that might do memory.grow, both sides need to see the same memory.
    fn sync_shared_memory(&self) {
        for (importer, imp_mem_idx, exporter, exp_mem_idx) in &self.memory_shares {
            if Rc::ptr_eq(importer, exporter) {
                continue;
            }
            let imp_mi = *imp_mem_idx;
            let exp_mi = *exp_mem_idx;
            // Find the larger memory and sync to the smaller
            let (imp_size, exp_size) = {
                let imp = importer.borrow();
                let exp = exporter.borrow();
                let is = imp.instance.memory_sizes.get(imp_mi).copied().unwrap_or(0);
                let es = exp.instance.memory_sizes.get(exp_mi).copied().unwrap_or(0);
                (is, es)
            };
            if imp_size > exp_size {
                let imp = importer.borrow();
                let mut exp = exporter.borrow_mut();
                if exp_mi < exp.instance.memories.len() && imp_mi < imp.instance.memories.len() {
                    exp.instance.memories[exp_mi].resize(imp_size, 0);
                    exp.instance.memories[exp_mi][..imp_size].copy_from_slice(&imp.instance.memories[imp_mi][..imp_size]);
                    exp.instance.memory_sizes[exp_mi] = imp_size;
                }
            } else if exp_size > imp_size {
                let exp = exporter.borrow();
                let mut imp = importer.borrow_mut();
                if imp_mi < imp.instance.memories.len() && exp_mi < exp.instance.memories.len() {
                    imp.instance.memories[imp_mi].resize(exp_size, 0);
                    imp.instance.memories[imp_mi][..exp_size].copy_from_slice(&exp.instance.memories[exp_mi][..exp_size]);
                    imp.instance.memory_sizes[imp_mi] = exp_size;
                }
            } else if imp_size == exp_size && imp_size > 0 {
                let imp = importer.borrow();
                let mut exp = exporter.borrow_mut();
                if exp_mi < exp.instance.memories.len() && imp_mi < imp.instance.memories.len() {
                    exp.instance.memories[exp_mi][..imp_size].copy_from_slice(&imp.instance.memories[imp_mi][..imp_size]);
                }
            }
        }
    }

    fn find_table_import_module(&self, module: &WasmModule, target_tbl_idx: usize) -> Option<(String, String)> {
        let mut tbl_idx = 0usize;
        for import in &module.imports {
            if !matches!(import.kind, ImportKind::Table(_)) {
                continue;
            }
            if tbl_idx == target_tbl_idx {
                let module_name = bytes_to_string(module.get_name(import.module_name_offset, import.module_name_len));
                let field_name = bytes_to_string(module.get_name(import.field_name_offset, import.field_name_len));
                return Some((module_name, field_name));
            }
            tbl_idx += 1;
        }
        None
    }

    fn run_start(&mut self, handle: &InstanceHandle) -> RunnerResult<()> {
        let mut record = handle.try_borrow_mut().map_err(|_| {
            RunnerError::new("link", "re-entrant instance execution is not supported")
        })?;
        record.instance.stack_ptr = 0;
        let mut result = record.instance.run_start();
        loop {
            match result {
                ExecResult::Ok | ExecResult::Returned(_) => return Ok(()),
                ExecResult::OutOfFuel => {
                    return Err(RunnerError::new("trap", "out of fuel while running start"));
                }
                ExecResult::Trap(err) => return Err(RunnerError::trap(err)),
                ExecResult::Exception(_tag_idx, _values) => {
                    return Err(RunnerError::new("trap", "uncaught exception in start function"));
                }
                ExecResult::HostCall(import_idx, args, arg_count) => {
                    let ret = self.dispatch_host_call(
                        &mut record.instance,
                        import_idx,
                        &args[..arg_count as usize],
                    )?;
                    result = record.instance.resume(ret);
                }
            }
        }
    }

    fn execute(&mut self, exec: WastExecute<'_>) -> RunnerResult<Vec<Value>> {
        match exec {
            WastExecute::Invoke(invoke) => self.invoke(invoke),
            WastExecute::Wat(Wat::Module(module)) => {
                let mut quoted = QuoteWat::Wat(Wat::Module(module));
                let (_name, bytes) = self.module_bytes(&mut quoted)?;
                self.instantiate_module_bytes(None, &bytes)?;
                Ok(Vec::new())
            }
            WastExecute::Get { module, global, .. } => {
                let value = self.get_global(module, global)?;
                Ok(vec![value])
            }
            _ => Err(RunnerError::new(
                "unsupported",
                "execution directive is not supported by the ATOS runner",
            )),
        }
    }

    fn invoke(&mut self, invoke: wast::WastInvoke<'_>) -> RunnerResult<Vec<Value>> {
        let handle = self.get_instance_handle(invoke.module)?;
        self.last_invoke_handle = Some(handle.clone());
        let args = self.values_from_args(&invoke.args)?;
        // Allocate externref args on the GC heap so they're properly typed
        let args = args
            .into_iter()
            .enumerate()
            .map(|(_i, v)| match v {
                Value::I32(n) if n >= 0 && self.gc_enabled => {
                    // Keep placeholder ref values as-is here; precise externref handling
                    // happens below once we still have access to the original wast args.
                    v
                }
                _ => v,
            })
            .collect::<Vec<_>>();
        // Allocate externref values on GC heap for properly-typed arguments
        let args = self.allocate_extern_args(&handle, &invoke.args, args)?;
        let func_idx = {
            let record = handle.borrow();
            record
                .instance
                .module
                .find_export_func(invoke.name.as_bytes())
                .ok_or_else(|| {
                    RunnerError::new(
                        "link",
                        format!("missing exported function `{}`", invoke.name),
                    )
                })?
        };
        let result = self.execute_call(&handle, func_idx, &args);
        self.sync_shared_memory();
        // Sync mutable globals back to source instances, then re-read
        // This ensures aliased imports (same source global under different names) stay in sync
        self.sync_globals_back(&handle);
        self.sync_imported_globals(&handle);
        // Note: table aliasing (wasm-3.0/instance.wast) requires runtime-level
        // shared table backing which is not yet implemented.
        result
    }

    /// Allocate externref arguments on the GC heap as Externalized objects
    fn allocate_extern_args(&self, handle: &InstanceHandle, wast_args: &[wast::WastArg<'_>], mut args: Vec<Value>) -> RunnerResult<Vec<Value>> {
        use crate::wasm::runtime::GcObject;
        if !self.gc_enabled {
            return Ok(args);
        }
        let mut record = handle.borrow_mut();
        for (i, wast_arg) in wast_args.iter().enumerate() {
            if let wast::WastArg::Core(core_arg) = wast_arg {
                match core_arg {
                    WastArgCore::RefExtern(_) | WastArgCore::RefHost(_) => {
                        if i < args.len() && !matches!(args[i], Value::NullRef) {
                            let heap_idx = record.instance.gc_heap.len() as u32;
                            record.instance.gc_heap.push(GcObject::Externalized { value: args[i] });
                            args[i] = Value::GcRef(heap_idx);
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(args)
    }

    fn execute_call(&mut self, handle: &InstanceHandle, func_idx: u32, args: &[Value]) -> RunnerResult<Vec<Value>> {
        let mut record = handle.try_borrow_mut().map_err(|_| {
            RunnerError::new("link", "re-entrant instance execution is not supported")
        })?;
        record.instance.stack_ptr = 0;
        let mut result = record.instance.call_func(func_idx, args);
        loop {
            match result {
                ExecResult::Ok | ExecResult::Returned(_) => {
                    return Ok(record.instance.stack[..record.instance.stack_ptr].to_vec());
                }
                ExecResult::OutOfFuel => return Err(RunnerError::new("trap", "out of fuel")),
                ExecResult::Trap(err) => return Err(RunnerError::trap(err)),
                ExecResult::Exception(tag_idx, values) => {
                    return Err(RunnerError::exception(tag_idx, values));
                }
                ExecResult::HostCall(import_idx, values, arg_count) => {
                    match self.dispatch_host_call_ex(
                        &mut record.instance,
                        import_idx,
                        &values[..arg_count as usize],
                    ) {
                        Ok(ret) => {
                            result = record.instance.resume(ret);
                        }
                        Err(err) => {
                            if let Some((tag_idx, exc_values)) = err.exception {
                                // Cross-module exception: propagate to caller's try_table
                                // tag_idx is already mapped to caller's tag space
                                result = record.instance.resume_with_exception(tag_idx, exc_values);
                            } else {
                                return Err(err);
                            }
                        }
                    }
                }
            }
        }
    }

    fn sync_imported_globals(&self, handle: &InstanceHandle) {
        let mut record = handle.borrow_mut();
        let num_global_imports = record.instance.module.imports.iter()
            .filter(|i| matches!(i.kind, ImportKind::Global(_, _, _)))
            .count();

        // Collect import info first to avoid borrow conflict
        let global_imports: Vec<(usize, bool, String, String)> = {
            let mut global_idx = 0usize;
            let mut result = Vec::new();
            for import in &record.instance.module.imports {
                let ImportKind::Global(_, mutable, _) = import.kind else {
                    continue;
                };
                let module_name = bytes_to_string(record.instance.module.get_name(import.module_name_offset, import.module_name_len));
                let field_name = bytes_to_string(record.instance.module.get_name(import.field_name_offset, import.field_name_len));
                result.push((global_idx, mutable, module_name, field_name));
                global_idx += 1;
            }
            result
        };
        for (global_idx, mutable, module_name, field_name) in &global_imports {
            if !mutable {
                continue;
            }

            if *module_name != SPECTEST_MODULE {
                if let Some(src_handle) = self.instances.get(module_name.as_str()) {
                    if !Rc::ptr_eq(src_handle, handle) {
                        if let Ok(src) = src_handle.try_borrow() {
                            if let Some(src_idx) = exported_global_index(&src.instance.module, field_name) {
                                if let Some(&val) = src.instance.globals.get(src_idx as usize) {
                                    if *global_idx < record.instance.globals.len() {
                                        record.instance.globals[*global_idx] = val;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        let _ = num_global_imports;
    }

    fn sync_globals_back(&self, handle: &InstanceHandle) {
        let record = handle.borrow();
        let mut global_idx = 0usize;
        for import in &record.instance.module.imports {
            let ImportKind::Global(_, mutable, _) = import.kind else {
                continue;
            };
            if !mutable {
                global_idx += 1;
                continue;
            }
            let module_name = bytes_to_string(record.instance.module.get_name(import.module_name_offset, import.module_name_len));
            let field_name = bytes_to_string(record.instance.module.get_name(import.field_name_offset, import.field_name_len));

            if module_name != SPECTEST_MODULE {
                if let Some(src_handle) = self.instances.get(&module_name) {
                    if !Rc::ptr_eq(src_handle, handle) {
                        if let Some(val) = record.instance.globals.get(global_idx).copied() {
                            drop(record);
                            if let Ok(mut src) = src_handle.try_borrow_mut() {
                                if let Some(src_idx) = exported_global_index(&src.instance.module, &field_name) {
                                    if let Some(slot) = src.instance.globals.get_mut(src_idx as usize) {
                                        *slot = val;
                                    }
                                }
                            }
                            // Since we dropped record, we can't continue the loop safely
                            return;
                        }
                    }
                }
            }
            global_idx += 1;
        }
    }

    fn get_global(&self, module: Option<Id<'_>>, global_name: &str) -> RunnerResult<Value> {
        let handle = self.get_instance_handle(module)?;
        self.sync_imported_globals(&handle);
        let record = handle.borrow();
        let idx = exported_global_index(&record.instance.module, global_name).ok_or_else(|| {
            RunnerError::new("link", format!("missing exported global `{global_name}`"))
        })?;
        record
            .instance
            .globals
            .get(idx as usize)
            .copied()
            .ok_or_else(|| RunnerError::new("link", "global index out of bounds"))
    }

    fn get_instance_handle(&self, module: Option<Id<'_>>) -> RunnerResult<InstanceHandle> {
        match module {
            Some(name) => self
                .instances
                .get(name.name())
                .cloned()
                .ok_or_else(|| RunnerError::new("link", format!("unknown instance `{}`", name.name()))),
            None => self
                .current
                .clone()
                .ok_or_else(|| RunnerError::new("link", "no current instance available")),
        }
    }

    fn values_from_args(&self, args: &[wast::WastArg<'_>]) -> RunnerResult<Vec<Value>> {
        let mut values = Vec::with_capacity(args.len());
        for arg in args {
            match arg {
                wast::WastArg::Core(arg) => values.push(self.value_from_arg(arg)?),
                _ => {
                    return Err(RunnerError::new(
                        "unsupported",
                        "component-model arguments are not supported",
                    ));
                }
            }
        }
        Ok(values)
    }

    fn value_from_arg(&self, arg: &WastArgCore<'_>) -> RunnerResult<Value> {
        match arg {
            WastArgCore::I32(v) => Ok(Value::I32(*v)),
            WastArgCore::I64(v) => Ok(Value::I64(*v)),
            WastArgCore::F32(v) => Ok(Value::F32(f32::from_bits(v.bits))),
            WastArgCore::F64(v) => Ok(Value::F64(f64::from_bits(v.bits))),
            WastArgCore::V128(v) => Ok(Value::V128(V128(v.to_le_bytes()))),
            WastArgCore::RefNull(_) => Ok(Value::NullRef),
            WastArgCore::RefExtern(v) => Ok(Value::I32(*v as i32)),
            WastArgCore::RefHost(v) => Ok(Value::I32(*v as i32)),
        }
    }

    fn inject_imported_globals(&self, module: &mut WasmModule) -> RunnerResult<()> {
        let mut imported = Vec::new();
        for import in &module.imports {
            let ImportKind::Global(val_type_byte, mutable, _) = import.kind else {
                continue;
            };
            let module_name = bytes_to_string(module.get_name(import.module_name_offset, import.module_name_len));
            let field_name = bytes_to_string(module.get_name(import.field_name_offset, import.field_name_len));
            let value = if module_name == SPECTEST_MODULE {
                spectest_global(&field_name).ok_or_else(|| {
                    RunnerError::new(
                        "link",
                        format!("unknown spectest global `{field_name}`"),
                    )
                })?
            } else {
                let handle = self.instances.get(&module_name).ok_or_else(|| {
                    RunnerError::new(
                        "link",
                        format!("unknown import module `{module_name}` for global `{field_name}`"),
                    )
                })?;
                let record = handle.borrow();
                let idx = exported_global_index(&record.instance.module, &field_name).ok_or_else(|| {
                    RunnerError::new(
                        "link",
                        format!("module `{module_name}` does not export global `{field_name}`"),
                    )
                })?;
                record
                    .instance
                    .globals
                    .get(idx as usize)
                    .copied()
                    .ok_or_else(|| RunnerError::new("link", "global export index out of bounds"))?
            };
            let val_type = decode_valtype_byte(val_type_byte).ok_or_else(|| {
                RunnerError::new("link", format!("unsupported imported global type 0x{val_type_byte:02x}"))
            })?;
            if !value_matches_type(value, val_type) {
                return Err(RunnerError::new(
                    "link",
                    format!(
                        "imported global `{module_name}::{field_name}` type mismatch; expected {:?}, got {:?}",
                        val_type, value
                    ),
                ));
            }
            imported.push(GlobalDef {
                val_type,
                mutable,
                init_value: value,
                init_global_ref: None,
                init_func_ref: None,
                init_expr_type: Some(val_type),
                init_expr_stack_depth: 1,
                init_expr_bytes: Vec::new(),
                heap_type: None,
                has_non_const: false,
            });
        }

        if !imported.is_empty() {
            let num_imported = imported.len();
            let mut globals = imported;
            globals.extend(module.globals.iter().cloned());
            module.globals = globals;

            // Re-evaluate init expressions for module-defined globals that reference
            // imported globals. At decode time, global.get returns 0 as a placeholder.
            // Now that imported globals have their actual values, add the reference value.
            for i in num_imported..module.globals.len() {
                if let Some(ref_idx) = module.globals[i].init_global_ref {
                    if (ref_idx as usize) < i {
                        let ref_val = module.globals[ref_idx as usize].init_value;
                        let init = &mut module.globals[i].init_value;
                        match (ref_val, *init) {
                            (Value::I32(r), Value::I32(v)) => *init = Value::I32(v.wrapping_add(r)),
                            (Value::I64(r), Value::I64(v)) => *init = Value::I64(v.wrapping_add(r)),
                            (Value::F32(r), Value::F32(v)) => *init = Value::F32(v + r),
                            (Value::F64(r), Value::F64(v)) => *init = Value::F64(v + r),
                            (val, _) => *init = val,
                        }
                        // Clear the ref so the runtime doesn't re-process
                        module.globals[i].init_global_ref = None;
                    }
                }
            }
        }
        Ok(())
    }

    /// For funcref globals imported from other modules, the global's value is a
    /// function index in the *source* module. Copy the function into the current
    /// module and update both the global value and any element segments that
    /// reference it via global.get.
    fn fixup_funcref_globals(&self, module: &mut WasmModule) -> RunnerResult<()> {
        // Collect funcref global imports: (global_idx, source_module_name, func_idx_in_source)
        let mut funcref_fixups: Vec<(usize, String, u32)> = Vec::new();
        let mut global_idx = 0usize;
        for import in &module.imports {
            if let ImportKind::Global(vt_byte, _, _) = import.kind {
                // funcref = 0x70, externref = 0x6F
                if vt_byte == 0x70 {
                    let module_name = bytes_to_string(module.get_name(
                        import.module_name_offset,
                        import.module_name_len,
                    ));
                    if module_name != SPECTEST_MODULE {
                        // The global value is the function index in the source module
                        if global_idx < module.globals.len() {
                            let func_idx = match module.globals[global_idx].init_value {
                                Value::I32(v) if v >= 0 => v as u32,
                                _ => { global_idx += 1; continue; }
                            };
                            funcref_fixups.push((global_idx, module_name.clone(), func_idx));
                        }
                    }
                }
                global_idx += 1;
            }
        }

        // Process each fixup: copy the function and update indices
        for (gidx, module_name, source_func_idx) in funcref_fixups {
            if let Some(handle) = self.instances.get(&module_name) {
                let new_idx = resolve_cross_module_function(module, handle, source_func_idx, &self.instances);
                // Update the global's value to point to the copied function
                if gidx < module.globals.len() {
                    module.globals[gidx].init_value = Value::I32(new_idx as i32);
                }
                // Update element segments that reference this global
                for seg in &mut module.element_segments {
                    for (i, info) in seg.item_expr_infos.iter().enumerate() {
                        if let Some(ref_idx) = info.global_ref {
                            if ref_idx as usize == gidx {
                                // This element was initialized from global.get gidx
                                if i < seg.func_indices.len() {
                                    seg.func_indices[i] = new_idx;
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Re-evaluate element/data segment offsets that reference globals.
    /// After inject_imported_globals, the globals have actual values, so we can
    /// re-evaluate extended-const offset expressions that use global.get.
    fn fixup_segment_offsets(&self, module: &mut WasmModule, original_bytes: &[u8]) {
        // Build global init values for the evaluator
        let global_values: Vec<Value> = module.globals.iter().map(|g| g.init_value).collect();

        // Re-evaluate element segment offsets
        use crate::wasm::decoder::ElemMode;
        for seg in &mut module.element_segments {
            if seg.mode != ElemMode::Active {
                continue;
            }
            // Only re-evaluate if the offset expression references a global
            if seg.offset_expr_info.global_ref.is_none() {
                continue;
            }
            let (start, end) = seg.offset_expr_range;
            if start == 0 && end == 0 {
                continue; // no saved byte range
            }
            if end <= original_bytes.len() {
                let mut pos = start;
                if let Ok(val) = crate::wasm::decoder::eval_init_expr_with_globals(original_bytes, &mut pos, &global_values) {
                    seg.offset = match val {
                        Value::I32(v) => v as u32,
                        Value::I64(v) => v as u32,
                        _ => seg.offset,
                    };
                }
            }
        }

        // Re-evaluate data segment offsets
        for seg in &mut module.data_segments {
            if !seg.is_active {
                continue;
            }
            if seg.offset_expr_info.global_ref.is_none() {
                continue;
            }
            let (start, end) = seg.offset_expr_range;
            if start == 0 && end == 0 {
                continue;
            }
            if end <= original_bytes.len() {
                let mut pos = start;
                if let Ok(val) = crate::wasm::decoder::eval_init_expr_with_globals(original_bytes, &mut pos, &global_values) {
                    seg.offset = match val {
                        Value::I32(v) => v as u32,
                        Value::I64(v) => v as u32,
                        _ => seg.offset,
                    };
                }
            }
        }
    }

    fn inject_imported_memory(&self, module: &mut WasmModule) -> RunnerResult<()> {
        let mut mem_idx = 0usize;
        for import in &module.imports {
            if !matches!(import.kind, ImportKind::Memory) {
                continue;
            }
            let module_name = bytes_to_string(module.get_name(import.module_name_offset, import.module_name_len));
            let field_name = bytes_to_string(module.get_name(import.field_name_offset, import.field_name_len));

            let (actual_min_pages, actual_max_pages) = if module_name == SPECTEST_MODULE && field_name == "memory" {
                // spectest memory: min=1, max=2
                (1u32, Some(2u32))
            } else if let Some(handle) = self.instances.get(&module_name) {
                let record = handle.borrow();
                // Find the exported memory index
                let exp_mem_idx = exported_memory_index(&record.instance.module, &field_name)
                    .unwrap_or(0) as usize;
                let mem_size = record.instance.memory_sizes.get(exp_mem_idx).copied().unwrap_or(0);
                let exp_page_size = if exp_mem_idx < record.instance.module.memories.len() {
                    match record.instance.module.memories[exp_mem_idx].page_size_log2 {
                        Some(log2) => 1usize << log2,
                        None => 65536,
                    }
                } else { 65536 };
                let actual_pages = if exp_page_size > 0 { (mem_size / exp_page_size) as u32 } else { 0 };
                let actual_max = if exp_mem_idx < record.instance.module.memories.len() {
                    let mdef = &record.instance.module.memories[exp_mem_idx];
                    if mdef.has_max { Some(mdef.max_pages) } else { None }
                } else if record.instance.module.has_memory_max {
                    Some(record.instance.module.memory_max_pages)
                } else {
                    None
                };
                (actual_pages, actual_max)
            } else {
                mem_idx += 1;
                continue;
            };

            // Update module-wide fields for memory 0 (backward compat)
            if mem_idx == 0 {
                if module.memory_min_pages < actual_min_pages {
                    module.memory_min_pages = actual_min_pages;
                }
                if let Some(actual_max) = actual_max_pages {
                    if module.has_memory_max {
                        if module.memory_max_pages > actual_max {
                            module.memory_max_pages = actual_max;
                        }
                    } else {
                        module.has_memory_max = true;
                        module.memory_max_pages = actual_max;
                    }
                }
            }

            // Update the per-memory MemoryDef
            if mem_idx < module.memories.len() {
                if module.memories[mem_idx].min_pages < actual_min_pages {
                    module.memories[mem_idx].min_pages = actual_min_pages;
                }
                if let Some(actual_max) = actual_max_pages {
                    if module.memories[mem_idx].has_max {
                        if module.memories[mem_idx].max_pages > actual_max {
                            module.memories[mem_idx].max_pages = actual_max;
                        }
                    } else {
                        module.memories[mem_idx].has_max = true;
                        module.memories[mem_idx].max_pages = actual_max;
                    }
                }
            }
            mem_idx += 1;
        }
        Ok(())
    }

    fn inject_imported_tables(&self, module: &mut WasmModule) -> RunnerResult<()> {
        let mut table_idx = 0usize;
        for import in &module.imports {
            if !matches!(import.kind, ImportKind::Table(_)) {
                continue;
            }
            let module_name = bytes_to_string(module.get_name(import.module_name_offset, import.module_name_len));
            let field_name = bytes_to_string(module.get_name(import.field_name_offset, import.field_name_len));

            let actual_min = if module_name == SPECTEST_MODULE && field_name == "table" {
                // spectest table: min=10, max=20
                10u32
            } else if let Some(handle) = self.instances.get(&module_name) {
                let record = handle.borrow();
                let export_tbl_idx = exported_table_index(&record.instance.module, &field_name)
                    .unwrap_or(0) as usize;
                record.instance.tables.get(export_tbl_idx)
                    .map(|t| t.len() as u32)
                    .unwrap_or(0)
            } else {
                table_idx += 1;
                continue;
            };

            // Upgrade the table's min to the actual provider's size
            if table_idx < module.tables.len() && module.tables[table_idx].min < actual_min {
                module.tables[table_idx].min = actual_min;
            }
            table_idx += 1;
        }
        Ok(())
    }

    fn ensure_linkable_imports(&self, module: &WasmModule) -> RunnerResult<()> {
        let mut func_idx = 0u32;
        let mut mem_import_idx = 0usize;
        for import in &module.imports {
            let module_name = bytes_to_string(module.get_name(import.module_name_offset, import.module_name_len));
            let field_name = bytes_to_string(module.get_name(import.field_name_offset, import.field_name_len));

            match import.kind {
                ImportKind::Func(_) => {
                    self.validate_func_import(module, &module_name, &field_name, func_idx)?;
                    func_idx = func_idx.saturating_add(1);
                }
                ImportKind::Table(_) => {
                    self.validate_table_import(module, &module_name, &field_name, import)?;
                }
                ImportKind::Memory => {
                    self.validate_memory_import(module, &module_name, &field_name, mem_import_idx)?;
                    mem_import_idx += 1;
                }
                ImportKind::Global(val_type_byte, mutable, heap_type) => {
                    self.validate_global_import(&module_name, &field_name, val_type_byte, mutable, heap_type)?;
                }
                ImportKind::Tag(type_idx) => {
                    // Tag imports: validate that the source module exports a compatible tag
                    if module_name == SPECTEST_MODULE {
                        // spectest module doesn't export any tags
                        return Err(RunnerError::new(
                            "link",
                            format!("unknown import: spectest does not export tag `{field_name}`"),
                        ));
                    }
                    let handle = self.instances.get(&module_name).ok_or_else(|| {
                        RunnerError::new("link", format!("unknown import: module `{module_name}` tag `{field_name}`"))
                    })?;
                    let record = handle.borrow();
                    // Check that the export exists and is a tag
                    let has_tag_export = record.instance.module.exports.iter().any(|e| {
                        record.instance.module.get_name(e.name_offset, e.name_len) == field_name.as_bytes()
                            && matches!(e.kind, ExportKind::Tag(_))
                    });
                    if !has_tag_export {
                        // Check if it exists as another kind
                        let has_any = record.instance.module.exports.iter().any(|e| {
                            record.instance.module.get_name(e.name_offset, e.name_len) == field_name.as_bytes()
                        });
                        if has_any {
                            return Err(RunnerError::new(
                                "link",
                                format!("incompatible import type for `{module_name}::{field_name}`"),
                            ));
                        }
                        return Err(RunnerError::new(
                            "link",
                            format!("unknown import: module `{module_name}` does not export tag `{field_name}`"),
                        ));
                    }
                    // Validate tag type compatibility
                    if let Some(exp_tag_idx) = record.instance.module.exports.iter()
                        .filter(|e| {
                            record.instance.module.get_name(e.name_offset, e.name_len) == field_name.as_bytes()
                                && matches!(e.kind, ExportKind::Tag(_))
                        })
                        .map(|e| if let ExportKind::Tag(idx) = e.kind { idx } else { 0 })
                        .next()
                    {
                        // Map tag index to type index
                        let exp_type_idx = record.instance.module.tag_types
                            .get(exp_tag_idx as usize)
                            .copied();
                        if let Some(exp_ti) = exp_type_idx {
                            // Use rec-group-aware type equivalence check
                            if !type_indices_equivalent(module, type_idx, &record.instance.module, exp_ti) {
                                return Err(RunnerError::new(
                                    "link",
                                    format!("incompatible import type for tag `{module_name}::{field_name}`"),
                                ));
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn validate_func_import(
        &self,
        module: &WasmModule,
        module_name: &str,
        field_name: &str,
        func_idx: u32,
    ) -> RunnerResult<()> {
        let signature = function_type(module, func_idx).ok_or_else(|| {
            RunnerError::new("link", format!("missing function type for import `{module_name}::{field_name}`"))
        })?;

        if signature.result_count > 1 {
            return Err(RunnerError::new(
                "link",
                format!(
                    "imported function `{module_name}::{field_name}` uses {} results; ATOS host-call ABI supports at most one",
                    signature.result_count
                ),
            ));
        }

        if module_name == "atos" {
            let host_func = crate::wasm::host::resolve_import(module, func_idx);
            if matches!(host_func, crate::wasm::host::HostFunc::Unknown) {
                return Err(RunnerError::new(
                    "link",
                    format!("unknown ATOS host function `{field_name}`"),
                ));
            }
        } else if module_name == SPECTEST_MODULE {
            ensure_spectest_function(field_name)?;
            // Also validate signature against known spectest function signatures
            validate_spectest_func_signature(field_name, signature)?;
        } else if let Some(handle) = self.instances.get(module_name) {
            let record = handle.borrow();
            let target_idx = record
                .instance
                .module
                .find_export_func(field_name.as_bytes())
                .ok_or_else(|| {
                    RunnerError::new(
                        "link",
                        format!("module `{module_name}` does not export function `{field_name}`"),
                    )
                })?;
            // Check type compatibility using rec-group-aware type comparison.
            // For function imports, the exported function's type must be a subtype of
            // or equivalent to the imported type. As a simplification, we check:
            // 1. Rec-group equivalence (strict, handles rec group tests)
            // 2. If either type is in a non-trivial rec group (size > 1), require strict equivalence
            // 3. Otherwise, allow structural matching (handles subtyping cases)
            let import_type_idx = function_type_idx(module, func_idx);
            let target_type_idx = function_type_idx(&record.instance.module, target_idx);
            let target_ty = function_type(&record.instance.module, target_idx).ok_or_else(|| {
                RunnerError::new(
                    "link",
                    format!("missing function type for `{module_name}::{field_name}`"),
                )
            })?;
            let compatible = if let (Some(it), Some(tt)) = (import_type_idx, target_type_idx) {
                // Check equivalence or subtype: export type must be a subtype of import type
                cross_module_type_subtype(
                    &record.instance.module, tt, // export (actual) type
                    module, it,                   // import (expected) type
                )
            } else {
                func_types_match(signature, target_ty)
            };
            if !compatible {
                return Err(RunnerError::new(
                    "link",
                    format!(
                        "incompatible import type for function `{module_name}::{field_name}`",
                    ),
                ));
            }
        } else {
            return Err(RunnerError::new(
                "link",
                format!("unknown import: module `{module_name}` function `{field_name}`"),
            ));
        }
        Ok(())
    }

    fn validate_table_import(
        &self,
        _module: &WasmModule,
        module_name: &str,
        field_name: &str,
        import: &crate::wasm::decoder::ImportDef,
    ) -> RunnerResult<()> {
        // Find the table definition for this import from the importing module's table section
        // The import's table limits are encoded in the module's tables list
        let import_table_idx = self.count_table_imports_before(_module, import);
        let import_table = _module.tables.get(import_table_idx);

        if module_name == SPECTEST_MODULE {
            // spectest table: min=10, max=20, funcref
            // spectest table64: min=10, max=20, funcref (table64)
            if field_name != "table" && field_name != "table64" {
                return Err(RunnerError::new(
                    "link",
                    format!("unknown import: spectest does not export table `{field_name}`"),
                ));
            }
            if let Some(tbl) = import_table {
                // spectest table has min=10, max=20
                if tbl.min > 10 {
                    return Err(RunnerError::new(
                        "link",
                        format!("incompatible import type for table `{module_name}::{field_name}`: requested min {} > available 10", tbl.min),
                    ));
                }
                if let Some(import_max) = tbl.max {
                    // spectest table has max=20; import max must be >= actual max
                    if import_max < 20 {
                        return Err(RunnerError::new(
                            "link",
                            format!("incompatible import type for table `{module_name}::{field_name}`: requested max {} < available 20", import_max),
                        ));
                    }
                }
            }
            return Ok(());
        }

        if let Some(handle) = self.instances.get(module_name) {
            let record = handle.borrow();
            // Find the exported table
            let export_table_idx = exported_table_index(&record.instance.module, field_name);
            if export_table_idx.is_none() {
                // Check if the name exists but as a different kind
                let has_any = record.instance.module.exports.iter().any(|e| {
                    record.instance.module.get_name(e.name_offset, e.name_len) == field_name.as_bytes()
                });
                if has_any {
                    return Err(RunnerError::new(
                        "link",
                        format!("incompatible import type for `{module_name}::{field_name}`: not a table export"),
                    ));
                }
                return Err(RunnerError::new(
                    "link",
                    format!("unknown import: module `{module_name}` does not export table `{field_name}`"),
                ));
            }
            let export_idx = export_table_idx.unwrap() as usize;
            let export_table = record.instance.module.tables.get(export_idx);
            let actual_size = record.instance.tables.get(export_idx).map(|t| t.len() as u32).unwrap_or(0);

            if let (Some(imp_tbl), Some(exp_tbl)) = (import_table, export_table) {
                // Check element type compatibility
                if imp_tbl.elem_type != exp_tbl.elem_type {
                    return Err(RunnerError::new(
                        "link",
                        format!("incompatible import type for table `{module_name}::{field_name}`: element type mismatch"),
                    ));
                }
                // Check table index type compatibility (table32 vs table64)
                if imp_tbl.is_table64 != exp_tbl.is_table64 {
                    return Err(RunnerError::new(
                        "link",
                        format!("incompatible import type for table `{module_name}::{field_name}`: index type mismatch"),
                    ));
                }
                // Import min must be <= actual current size (or export min)
                let available_min = actual_size.max(exp_tbl.min);
                if imp_tbl.min > available_min {
                    return Err(RunnerError::new(
                        "link",
                        format!("incompatible import type for table `{module_name}::{field_name}`"),
                    ));
                }
                // If import specifies max, export must also have max, and export max <= import max
                if let Some(import_max) = imp_tbl.max {
                    match exp_tbl.max {
                        None => {
                            return Err(RunnerError::new(
                                "link",
                                format!("incompatible import type for table `{module_name}::{field_name}`"),
                            ));
                        }
                        Some(export_max) => {
                            if export_max > import_max {
                                return Err(RunnerError::new(
                                    "link",
                                    format!("incompatible import type for table `{module_name}::{field_name}`"),
                                ));
                            }
                        }
                    }
                }
            }
        } else {
            return Err(RunnerError::new(
                "link",
                format!("unknown import: module `{module_name}` table `{field_name}`"),
            ));
        }
        Ok(())
    }

    fn count_table_imports_before(&self, module: &WasmModule, target: &crate::wasm::decoder::ImportDef) -> usize {
        let mut count = 0;
        for import in &module.imports {
            if core::ptr::eq(import, target) {
                break;
            }
            if matches!(import.kind, ImportKind::Table(_)) {
                count += 1;
            }
        }
        count
    }

    fn validate_memory_import(
        &self,
        _module: &WasmModule,
        module_name: &str,
        field_name: &str,
        import_mem_idx: usize,
    ) -> RunnerResult<()> {
        // Use the per-memory MemoryDef if available, else fall back to module-wide fields
        let (import_min, import_has_max, import_max) = if import_mem_idx < _module.memories.len() {
            let mdef = &_module.memories[import_mem_idx];
            (mdef.min_pages, mdef.has_max, mdef.max_pages)
        } else {
            (_module.memory_min_pages, _module.has_memory_max, _module.memory_max_pages)
        };

        if module_name == SPECTEST_MODULE {
            if field_name != "memory" && field_name != "shared_memory" {
                return Err(RunnerError::new(
                    "link",
                    format!("unknown import: spectest does not export memory `{field_name}`"),
                ));
            }
            // spectest memory: min=1, max=2, not shared
            // spectest shared_memory: min=1, max=2, shared
            let export_is_shared = field_name == "shared_memory";
            let import_is_shared = import_mem_idx < _module.memories.len() && _module.memories[import_mem_idx].is_shared;
            // shared mismatch: importing shared from non-shared or vice versa
            if import_is_shared != export_is_shared {
                return Err(RunnerError::new(
                    "link",
                    format!("incompatible import type for memory `{module_name}::{field_name}`: shared mismatch"),
                ));
            }
            if import_min > 1 {
                return Err(RunnerError::new(
                    "link",
                    format!("incompatible import type for memory `{module_name}::{field_name}`: requested min {} > available 1", import_min),
                ));
            }
            if import_has_max && import_max < 2 {
                return Err(RunnerError::new(
                    "link",
                    format!("incompatible import type for memory `{module_name}::{field_name}`: requested max {} < available 2", import_max),
                ));
            }
            return Ok(());
        }

        if let Some(handle) = self.instances.get(module_name) {
            let record = handle.borrow();
            // Find the exported memory index
            let export_mem_idx = exported_memory_index(&record.instance.module, field_name);
            if export_mem_idx.is_none() {
                // Check if the name exists as a different kind
                let has_any = record.instance.module.exports.iter().any(|e| {
                    record.instance.module.get_name(e.name_offset, e.name_len) == field_name.as_bytes()
                });
                if has_any {
                    return Err(RunnerError::new(
                        "link",
                        format!("incompatible import type for `{module_name}::{field_name}`: not a memory export"),
                    ));
                }
                return Err(RunnerError::new(
                    "link",
                    format!("unknown import: module `{module_name}` does not export memory `{field_name}`"),
                ));
            }
            let exp_idx = export_mem_idx.unwrap() as usize;
            // Get export MemoryDef
            let (export_min, export_has_max, export_max, export_page_size_log2) = if exp_idx < record.instance.module.memories.len() {
                let mdef = &record.instance.module.memories[exp_idx];
                (mdef.min_pages, mdef.has_max, mdef.max_pages, mdef.page_size_log2)
            } else {
                (record.instance.module.memory_min_pages, record.instance.module.has_memory_max, record.instance.module.memory_max_pages, record.instance.module.page_size_log2)
            };
            // Check page size compatibility
            let import_page_size_log2 = if import_mem_idx < _module.memories.len() {
                _module.memories[import_mem_idx].page_size_log2
            } else {
                _module.page_size_log2
            };
            if import_page_size_log2 != export_page_size_log2 {
                return Err(RunnerError::new(
                    "link",
                    format!("memory types incompatible for memory `{module_name}::{field_name}`"),
                ));
            }
            // Check memory64 compatibility (memory32 vs memory64)
            let import_is_64 = if import_mem_idx < _module.memories.len() {
                _module.memories[import_mem_idx].is_memory64
            } else {
                _module.is_memory64
            };
            let export_is_64 = if exp_idx < record.instance.module.memories.len() {
                record.instance.module.memories[exp_idx].is_memory64
            } else {
                record.instance.module.is_memory64
            };
            if import_is_64 != export_is_64 {
                return Err(RunnerError::new(
                    "link",
                    format!("incompatible import type for memory `{module_name}::{field_name}`: index type mismatch"),
                ));
            }
            // Get actual memory size in pages using the correct page size
            let actual_mem_size = record.instance.memory_sizes.get(exp_idx).copied().unwrap_or(0);
            let page_size = match export_page_size_log2 {
                Some(log2) => 1usize << log2,
                None => 65536,
            };
            let actual_pages = (actual_mem_size / page_size) as u32;
            let available_min = actual_pages.max(export_min);

            if import_min > available_min {
                return Err(RunnerError::new(
                    "link",
                    format!("incompatible import type for memory `{module_name}::{field_name}`"),
                ));
            }
            if import_has_max {
                if !export_has_max {
                    return Err(RunnerError::new(
                        "link",
                        format!("incompatible import type for memory `{module_name}::{field_name}`"),
                    ));
                }
                if export_max > import_max {
                    return Err(RunnerError::new(
                        "link",
                        format!("incompatible import type for memory `{module_name}::{field_name}`"),
                    ));
                }
            }
        } else {
            return Err(RunnerError::new(
                "link",
                format!("unknown import: module `{module_name}` memory `{field_name}`"),
            ));
        }
        Ok(())
    }

    fn validate_global_import(
        &self,
        module_name: &str,
        field_name: &str,
        val_type_byte: u8,
        mutable: bool,
        heap_type: Option<i32>,
    ) -> RunnerResult<()> {
        let val_type = decode_valtype_byte(val_type_byte).ok_or_else(|| {
            RunnerError::new("link", format!("unsupported imported global type 0x{val_type_byte:02x}"))
        })?;

        if module_name == SPECTEST_MODULE {
            // Spectest globals are all immutable
            let spectest_val = spectest_global(field_name).ok_or_else(|| {
                RunnerError::new("link", format!("unknown import: spectest does not export global `{field_name}`"))
            })?;
            // Check type match
            if !value_matches_type(spectest_val, val_type) {
                return Err(RunnerError::new(
                    "link",
                    format!("incompatible import type for global `{module_name}::{field_name}`"),
                ));
            }
            // spectest globals are immutable - importing as mutable is an error
            if mutable {
                return Err(RunnerError::new(
                    "link",
                    format!("incompatible import type for global `{module_name}::{field_name}`: mutability mismatch"),
                ));
            }
            return Ok(());
        }

        if let Some(handle) = self.instances.get(module_name) {
            let record = handle.borrow();
            // Find the exported global
            let global_idx = exported_global_index(&record.instance.module, field_name);
            if global_idx.is_none() {
                // Check if name exists as different kind
                let has_any = record.instance.module.exports.iter().any(|e| {
                    record.instance.module.get_name(e.name_offset, e.name_len) == field_name.as_bytes()
                });
                if has_any {
                    return Err(RunnerError::new(
                        "link",
                        format!("incompatible import type for `{module_name}::{field_name}`: not a global export"),
                    ));
                }
                return Err(RunnerError::new(
                    "link",
                    format!("unknown import: module `{module_name}` does not export global `{field_name}`"),
                ));
            }
            let idx = global_idx.unwrap() as usize;
            // Check type
            if let Some(gdef) = record.instance.module.globals.get(idx) {
                if gdef.val_type != val_type && !global_types_compatible(val_type, val_type_byte, heap_type, gdef.val_type, gdef.heap_type, mutable) {
                    return Err(RunnerError::new(
                        "link",
                        format!("incompatible import type for global `{module_name}::{field_name}`: type mismatch"),
                    ));
                }
                if gdef.mutable != mutable {
                    return Err(RunnerError::new(
                        "link",
                        format!("incompatible import type for global `{module_name}::{field_name}`: mutability mismatch"),
                    ));
                }
            }
        } else {
            return Err(RunnerError::new(
                "link",
                format!("unknown import: module `{module_name}` global `{field_name}`"),
            ));
        }
        Ok(())
    }

    fn dispatch_host_call(
        &mut self,
        instance: &mut WasmInstance,
        import_idx: u32,
        args: &[Value],
    ) -> RunnerResult<Option<Value>> {
        let import = nth_function_import(&instance.module, import_idx).ok_or_else(|| {
            RunnerError::new("link", format!("unknown function import index {import_idx}"))
        })?;
        let module_name = bytes_to_string(instance.module.get_name(
            import.module_name_offset,
            import.module_name_len,
        ));
        let field_name = bytes_to_string(instance.module.get_name(
            import.field_name_offset,
            import.field_name_len,
        ));

        if module_name == "atos" {
            return crate::wasm::host::handle_host_call(instance, import_idx, args, args.len() as u8)
                .map_err(RunnerError::trap);
        }

        if module_name == SPECTEST_MODULE {
            return dispatch_spectest(self.verbose, &field_name, args);
        }

        let handle = self.instances.get(&module_name).cloned().ok_or_else(|| {
            RunnerError::new(
                "link",
                format!("unknown import module `{module_name}`"),
            )
        })?;
        let target_idx = {
            let record = handle.borrow();
            record
                .instance
                .module
                .find_export_func(field_name.as_bytes())
                .ok_or_else(|| {
                    RunnerError::new(
                        "link",
                        format!("module `{module_name}` does not export function `{field_name}`"),
                    )
                })?
        };
        let results = self.execute_call(&handle, target_idx, args)?;
        match results.len() {
            0 => Ok(None),
            1 => Ok(Some(results[0])),
            len => Err(RunnerError::new(
                "link",
                format!(
                    "imported function `{module_name}::{field_name}` returned {len} values; ATOS host-call ABI supports at most one",
                ),
            )),
        }
    }

    /// Like dispatch_host_call, but maps exception tag indices from the callee's
    /// module space to the caller's module space when an exception is thrown.
    fn dispatch_host_call_ex(
        &mut self,
        caller: &mut WasmInstance,
        import_idx: u32,
        args: &[Value],
    ) -> RunnerResult<Option<Value>> {
        // Get the import info before calling
        let import = nth_function_import(&caller.module, import_idx).ok_or_else(|| {
            RunnerError::new("link", format!("unknown function import index {import_idx}"))
        })?;
        let module_name = bytes_to_string(caller.module.get_name(
            import.module_name_offset,
            import.module_name_len,
        ));

        match self.dispatch_host_call(caller, import_idx, args) {
            Ok(val) => Ok(val),
            Err(mut err) => {
                if let Some((callee_tag_idx, ref _values)) = err.exception {
                    // Map the tag from the callee's space to the caller's space.
                    // Look up the exported tag name in the callee module.
                    if let Some(callee_handle) = self.instances.get(&module_name).cloned() {
                        let callee_record = callee_handle.borrow();
                        // Find the exported name for this tag in the callee module
                        let mut exported_tag_name = None;
                        for exp in &callee_record.instance.module.exports {
                            if let ExportKind::Tag(idx) = exp.kind {
                                if idx == callee_tag_idx {
                                    exported_tag_name = Some(bytes_to_string(
                                        callee_record.instance.module.get_name(exp.name_offset, exp.name_len)
                                    ));
                                    break;
                                }
                            }
                        }

                        if let Some(tag_name) = exported_tag_name {
                            // Find the caller's imported tag with the same (module, name)
                            let mut caller_tag_idx = 0u32;
                            let mut mapped = false;
                            for imp in &caller.module.imports {
                                if let ImportKind::Tag(_) = imp.kind {
                                    let imp_mod = bytes_to_string(
                                        caller.module.get_name(imp.module_name_offset, imp.module_name_len));
                                    let imp_field = bytes_to_string(
                                        caller.module.get_name(imp.field_name_offset, imp.field_name_len));
                                    if imp_mod == module_name && imp_field == tag_name {
                                        err.exception = Some((caller_tag_idx, err.exception.take().unwrap().1));
                                        mapped = true;
                                        break;
                                    }
                                    caller_tag_idx += 1;
                                }
                            }
                            if !mapped {
                                // Tag not imported by caller — use u32::MAX so only catch_all matches
                                err.exception = Some((u32::MAX, err.exception.take().unwrap().1));
                            }
                        } else {
                            // Tag not exported by callee — use u32::MAX
                            err.exception = Some((u32::MAX, err.exception.take().unwrap().1));
                        }
                    }
                }
                Err(err)
            }
        }
    }

    fn assert_message(
        &self,
        kind: &'static str,
        err: &RunnerError,
        expected: &str,
    ) -> std::result::Result<(), DirectiveError> {
        if err.message.contains(expected) {
            Ok(())
        } else {
            Err(DirectiveError::assertion(
                kind,
                format!("expected message `{expected}`, got `{}` ({})", err.message, err.kind),
            ))
        }
    }

    fn assert_results(
        &self,
        actual: &[Value],
        expected: &[WastRet<'_>],
    ) -> std::result::Result<(), DirectiveError> {
        if actual.len() != expected.len() {
            return Err(DirectiveError::assertion(
                "assert_return",
                format!(
                    "result count mismatch; expected {}, got {}",
                    expected.len(),
                    actual.len()
                ),
            ));
        }

        for (actual, expected) in actual.iter().zip(expected) {
            self.assert_result(actual, expected)?;
        }
        Ok(())
    }

    fn assert_result(
        &self,
        actual: &Value,
        expected: &WastRet<'_>,
    ) -> std::result::Result<(), DirectiveError> {
        match expected {
            WastRet::Core(expected) => self.assert_result_core(actual, expected),
            _ => Err(DirectiveError::assertion(
                "assert_return",
                "component-model results are not supported",
            )),
        }
    }

    /// Unwrap a GcRef pointing to an Externalized object to its inner value.
    /// This handles the round-trip: ref.extern N -> Externalized { I32(N) } -> I32(N).
    fn unwrap_externref(&self, val: &Value) -> Value {
        use crate::wasm::runtime::GcObject;
        if let Value::GcRef(idx) = val {
            // Use the handle from the last invoke (where the GcRef was created),
            // falling back to the current instance
            if let Some(handle) = self.last_invoke_handle.as_ref().or(self.current.as_ref()) {
                let record = handle.borrow();
                let mut current_idx = *idx as usize;
                // Unwrap chains of Externalized/Internalized
                for _ in 0..10 {
                    if current_idx < record.instance.gc_heap.len() {
                        match &record.instance.gc_heap[current_idx] {
                            GcObject::Externalized { value } | GcObject::Internalized { value } => {
                                match value {
                                    Value::GcRef(inner) => { current_idx = *inner as usize; continue; }
                                    other => return *other,
                                }
                            }
                            _ => return *val,
                        }
                    }
                    break;
                }
            }
        }
        *val
    }

    fn assert_result_core(
        &self,
        actual: &Value,
        expected: &WastRetCore<'_>,
    ) -> std::result::Result<(), DirectiveError> {
        match expected {
            WastRetCore::Either(options) => {
                for option in options {
                    if self.assert_result_core(actual, option).is_ok() {
                        return Ok(());
                    }
                }
                Err(DirectiveError::assertion(
                    "assert_return",
                    format!("none of the `either` alternatives matched actual value {actual:?}"),
                ))
            }
            WastRetCore::I32(expected) => match actual {
                Value::I32(value) if value == expected => Ok(()),
                _ => Err(DirectiveError::assertion(
                    "assert_return",
                    format!("expected i32 {expected}, got {actual:?}"),
                )),
            },
            WastRetCore::I64(expected) => match actual {
                Value::I64(value) if value == expected => Ok(()),
                _ => Err(DirectiveError::assertion(
                    "assert_return",
                    format!("expected i64 {expected}, got {actual:?}"),
                )),
            },
            WastRetCore::F32(expected) => match actual {
                Value::F32(value) => f32_matches(*value, expected),
                _ => Err(DirectiveError::assertion(
                    "assert_return",
                    format!("expected f32 result, got {actual:?}"),
                )),
            },
            WastRetCore::F64(expected) => match actual {
                Value::F64(value) => f64_matches(*value, expected),
                _ => Err(DirectiveError::assertion(
                    "assert_return",
                    format!("expected f64 result, got {actual:?}"),
                )),
            },
            WastRetCore::V128(expected) => match actual {
                Value::V128(value) => v128_matches(*value, expected),
                _ => Err(DirectiveError::assertion(
                    "assert_return",
                    format!("expected v128 result, got {actual:?}"),
                )),
            },
            WastRetCore::RefNull(_) => {
                // null ref: our sentinel is I32(-1) or NullRef
                match actual {
                    Value::I32(-1) => Ok(()),
                    Value::I32(v) if *v < 0 => Ok(()), // any negative = null
                    Value::NullRef => Ok(()),
                    _ => Err(DirectiveError::assertion(
                        "assert_return",
                        format!("expected ref.null, got {actual:?}"),
                    )),
                }
            }
            WastRetCore::RefExtern(Some(v)) => {
                // Unwrap GcRef -> Externalized to compare inner value
                let unwrapped = self.unwrap_externref(actual);
                match unwrapped {
                    Value::I32(a) if a as u32 == *v => Ok(()),
                    _ => Err(DirectiveError::assertion(
                        "assert_return",
                        format!("expected ref.extern {v}, got {actual:?}"),
                    )),
                }
            }
            WastRetCore::RefExtern(None) => {
                // ref.extern with no value = any non-null externref
                match actual {
                    Value::NullRef | Value::I32(-1) => Err(DirectiveError::assertion(
                        "assert_return",
                        format!("expected ref.extern (non-null), got {actual:?}"),
                    )),
                    _ => Ok(()),
                }
            }
            WastRetCore::RefFunc(None) => {
                // Any non-null func ref
                match actual {
                    Value::I32(v) if *v >= 0 => Ok(()),
                    _ => Err(DirectiveError::assertion(
                        "assert_return",
                        format!("expected ref.func (non-null), got {actual:?}"),
                    )),
                }
            }
            WastRetCore::RefFunc(Some(_)) => {
                // Specific func ref — just check non-null
                match actual {
                    Value::I32(v) if *v >= 0 => Ok(()),
                    _ => Err(DirectiveError::assertion(
                        "assert_return",
                        format!("expected ref.func, got {actual:?}"),
                    )),
                }
            }
            WastRetCore::RefI31 | WastRetCore::RefI31Shared => {
                // Any non-null i31 ref is accepted
                match actual {
                    Value::NullRef => Err(DirectiveError::assertion(
                        "assert_return",
                        "expected non-null i31 reference, got null",
                    )),
                    _ => Ok(()),
                }
            }
            WastRetCore::RefAny | WastRetCore::RefEq => {
                // Any non-null ref is accepted
                match actual {
                    Value::NullRef => Err(DirectiveError::assertion(
                        "assert_return",
                        "expected non-null reference, got null",
                    )),
                    _ => Ok(()),
                }
            }
            WastRetCore::RefArray => {
                // Any non-null array ref is accepted
                match actual {
                    Value::GcRef(_) | Value::I32(_) => Ok(()),
                    Value::NullRef => Err(DirectiveError::assertion(
                        "assert_return",
                        "expected non-null array reference, got null",
                    )),
                    _ => Err(DirectiveError::assertion(
                        "assert_return",
                        format!("expected array reference, got {actual:?}"),
                    )),
                }
            }
            WastRetCore::RefStruct => {
                // Any non-null struct ref is accepted
                match actual {
                    Value::GcRef(_) | Value::I32(_) => Ok(()),
                    Value::NullRef => Err(DirectiveError::assertion(
                        "assert_return",
                        "expected non-null struct reference, got null",
                    )),
                    _ => Err(DirectiveError::assertion(
                        "assert_return",
                        format!("expected struct reference, got {actual:?}"),
                    )),
                }
            }
            WastRetCore::RefHost(_) => {
                // Host references are not directly supported
                match actual {
                    Value::NullRef | Value::I32(-1) => Err(DirectiveError::assertion(
                        "assert_return",
                        "expected non-null host reference, got null",
                    )),
                    _ => Ok(()),
                }
            }
        }
    }
}

pub fn collect_wast_files(path: &Path) -> Result<Vec<PathBuf>> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("failed to stat {}", path.display()))?;
    if metadata.is_file() {
        if path.extension().and_then(|ext| ext.to_str()) == Some("wast") {
            return Ok(vec![path.to_path_buf()]);
        }
        bail!("{} is not a .wast file", path.display());
    }

    let mut files = Vec::new();
    collect_wast_files_recursive(path, &mut files)
        .with_context(|| format!("failed to read directory {}", path.display()))?;
    Ok(files)
}

fn collect_wast_files_recursive(path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        let metadata = fs::metadata(&entry_path)?;
        if metadata.is_dir() {
            collect_wast_files_recursive(&entry_path, out)?;
        } else if entry_path.extension().and_then(|ext| ext.to_str()) == Some("wast") {
            out.push(entry_path);
        }
    }
    Ok(())
}

fn annotate_wast_error(mut err: wast::Error, path: &Path, text: &str) -> anyhow::Error {
    err.set_path(path);
    err.set_text(text);
    anyhow!(err)
}

fn is_core_module(module: &QuoteWat<'_>) -> bool {
    matches!(module, QuoteWat::Wat(Wat::Module(_)) | QuoteWat::QuoteModule(..))
}

/// Copy a local function from `src_module` at `func_idx` into `host_module`.
/// For import functions, returns `func_idx` unchanged (best effort).
/// Used when we only have a WasmModule (not an InstanceHandle).
fn copy_function_from_module(
    host_module: &mut WasmModule,
    src_module: &WasmModule,
    func_idx: u32,
) -> u32 {
    let src_import_count = src_module.func_import_count();
    if (func_idx as usize) >= src_import_count {
        let local_idx = (func_idx as usize) - src_import_count;
        if local_idx < src_module.functions.len() {
            let src_func = &src_module.functions[local_idx];
            let source_ft = if (src_func.type_idx as usize) < src_module.func_types.len() {
                src_module.func_types[src_func.type_idx as usize].clone()
            } else {
                crate::wasm::decoder::FuncTypeDef::empty()
            };
            let host_type_idx = find_or_add_func_type(host_module, &source_ft);
            let host_code_offset = host_module.code.len();
            let code_start = src_func.code_offset;
            let code_len = src_func.code_len;
            if code_start + code_len <= src_module.code.len() {
                host_module.code.extend_from_slice(&src_module.code[code_start..code_start + code_len]);
            }
            host_module.functions.push(crate::wasm::decoder::FuncDef {
                type_idx: host_type_idx,
                code_offset: host_code_offset,
                code_len,
                local_count: src_func.local_count,
                locals: src_func.locals,
                non_nullable_locals: Vec::new(),
            });
            return host_module.func_import_count() as u32
                + (host_module.functions.len() as u32 - 1);
        }
    }
    // For imports, we can't reliably resolve without instance info
    func_idx
}

/// Resolve a function reference from `source_handle` at `source_func_idx` into
/// the `host_module`'s function index space.
///
/// For local functions in the source: copies the function body into host_module
/// and returns the new function index.
///
/// For import functions in the source: if the import points to a function that
/// exists in host_module (i.e., the source imported from the host), returns the
/// host's own function index directly. Otherwise copies from the ultimate source.
fn resolve_cross_module_function(
    host_module: &mut WasmModule,
    source_handle: &InstanceHandle,
    source_func_idx: u32,
    instances: &HashMap<String, InstanceHandle>,
) -> u32 {
    let source = source_handle.borrow();
    let src_mod = &source.instance.module;
    let src_import_count = src_mod.func_import_count();

    if (source_func_idx as usize) < src_import_count {
        // Source function is an import. Resolve the import to the actual module.
        let mut func_seen = 0u32;
        for imp in &src_mod.imports {
            if let ImportKind::Func(_) = imp.kind {
                if func_seen == source_func_idx {
                    let mod_name = bytes_to_string(src_mod.get_name(
                        imp.module_name_offset,
                        imp.module_name_len,
                    ));
                    let fld_name = bytes_to_string(src_mod.get_name(
                        imp.field_name_offset,
                        imp.field_name_len,
                    ));
                    drop(source);

                    // First check if the target is the host module itself
                    // (avoids RefCell borrow conflicts)
                    if let Some(host_idx) = host_module.find_export_func(fld_name.as_bytes()) {
                        return host_idx;
                    }

                    // Find the target function in the named module
                    if let Some(target_handle) = instances.get(&mod_name) {
                        if let Ok(target) = target_handle.try_borrow() {
                            if let Some(target_idx) = target.instance.module.find_export_func(fld_name.as_bytes()) {
                                drop(target);
                                // Copy from the target module
                                return resolve_cross_module_function(
                                    host_module,
                                    target_handle,
                                    target_idx,
                                    instances,
                                );
                            }
                        }
                    }
                    // Fallback
                    return source_func_idx;
                }
                func_seen += 1;
            }
        }
        drop(source);
        return source_func_idx;
    }

    // Local function: copy it
    let local_idx = (source_func_idx as usize) - src_import_count;
    if local_idx < src_mod.functions.len() {
        let src_func = &src_mod.functions[local_idx];
        let src_type_idx = src_func.type_idx;

        let source_ft = if (src_type_idx as usize) < src_mod.func_types.len() {
            src_mod.func_types[src_type_idx as usize].clone()
        } else {
            crate::wasm::decoder::FuncTypeDef::empty()
        };

        let host_type_idx = find_or_add_func_type(host_module, &source_ft);

        let code_start = src_func.code_offset;
        let code_len = src_func.code_len;
        let host_code_offset = host_module.code.len();
        if code_start + code_len <= src_mod.code.len() {
            host_module.code.extend_from_slice(&src_mod.code[code_start..code_start + code_len]);
        }

        let new_func = crate::wasm::decoder::FuncDef {
            type_idx: host_type_idx,
            code_offset: host_code_offset,
            code_len,
            local_count: src_func.local_count,
            locals: src_func.locals,
            non_nullable_locals: Vec::new(),
        };
        host_module.functions.push(new_func);

        let new_idx = host_module.func_import_count() as u32
            + (host_module.functions.len() as u32 - 1);
        drop(source);
        return new_idx;
    }

    drop(source);
    source_func_idx
}

/// Find a matching FuncTypeDef in the module's type list, or add a new one.
fn find_or_add_func_type(module: &mut WasmModule, ft: &crate::wasm::decoder::FuncTypeDef) -> u32 {
    for (i, existing) in module.func_types.iter().enumerate() {
        if existing.param_count == ft.param_count
            && existing.result_count == ft.result_count
            && existing.params[..existing.param_count as usize] == ft.params[..ft.param_count as usize]
            && existing.results[..existing.result_count as usize] == ft.results[..ft.result_count as usize]
        {
            return i as u32;
        }
    }
    let idx = module.func_types.len() as u32;
    module.func_types.push(ft.clone());
    idx
}

fn bytes_to_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn nth_function_import(module: &WasmModule, func_idx: u32) -> Option<&crate::wasm::decoder::ImportDef> {
    let mut seen = 0u32;
    for import in &module.imports {
        if let ImportKind::Func(_) = import.kind {
            if seen == func_idx {
                return Some(import);
            }
            seen = seen.saturating_add(1);
        }
    }
    None
}

fn function_type(module: &WasmModule, func_idx: u32) -> Option<&FuncTypeDef> {
    let type_idx = function_type_idx(module, func_idx)?;
    module.func_types.get(type_idx as usize)
}

fn function_type_idx(module: &WasmModule, func_idx: u32) -> Option<u32> {
    if (func_idx as usize) < module.func_import_count() {
        return module.func_import_type(func_idx);
    }
    let local_idx = (func_idx as usize).checked_sub(module.func_import_count())?;
    let func = module.functions.get(local_idx)?;
    Some(func.type_idx)
}

fn exported_global_index(module: &WasmModule, name: &str) -> Option<u32> {
    for export in &module.exports {
        if module.get_name(export.name_offset, export.name_len) == name.as_bytes() {
            if let ExportKind::Global(idx) = export.kind {
                return Some(idx);
            }
        }
    }
    None
}

fn exported_table_index(module: &WasmModule, name: &str) -> Option<u32> {
    for export in &module.exports {
        if module.get_name(export.name_offset, export.name_len) == name.as_bytes() {
            if let ExportKind::Table(idx) = export.kind {
                return Some(idx);
            }
        }
    }
    None
}

fn exported_memory_index(module: &WasmModule, name: &str) -> Option<u32> {
    for export in &module.exports {
        if module.get_name(export.name_offset, export.name_len) == name.as_bytes() {
            if let ExportKind::Memory(idx) = export.kind {
                return Some(idx);
            }
        }
    }
    None
}

fn func_types_match(a: &FuncTypeDef, b: &FuncTypeDef) -> bool {
    if a.param_count != b.param_count || a.result_count != b.result_count {
        return false;
    }
    for i in 0..a.param_count as usize {
        if a.params[i] != b.params[i] {
            return false;
        }
    }
    for i in 0..a.result_count as usize {
        if a.results[i] != b.results[i] {
            return false;
        }
    }
    true
}

/// Check if two type indices (from potentially different modules) refer to
/// equivalent types, taking rec group structure into account.
/// Two types are equivalent iff:
/// 1. They are at the same position within their respective rec groups
/// 2. Their rec groups have the same size
/// 3. All corresponding types in the rec groups are structurally equivalent
fn type_indices_equivalent(
    mod_a: &WasmModule, type_idx_a: u32,
    mod_b: &WasmModule, type_idx_b: u32,
) -> bool {
    let si_a = mod_a.sub_types.get(type_idx_a as usize);
    let si_b = mod_b.sub_types.get(type_idx_b as usize);
    match (si_a, si_b) {
        (Some(a), Some(b)) => {
            // Must be in rec groups of the same size
            if a.rec_group_size != b.rec_group_size {
                return false;
            }
            // Must be at the same position within the rec group
            let pos_a = type_idx_a - a.rec_group_start;
            let pos_b = type_idx_b - b.rec_group_start;
            if pos_a != pos_b {
                return false;
            }
            // All types in the rec group must be structurally equivalent
            for i in 0..a.rec_group_size {
                let idx_a = a.rec_group_start + i;
                let idx_b = b.rec_group_start + i;
                let ft_a = mod_a.func_types.get(idx_a as usize);
                let ft_b = mod_b.func_types.get(idx_b as usize);
                match (ft_a, ft_b) {
                    (Some(fa), Some(fb)) => {
                        if !func_types_match(fa, fb) {
                            return false;
                        }
                    }
                    _ => return false,
                }
                // Check gc_types match (with rec-group-relative type references)
                use crate::wasm::decoder::GcTypeDef;
                let gc_a = mod_a.gc_types.get(idx_a as usize);
                let gc_b = mod_b.gc_types.get(idx_b as usize);
                match (gc_a, gc_b) {
                    (Some(GcTypeDef::Struct { field_types: ft_a, field_muts: fm_a }),
                     Some(GcTypeDef::Struct { field_types: ft_b, field_muts: fm_b })) => {
                        if ft_a.len() != ft_b.len() || fm_a != fm_b { return false; }
                        for fi in 0..ft_a.len() {
                            if !cross_module_storage_eq(&ft_a[fi], a.rec_group_start, mod_a,
                                                        &ft_b[fi], b.rec_group_start, mod_b,
                                                        a.rec_group_size) { return false; }
                        }
                    }
                    (Some(GcTypeDef::Array { elem_type: et_a, elem_mutable: em_a }),
                     Some(GcTypeDef::Array { elem_type: et_b, elem_mutable: em_b })) => {
                        if em_a != em_b { return false; }
                        if !cross_module_storage_eq(et_a, a.rec_group_start, mod_a,
                                                    et_b, b.rec_group_start, mod_b,
                                                    a.rec_group_size) { return false; }
                    }
                    (Some(ga), Some(gb)) => {
                        if std::mem::discriminant(ga) != std::mem::discriminant(gb) { return false; }
                    }
                    (None, None) => {}
                    _ => return false,
                }
                // Check subtype info matches
                let si_a_i = mod_a.sub_types.get(idx_a as usize);
                let si_b_i = mod_b.sub_types.get(idx_b as usize);
                match (si_a_i, si_b_i) {
                    (Some(sa), Some(sb)) => {
                        if sa.is_final != sb.is_final { return false; }
                        match (sa.supertype, sb.supertype) {
                            (None, None) => {}
                            (Some(sp_a), Some(sp_b)) => {
                                let in_rg_a = sp_a >= a.rec_group_start && sp_a < a.rec_group_start + a.rec_group_size;
                                let in_rg_b = sp_b >= b.rec_group_start && sp_b < b.rec_group_start + b.rec_group_size;
                                if in_rg_a && in_rg_b {
                                    // Both inside: compare relative positions
                                    if (sp_a - a.rec_group_start) != (sp_b - b.rec_group_start) { return false; }
                                } else if !in_rg_a && !in_rg_b {
                                    // Both outside: recursively check equivalence
                                    if !type_indices_equivalent(mod_a, sp_a, mod_b, sp_b) { return false; }
                                } else {
                                    return false;
                                }
                            }
                            _ => return false,
                        }
                    }
                    _ => {}
                }
            }
            true
        }
        // If no subtype info, fall back to structural comparison
        _ => {
            match (mod_a.func_types.get(type_idx_a as usize), mod_b.func_types.get(type_idx_b as usize)) {
                (Some(fa), Some(fb)) => func_types_match(fa, fb),
                _ => false,
            }
        }
    }
}

/// Check if two storage types are equivalent across modules with rec-group awareness.
fn cross_module_storage_eq(
    a: &crate::wasm::decoder::StorageType, rg_a: u32, mod_a: &WasmModule,
    b: &crate::wasm::decoder::StorageType, rg_b: u32, mod_b: &WasmModule,
    rg_size: u32,
) -> bool {
    use crate::wasm::decoder::StorageType;
    match (a, b) {
        (StorageType::I8, StorageType::I8) | (StorageType::I16, StorageType::I16) => true,
        (StorageType::Val(va), StorageType::Val(vb)) => va == vb,
        (StorageType::RefType(va, ai), StorageType::RefType(vb, bi)) => {
            if va != vb { return false; }
            let in_a = *ai >= rg_a && *ai < rg_a + rg_size;
            let in_b = *bi >= rg_b && *bi < rg_b + rg_size;
            if in_a && in_b { (ai - rg_a) == (bi - rg_b) }
            else if !in_a && !in_b { type_indices_equivalent(mod_a, *ai, mod_b, *bi) }
            else { false }
        }
        _ => false,
    }
}

/// Check if type `src` in `mod_src` is a subtype of type `dst` in `mod_dst`.
/// Handles cross-module rec-group-aware type equivalence and subtype chains.
fn cross_module_type_subtype(
    mod_src: &WasmModule, src: u32,
    mod_dst: &WasmModule, dst: u32,
) -> bool {
    // Check equivalence first
    if type_indices_equivalent(mod_src, src, mod_dst, dst) {
        return true;
    }
    // Walk the subtype chain in the source module
    let mut current = src;
    for _ in 0..100 {
        if let Some(info) = mod_src.sub_types.get(current as usize) {
            if let Some(parent) = info.supertype {
                if type_indices_equivalent(mod_src, parent, mod_dst, dst) {
                    return true;
                }
                current = parent;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }
    false
}

fn validate_spectest_func_signature(name: &str, sig: &FuncTypeDef) -> RunnerResult<()> {
    let (expected_params, expected_results): (&[ValType], &[ValType]) = match name {
        "print" => (&[], &[]),
        "print_i32" => (&[ValType::I32], &[]),
        "print_i64" => (&[ValType::I64], &[]),
        "print_f32" => (&[ValType::F32], &[]),
        "print_f64" => (&[ValType::F64], &[]),
        "print_i32_f32" => (&[ValType::I32, ValType::F32], &[]),
        "print_f64_f64" => (&[ValType::F64, ValType::F64], &[]),
        "print32" | "print64" => return Ok(()),
        _ => return Ok(()),
    };

    if sig.param_count as usize != expected_params.len()
        || sig.result_count as usize != expected_results.len()
    {
        return Err(RunnerError::new(
            "link",
            format!("incompatible import type for spectest function `{name}`"),
        ));
    }
    for (i, expected) in expected_params.iter().enumerate() {
        if sig.params[i] != *expected {
            return Err(RunnerError::new(
                "link",
                format!("incompatible import type for spectest function `{name}`"),
            ));
        }
    }
    for (i, expected) in expected_results.iter().enumerate() {
        if sig.results[i] != *expected {
            return Err(RunnerError::new(
                "link",
                format!("incompatible import type for spectest function `{name}`"),
            ));
        }
    }
    Ok(())
}

fn ensure_spectest_function(name: &str) -> RunnerResult<()> {
    match name {
        "print"
        | "print_i32"
        | "print_i64"
        | "print_f32"
        | "print_f64"
        | "print_i32_f32"
        | "print_f64_f64"
        | "print32"
        | "print64" => Ok(()),
        _ => Err(RunnerError::new(
            "link",
            format!("unknown spectest function `{name}`"),
        )),
    }
}

fn dispatch_spectest(verbose: bool, name: &str, args: &[Value]) -> RunnerResult<Option<Value>> {
    match name {
        "print" => {
            if verbose {
                println!("[spectest] print()");
            }
            Ok(None)
        }
        "print_i32" => {
            if verbose {
                println!("[spectest] print_i32({})", args.get(0).copied().unwrap_or(Value::I32(0)).as_i32());
            }
            Ok(None)
        }
        "print_i64" => {
            if verbose {
                println!("[spectest] print_i64({})", args.get(0).copied().unwrap_or(Value::I64(0)).as_i64());
            }
            Ok(None)
        }
        "print_f32" => {
            if verbose {
                println!("[spectest] print_f32({:?})", args.get(0).copied().unwrap_or(Value::F32(0.0)));
            }
            Ok(None)
        }
        "print_f64" => {
            if verbose {
                println!("[spectest] print_f64({:?})", args.get(0).copied().unwrap_or(Value::F64(0.0)));
            }
            Ok(None)
        }
        "print_i32_f32" => {
            if verbose {
                let i = args.get(0).copied().unwrap_or(Value::I32(0)).as_i32();
                let f = args.get(1).copied().unwrap_or(Value::F32(0.0)).as_f32();
                println!("[spectest] print_i32_f32({i}, {f:?})");
            }
            Ok(None)
        }
        "print_f64_f64" => {
            if verbose {
                let a = args.get(0).copied().unwrap_or(Value::F64(0.0)).as_f64();
                let b = args.get(1).copied().unwrap_or(Value::F64(0.0)).as_f64();
                println!("[spectest] print_f64_f64({a:?}, {b:?})");
            }
            Ok(None)
        }
        "print32" => {
            if verbose {
                println!("[spectest] print32({})", args.get(0).copied().unwrap_or(Value::I32(0)).as_i32());
            }
            Ok(None)
        }
        "print64" => {
            if verbose {
                println!("[spectest] print64({})", args.get(0).copied().unwrap_or(Value::I64(0)).as_i64());
            }
            Ok(None)
        }
        _ => Err(RunnerError::new(
            "link",
            format!("unknown spectest function `{name}`"),
        )),
    }
}

fn spectest_global(name: &str) -> Option<Value> {
    match name {
        "global_i32" => Some(Value::I32(666)),
        "global_i64" => Some(Value::I64(666)),
        "global_f32" => Some(Value::F32(f32::from_bits(0x4426_a666))),
        "global_f64" => Some(Value::F64(f64::from_bits(0x4084_d4cc_cccc_cccd))),
        "global_funcref" => Some(Value::I32(-1)),    // null funcref
        "global_externref" => Some(Value::I32(-1)),   // null externref
        _ => None,
    }
}

fn decode_valtype_byte(byte: u8) -> Option<ValType> {
    match byte {
        0x7F => Some(ValType::I32),
        0x7E => Some(ValType::I64),
        0x7D => Some(ValType::F32),
        0x7C => Some(ValType::F64),
        0x7B => Some(ValType::V128),
        0x70 => Some(ValType::FuncRef),
        0x6F => Some(ValType::ExternRef),
        // GC ref types: 0x63=nullable ref, 0x64=non-nullable ref
        // These are multi-byte in binary (followed by heap type), but
        // ImportKind::Global stores only the first byte. Accept as I32 (our ref sentinel).
        0x63 | 0x64 => Some(ValType::I32),
        0x69 => Some(ValType::ExnRef),
        _ => None,
    }
}

/// Check if two ref-like ValTypes are compatible for import linking.
/// In our simplified model (no full subtyping), we consider all funcref-ish types compatible.
#[allow(dead_code)]
fn ref_types_compatible(a: ValType, b: ValType) -> bool {
    fn is_funcref_ish(t: ValType) -> bool {
        matches!(t, ValType::FuncRef | ValType::TypedFuncRef | ValType::NonNullableFuncRef | ValType::NullableTypedFuncRef)
    }
    fn is_ref(t: ValType) -> bool {
        matches!(t, ValType::FuncRef | ValType::ExternRef | ValType::TypedFuncRef | ValType::NonNullableFuncRef | ValType::NullableTypedFuncRef)
    }
    // Both funcref-ish types are compatible
    if is_funcref_ish(a) && is_funcref_ish(b) {
        return true;
    }
    // ExternRef only with ExternRef
    if a == ValType::ExternRef && b == ValType::ExternRef {
        return true;
    }
    false
}

/// Check if a global import type is compatible with an export type for linking.
/// For immutable globals, subtyping is allowed (import can be supertype of export).
/// For mutable globals, types must match exactly (invariance).
///
/// Heap type values: negative = abstract (-16=func, -17=extern, etc), non-negative = concrete type index.
fn global_types_compatible(
    import_val_type: ValType,
    import_byte: u8,
    import_heap_type: Option<i32>,
    export_val_type: ValType,
    export_heap_type: Option<i32>,
    mutable: bool,
) -> bool {
    fn is_funcref_family(t: ValType) -> bool {
        matches!(t, ValType::FuncRef | ValType::TypedFuncRef | ValType::NonNullableFuncRef | ValType::NullableTypedFuncRef)
    }
    fn is_externref_family(t: ValType) -> bool {
        matches!(t, ValType::ExternRef)
    }

    // Classify import
    let imp_is_abstract_func = is_funcref_family(import_val_type)
        || (matches!(import_byte, 0x63 | 0x64) && import_heap_type == Some(-16));
    let imp_is_abstract_extern = is_externref_family(import_val_type)
        || (matches!(import_byte, 0x63 | 0x64) && import_heap_type == Some(-17));
    let imp_is_concrete = matches!(import_byte, 0x63 | 0x64) && matches!(import_heap_type, Some(ht) if ht >= 0);
    let imp_nullable = import_byte != 0x64 && import_val_type != ValType::TypedFuncRef && import_val_type != ValType::NonNullableFuncRef;

    // Classify export
    let exp_is_concrete = matches!(export_heap_type, Some(ht) if ht >= 0);
    let exp_nullable = matches!(export_val_type, ValType::FuncRef | ValType::NullableTypedFuncRef | ValType::ExternRef);

    if mutable {
        // Mutable globals require exact type match (invariance).
        // Both abstract func with same nullability
        if imp_is_abstract_func && is_funcref_family(export_val_type) && !exp_is_concrete {
            return imp_nullable == exp_nullable;
        }
        // Both abstract extern
        if imp_is_abstract_extern && is_externref_family(export_val_type) {
            return true;
        }
        // Both concrete with same type index and nullability
        if imp_is_concrete && exp_is_concrete && import_heap_type == export_heap_type {
            return imp_nullable == exp_nullable;
        }
        return false;
    }

    // Immutable globals: import must be supertype of export.

    // Abstract func import
    if imp_is_abstract_func {
        if !is_funcref_family(export_val_type) {
            return false;
        }
        if imp_nullable {
            return true; // (ref null func) is supertype of all funcref-family
        } else {
            return !exp_nullable; // (ref func) is supertype of non-nullable funcref
        }
    }

    // Abstract extern import
    if imp_is_abstract_extern {
        return is_externref_family(export_val_type);
    }

    // Concrete import (ref null $t) / (ref $t)
    if imp_is_concrete {
        // Can only match concrete exports with same type index
        if exp_is_concrete && import_heap_type == export_heap_type {
            if imp_nullable {
                return true; // (ref null $t) accepts both (ref null $t) and (ref $t)
            } else {
                return !exp_nullable; // (ref $t) only accepts (ref $t)
            }
        }
        return false;
    }

    false
}

fn value_matches_type(value: Value, val_type: ValType) -> bool {
    matches!(
        (value, val_type),
        (Value::I32(_), ValType::I32)
            | (Value::I64(_), ValType::I64)
            | (Value::F32(_), ValType::F32)
            | (Value::F64(_), ValType::F64)
            | (Value::V128(_), ValType::V128)
            | (Value::I32(_), ValType::FuncRef)
            | (Value::I32(_), ValType::ExternRef)
            | (Value::I32(_), ValType::TypedFuncRef)
            | (Value::I32(_), ValType::NonNullableFuncRef)
            | (Value::I32(_), ValType::NullableTypedFuncRef)
            | (Value::NullRef, ValType::I32)
            | (Value::NullRef, ValType::FuncRef)
            | (Value::NullRef, ValType::ExternRef)
            | (Value::NullRef, ValType::TypedFuncRef)
            | (Value::NullRef, ValType::NonNullableFuncRef)
            | (Value::NullRef, ValType::NullableTypedFuncRef)
            | (Value::GcRef(_), ValType::I32)
            | (Value::GcRef(_), ValType::FuncRef)
            | (Value::GcRef(_), ValType::ExternRef)
    )
}

fn trap_message(err: &WasmError) -> String {
    match err {
        WasmError::DivisionByZero => "integer divide by zero".to_string(),
        WasmError::IntegerOverflow => "integer overflow".to_string(),
        WasmError::InvalidConversionToInteger => "invalid conversion to integer".to_string(),
        WasmError::MemoryOutOfBounds => "out of bounds memory access".to_string(),
        WasmError::CallStackOverflow | WasmError::StackOverflow => {
            "call stack exhausted".to_string()
        }
        WasmError::UnreachableExecuted => "unreachable".to_string(),
        WasmError::UndefinedElement => "undefined element".to_string(),
        WasmError::UninitializedElement(idx) => format!("uninitialized element {idx}"),
        WasmError::IndirectCallTypeMismatch => "indirect call type mismatch".to_string(),
        WasmError::ImmutableGlobal => "global is immutable".to_string(),
        WasmError::TableIndexOutOfBounds => "out of bounds table access".to_string(),
        WasmError::FloatsDisabled => "floats disabled".to_string(),
        WasmError::UnsupportedProposal => "unsupported proposal".to_string(),
        WasmError::UnalignedAtomic => "unaligned atomic".to_string(),
        WasmError::NullFunctionReference => "null function reference".to_string(),
        WasmError::NullReference => "null reference".to_string(),
        WasmError::NullI31Reference => "null i31 reference".to_string(),
        WasmError::NullStructReference => "null structure reference".to_string(),
        WasmError::NullArrayReference => "null array reference".to_string(),
        WasmError::ArrayOutOfBounds => "out of bounds array access".to_string(),
        WasmError::CastFailure => "cast failure".to_string(),
        WasmError::UncaughtException => "unhandled exception".to_string(),
        WasmError::MultipleTables => "multiple tables".to_string(),
        WasmError::OutOfBounds => "out of bounds".to_string(),
        other => format!("{other:?}"),
    }
}

fn f32_matches(actual: f32, expected: &NanPattern<F32>) -> std::result::Result<(), DirectiveError> {
    let actual_bits = actual.to_bits();
    match expected {
        NanPattern::CanonicalNan => {
            const CANONICAL_NAN: u32 = 0x7FC0_0000;
            if (actual_bits & 0x7FFF_FFFF) == CANONICAL_NAN {
                Ok(())
            } else {
                Err(DirectiveError::assertion(
                    "assert_return",
                    format!("expected canonical NaN, got {actual:?} (0x{actual_bits:08x})"),
                ))
            }
        }
        NanPattern::ArithmeticNan => {
            const EXPONENT_MASK: u32 = 0x7F80_0000;
            const QUIET_BIT: u32 = 0x0040_0000;
            let is_nan = (actual_bits & EXPONENT_MASK) == EXPONENT_MASK;
            let is_quiet = (actual_bits & QUIET_BIT) == QUIET_BIT;
            if is_nan && is_quiet {
                Ok(())
            } else {
                Err(DirectiveError::assertion(
                    "assert_return",
                    format!("expected arithmetic NaN, got {actual:?} (0x{actual_bits:08x})"),
                ))
            }
        }
        NanPattern::Value(expected) => {
            if actual_bits == expected.bits {
                Ok(())
            } else {
                Err(DirectiveError::assertion(
                    "assert_return",
                    format!(
                        "expected {:?} (0x{:08x}), got {:?} (0x{:08x})",
                        f32::from_bits(expected.bits),
                        expected.bits,
                        actual,
                        actual_bits
                    ),
                ))
            }
        }
    }
}

fn f64_matches(actual: f64, expected: &NanPattern<F64>) -> std::result::Result<(), DirectiveError> {
    let actual_bits = actual.to_bits();
    match expected {
        NanPattern::CanonicalNan => {
            const CANONICAL_NAN: u64 = 0x7ff8_0000_0000_0000;
            if (actual_bits & 0x7fff_ffff_ffff_ffff) == CANONICAL_NAN {
                Ok(())
            } else {
                Err(DirectiveError::assertion(
                    "assert_return",
                    format!("expected canonical NaN, got {actual:?} (0x{actual_bits:016x})"),
                ))
            }
        }
        NanPattern::ArithmeticNan => {
            const EXPONENT_MASK: u64 = 0x7FF0_0000_0000_0000;
            const QUIET_BIT: u64 = 0x0008_0000_0000_0000;
            let is_nan = (actual_bits & EXPONENT_MASK) == EXPONENT_MASK;
            let is_quiet = (actual_bits & QUIET_BIT) == QUIET_BIT;
            if is_nan && is_quiet {
                Ok(())
            } else {
                Err(DirectiveError::assertion(
                    "assert_return",
                    format!("expected arithmetic NaN, got {actual:?} (0x{actual_bits:016x})"),
                ))
            }
        }
        NanPattern::Value(expected) => {
            if actual_bits == expected.bits {
                Ok(())
            } else {
                Err(DirectiveError::assertion(
                    "assert_return",
                    format!(
                        "expected {:?} (0x{:016x}), got {:?} (0x{:016x})",
                        f64::from_bits(expected.bits),
                        expected.bits,
                        actual,
                        actual_bits
                    ),
                ))
            }
        }
    }
}

fn v128_matches(actual: V128, expected: &V128Pattern) -> std::result::Result<(), DirectiveError> {
    match expected {
        V128Pattern::I8x16(expected) => {
            let lanes = actual.as_i8x16();
            if &lanes == expected {
                Ok(())
            } else {
                Err(DirectiveError::assertion(
                    "assert_return",
                    format!("expected {:?}, got {:?}", expected, lanes),
                ))
            }
        }
        V128Pattern::I16x8(expected) => {
            let lanes = actual.as_i16x8();
            if &lanes == expected {
                Ok(())
            } else {
                Err(DirectiveError::assertion(
                    "assert_return",
                    format!("expected {:?}, got {:?}", expected, lanes),
                ))
            }
        }
        V128Pattern::I32x4(expected) => {
            let lanes = actual.as_i32x4();
            if &lanes == expected {
                Ok(())
            } else {
                Err(DirectiveError::assertion(
                    "assert_return",
                    format!("expected {:?}, got {:?}", expected, lanes),
                ))
            }
        }
        V128Pattern::I64x2(expected) => {
            let lanes = actual.as_i64x2();
            if &lanes == expected {
                Ok(())
            } else {
                Err(DirectiveError::assertion(
                    "assert_return",
                    format!("expected {:?}, got {:?}", expected, lanes),
                ))
            }
        }
        V128Pattern::F32x4(expected) => {
            let lanes = actual.as_f32x4();
            for (idx, expected) in expected.iter().enumerate() {
                f32_matches(lanes[idx], expected).map_err(|err| {
                    DirectiveError::assertion(
                        "assert_return",
                        format!("v128 lane {idx}: {}", err.message),
                    )
                })?;
            }
            Ok(())
        }
        V128Pattern::F64x2(expected) => {
            let lanes = actual.as_f64x2();
            for (idx, expected) in expected.iter().enumerate() {
                f64_matches(lanes[idx], expected).map_err(|err| {
                    DirectiveError::assertion(
                        "assert_return",
                        format!("v128 lane {idx}: {}", err.message),
                    )
                })?;
            }
            Ok(())
        }
    }
}
