//! atos inspect — parse ATOS serial event log
//!
//! Usage:
//!   atos inspect <event-log.txt>
//!
//! Reads a text file captured from ATOS serial output and provides
//! statistics about events, agents, and system state.

use std::fs;
use std::collections::HashMap;

pub fn run(args: &[String]) {
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        println!("Usage: atos inspect <event-log.txt>");
        println!();
        println!("Parse ATOS serial output and display statistics.");
        return;
    }

    let path = &args[0];
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[atos-inspect] Failed to read {}: {}", path, e);
            std::process::exit(1);
        }
    };

    let mut event_count = 0u64;
    let mut event_types: HashMap<String, u64> = HashMap::new();
    let mut agent_events: HashMap<String, u64> = HashMap::new();
    let mut max_tick = 0u64;
    let mut max_seq = 0u64;

    for line in content.lines() {
        if !line.starts_with("[EVENT") { continue; }
        event_count += 1;

        // Parse: [EVENT seq=N tick=N agent=N type=TYPE arg0=N arg1=N status=N]
        if let Some(seq) = extract_field(line, "seq=") {
            if seq > max_seq { max_seq = seq; }
        }
        if let Some(tick) = extract_field(line, "tick=") {
            if tick > max_tick { max_tick = tick; }
        }
        if let Some(agent) = extract_field(line, "agent=") {
            let key = format!("agent_{}", agent);
            *agent_events.entry(key).or_insert(0) += 1;
        }
        if let Some(etype) = extract_str_field(line, "type=") {
            *event_types.entry(etype).or_insert(0) += 1;
        }
    }

    println!("╔══════════════════════════════════════════════╗");
    println!("║         ATOS EVENT LOG ANALYSIS              ║");
    println!("╠══════════════════════════════════════════════╣");
    println!("║ File: {:38} ║", truncate(path, 38));
    println!("║ Total events: {:30} ║", event_count);
    println!("║ Max sequence: {:30} ║", max_seq);
    println!("║ Max tick:     {:30} ║", max_tick);
    println!("╠══════════════════════════════════════════════╣");
    println!("║ Events by type:                             ║");

    let mut types_vec: Vec<_> = event_types.iter().collect();
    types_vec.sort_by(|a, b| b.1.cmp(a.1));
    for (etype, count) in types_vec.iter().take(10) {
        println!("║   {:28} {:10} ║", truncate(etype, 28), count);
    }

    println!("╠══════════════════════════════════════════════╣");
    println!("║ Events by agent:                            ║");

    let mut agents_vec: Vec<_> = agent_events.iter().collect();
    agents_vec.sort_by(|a, b| a.0.cmp(b.0));
    for (agent, count) in agents_vec.iter().take(16) {
        println!("║   {:28} {:10} ║", agent, count);
    }

    println!("╚══════════════════════════════════════════════╝");
}

fn extract_field(line: &str, prefix: &str) -> Option<u64> {
    let start = line.find(prefix)? + prefix.len();
    let rest = &line[start..];
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn extract_str_field(line: &str, prefix: &str) -> Option<String> {
    let start = line.find(prefix)? + prefix.len();
    let rest = &line[start..];
    let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max { s } else { &s[..max] }
}
