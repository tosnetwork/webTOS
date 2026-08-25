//! Milestone-6 workload gates: OpenFox (a real Go agent binary) inside the
//! machine.
//!
//! Requires the fixture from `tools/build_openfox_fixture.sh` (a static
//! CGO-free build of the pinned OpenFox commit); every test skips with a
//! message when it is absent. These gates exercise the whole Go runtime:
//! threads over CLONE_VM with a shared group address space, timed futexes,
//! timed epoll waits, nanosleep parking, and signal dispositions.

use std::path::PathBuf;

use linux_compat::Machine;
use x64_engine::{CpuExit, EngineConfig};

fn ldef_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .try_init();
}

fn compile_c(name: &str, source: &str, extra: &[&str]) -> Option<Vec<u8>> {
    use std::process::Command;
    let dir = std::env::temp_dir().join("webtos-m6-fixture");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let src = dir.join(format!("{name}.c"));
    let out = dir.join(name);
    std::fs::write(&src, source).expect("write source");
    let mut cmd = Command::new("gcc");
    cmd.arg("-O1")
        .arg("-static")
        .arg("-o")
        .arg(&out)
        .arg(&src)
        .args(extra);
    match cmd.status() {
        Ok(status) if status.success() => Some(std::fs::read(&out).expect("compiler output")),
        _ => {
            eprintln!("skipping: fixture compiler unavailable ({cmd:?})");
            None
        }
    }
}

fn openfox() -> Option<Vec<u8>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_data/openfox");
    match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(_) => {
            eprintln!(
                "skipping: {} missing (run tools/build_openfox_fixture.sh)",
                path.display()
            );
            None
        }
    }
}

struct Run {
    exit: CpuExit,
    output: String,
}

fn machine_with_openfox(image: Vec<u8>) -> Machine {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .try_init();
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/openfox", image, 0o755)
        .expect("add openfox");
    machine
}

fn run_openfox(machine: &mut Machine, args: &[&str]) -> Run {
    let mut argv: Vec<Vec<u8>> = vec![b"openfox".to_vec()];
    argv.extend(args.iter().map(|a| a.as_bytes().to_vec()));
    machine.set_args(
        argv,
        vec![
            b"HOME=/root".to_vec(),
            b"PATH=/bin".to_vec(),
            b"TERM=xterm".to_vec(),
            // Belt and braces: preemption signals are dropped anyway.
            b"GODEBUG=asyncpreemptoff=1".to_vec(),
        ],
    );
    machine.load(b"/bin/openfox").expect("ELF load failed");
    machine.vm_mut().icount_limit = machine.icount() + 20_000_000_000;
    let exit = machine.run();
    let output = String::from_utf8_lossy(&machine.take_output()).into_owned();
    Run { exit, output }
}

fn expect_clean(run: &Run) {
    assert_eq!(
        run.exit,
        CpuExit::Halt { code: Some(0) },
        "guest did not exit cleanly; output tail: {:?}",
        &run.output[run.output.len().saturating_sub(600)..]
    );
}

#[test]
fn openfox_version_reports_cleanly() {
    let Some(image) = openfox() else { return };
    let mut machine = machine_with_openfox(image);
    let run = run_openfox(&mut machine, &["version"]);
    expect_clean(&run);
    assert!(
        run.output.contains("openfox") && run.output.contains("Go: go1."),
        "version output tail: {:?}",
        &run.output[run.output.len().saturating_sub(300)..]
    );
}

#[test]
fn openfox_help_lists_commands() {
    let Some(image) = openfox() else { return };
    let mut machine = machine_with_openfox(image);
    let run = run_openfox(&mut machine, &["--help"]);
    expect_clean(&run);
    for expected in ["Usage", "version", "status"] {
        assert!(
            run.output.contains(expected),
            "help output missing {expected:?}: {:?}",
            &run.output[run.output.len().saturating_sub(400)..]
        );
    }
}

#[test]
fn openfox_status_sees_configuration_across_a_snapshot() {
    let Some(image) = openfox() else { return };
    let mut machine = machine_with_openfox(image);

    // Fresh profile: status must run cleanly and report missing config.
    let run = run_openfox(&mut machine, &["status"]);
    expect_clean(&run);
    assert!(
        run.output.contains("config.json \u{2717}"),
        "expected missing-config marker: {:?}",
        &run.output[run.output.len().saturating_sub(400)..]
    );

    // Seed a configuration and workspace, snapshot the filesystem
    // (browser-reload semantics), restore into a new machine: status must
    // now see both.
    machine
        .add_file(b"/root/.openfox/config.json", b"{}\n".to_vec(), 0o644)
        .expect("seed config");
    machine
        .env()
        .vfs
        .mkdir_p(b"/root/.openfox/workspace")
        .expect("seed workspace");
    let snapshot = machine.export_fs();

    let mut reborn =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    reborn.import_fs(&snapshot).expect("snapshot import failed");
    let run = run_openfox(&mut reborn, &["status"]);
    expect_clean(&run);
    assert!(
        run.output.contains("config.json \u{2713}"),
        "config did not survive the snapshot: {:?}",
        &run.output[run.output.len().saturating_sub(400)..]
    );
    assert!(
        run.output.contains("workspace \u{2713}"),
        "workspace did not survive the snapshot: {:?}",
        &run.output[run.output.len().saturating_sub(400)..]
    );
}

// ── Scripted network-backed agent task ──────────────────────────────────────

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::LazyLock;
use std::sync::{Arc, Mutex};

static REQUEST_AUTH: LazyLock<Arc<Mutex<Vec<String>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(Vec::new())));

/// A scripted OpenAI-compatible endpoint: turn 1 instructs the agent to
/// read NOTES.md via its read_file tool; once the tool result (containing
/// the repository marker) comes back, it answers with a final message.
/// Handles both plain JSON and SSE streaming responses, and keep-alive
/// connections. Every request body is recorded for assertions.
fn spawn_mock_llm(marker: &'static str) -> (SocketAddrV4, Arc<Mutex<Vec<String>>>) {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let addr = match listener.local_addr().expect("local addr") {
        std::net::SocketAddr::V4(addr) => addr,
        _ => unreachable!("bound to IPv4"),
    };
    let bodies: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&bodies);
    let auth = Arc::clone(&REQUEST_AUTH);

    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let recorded = Arc::clone(&recorded);
            let auth = Arc::clone(&auth);
            std::thread::spawn(move || {
                let mut stream = stream;
                loop {
                    // Read one HTTP request (headers, then Content-Length body).
                    let mut buf = Vec::new();
                    let mut byte = [0_u8; 1];
                    let header_end;
                    loop {
                        match stream.read(&mut byte) {
                            Ok(0) => return,
                            Ok(_) => buf.push(byte[0]),
                            Err(_) => return,
                        }
                        if buf.ends_with(b"\r\n\r\n") {
                            header_end = buf.len();
                            break;
                        }
                        if buf.len() > 65536 {
                            return;
                        }
                    }
                    let headers = String::from_utf8_lossy(&buf[..header_end]).to_string();
                    for line in headers.lines() {
                        if line.to_ascii_lowercase().starts_with("authorization:") {
                            auth.lock().expect("lock").push(line.to_string());
                        }
                    }
                    let content_length: usize = headers
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    let mut body = vec![0_u8; content_length];
                    if content_length > 0 && stream.read_exact(&mut body).is_err() {
                        return;
                    }
                    let body = String::from_utf8_lossy(&body).to_string();
                    recorded.lock().expect("lock").push(body.clone());

                    let streaming = body.contains("\"stream\":true");
                    let tool_result_round = body.contains(marker);
                    let response_payload = if tool_result_round {
                        format!(
                            "{{\"role\":\"assistant\",\"content\":\"TASK-RESULT: the note says {marker}\"}}"
                        )
                    } else {
                        "{\"role\":\"assistant\",\"content\":null,\"tool_calls\":[{\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"read_file\",\"arguments\":\"{\\\"path\\\":\\\"NOTES.md\\\"}\"}}]}".to_string()
                    };
                    let finish = if tool_result_round {
                        "stop"
                    } else {
                        "tool_calls"
                    };

                    let http = if streaming {
                        // SSE: one delta chunk carrying the whole message,
                        // then the finish chunk and [DONE].
                        let delta = response_payload.replacen("\"role\":\"assistant\",", "", 1);
                        let chunk1 = "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-test\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null}]}\n\n".to_string();
                        let chunk2 = format!(
                            "data: {{\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-test\",\"choices\":[{{\"index\":0,\"delta\":{delta},\"finish_reason\":null}}]}}\n\n"
                        );
                        let chunk3 = format!(
                            "data: {{\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-test\",\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"{finish}\"}}]}}\n\ndata: [DONE]\n\n"
                        );
                        let sse = format!("{chunk1}{chunk2}{chunk3}");
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\n\r\n{sse}",
                            sse.len()
                        )
                    } else {
                        let json = format!(
                            "{{\"id\":\"r1\",\"object\":\"chat.completion\",\"created\":1,\"model\":\"gpt-test\",\"choices\":[{{\"index\":0,\"message\":{response_payload},\"finish_reason\":\"{finish}\"}}],\"usage\":{{\"prompt_tokens\":1,\"completion_tokens\":1,\"total_tokens\":2}}}}"
                        );
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{json}",
                            json.len()
                        )
                    };
                    if stream.write_all(http.as_bytes()).is_err() {
                        return;
                    }
                }
            });
        }
    });
    (addr, bodies)
}

#[test]
fn openfox_completes_a_scripted_network_agent_task() {
    use linux_compat::net::NativeBroker;
    use std::cell::RefCell;
    use std::rc::Rc;

    const MARKER: &str = "hello-from-repo-42";
    let Some(image) = openfox() else { return };
    let (llm, bodies) = spawn_mock_llm(MARKER);

    let mut machine = machine_with_openfox(image);

    // "Mounted test repository": the agent workspace with a note to read.
    machine
        .add_file(
            b"/root/.openfox/workspace/NOTES.md",
            format!("{MARKER}\n").into_bytes(),
            0o644,
        )
        .expect("seed repository");

    // Configuration pointing the model at the mock endpoint.
    let config = r#"{
  "version": 3,
  "agents": {
    "defaults": {
      "workspace": "~/.openfox/workspace",
      "restrict_to_workspace": true,
      "model_name": "gpt-test",
      "max_tokens": 1024,
      "context_window": 32768,
      "max_tool_iterations": 4
    }
  },
  "model_list": [
    {
      "model_name": "gpt-test",
      "model": "openai/gpt-test",
      "api_keys": ["${OPENAI_API_KEY}"],
      "api_base": "http://10.0.0.7/v1"
    }
  ]
}
"#;
    machine
        .add_file(
            b"/root/.openfox/config.json",
            config.as_bytes().to_vec(),
            0o644,
        )
        .expect("seed config");

    // The API key is injected by the host, never written into the config on
    // disk. A snapshot taken now must contain the placeholder, not the key.
    const SECRET_KEY: &str = "sk-webtos-secret-do-not-persist";
    machine.set_secret("OPENAI_API_KEY", SECRET_KEY);
    let snapshot_before = machine.export_fs();
    let snap_text = String::from_utf8_lossy(&snapshot_before);
    assert!(
        !snap_text.contains(SECRET_KEY),
        "the injected secret leaked into the filesystem snapshot"
    );
    assert!(
        snap_text.contains("${OPENAI_API_KEY}"),
        "snapshot should keep the secret placeholder"
    );
    machine.expand_secrets();

    let mut broker = NativeBroker::new();
    broker.redirect(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 7), 80), llm);
    broker.restrict_to_redirects();
    machine.set_network(Rc::new(RefCell::new(broker)));

    let run = run_openfox(
        &mut machine,
        &["agent", "-m", "Read NOTES.md and report what it says."],
    );
    expect_clean(&run);
    assert!(
        run.output.contains("TASK-RESULT") && run.output.contains(MARKER),
        "agent did not deliver the scripted result; output tail: {:?}",
        &run.output[run.output.len().saturating_sub(800)..]
    );

    // The repository content must have travelled over the network as a
    // tool result — proof the agent actually read the mounted file.
    let bodies = bodies.lock().expect("lock");
    assert!(
        bodies.len() >= 2,
        "expected at least two model calls, got {}",
        bodies.len()
    );
    assert!(
        bodies.iter().any(|b| b.contains(MARKER)),
        "tool result with repository content never reached the model"
    );

    // The host-injected key must have reached the endpoint (Authorization
    // header), proving in-memory expansion worked without persisting it.
    let recorded_headers = REQUEST_AUTH.lock().expect("lock").clone();
    assert!(
        recorded_headers.iter().any(|h| h.contains(SECRET_KEY)),
        "injected key never reached the model endpoint"
    );
}

#[test]
fn crash_bundle_is_produced_without_secrets() {
    // A binary that faults (jumps to an unmapped address) yields a crash
    // bundle; a clean exit does not, and the bundle carries no secret.
    let source = r#"
int main(void) {
    void (*bad)(void) = (void (*)(void))0xdeadbeef000ULL;
    bad();
    return 0;
}
"#;
    let Some(image) = compile_c("crasher", source, &[]) else {
        return;
    };
    init_logging();
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine.set_secret("OPENAI_API_KEY", "sk-must-not-appear");
    machine
        .add_file(b"/bin/crasher", image, 0o755)
        .expect("add crasher");
    machine.set_args(vec![b"crasher".to_vec()], vec![]);
    machine.load(b"/bin/crasher").expect("ELF load failed");
    machine.vm_mut().icount_limit = 1_000_000_000;
    let exit = machine.run();

    let bundle = machine
        .crash_bundle(&exit)
        .expect("a faulting run must produce a crash bundle");
    assert!(bundle.contains("webtos-crash-bundle"), "bundle: {bundle}");
    assert!(bundle.contains("syscall_trail"), "bundle: {bundle}");
    assert!(
        !bundle.contains("sk-must-not-appear"),
        "secret leaked into crash bundle: {bundle}"
    );

    // A clean exit yields no bundle.
    let Some(hello) = openfox() else { return };
    let mut ok = machine_with_openfox(hello);
    let ok_exit = run_openfox(&mut ok, &["version"]);
    assert!(
        ok.crash_bundle(&ok_exit.exit).is_none(),
        "a clean exit must not produce a crash bundle"
    );
}

/// A compressed soak: OpenFox runs many short commands back to back on one
/// machine. The filesystem must not grow without bound between runs
/// (proxy for the 60-minute interactive soak the milestone calls for).
#[test]
#[ignore = "slow soak; run explicitly with --ignored"]
fn openfox_soak_is_bounded() {
    let Some(image) = openfox() else { return };
    let mut machine = machine_with_openfox(image);
    machine
        .add_file(b"/root/.openfox/config.json", b"{}\n".to_vec(), 0o644)
        .expect("seed config");

    let mut prev_fs = machine.export_fs().len();
    for round in 0..25 {
        let cmd = if round % 2 == 0 { "status" } else { "version" };
        let run = run_openfox(&mut machine, &[cmd]);
        expect_clean(&run);
        let fs = machine.export_fs().len();
        // Allow a little jitter but no unbounded growth per round.
        assert!(
            fs <= prev_fs + 4096,
            "filesystem grew by {} bytes on round {round}",
            fs.saturating_sub(prev_fs)
        );
        prev_fs = fs;
    }
}
