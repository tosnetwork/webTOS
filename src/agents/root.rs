//! TOS Root Agent
//!
//! The root agent is the system supervisor. It holds wildcard capabilities
//! for all capability types, enabling it to delegate narrowed capabilities
//! to child agents.
//!
//! In Stage-1, the root agent periodically yields to let other agents run.
//! In later stages, it will supervise child agents, handle faults, and
//! manage resource allocation.

use crate::agent::*;
use crate::serial_println;
use crate::syscall;

#[derive(Clone, Copy, PartialEq, Eq)]
enum LinuxRuntimeSmokeFocus {
    Java,
    Node,
    Python,
    All,
}

#[inline]
fn linux_runtime_smoke_focus() -> LinuxRuntimeSmokeFocus {
    match option_env!("TOS_RUNTIME_SMOKE_FOCUS") {
        Some("node") => LinuxRuntimeSmokeFocus::Node,
        Some("python") => LinuxRuntimeSmokeFocus::Python,
        Some("all") => LinuxRuntimeSmokeFocus::All,
        _ => LinuxRuntimeSmokeFocus::Java,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum JavaSmokeFocus {
    Version,
    Hello,
    Fs,
    Jar,
    JtregJavac,
    Jtreg,
    Phase6,
    Full,
}

#[inline]
fn java_smoke_focus() -> JavaSmokeFocus {
    match option_env!("TOS_JAVA_SMOKE_FOCUS") {
        Some("version") => JavaSmokeFocus::Version,
        Some("hello") => JavaSmokeFocus::Hello,
        Some("fs") => JavaSmokeFocus::Fs,
        Some("jtreg-javac") => JavaSmokeFocus::JtregJavac,
        Some("jtreg") => JavaSmokeFocus::Jtreg,
        Some("phase6") => JavaSmokeFocus::Phase6,
        Some("full") => JavaSmokeFocus::Full,
        _ => JavaSmokeFocus::Jar,
    }
}

#[inline]
fn focus_runs_python() -> bool {
    matches!(
        linux_runtime_smoke_focus(),
        LinuxRuntimeSmokeFocus::Python | LinuxRuntimeSmokeFocus::All
    )
}

#[inline]
fn focus_runs_node() -> bool {
    matches!(
        linux_runtime_smoke_focus(),
        LinuxRuntimeSmokeFocus::Node | LinuxRuntimeSmokeFocus::All
    )
}

#[inline]
fn focus_runs_java() -> bool {
    matches!(
        linux_runtime_smoke_focus(),
        LinuxRuntimeSmokeFocus::Java | LinuxRuntimeSmokeFocus::All
    )
}

#[inline]
fn java_focus_runs_version() -> bool {
    matches!(
        java_smoke_focus(),
        JavaSmokeFocus::Version | JavaSmokeFocus::Full
    )
}

#[inline]
fn java_focus_runs_hello() -> bool {
    matches!(
        java_smoke_focus(),
        JavaSmokeFocus::Hello | JavaSmokeFocus::Full
    )
}

#[inline]
fn java_focus_runs_fs() -> bool {
    matches!(
        java_smoke_focus(),
        JavaSmokeFocus::Fs | JavaSmokeFocus::Full
    )
}

#[inline]
fn java_focus_runs_jar() -> bool {
    matches!(
        java_smoke_focus(),
        JavaSmokeFocus::Jar | JavaSmokeFocus::Phase6 | JavaSmokeFocus::Full
    )
}

#[inline]
fn java_focus_runs_jtreg() -> bool {
    matches!(java_smoke_focus(), JavaSmokeFocus::Jtreg)
}

#[inline]
fn java_focus_runs_jtreg_javac() -> bool {
    matches!(java_smoke_focus(), JavaSmokeFocus::JtregJavac)
}

#[inline]
fn java_focus_runs_phase6() -> bool {
    matches!(
        java_smoke_focus(),
        JavaSmokeFocus::Phase6 | JavaSmokeFocus::Full
    )
}

#[inline]
fn java_focus_label() -> &'static str {
    match java_smoke_focus() {
        JavaSmokeFocus::Version => "version",
        JavaSmokeFocus::Hello => "hello",
        JavaSmokeFocus::Fs => "fs",
        JavaSmokeFocus::Jar => "jar",
        JavaSmokeFocus::JtregJavac => "jtreg-javac",
        JavaSmokeFocus::Jtreg => "jtreg",
        JavaSmokeFocus::Phase6 => "phase6",
        JavaSmokeFocus::Full => "full",
    }
}

#[inline]
fn focus_label() -> &'static str {
    match linux_runtime_smoke_focus() {
        LinuxRuntimeSmokeFocus::Java => "java",
        LinuxRuntimeSmokeFocus::Node => "node",
        LinuxRuntimeSmokeFocus::Python => "python",
        LinuxRuntimeSmokeFocus::All => "all",
    }
}

fn linux_path_exists(path: &[u8]) -> bool {
    let (ks, key) = crate::linux_compat::vfs::resolve_path(0, path);
    crate::state::query_file_size(ks, key) > 0 || crate::state::state_get(ks, key).is_some()
}

fn reap_root_children(root_id: u16) {
    while let Some((child_id, child_status)) = crate::agent::find_terminated_child(root_id, -1) {
        crate::agent::reap_agent(child_id);
        serial_println!(
            "[ROOT] Reaped child agent {} ({:?})",
            child_id,
            child_status
        );
    }
}

fn spawn_node_smoke(root_id: u16) {
    static NODE_EXECVE_ELF: &[u8] = include_bytes!("../../test_data/test_node_execve.elf");
    serial_println!(
        "[ROOT] Loading Node smoke test ({} bytes)...",
        NODE_EXECVE_ELF.len()
    );
    match crate::agent_loader::spawn_linux_agent(
        root_id,
        NODE_EXECVE_ELF,
        10_000_000,
        16_384,
        b"/app/test_node_execve",
        &[b"/app/test_node_execve" as &[u8]],
    ) {
        Ok(id) => serial_println!("[ROOT] Node smoke test agent created: id={}", id),
        Err(e) => serial_println!("[ROOT] Node smoke test load failed: error {}", e),
    }
}

fn spawn_node_child_smoke(root_id: u16) {
    static NODE_CHILD_EXECVE_ELF: &[u8] =
        include_bytes!("../../test_data/test_node_child_execve.elf");
    serial_println!(
        "[ROOT] Loading Node child-process smoke test ({} bytes)...",
        NODE_CHILD_EXECVE_ELF.len()
    );
    match crate::agent_loader::spawn_linux_agent(
        root_id,
        NODE_CHILD_EXECVE_ELF,
        50_000_000,
        16_384,
        b"/app/test_node_child_execve",
        &[b"/app/test_node_child_execve" as &[u8]],
    ) {
        Ok(id) => serial_println!(
            "[ROOT] Node child-process smoke test agent created: id={}",
            id
        ),
        Err(e) => serial_println!(
            "[ROOT] Node child-process smoke test load failed: error {}",
            e
        ),
    }
}

fn spawn_node_thread_smoke(root_id: u16) {
    static NODE_THREAD_EXECVE_ELF: &[u8] =
        include_bytes!("../../test_data/test_node_thread_execve.elf");
    serial_println!(
        "[ROOT] Loading Node thread smoke test ({} bytes)...",
        NODE_THREAD_EXECVE_ELF.len()
    );
    match crate::agent_loader::spawn_linux_agent(
        root_id,
        NODE_THREAD_EXECVE_ELF,
        500_000_000,
        32_768,
        b"/app/test_node_thread_execve",
        &[b"/app/test_node_thread_execve" as &[u8]],
    ) {
        Ok(id) => serial_println!("[ROOT] Node thread smoke test agent created: id={}", id),
        Err(e) => serial_println!("[ROOT] Node thread smoke test load failed: error {}", e),
    }
}

fn spawn_java_smoke(root_id: u16) {
    static JAVA_EXECVE_ELF: &[u8] = include_bytes!("../../test_data/test_java_execve.elf");
    serial_println!(
        "[ROOT] Loading Java smoke test ({} bytes)...",
        JAVA_EXECVE_ELF.len()
    );
    match crate::agent_loader::spawn_linux_agent(
        root_id,
        JAVA_EXECVE_ELF,
        2_000_000,
        131_072,
        b"/app/test_java_execve",
        &[b"/app/test_java_execve" as &[u8]],
    ) {
        Ok(id) => serial_println!("[ROOT] Java smoke test agent created: id={}", id),
        Err(e) => serial_println!("[ROOT] Java smoke test load failed: error {}", e),
    }
}

fn spawn_java_child_smoke(root_id: u16) {
    static JAVA_CHILD_EXECVE_ELF: &[u8] =
        include_bytes!("../../test_data/test_java_child_execve.elf");
    serial_println!(
        "[ROOT] Loading Java child-process smoke test ({} bytes)...",
        JAVA_CHILD_EXECVE_ELF.len()
    );
    match crate::agent_loader::spawn_linux_agent(
        root_id,
        JAVA_CHILD_EXECVE_ELF,
        50_000_000,
        262_144,
        b"/app/test_java_child_execve",
        &[b"/app/test_java_child_execve" as &[u8]],
    ) {
        Ok(id) => serial_println!(
            "[ROOT] Java child-process smoke test agent created: id={}",
            id
        ),
        Err(e) => serial_println!(
            "[ROOT] Java child-process smoke test load failed: error {}",
            e
        ),
    }
}

fn spawn_java_thread_smoke(root_id: u16) {
    static JAVA_THREAD_EXECVE_ELF: &[u8] =
        include_bytes!("../../test_data/test_java_thread_execve.elf");
    serial_println!(
        "[ROOT] Loading Java thread smoke test ({} bytes)...",
        JAVA_THREAD_EXECVE_ELF.len()
    );
    match crate::agent_loader::spawn_linux_agent(
        root_id,
        JAVA_THREAD_EXECVE_ELF,
        50_000_000,
        262_144,
        b"/app/test_java_thread_execve",
        &[b"/app/test_java_thread_execve" as &[u8]],
    ) {
        Ok(id) => serial_println!("[ROOT] Java thread smoke test agent created: id={}", id),
        Err(e) => serial_println!("[ROOT] Java thread smoke test load failed: error {}", e),
    }
}

fn spawn_java_hello_smoke(root_id: u16) {
    static JAVA_HELLO_EXECVE_ELF: &[u8] =
        include_bytes!("../../test_data/test_java_hello_execve.elf");
    serial_println!(
        "[ROOT] Loading Java Hello smoke test ({} bytes)...",
        JAVA_HELLO_EXECVE_ELF.len()
    );
    match crate::agent_loader::spawn_linux_agent(
        root_id,
        JAVA_HELLO_EXECVE_ELF,
        2_000_000,
        131_072,
        b"/app/test_java_hello_execve",
        &[b"/app/test_java_hello_execve" as &[u8]],
    ) {
        Ok(id) => serial_println!("[ROOT] Java Hello smoke test agent created: id={}", id),
        Err(e) => serial_println!("[ROOT] Java Hello smoke test load failed: error {}", e),
    }
}

fn spawn_java_fs_smoke(root_id: u16) {
    static JAVA_FS_EXECVE_ELF: &[u8] = include_bytes!("../../test_data/test_java_fs_execve.elf");
    serial_println!(
        "[ROOT] Loading Java FS smoke test ({} bytes)...",
        JAVA_FS_EXECVE_ELF.len()
    );
    match crate::agent_loader::spawn_linux_agent(
        root_id,
        JAVA_FS_EXECVE_ELF,
        10_000_000,
        131_072,
        b"/app/test_java_fs_execve",
        &[b"/app/test_java_fs_execve" as &[u8]],
    ) {
        Ok(id) => serial_println!("[ROOT] Java FS smoke test agent created: id={}", id),
        Err(e) => serial_println!("[ROOT] Java FS smoke test load failed: error {}", e),
    }
}

fn spawn_java_jar_smoke(root_id: u16) {
    static JAVA_JAR_EXECVE_ELF: &[u8] = include_bytes!("../../test_data/test_java_jar_execve.elf");
    serial_println!(
        "[ROOT] Loading Java JAR smoke test ({} bytes)...",
        JAVA_JAR_EXECVE_ELF.len()
    );
    match crate::agent_loader::spawn_linux_agent(
        root_id,
        JAVA_JAR_EXECVE_ELF,
        10_000_000,
        131_072,
        b"/app/test_java_jar_execve",
        &[b"/app/test_java_jar_execve" as &[u8]],
    ) {
        Ok(id) => serial_println!("[ROOT] Java JAR smoke test agent created: id={}", id),
        Err(e) => serial_println!("[ROOT] Java JAR smoke test load failed: error {}", e),
    }
}

fn spawn_java_jtreg_smoke(root_id: u16) {
    static JAVA_JTREG_EXECVE_ELF: &[u8] =
        include_bytes!("../../test_data/test_java_jtreg_execve.elf");
    serial_println!(
        "[ROOT] Loading Java jtreg smoke test ({} bytes)...",
        JAVA_JTREG_EXECVE_ELF.len()
    );
    match crate::agent_loader::spawn_linux_agent(
        root_id,
        JAVA_JTREG_EXECVE_ELF,
        2_000_000_000,
        262_144,
        b"/app/test_java_jtreg_execve",
        &[b"/app/test_java_jtreg_execve" as &[u8]],
    ) {
        Ok(id) => serial_println!("[ROOT] Java jtreg smoke test agent created: id={}", id),
        Err(e) => serial_println!("[ROOT] Java jtreg smoke test load failed: error {}", e),
    }
}

fn spawn_java_jtreg_javac_smoke(root_id: u16) {
    static JAVA_JTREG_JAVAC_EXECVE_ELF: &[u8] =
        include_bytes!("../../test_data/test_java_jtreg_javac_execve.elf");
    serial_println!(
        "[ROOT] Loading Java jtreg javac smoke test ({} bytes)...",
        JAVA_JTREG_JAVAC_EXECVE_ELF.len()
    );
    match crate::agent_loader::spawn_linux_agent(
        root_id,
        JAVA_JTREG_JAVAC_EXECVE_ELF,
        1_000_000_000,
        262_144,
        b"/app/test_java_jtreg_javac_execve",
        &[b"/app/test_java_jtreg_javac_execve" as &[u8]],
    ) {
        Ok(id) => serial_println!(
            "[ROOT] Java jtreg javac smoke test agent created: id={}",
            id
        ),
        Err(e) => serial_println!(
            "[ROOT] Java jtreg javac smoke test load failed: error {}",
            e
        ),
    }
}

fn spawn_signal_smoke(root_id: u16) {
    static SIGNAL_SMOKE_ELF: &[u8] = include_bytes!("../../test_data/test_signal_smoke.elf");
    serial_println!(
        "[ROOT] Loading signal smoke test ({} bytes)...",
        SIGNAL_SMOKE_ELF.len()
    );
    match crate::agent_loader::spawn_linux_agent(
        root_id,
        SIGNAL_SMOKE_ELF,
        200_000,
        512,
        b"/app/test_signal_smoke",
        &[b"/app/test_signal_smoke" as &[u8]],
    ) {
        Ok(id) => serial_println!("[ROOT] signal smoke test agent created: id={}", id),
        Err(e) => serial_println!("[ROOT] signal smoke test load failed: error {}", e),
    }
}

fn spawn_python_child_smoke(root_id: u16) {
    static PYTHON_CHILD_EXECVE_ELF: &[u8] =
        include_bytes!("../../test_data/test_python_child_execve.elf");
    serial_println!(
        "[ROOT] Loading Python child-process smoke test ({} bytes)...",
        PYTHON_CHILD_EXECVE_ELF.len()
    );
    match crate::agent_loader::spawn_linux_agent(
        root_id,
        PYTHON_CHILD_EXECVE_ELF,
        300_000,
        512,
        b"/app/test_python_child_execve",
        &[b"/app/test_python_child_execve" as &[u8]],
    ) {
        Ok(id) => serial_println!(
            "[ROOT] Python child-process smoke test agent created: id={}",
            id
        ),
        Err(e) => serial_println!(
            "[ROOT] Python child-process smoke test load failed: error {}",
            e
        ),
    }
}

fn spawn_at_paths_smoke(root_id: u16) {
    static AT_PATHS_ELF: &[u8] = include_bytes!("../../test_data/test_at_paths.elf");
    serial_println!(
        "[ROOT] Loading *at path smoke test ({} bytes)...",
        AT_PATHS_ELF.len()
    );
    match crate::agent_loader::spawn_linux_agent(
        root_id,
        AT_PATHS_ELF,
        200_000,
        512,
        b"/app/test_at_paths",
        &[b"/app/test_at_paths" as &[u8]],
    ) {
        Ok(id) => serial_println!("[ROOT] *at path smoke test agent created: id={}", id),
        Err(e) => serial_println!("[ROOT] *at path smoke test load failed: error {}", e),
    }
}

fn spawn_ioctl_smoke(root_id: u16) {
    static IOCTL_SMOKE_ELF: &[u8] = include_bytes!("../../test_data/test_ioctl_smoke.elf");
    serial_println!(
        "[ROOT] Loading ioctl smoke test ({} bytes)...",
        IOCTL_SMOKE_ELF.len()
    );
    match crate::agent_loader::spawn_linux_agent(
        root_id,
        IOCTL_SMOKE_ELF,
        200_000,
        512,
        b"/app/test_ioctl_smoke",
        &[b"/app/test_ioctl_smoke" as &[u8]],
    ) {
        Ok(id) => serial_println!("[ROOT] ioctl smoke test agent created: id={}", id),
        Err(e) => serial_println!("[ROOT] ioctl smoke test load failed: error {}", e),
    }
}

fn spawn_tls_clone_smoke(root_id: u16) {
    static TLS_CLONE_SMOKE_ELF: &[u8] = include_bytes!("../../test_data/test_tls_clone.elf");
    serial_println!(
        "[ROOT] Loading TLS/clone smoke test ({} bytes)...",
        TLS_CLONE_SMOKE_ELF.len()
    );
    match crate::agent_loader::spawn_linux_agent(
        root_id,
        TLS_CLONE_SMOKE_ELF,
        300_000,
        1024,
        b"/app/test_tls_clone",
        &[b"/app/test_tls_clone" as &[u8]],
    ) {
        Ok(id) => serial_println!("[ROOT] TLS/clone smoke test agent created: id={}", id),
        Err(e) => serial_println!("[ROOT] TLS/clone smoke test load failed: error {}", e),
    }
}

fn spawn_mux_smoke(root_id: u16) {
    static MUX_SMOKE_ELF: &[u8] = include_bytes!("../../test_data/test_mux_smoke.elf");
    serial_println!(
        "[ROOT] Loading mux smoke test ({} bytes)...",
        MUX_SMOKE_ELF.len()
    );
    match crate::agent_loader::spawn_linux_agent(
        root_id,
        MUX_SMOKE_ELF,
        200_000,
        1024,
        b"/app/test_mux_smoke",
        &[b"/app/test_mux_smoke" as &[u8]],
    ) {
        Ok(id) => serial_println!("[ROOT] mux smoke test agent created: id={}", id),
        Err(e) => serial_println!("[ROOT] mux smoke test load failed: error {}", e),
    }
}

/// Root agent entry point.
///
/// Runs an infinite loop, periodically logging a tick count and yielding
/// to allow other agents to execute.
pub extern "C" fn root_entry() -> ! {
    serial_println!("[ROOT] Root agent started");
    serial_println!("[ROOT] Linux runtime smoke focus: {}", focus_label());
    crate::heap::run_smoke();
    if focus_runs_java() {
        serial_println!("[ROOT] Java smoke focus: {}", java_focus_label());
    }

    // Load relative *at path smoke test
    {
        spawn_at_paths_smoke(1);
        spawn_ioctl_smoke(1);
        spawn_tls_clone_smoke(1);
        spawn_mux_smoke(1);
    }
    const TICK_LOG_INTERVAL: u64 = 100_000;
    const ENABLE_CHECKPOINT_SMOKE: bool = false;
    const PYTHON_CHILD_SMOKE_DELAY_TICKS: u64 = 150_000;
    const NODE_SMOKE_DELAY_TICKS: u64 = 150_000;
    const NODE_CHILD_SMOKE_DELAY_TICKS: u64 = 450_000;
    const NODE_THREAD_SMOKE_DELAY_TICKS: u64 = 1_200_000;
    const JAVA_SMOKE_DELAY_TICKS: u64 = 300_000;
    const JAVA_HELLO_SMOKE_DELAY_TICKS: u64 = 450_000;
    const JAVA_FS_SMOKE_DELAY_TICKS: u64 = 600_000;
    const JAVA_JAR_SMOKE_DELAY_TICKS: u64 = 300_000;
    const JAVA_JTREG_SMOKE_DELAY_TICKS: u64 = 1_050_000;
    const JAVA_CHILD_SMOKE_DELAY_TICKS: u64 = 750_000;
    const JAVA_THREAD_SMOKE_DELAY_TICKS: u64 = 900_000;
    let java_phase6_focus = matches!(java_smoke_focus(), JavaSmokeFocus::Phase6);
    let java_child_smoke_delay_ticks = if java_phase6_focus {
        450_000
    } else {
        JAVA_CHILD_SMOKE_DELAY_TICKS
    };
    let java_thread_smoke_delay_ticks = if java_phase6_focus {
        600_000
    } else {
        JAVA_THREAD_SMOKE_DELAY_TICKS
    };

    // ── Stage 9: Load Linux ELF test binary ────────────────────────────
    // Done in root agent (not init) to avoid boot stack overflow.
    {
        static HELLO_ELF: &[u8] = include_bytes!("../../test_data/test_syscalls.elf");
        serial_println!(
            "[ROOT] Loading Linux ELF test binary ({} bytes)...",
            HELLO_ELF.len()
        );
        match crate::agent_loader::spawn_from_image(
            1, // root_id
            HELLO_ELF,
            crate::agent::RuntimeKind::LinuxCompat,
            1_000_000, // generous energy for syscall test suite
            256,       // memory quota for mmap tests
        ) {
            Ok(id) => serial_println!("[ROOT] Linux ELF agent created: id={} (LinuxCompat)", id),
            Err(e) => serial_println!("[ROOT] Linux ELF load failed: error {}", e),
        }
    }

    // Load argv/envp/auxv smoke test
    {
        static ARGV_ELF: &[u8] = include_bytes!("../../test_data/test_argv.elf");
        serial_println!(
            "[ROOT] Loading argv test binary ({} bytes)...",
            ARGV_ELF.len()
        );
        match crate::agent_loader::spawn_linux_agent(
            1,
            ARGV_ELF,
            100_000,
            64,
            b"/app/test_argv",
            &[b"/app/test_argv" as &[u8], b"--hello"],
        ) {
            Ok(id) => serial_println!("[ROOT] argv test agent created: id={}", id),
            Err(e) => serial_println!("[ROOT] argv test load failed: error {}", e),
        }
    }

    // ── Install embedded base-image files and test dynamic linking ─────────
    {
        serial_println!(
            "[ROOT] {} embedded base-image file(s) available",
            crate::base_image::embedded_file_count()
        );

        // Load a dynamically-linked ELF directly from memory.
        static DYNAMIC_ELF: &[u8] = include_bytes!("../../test_data/hello_dynamic.elf");
        serial_println!(
            "[ROOT] Loading dynamic ELF test ({} bytes)...",
            DYNAMIC_ELF.len()
        );
        match crate::agent_loader::spawn_linux_agent(
            1,
            DYNAMIC_ELF,
            1_000_000,
            512, // more memory for dynamic linker
            b"/app/hello_dynamic",
            &[b"/app/hello_dynamic" as &[u8]],
        ) {
            Ok(id) => serial_println!("[ROOT] dynamic ELF agent created: id={}", id),
            Err(e) => serial_println!("[ROOT] dynamic ELF load failed: error {}", e),
        }

        static EXECVE_ELF: &[u8] = include_bytes!("../../test_data/test_execve.elf");
        serial_println!(
            "[ROOT] Loading execve smoke test ({} bytes)...",
            EXECVE_ELF.len()
        );
        match crate::agent_loader::spawn_linux_agent(
            1,
            EXECVE_ELF,
            100_000,
            64,
            b"/app/test_execve",
            &[b"/app/test_execve" as &[u8]],
        ) {
            Ok(id) => serial_println!("[ROOT] execve smoke test agent created: id={}", id),
            Err(e) => serial_println!("[ROOT] execve smoke test load failed: error {}", e),
        }

        spawn_signal_smoke(1);

        if focus_runs_python() && linux_path_exists(b"/usr/bin/python3") {
            static PYTHON_EXECVE_ELF: &[u8] =
                include_bytes!("../../test_data/test_python_execve.elf");
            serial_println!(
                "[ROOT] Loading Python smoke test ({} bytes)...",
                PYTHON_EXECVE_ELF.len()
            );
            match crate::agent_loader::spawn_linux_agent(
                1,
                PYTHON_EXECVE_ELF,
                200_000,
                256,
                b"/app/test_python_execve",
                &[b"/app/test_python_execve" as &[u8]],
            ) {
                Ok(id) => serial_println!("[ROOT] Python smoke test agent created: id={}", id),
                Err(e) => serial_println!("[ROOT] Python smoke test load failed: error {}", e),
            }
            serial_println!(
                "[ROOT] Python child-process smoke test available; delaying until root tick {}",
                PYTHON_CHILD_SMOKE_DELAY_TICKS
            );
        } else if !focus_runs_python() {
            serial_println!("[ROOT] Python smoke test disabled by runtime focus");
        } else {
            serial_println!("[ROOT] Python runtime not installed, skipping Python smoke test");
        }

        if focus_runs_node() && linux_path_exists(b"/usr/bin/node") {
            serial_println!(
                "[ROOT] Node runtime installed; delaying Node smoke test until root tick {}",
                NODE_SMOKE_DELAY_TICKS
            );
            serial_println!(
                "[ROOT] Node child-process smoke test available; delaying until root tick {}",
                NODE_CHILD_SMOKE_DELAY_TICKS
            );
            serial_println!(
                "[ROOT] Node thread smoke test available; delaying until root tick {}",
                NODE_THREAD_SMOKE_DELAY_TICKS
            );
        } else if !focus_runs_node() {
            serial_println!("[ROOT] Node smoke test disabled by runtime focus");
        } else {
            serial_println!("[ROOT] Node runtime not installed, skipping Node smoke test");
        }

        if focus_runs_java() && linux_path_exists(b"/usr/lib/jvm/java-11-openjdk-amd64/bin/java") {
            if java_focus_runs_version() {
                serial_println!(
                    "[ROOT] Java runtime installed; delaying Java smoke test until root tick {}",
                    JAVA_SMOKE_DELAY_TICKS
                );
            }
            if java_focus_runs_hello() && linux_path_exists(b"/usr/lib/tos-tests/Hello.class") {
                serial_println!(
                    "[ROOT] Java Hello smoke test available; delaying until root tick {}",
                    JAVA_HELLO_SMOKE_DELAY_TICKS
                );
            } else {
                serial_println!("[ROOT] Java Hello smoke test disabled or payload missing");
            }
            if java_focus_runs_fs() && linux_path_exists(b"/usr/lib/tos-tests/FsProbe.class") {
                serial_println!(
                    "[ROOT] Java FS smoke test available; delaying until root tick {}",
                    JAVA_FS_SMOKE_DELAY_TICKS
                );
            } else {
                serial_println!("[ROOT] Java FS smoke test disabled or payload missing");
            }
            if java_focus_runs_jar() && linux_path_exists(b"/usr/lib/tos-tests/java-smoke.jar") {
                serial_println!(
                    "[ROOT] Java JAR smoke test available; delaying until root tick {}",
                    JAVA_JAR_SMOKE_DELAY_TICKS
                );
            } else {
                serial_println!("[ROOT] Java JAR smoke test disabled or payload missing");
            }
            if java_focus_runs_jtreg_javac()
                && linux_path_exists(b"/jdk/test/lib/jdk/test/lib/Platform.java")
                && linux_path_exists(b"/jdk/test/lib/sun/hotspot/WhiteBox.java")
            {
                serial_println!(
                    "[ROOT] Java jtreg javac smoke test available; delaying until root tick {}",
                    JAVA_JTREG_SMOKE_DELAY_TICKS
                );
            } else if java_focus_runs_jtreg_javac() {
                serial_println!("[ROOT] Java jtreg javac smoke test disabled or payload missing");
            }
            if java_focus_runs_jtreg()
                && linux_path_exists(b"/jdk/jtreg/lib/jtreg.jar")
                && linux_path_exists(b"/jdk/test/jdk/java/lang/String/Chars.java")
            {
                serial_println!(
                    "[ROOT] Java jtreg smoke test available; delaying until root tick {}",
                    JAVA_JTREG_SMOKE_DELAY_TICKS
                );
            } else {
                serial_println!("[ROOT] Java jtreg smoke test disabled or payload missing");
            }
            if java_focus_runs_phase6()
                && linux_path_exists(b"/usr/lib/tos-tests/JavaChildSmoke.class")
            {
                serial_println!(
                    "[ROOT] Java child-process smoke test available; delaying until root tick {}",
                    java_child_smoke_delay_ticks
                );
            } else {
                serial_println!("[ROOT] Java child-process smoke test disabled or payload missing");
            }
            if java_focus_runs_phase6()
                && linux_path_exists(b"/usr/lib/tos-tests/JavaThreadSmoke.class")
            {
                serial_println!(
                    "[ROOT] Java thread smoke test available; delaying until root tick {}",
                    java_thread_smoke_delay_ticks
                );
            } else {
                serial_println!("[ROOT] Java thread smoke test disabled or payload missing");
            }
        } else if !focus_runs_java() {
            serial_println!("[ROOT] Java smoke test disabled by runtime focus");
        } else {
            serial_println!("[ROOT] Java runtime not installed, skipping Java smoke test");
        }
    }

    let mut count: u64 = 0;
    let mut checkpoint_done = false;
    let node_runtime_available = focus_runs_node() && linux_path_exists(b"/usr/bin/node");
    let python_child_available = focus_runs_python() && linux_path_exists(b"/usr/bin/python3");
    let node_child_available = focus_runs_node() && linux_path_exists(b"/usr/bin/node");
    let node_thread_available = focus_runs_node() && linux_path_exists(b"/usr/bin/node");
    let java_runtime_available = focus_runs_java()
        && java_focus_runs_version()
        && linux_path_exists(b"/usr/lib/jvm/java-11-openjdk-amd64/bin/java");
    let java_hello_available = focus_runs_java()
        && java_focus_runs_hello()
        && linux_path_exists(b"/usr/lib/jvm/java-11-openjdk-amd64/bin/java")
        && linux_path_exists(b"/usr/lib/tos-tests/Hello.class");
    let java_fs_available = focus_runs_java()
        && java_focus_runs_fs()
        && linux_path_exists(b"/usr/lib/jvm/java-11-openjdk-amd64/bin/java")
        && linux_path_exists(b"/usr/lib/tos-tests/FsProbe.class");
    let java_jar_available = focus_runs_java()
        && java_focus_runs_jar()
        && linux_path_exists(b"/usr/lib/jvm/java-11-openjdk-amd64/bin/java")
        && linux_path_exists(b"/usr/lib/tos-tests/java-smoke.jar");
    let java_jtreg_available = focus_runs_java()
        && java_focus_runs_jtreg()
        && linux_path_exists(b"/usr/lib/jvm/java-11-openjdk-amd64/bin/java")
        && linux_path_exists(b"/jdk/jtreg/lib/jtreg.jar")
        && linux_path_exists(b"/jdk/test/jdk/java/lang/String/Chars.java");
    let java_jtreg_javac_available = focus_runs_java()
        && java_focus_runs_jtreg_javac()
        && linux_path_exists(b"/usr/lib/jvm/java-11-openjdk-amd64/bin/javac")
        && linux_path_exists(b"/jdk/test/lib/jdk/test/lib/Platform.java")
        && linux_path_exists(b"/jdk/test/lib/sun/hotspot/WhiteBox.java");
    let java_child_available = focus_runs_java()
        && java_focus_runs_phase6()
        && linux_path_exists(b"/usr/lib/jvm/java-11-openjdk-amd64/bin/java")
        && linux_path_exists(b"/usr/lib/tos-tests/JavaChildSmoke.class");
    let java_thread_available = focus_runs_java()
        && java_focus_runs_phase6()
        && linux_path_exists(b"/usr/lib/jvm/java-11-openjdk-amd64/bin/java")
        && linux_path_exists(b"/usr/lib/tos-tests/JavaThreadSmoke.class");
    let mut python_child_smoke_launched = false;
    let mut node_smoke_launched = false;
    let mut node_child_smoke_launched = false;
    let mut node_thread_smoke_launched = false;
    let mut java_smoke_launched = false;
    let mut java_hello_smoke_launched = false;
    let mut java_fs_smoke_launched = false;
    let mut java_jar_smoke_launched = false;
    let mut java_jtreg_javac_smoke_launched = false;
    let mut java_jtreg_smoke_launched = false;
    let mut java_child_smoke_launched = false;
    let mut java_thread_smoke_launched = false;
    loop {
        count += 1;
        reap_root_children(1);
        if count % TICK_LOG_INTERVAL == 0 {
            serial_println!("[ROOT] Root agent tick {}", count);
        }

        if python_child_available
            && !python_child_smoke_launched
            && count >= PYTHON_CHILD_SMOKE_DELAY_TICKS
        {
            spawn_python_child_smoke(1);
            python_child_smoke_launched = true;
        }

        if node_runtime_available && !node_smoke_launched && count >= NODE_SMOKE_DELAY_TICKS {
            spawn_node_smoke(1);
            node_smoke_launched = true;
        }

        if node_child_available
            && !node_child_smoke_launched
            && count >= NODE_CHILD_SMOKE_DELAY_TICKS
        {
            spawn_node_child_smoke(1);
            node_child_smoke_launched = true;
        }

        if node_thread_available
            && !node_thread_smoke_launched
            && count >= NODE_THREAD_SMOKE_DELAY_TICKS
        {
            spawn_node_thread_smoke(1);
            node_thread_smoke_launched = true;
        }

        if java_runtime_available && !java_smoke_launched && count >= JAVA_SMOKE_DELAY_TICKS {
            spawn_java_smoke(1);
            java_smoke_launched = true;
        }

        if java_hello_available
            && !java_hello_smoke_launched
            && count >= JAVA_HELLO_SMOKE_DELAY_TICKS
        {
            spawn_java_hello_smoke(1);
            java_hello_smoke_launched = true;
        }

        if java_fs_available && !java_fs_smoke_launched && count >= JAVA_FS_SMOKE_DELAY_TICKS {
            spawn_java_fs_smoke(1);
            java_fs_smoke_launched = true;
        }

        if java_jar_available && !java_jar_smoke_launched && count >= JAVA_JAR_SMOKE_DELAY_TICKS {
            spawn_java_jar_smoke(1);
            java_jar_smoke_launched = true;
        }

        if java_jtreg_javac_available
            && !java_jtreg_javac_smoke_launched
            && count >= JAVA_JTREG_SMOKE_DELAY_TICKS
        {
            spawn_java_jtreg_javac_smoke(1);
            java_jtreg_javac_smoke_launched = true;
        }

        if java_jtreg_available
            && !java_jtreg_smoke_launched
            && count >= JAVA_JTREG_SMOKE_DELAY_TICKS
        {
            spawn_java_jtreg_smoke(1);
            java_jtreg_smoke_launched = true;
        }

        if java_child_available
            && !java_child_smoke_launched
            && count >= java_child_smoke_delay_ticks
        {
            spawn_java_child_smoke(1);
            java_child_smoke_launched = true;
        }

        if java_thread_available
            && !java_thread_smoke_launched
            && count >= java_thread_smoke_delay_ticks
        {
            spawn_java_thread_smoke(1);
            java_thread_smoke_launched = true;
        }

        // Trigger a checkpoint once at tick 500
        if ENABLE_CHECKPOINT_SMOKE && count == 500 && !checkpoint_done {
            serial_println!("[ROOT] Triggering checkpoint...");
            let result = syscall::syscall(SYS_CHECKPOINT, 0, 0, 0, 0, 0);
            serial_println!("[ROOT] Checkpoint result: {}", result);
            checkpoint_done = true;
        }
        // Verify checkpoint roundtrip at tick 600 (checkpoint was at tick 500)
        if ENABLE_CHECKPOINT_SMOKE && count == 600 && checkpoint_done {
            serial_println!("[ROOT] Verifying checkpoint from disk...");

            // Load header
            if let Some(header) = crate::checkpoint::load_header_from_disk() {
                serial_println!("[ROOT] \u{2713} Checkpoint loaded: tick={} event_seq={} agents={} merkle_roots={}",
                    header.tick, header.event_sequence, header.agent_count, header.merkle_root_count);

                // Verify magic
                if header.magic == 0x41545343 {
                    serial_println!("[ROOT] \u{2713} Magic: ATSC (valid)");
                } else {
                    serial_println!("[ROOT] \u{2717} Magic: {:#x} (INVALID)", header.magic);
                }

                // Load and verify Merkle roots
                let roots = crate::checkpoint::load_merkle_from_disk(&header);
                let mut non_zero = 0;
                for root in roots.iter() {
                    if root.iter().any(|&b| b != 0) {
                        non_zero += 1;
                    }
                }
                serial_println!(
                    "[ROOT] \u{2713} Merkle roots loaded: {} non-zero keyspaces",
                    non_zero
                );

                // Run replay divergence check
                serial_println!("[ROOT] Running Merkle divergence check...");
                match crate::replay::enter_replay() {
                    Ok(()) => {
                        let report = crate::replay::check_divergence();
                        crate::replay::print_report(&report);
                        crate::replay::exit_replay();
                    }
                    Err(e) => {
                        serial_println!("[ROOT] Replay failed: {}", e);
                    }
                }

                serial_println!("[ROOT] === CHECKPOINT ROUNDTRIP TEST COMPLETE ===");
            } else {
                serial_println!("[ROOT] \u{2717} No checkpoint found on disk!");
            }
        }

        // Proof and attestation disabled: SHA-256 chain hashing in
        // proof::generate_proof triggers #UD on QEMU's qemu64 CPU.
        // These work correctly in earlier commits with smaller binaries.

        // Yield to let other agents run
        syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0);
    }
}
