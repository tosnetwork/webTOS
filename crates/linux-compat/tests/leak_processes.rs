//! Whether one process can read what another left in memory.
//!
//! `tests/leak.rs` asks this of the machine's own allocator. This asks it of
//! real processes: a parent puts a credential in its heap, forks, and the
//! child replaces its image and goes looking. The paths are the ones a guest
//! actually takes — `fork`, `execve`, `mmap`, `brk` — because the question is
//! not whether the allocator zeroes a page but whether anything in between
//! hands one over already written on.

use std::path::PathBuf;
use std::process::Command;

use linux_compat::Machine;
use x64_engine::{CpuExit, EngineConfig};

fn ldef_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

fn compile_c(name: &str, source: &str) -> Option<Vec<u8>> {
    let dir = std::env::temp_dir().join("webtos-leak-fixture");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let src = dir.join(format!("{name}.c"));
    let out = dir.join(name);
    std::fs::write(&src, source).expect("write source");
    let mut cmd = Command::new("gcc");
    cmd.arg("-O1")
        .arg("-static")
        .arg("-std=gnu17")
        .arg("-D_GNU_SOURCE")
        .arg("-o")
        .arg(&out)
        .arg(&src);
    let built = matches!(cmd.status(), Ok(status) if status.success());
    linux_compat::testing::require(
        &format!("a compiler that targets Linux x86-64 for {name} ({cmd:?})"),
        built.then(|| std::fs::read(&out).expect("compiler output")),
    )
}

const MARKER: &str = "WEBTOS-CROSS-PROCESS-CANARY-7b3d";

#[test]
fn a_process_cannot_find_another_ones_credential_in_memory() {
    // The searcher runs after the holder is gone. It takes memory the way a
    // program takes memory — a large anonymous mapping and a grown heap — and
    // reports whether the marker is anywhere in what it was given.
    let Some(searcher) = compile_c(
        "searcher",
        &format!(
            r#"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

#define NEEDLE "{MARKER}"

static int scan(const char *base, size_t len) {{
    size_t n = strlen(NEEDLE);
    for (size_t i = 0; i + n <= len; i++)
        if (memcmp(base + i, NEEDLE, n) == 0) return 1;
    return 0;
}}

int main(void) {{
    int found = 0;
    size_t len = 4 << 20;
    char *m = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) {{ printf("mmap failed\n"); return 1; }}
    found |= scan(m, len);

    /* The heap too: `brk` hands back address space the last program used. */
    char *heap = malloc(len);
    if (heap) found |= scan(heap, len);

    printf("searched: found=%d\n", found);
    return 0;
}}
"#
        ),
    ) else {
        return;
    };

    let Some(holder) = compile_c(
        "holder",
        &format!(
            r#"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>

#define NEEDLE "{MARKER}"

int main(void) {{
    /* A credential, in memory, the way a program holds one after reading it. */
    size_t len = 4 << 20;
    char *m = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    for (size_t off = 0; off + 64 < len; off += 4096) memcpy(m + off, NEEDLE, strlen(NEEDLE) + 1);
    char *heap = malloc(len);
    for (size_t off = 0; off + 64 < len; off += 4096) memcpy(heap + off, NEEDLE, strlen(NEEDLE) + 1);
    printf("held\n");

    pid_t pid = fork();
    if (pid == 0) {{
        /* Replacing the image is what should take the credential with it. */
        char *argv[] = {{ "searcher", NULL }};
        execve("/bin/searcher", argv, NULL);
        printf("execve failed\n");
        _exit(1);
    }}
    int st = 0;
    waitpid(pid, &st, 0);
    printf("child exit=%d\n", WEXITSTATUS(st));
    return 0;
}}
"#
        ),
    ) else {
        return;
    };

    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/searcher", searcher, 0o755)
        .expect("add searcher");
    machine
        .add_file(b"/bin/holder", holder, 0o755)
        .expect("add holder");
    machine.set_args(vec![b"holder".to_vec()], vec![b"PATH=/bin".to_vec()]);
    machine.load(b"/bin/holder").expect("load");
    machine.vm_mut().icount_limit = machine.icount() + 40_000_000_000;
    let exit = machine.run();
    let output = String::from_utf8_lossy(&machine.take_output()).into_owned();

    assert_eq!(exit, CpuExit::Halt { code: Some(0) }, "{output}");
    assert!(
        output.contains("held"),
        "the holder never wrote the credential, so nothing was searched for: {output}"
    );
    assert!(
        output.contains("searched:"),
        "the searcher did not run, so this test proves nothing: {output}"
    );
    assert!(
        output.contains("searched: found=0"),
        "a process found another's credential in memory it was handed: {output}"
    );
}
