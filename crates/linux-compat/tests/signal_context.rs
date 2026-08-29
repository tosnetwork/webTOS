//! Linux x86-64 signal frames are architectural guest state, not a host-side
//! checkpoint. A SA_SIGINFO handler must see the interrupted GPR and complete
//! standard xstate image, and lawful edits must be applied by rt_sigreturn.

use std::path::PathBuf;
use std::process::Command;

use linux_compat::Machine;
use x64_engine::{CpuExit, EngineConfig};

fn ldef_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

fn compile_fixture() -> Option<Vec<u8>> {
    let dir = std::env::temp_dir().join("webtos-signal-context-fixture");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let src = dir.join("signal-context.c");
    let out = dir.join("signal-context");
    std::fs::write(
        &src,
        r#"
#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

#define XSTATE_SIZE 2688
#define XFEATURES 0xe7u
static unsigned char input[XSTATE_SIZE] __attribute__((aligned(64)));
static unsigned char output[XSTATE_SIZE] __attribute__((aligned(64)));
static volatile int frame_ok;

static void fill(unsigned char *p, int n, unsigned char value) {
    for (int i = 0; i < n; ++i) p[i] = value;
}

static int all(const unsigned char *p, int n, unsigned char value) {
    for (int i = 0; i < n; ++i) if (p[i] != value) return 0;
    return 1;
}

__attribute__((noinline)) static void load_xstate(void) {
    unsigned eax = XFEATURES, edx = 0;
    __asm__ volatile("xrstor64 (%0)" :: "r"(input), "a"(eax), "d"(edx) : "memory");
}

__attribute__((noinline)) static void save_xstate(void) {
    unsigned eax = XFEATURES, edx = 0;
    __asm__ volatile("xsave64 (%0)" :: "r"(output), "a"(eax), "d"(edx) : "memory");
}

static void handler(int sig, siginfo_t *info, void *opaque) {
    ucontext_t *uc = (ucontext_t *)opaque;
    unsigned char *x = (unsigned char *)uc->uc_mcontext.fpregs;
    uint32_t magic1, extended_size, xstate_size, magic2;
    uint64_t layout, present;
    memcpy(&magic1, x + 464, 4);
    memcpy(&extended_size, x + 468, 4);
    memcpy(&layout, x + 472, 8);
    memcpy(&xstate_size, x + 480, 4);
    memcpy(&present, x + 512, 8);
    memcpy(&magic2, x + extended_size - 4, 4);
    frame_ok = sig == SIGUSR1 && info->si_signo == SIGUSR1
        && ((uintptr_t)x & 63) == 0
        && magic1 == 0x46505853u && magic2 == 0x46505845u
        && extended_size == XSTATE_SIZE + 4 && xstate_size == XSTATE_SIZE
        && layout == XFEATURES && (present & 0xe6u) == 0xe6u
        && all(x + 160 + 7 * 16, 16, 0x17)
        && all(x + 576 + 7 * 16, 16, 0x27)
        && all(x + 1088 + 3 * 8, 8, 0x35)
        && all(x + 1152 + 7 * 32, 32, 0x67)
        && all(x + 1664 + 4 * 64, 64, 0x94);

    uc->uc_mcontext.gregs[REG_R12] = 0x8877665544332211ULL;
    fill(x + 160 + 7 * 16, 16, 0xa1);
    fill(x + 576 + 7 * 16, 16, 0xa2);
    fill(x + 1088 + 3 * 8, 8, 0xa5);
    fill(x + 1152 + 7 * 32, 32, 0xa6);
    fill(x + 1664 + 4 * 64, 64, 0xa7);
}

static void corrupt_handler(int sig, siginfo_t *info, void *opaque) {
    (void)sig;
    (void)info;
    ucontext_t *uc = (ucontext_t *)opaque;
    unsigned char *x = (unsigned char *)uc->uc_mcontext.fpregs;
    x[520] = 1; /* reserved XSAVE-header byte: rt_sigreturn must reject it */
}

int main(void) {
    memset(input, 0, sizeof input);
    *(uint16_t *)(input + 0) = 0x037f;
    *(uint32_t *)(input + 24) = 0x1f80;
    *(uint32_t *)(input + 28) = 0xffff;
    *(uint64_t *)(input + 512) = XFEATURES;
    fill(input + 160 + 7 * 16, 16, 0x17);
    fill(input + 576 + 7 * 16, 16, 0x27);
    fill(input + 1088 + 3 * 8, 8, 0x35);
    fill(input + 1152 + 7 * 32, 32, 0x67);
    fill(input + 1664 + 4 * 64, 64, 0x94);

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGUSR1, &sa, 0) != 0) return 2;

    long pid = syscall(SYS_getpid);
    long tid = syscall(SYS_gettid);
    load_xstate();
    unsigned long marker;
    __asm__ volatile(
        "movabs $0x1020304050607080, %%r12\n\t"
        "mov $234, %%rax\n\t"
        "syscall\n\t"
        "mov %%r12, %0"
        : "=r"(marker)
        : "D"(pid), "S"(tid), "d"(SIGUSR1)
        : "rax", "rcx", "r11", "r12", "memory");
    save_xstate();

    int restored = marker == 0x8877665544332211ULL
        && all(output + 160 + 7 * 16, 16, 0xa1)
        && all(output + 576 + 7 * 16, 16, 0xa2)
        && all(output + 1088 + 3 * 8, 8, 0xa5)
        && all(output + 1152 + 7 * 32, 32, 0xa6)
        && all(output + 1664 + 4 * 64, 64, 0xa7);

    int bad_frame_rejected = 0;
    pid_t child = fork();
    if (child == 0) {
        sa.sa_sigaction = corrupt_handler;
        if (sigaction(SIGUSR2, &sa, 0) != 0) _exit(98);
        raise(SIGUSR2);
        _exit(99);
    }
    if (child > 0) {
        int status = 0;
        if (waitpid(child, &status, 0) == child)
            bad_frame_rejected = WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV;
    }
    printf("frame=%d restored=%d rejected=%d marker=%lx\n",
           frame_ok, restored, bad_frame_rejected, marker);
    return frame_ok && restored && bad_frame_rejected ? 0 : 1;
}
"#,
    )
    .expect("write source");
    let mut cmd = Command::new("gcc");
    cmd.arg("-O1")
        .arg("-static")
        .arg("-std=gnu17")
        .arg("-mxsave")
        .arg("-o")
        .arg(&out)
        .arg(&src);
    let built = matches!(cmd.status(), Ok(status) if status.success());
    linux_compat::testing::require(
        &format!("a compiler that targets Linux x86-64 signal xstate ({cmd:?})"),
        built.then(|| std::fs::read(&out).expect("compiler output")),
    )
}

#[test]
fn handler_edits_to_gprs_and_full_xstate_are_restored() {
    let Some(image) = compile_fixture() else {
        return;
    };
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/fixture", image, 0o755)
        .expect("add fixture");
    machine.set_args(vec![b"fixture".to_vec()], vec![b"PATH=/bin".to_vec()]);
    machine.load(b"/bin/fixture").expect("ELF load failed");
    machine.vm_mut().icount_limit = machine.icount() + 4_000_000_000;
    let exit = machine.run();
    let output = String::from_utf8_lossy(&machine.take_output()).into_owned();
    assert_eq!(exit, CpuExit::Halt { code: Some(0) }, "{output}");
    assert!(output.contains("frame=1 restored=1 rejected=1"), "{output}");
}
