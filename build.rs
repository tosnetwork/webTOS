use std::env;
use std::path::Path;
use std::process::Command;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_dir = env::var("OUT_DIR").unwrap();
    let asm_dir = Path::new(&manifest_dir).join("asm");

    // Assemble all .asm files in the asm/ directory using NASM
    let asm_files = [
        "multiboot_header.asm",
        "boot.asm",
        "syscall_entry.asm",
        "trap_entry.asm",
        "switch.asm",
    ];

    for asm_file in &asm_files {
        let src = asm_dir.join(asm_file);
        let obj_name = asm_file.replace(".asm", ".o");
        let obj = Path::new(&out_dir).join(&obj_name);

        let status = Command::new("nasm")
            .args(["-f", "elf64", "-o"])
            .arg(&obj)
            .arg(&src)
            .status()
            .expect("Failed to run nasm. Is nasm installed?");

        if !status.success() {
            panic!("nasm failed to assemble {}", asm_file);
        }

        // Link the object file into the final binary
        println!("cargo:rustc-link-arg={}", obj.display());
    }

    // Pass the linker script
    let linker_script = Path::new(&manifest_dir).join("linker.ld");
    println!("cargo:rustc-link-arg=-T{}", linker_script.display());

    // Rerun triggers
    println!("cargo:rerun-if-changed=asm/");
    println!("cargo:rerun-if-changed=linker.ld");
    for asm_file in &asm_files {
        println!("cargo:rerun-if-changed=asm/{}", asm_file);
    }
}
