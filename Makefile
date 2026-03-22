.PHONY: build run release clean debug

KERNEL_DEBUG = target/x86_64-unknown-none/debug/aos
KERNEL_RELEASE = target/x86_64-unknown-none/release/aos
KERNEL_ELF32 = target/aos_32.elf

build:
	cargo build --release

run: build
	objcopy -I elf64-x86-64 -O elf32-i386 $(KERNEL_RELEASE) $(KERNEL_ELF32)
	qemu-system-x86_64 -serial stdio -display none -kernel $(KERNEL_ELF32) -no-reboot -no-shutdown

debug-build:
	cargo build

debug-run: debug-build
	objcopy -I elf64-x86-64 -O elf32-i386 $(KERNEL_DEBUG) $(KERNEL_ELF32)
	qemu-system-x86_64 -serial stdio -display none -kernel $(KERNEL_ELF32) -no-reboot -no-shutdown -s -S &
	@echo "GDB: target remote :1234"

clean:
	cargo clean
	rm -f $(KERNEL_ELF32)
