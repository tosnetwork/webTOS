# This Makefile builds and boots the dormant Stage-1 kernel (`tos`) at the
# repository root under QEMU/UEFI. It is not the current project: webTOS is the
# browser x86-64 runtime under `crates/`, built with cargo from that directory
# and with `web/build.sh`. The pre-pivot kernel-validation targets (jtreg, the
# phase runners, the API and cross-node harnesses) and their scripts were
# removed; what remains here builds and boots the kernel itself.
.PHONY: build run debug-build debug-run clean uefi-build uefi-run uefi-test uefi-img

KERNEL_DEBUG = target/x86_64-unknown-tos/debug/tos
KERNEL_RELEASE = target/x86_64-unknown-tos/release/tos
KERNEL_ELF32 = target/tos_32.elf
QEMU_MEMORY ?= 1024M

build:
	cargo build --release

run: build
	objcopy -I elf64-x86-64 -O elf32-i386 $(KERNEL_RELEASE) $(KERNEL_ELF32)
	qemu-system-x86_64 -m $(QEMU_MEMORY) -serial stdio -display none -kernel $(KERNEL_ELF32) -no-reboot -no-shutdown

debug-build:
	cargo build

debug-run: debug-build
	objcopy -I elf64-x86-64 -O elf32-i386 $(KERNEL_DEBUG) $(KERNEL_ELF32)
	qemu-system-x86_64 -m $(QEMU_MEMORY) -serial stdio -display none -kernel $(KERNEL_ELF32) -no-reboot -no-shutdown -s -S &
	@echo "GDB: target remote :1234"

# ─── UEFI targets ─────────────────────────────────────────────
OVMF = /usr/share/ovmf/OVMF.fd
ESP_DIR = target/esp
UEFI_EFI = uefi/target/x86_64-unknown-uefi/release/tos-uefi.efi

uefi-build: build
	cd uefi && cargo build --release

uefi-run: uefi-build
	mkdir -p $(ESP_DIR)/EFI/BOOT
	cp $(UEFI_EFI) $(ESP_DIR)/EFI/BOOT/BOOTX64.EFI
	qemu-system-x86_64 -m $(QEMU_MEMORY) -bios $(OVMF) \
		-drive format=raw,file=fat:rw:$(ESP_DIR) \
		-serial stdio -display none -no-reboot -no-shutdown

uefi-test: uefi-build
	mkdir -p $(ESP_DIR)/EFI/BOOT
	cp $(UEFI_EFI) $(ESP_DIR)/EFI/BOOT/BOOTX64.EFI
	@echo "Running UEFI boot test..."
	timeout 10 qemu-system-x86_64 -m $(QEMU_MEMORY) -bios $(OVMF) \
		-drive format=raw,file=fat:rw:$(ESP_DIR) \
		-serial stdio -display none -no-reboot -no-shutdown 2>&1 | head -40

# ─── VirtualBox / USB disk image ──────────────────────────────
UEFI_IMG = target/tos-uefi.img

uefi-img: uefi-build
	@echo "Creating UEFI boot disk image..."
	dd if=/dev/zero of=$(UEFI_IMG) bs=1M count=64 2>/dev/null
	mformat -i $(UEFI_IMG) -F ::
	mmd -i $(UEFI_IMG) ::/EFI
	mmd -i $(UEFI_IMG) ::/EFI/BOOT
	mcopy -i $(UEFI_IMG) $(UEFI_EFI) ::/EFI/BOOT/BOOTX64.EFI
	@echo "Done: $(UEFI_IMG)"
	@echo "Use with VirtualBox (EFI enabled) or dd to USB drive"

clean:
	cargo clean
	rm -f $(KERNEL_ELF32) $(UEFI_IMG)
	rm -rf $(ESP_DIR)
