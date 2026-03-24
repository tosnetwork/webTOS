.PHONY: build run release clean debug test test-crossnode

KERNEL_DEBUG = target/x86_64-unknown-atos/debug/atos
KERNEL_RELEASE = target/x86_64-unknown-atos/release/atos
KERNEL_ELF32 = target/atos_32.elf

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

test: build
	@echo "Running single-node test..."
	objcopy -I elf64-x86-64 -O elf32-i386 $(KERNEL_RELEASE) $(KERNEL_ELF32)
	timeout 8 qemu-system-x86_64 -serial stdio -display none -kernel $(KERNEL_ELF32) \
		-device virtio-net-pci,netdev=n0 -netdev user,id=n0 \
		-drive file=/tmp/atos_test.img,format=raw,if=ide \
		-no-reboot -no-shutdown 2>&1 | head -50

test-crossnode:
	./tools/test_crossnode.sh

# ─── UEFI targets ─────────────────────────────────────────────
OVMF = /usr/share/ovmf/OVMF.fd
ESP_DIR = target/esp
UEFI_EFI = uefi/target/x86_64-unknown-uefi/release/atos-uefi.efi

uefi-build: build
	cd uefi && cargo build --release

uefi-run: uefi-build
	mkdir -p $(ESP_DIR)/EFI/BOOT
	cp $(UEFI_EFI) $(ESP_DIR)/EFI/BOOT/BOOTX64.EFI
	qemu-system-x86_64 -bios $(OVMF) \
		-drive format=raw,file=fat:rw:$(ESP_DIR) \
		-serial stdio -display none -no-reboot -no-shutdown

uefi-test: uefi-build
	mkdir -p $(ESP_DIR)/EFI/BOOT
	cp $(UEFI_EFI) $(ESP_DIR)/EFI/BOOT/BOOTX64.EFI
	@echo "Running UEFI boot test..."
	timeout 10 qemu-system-x86_64 -bios $(OVMF) \
		-drive format=raw,file=fat:rw:$(ESP_DIR) \
		-serial stdio -display none -no-reboot -no-shutdown 2>&1 | head -40

# ─── VirtualBox / USB disk image ──────────────────────────────
UEFI_IMG = target/atos-uefi.img

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
