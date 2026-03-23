# AOS Real Hardware Testing Guide

This document describes how to boot AOS on a physical x86_64 machine using the UEFI boot path. AOS was developed VM-first, so real hardware testing requires extra steps. Follow this guide carefully.

---

## 1. Prerequisites

### Hardware Requirements

- **CPU:** Any x86_64 (64-bit) processor, 2010 or later. Intel Core i3/i5/i7 or AMD Ryzen recommended.
- **RAM:** 512 MB minimum (AOS identity-maps the first 512 MB). 1 GB or more is fine.
- **Storage:** Any USB 2.0 or 3.0 flash drive (1 GB minimum) to boot from.
- **Serial port (recommended):** DB9 RS-232 COM1 port, or a USB-to-serial adapter (FTDI chip preferred). Required to see any output — AOS has no video driver and produces no screen output.
- **USB keyboard:** Required to interact with BIOS/UEFI firmware menus only. AOS itself has no keyboard driver.

### Build Host Requirements

The build host (where you compile AOS) must have:

```bash
# Rust nightly toolchain — managed via rust-toolchain.toml
rustup show   # Confirm nightly is active

# Required tools
sudo apt install nasm qemu-system-x86 binutils dosfstools mtools ovmf
```

Verify the UEFI build succeeds before touching any hardware:

```bash
make uefi-build
# Confirm: uefi/target/x86_64-unknown-uefi/release/aos-uefi.efi exists
ls -lh uefi/target/x86_64-unknown-uefi/release/aos-uefi.efi
```

---

## 2. Creating the Boot USB

AOS boots as a standard UEFI application placed at `EFI/BOOT/BOOTX64.EFI` on a FAT32 ESP (EFI System Partition).

### Step 1 — Build the UEFI image

```bash
cd /home/tomi/aos
make uefi-build
```

This runs `cargo build --release` in the kernel root, then `cd uefi && cargo build --release`. The kernel ELF is embedded directly into the UEFI binary via `include_bytes!` in `uefi/src/main.rs` — so the `.efi` file is self-contained and includes the entire kernel.

### Step 2 — Identify your USB drive

```bash
lsblk
# Look for your USB device, e.g. /dev/sdb or /dev/sdc
# DOUBLE-CHECK the device. The next step is destructive.
```

Assume the USB drive is `/dev/sdX` in the commands below. Replace with your actual device.

### Step 3 — Partition and format the USB drive

```bash
# Wipe existing partition table and create a new GPT with one FAT32 ESP
sudo parted /dev/sdX --script mklabel gpt
sudo parted /dev/sdX --script mkpart ESP fat32 1MiB 100%
sudo parted /dev/sdX --script set 1 esp on

# Format the partition as FAT32
sudo mkfs.fat -F32 /dev/sdX1
```

### Step 4 — Copy the UEFI binary onto the USB

```bash
# Mount the USB partition
sudo mkdir -p /mnt/aos-usb
sudo mount /dev/sdX1 /mnt/aos-usb

# Create the UEFI boot path
sudo mkdir -p /mnt/aos-usb/EFI/BOOT

# Copy the AOS UEFI loader
sudo cp uefi/target/x86_64-unknown-uefi/release/aos-uefi.efi \
        /mnt/aos-usb/EFI/BOOT/BOOTX64.EFI

# Verify
ls -lh /mnt/aos-usb/EFI/BOOT/BOOTX64.EFI

# Unmount cleanly
sudo umount /mnt/aos-usb
sync
```

The USB is now bootable. Safely remove it from the build host before plugging it into the test machine.

---

## 3. BIOS/UEFI Setup

Boot the test machine and enter the BIOS/UEFI setup menu (usually Del, F2, F10, or F12 at POST). The exact menu layout varies by vendor, but you must change three settings.

### 3.1 Disable Secure Boot

Secure Boot will refuse to run AOS because the `.efi` binary is not signed by a trusted certificate authority.

- Navigate to: **Security** or **Boot** tab.
- Find: **Secure Boot** or **Secure Boot Control**.
- Set to: **Disabled**.

On some machines you must also clear enrolled keys or switch from "Standard Mode" to "Custom Mode" to enable the disable option.

### 3.2 Set USB as First Boot Device

- Navigate to: **Boot** tab.
- Find: **Boot Priority** or **Boot Order**.
- Move **USB** or **Removable Device** to position 1, above the internal SSD/HDD.

Some firmware shows individual EFI entries. If you see `UEFI: [Your USB brand] Partition 1`, select that.

### 3.3 Disable Fast Boot

Fast Boot skips USB enumeration on resume, which can prevent the USB from appearing.

- Navigate to: **Boot** tab.
- Find: **Fast Boot** or **Fast Startup**.
- Set to: **Disabled**.

### 3.4 Save and Exit

Select **Save & Exit** (usually F10). The machine will reboot.

---

## 4. First Boot Test

### What to Expect

AOS has **no video driver**. The screen will either stay blank or show only the UEFI firmware splash. All AOS output goes to COM1 serial at 115200 baud 8N1.

If you do not have a serial connection attached yet, proceed anyway. The machine will either:
- Boot silently (AOS is running but you cannot see output), or
- Hang at a black screen (a failure occurred before the kernel halted).

### Verifying a Successful Boot Without Serial

A successful UEFI boot with no serial cable shows no visible activity after the firmware splash disappears. The CPU will be executing the AOS kernel idle loop. If the machine reboots in a loop or shows a UEFI "Boot Manager" error screen, something went wrong — see Section 6 (Troubleshooting).

### Expected Serial Output — UEFI Phase

The UEFI loader (`uefi/src/main.rs`) emits these lines over COM1 before jumping to the kernel:

```
[UEFI] AOS UEFI boot loader starting
[UEFI] Loading kernel ELF...
[UEFI] Page tables allocated at: 0x<address>
[UEFI] Dual page tables configured (identity + higher-half)
[UEFI] Memory map: 0x<size> bytes, desc_size=0x<n>
[UEFI] Calling ExitBootServices...
[UEFI] Boot services exited. Saving memory map...
[UEFI] BootInfo written at 0x7000, mmap_size=0x<n>, desc_count=0x<n>
[UEFI] CR3 loaded. Jumping to kernel...
```

### Expected Serial Output — Kernel Phase

After the jump to `kernel_main`, the kernel (`src/main.rs`) produces:

```
AOS boot ok
AOS v0.1 - AI-native Operating System
[OK] Architecture initialized
[OK] Scheduler initialized
[EVENT seq=0 tick=0 agent=0 type=SYSTEM_BOOT arg0=0 arg1=0 status=0]
[INIT] Idle agent created: id=0
[INIT] Root agent created: id=1
[INIT] Ping agent created: id=2
[INIT] Pong agent created: id=3
[SCHED] Context switching to first agent: id=1
[ROOT] Root agent started
[PING] Ping agent started (id=2)
[PONG] Received: "ping"
[PING] Received reply: "pong"
```

If you see all of the above, AOS is running correctly on real hardware.

---

## 5. Serial Port Setup

Serial is the only output channel. Setting it up is mandatory for any meaningful hardware testing.

### 5.1 Serial Parameters

AOS initializes COM1 to:
- **Port:** COM1 (I/O base address 0x3F8)
- **Baud rate:** 115200
- **Data bits:** 8
- **Parity:** None
- **Stop bits:** 1
- **Flow control:** None

This is configured identically in `uefi/src/serial.rs` (UEFI phase) and `src/arch/x86_64/serial.rs` (kernel phase).

### 5.2 Hardware Connection

**Option A — DB9 RS-232 to DB9 RS-232 (null modem cable)**

If the test machine has a physical DB9 serial port and your build/monitor host also has one:
1. Use a **null modem cable** (not a straight-through cable). Null modem crosses TX/RX and RTS/CTS.
2. Connect DB9 on the test machine's COM1 to DB9 on the monitoring host's serial port.

**Option B — DB9 RS-232 to USB-serial adapter**

If the monitoring host has no serial port:
1. Connect a USB-to-serial adapter (FTDI FT232RL or Prolific PL2303 chipsets work reliably) to the monitoring host.
2. Connect the DB9 end to the test machine's COM1.
3. Use a null modem adapter if the cable is a straight-through type.
4. On Linux the adapter appears as `/dev/ttyUSB0` or `/dev/ttyACM0`.

**Option C — USB-serial adapter on the test machine**

If the test machine has no DB9 port: AOS does not support USB serial. COM1 (port 0x3F8) must be a physical 16550-compatible UART. Check the motherboard manual — many desktop boards with no external DB9 connector still have a COM1 header on the PCB (9-pin shrouded header). A DB9 bracket cable can expose it.

### 5.3 Terminal Software

On the monitoring Linux host:

```bash
# minicom
sudo apt install minicom
minicom -D /dev/ttyUSB0 -b 115200

# picocom (simpler)
sudo apt install picocom
picocom -b 115200 /dev/ttyUSB0

# screen
screen /dev/ttyUSB0 115200
# Exit screen: Ctrl+A then k

# Add yourself to the dialout group to avoid needing sudo each time
sudo usermod -aG dialout $USER
# Log out and back in for the group change to take effect
```

On macOS:

```bash
screen /dev/cu.usbserial-* 115200
```

On Windows: use PuTTY, set connection type Serial, speed 115200, the correct COM port number.

### 5.4 Capturing a Full Log

```bash
picocom -b 115200 /dev/ttyUSB0 --logfile /tmp/aos-boot-$(date +%Y%m%d-%H%M%S).txt
```

This saves everything to a timestamped file for later inspection with `sdk/aos-cli`:

```bash
cd sdk/aos-cli
cargo build --release
./target/x86_64-unknown-linux-gnu/release/aos inspect /tmp/aos-boot-*.txt
```

---

## 6. Troubleshooting

### Machine reboots immediately or shows "Boot device not found"

**Cause:** UEFI firmware did not find a valid boot entry on the USB, or Secure Boot blocked the unsigned EFI binary.

**Fixes:**
- Confirm Secure Boot is **Disabled** in BIOS.
- Re-seat the USB and re-enter BIOS boot menu (usually F12 at POST) to select the USB manually.
- Verify the FAT32 partition is marked as ESP: `sudo parted /dev/sdX print` should show `esp` flag on partition 1.
- Verify the file path is exactly `EFI/BOOT/BOOTX64.EFI` (case may matter on some firmware).
- Try a different USB port (prefer rear ports or USB 2.0 ports if USB 3.0 is unreliable with your firmware).

### Serial terminal shows nothing

**Cause:** Wrong port, wrong baud rate, or no serial cable connected when the machine ran.

**Fixes:**
- Confirm the terminal is set to 115200 baud, 8N1, no flow control.
- Confirm you are connected to COM1 on the test machine (0x3F8), not COM2.
- Run `dmesg | grep ttyUSB` on the monitoring host after plugging in the USB-serial adapter to confirm the device node.
- Test the cable by looping TX to RX on the adapter and typing — you should see your own characters echoed.
- If using a null modem: confirm it is a null modem cable, not a straight-through.

### UEFI phase messages appear but kernel output does not

**Cause:** The kernel ELF failed to load, or the page table switch at step 8 in `uefi/src/main.rs` caused a fault.

**Expected last UEFI message before failure:** `[UEFI] CR3 loaded. Jumping to kernel...`

**Fixes:**
- Confirm `make uefi-build` completed without errors. The kernel ELF is embedded via `include_bytes!` — a stale or partial build will cause a boot failure.
- Run `make uefi-test` in QEMU first to confirm the full boot sequence works before going to hardware.
- Check that the machine has at least 512 MB of RAM below the 4 GB boundary — the UEFI loader identity-maps the first 512 MB using 2 MB huge pages (`uefi/src/main.rs`, `setup_page_tables`).

### Kernel panics after "AOS boot ok"

**Cause:** A hardware feature assumed by AOS is absent or behaves differently than on QEMU.

**Most common causes:**
- ACPI table parsing (`src/arch/x86_64/acpi.rs`) failing on unusual MADT layout.
- LAPIC address at a non-standard physical address.
- SMP AP bootstrap timing — real hardware INIT/SIPI sequences can be slower than QEMU.

**Diagnostic:** Capture the full serial log. The last few lines before the hang or panic will identify the failing subsystem.

### ExitBootServices fails

The UEFI loader retries ExitBootServices once if the first attempt fails (stale `map_key`). If the retry also fails, it prints:

```
[UEFI] ERROR: ExitBootServices failed on retry
```

and halts. This indicates the firmware's memory map changed between the two `GetMemoryMap` calls, which is unusual. Try a different machine or a firmware update.

### Machine hangs silently with no serial output at all

**Cause:** The UEFI firmware did not run `BOOTX64.EFI`, or COM1 I/O ports are disabled in the BIOS.

**Fixes:**
- Some machines disable legacy COM ports in BIOS under **Advanced > Super IO** or **Peripheral Configuration**. Enable COM1, set I/O base to 0x3F8, IRQ 4.
- Try booting from the UEFI Shell (if available in firmware) and manually running: `FS0:\EFI\BOOT\BOOTX64.EFI`
- Check if the USB drive itself is the issue by running `make uefi-run` on the build host to confirm the QEMU path works.

---

## 7. Test Checklist

Work through these stages in order. Each stage depends on the previous one succeeding.

### Stage 0 — QEMU Verification (required before hardware)

- [ ] `make uefi-test` runs without error and exits within 10 seconds
- [ ] Serial output shows all UEFI phase messages
- [ ] Serial output shows `AOS boot ok` and agent startup messages
- [ ] `make test` passes (single-node test with disk and network)

### Stage 1 — USB Boot

- [ ] USB drive partitioned as GPT with FAT32 ESP
- [ ] `EFI/BOOT/BOOTX64.EFI` present on the USB (verify with `ls` after mounting)
- [ ] Secure Boot disabled in target machine BIOS
- [ ] Fast Boot disabled
- [ ] USB appears in BIOS boot device list
- [ ] Machine boots from USB without firmware error

### Stage 2 — UEFI Phase Output

- [ ] Serial terminal connected and receiving characters
- [ ] `[UEFI] AOS UEFI boot loader starting` appears
- [ ] `[UEFI] Loading kernel ELF...` appears
- [ ] `[UEFI] Dual page tables configured` appears
- [ ] `[UEFI] BootInfo written at 0x7000` appears
- [ ] `[UEFI] CR3 loaded. Jumping to kernel...` appears

### Stage 3 — Kernel Startup

- [ ] `AOS boot ok` appears
- [ ] `[OK] Architecture initialized` appears
- [ ] `[OK] Scheduler initialized` appears
- [ ] `[EVENT seq=0 tick=0 ... type=SYSTEM_BOOT]` appears
- [ ] All 12 agent init messages appear (`[INIT] ... created`)
- [ ] `[SCHED] Context switching to first agent: id=1` appears

### Stage 4 — Agent Execution

- [ ] `[ROOT] Root agent started` appears
- [ ] `[PING]` / `[PONG]` message exchange appears and repeats
- [ ] No crash or hang within the first 30 seconds
- [ ] Energy budget events appear (`[ACCOUNTD]` or similar)
- [ ] eBPF policy agent starts (`[POLICYD]`)

### Stage 5 — Extended Run

- [ ] System runs stably for 5 minutes without hang or reset
- [ ] Serial log saved to file using picocom `--logfile`
- [ ] Log analyzed with `aos inspect` from the SDK CLI
- [ ] No unexpected PANIC or fault messages in the log

---

## 8. Known Limitations on Real Hardware

The following features work in QEMU but will not function correctly on real hardware in the current implementation.

### No Video Output

AOS has no framebuffer driver, no VGA driver, and no GOP (Graphics Output Protocol) initialization. The screen remains blank or shows only the firmware splash. All output is COM1 serial only.

### No USB Input

AOS has no USB HID driver. Keyboards and mice connected via USB are non-functional inside AOS. The only input path is serial, and AOS currently has no interactive serial shell — serial is output-only.

### Network Drivers are QEMU-Specific

`src/arch/x86_64/virtio_net.rs` targets the virtio-net PCI device that QEMU presents. `src/arch/x86_64/e1000.rs` targets the QEMU e1000 emulation. Neither driver is tested against physical NICs. Real hardware will enumerate different PCI vendor/device IDs. `netd` auto-detects by PCI ID at boot; if no match is found it logs a warning and network is unavailable.

### NVMe Driver is Untested on Real Controllers

`src/arch/x86_64/nvme.rs` implements the NVMe admin and I/O queue protocol correctly per spec, but has only been exercised against QEMU's NVMe emulation. Real NVMe controllers may have different timing characteristics or firmware quirks that trigger timeouts.

### SMP May Not Start APs

The AP trampoline in `asm/ap_trampoline.asm` sends INIT/SIPI sequences to bring up secondary cores. QEMU responds predictably. Real hardware BIOS/firmware may park APs in a different state (ACPI parking protocol or PSCI on some platforms). If APs do not start, AOS falls back to single-core operation — the scheduler will run but only on CPU 0.

### ACPI Parsing is Minimal

`src/arch/x86_64/acpi.rs` parses RSDP, RSDT, and MADT to find LAPIC addresses and AP APIC IDs. It does not handle XSDT (64-bit ACPI) or extended table variants. Machines with firmware that provides only XSDT (most post-2015 UEFI systems) may cause the ACPI parser to report zero APs, disabling SMP.

### No IOMMU / VT-d Support

AOS does not configure the IOMMU. DMA from devices with an IOMMU-enforcing firmware (VT-d enabled) may be blocked or fault silently.

### No Power Management

AOS has no ACPI power management, no sleep states, and no thermal management. The machine will run at full power until physically powered off. There is no `shutdown` or `reboot` command — power off the test machine using its physical power button.

### Hardware Watchdog

Some enterprise machines have a hardware watchdog that the BIOS arms and expects the OS to service. AOS does not service any watchdog. If the target machine has an armed watchdog, it will reset the machine after a timeout (commonly 60–300 seconds). Disable the watchdog in BIOS if present, or look for a **Watchdog Timer** setting under the **Advanced** or **Server Management** tab.
