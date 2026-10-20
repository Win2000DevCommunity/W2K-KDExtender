# KDTransport — Session Handover & State Summary

**Date:** October 20, 2026  
**Repository:** [https://github.com/Win2000DevCommunity/W2K-KDExtender](https://github.com/Win2000DevCommunity/W2K-KDExtender)  
**Branch:** `main` (tracked, clean working tree)  

---

## 1. Project Overview & Working Architecture

KDTransport implements a high-speed kernel debugging transport layer injected directly into the Windows 2000 Hardware Abstraction Layer (`.kdtrans` PE section). It provides modern debugging capabilities:
1. **Network Kernel Debugging (KDNET):** Raw Ethernet (EtherType `0x88B5`) over AMD PCnet Am79C973 and Realtek RTL8168/8111 Gigabit PCIe NICs, bridged to Windows debuggers via `\\.\pipe\KdNet`.
2. **USB 2.0 Kernel Debugging (KDUSB):** Direct hardware debugging via Intel EHCI USB 2.0 Debug Port (`ehci-dbgp`), directly attached to Windows debuggers via `\\.\pipe\KdUsb`.
3. **Legacy COM Fallback:** 100% untouched Microsoft serial routines when `/DEBUGPORT=COMx` is chosen.

```
Target VM (W2K) [ntoskrnl <-> hal.dll (.kdtrans)]
       |
       +---> [PCnet / RTL8168] ---> Raw Ethernet (0x88B5) ---> Host Bridge (kdbridge.py) ---> \\.\pipe\KdNet ---> WinDbg
       |
       +---> [EHCI USB 2.0 DBGP] ---> USB Debug Port MMIO ---> QEMU Named Pipe (\\.\pipe\KdUsb) ---> WinDbg
       |
       +---> [16550 UART COM] ---> Legacy Serial Fallback ---> COM Port / Named Pipe ---> WinDbg
```

---

## 2. Completed Milestones & Implemented Components

### A. All 6 Original Windows 2000 HAL Variants (100% Functional)
All 6 Windows 2000 HAL variants have been patched, validated, and confirmed booting with active KD USB and KD NET transports:
- `hal.dll` (Standard PC)
- `halaacpi.dll` (ACPI Uniprocessor PC)
- `halacpi.dll` (Advanced Configuration and Power Interface PC)
- `halapic.dll` (MPS Uniprocessor PC)
- `halmacpi_original.dll` (ACPI Multiprocessor PC)
- `halmps.dll` (MPS Multiprocessor PC)

### B. Windows XP HAL (`NT 5.1 HALMACPI.DLL`) Dedicated Support
A dedicated, isolated patch pipeline exists in [patcher/patch_xp_hal.py](file:///c:/Users/Win2000/Downloads/kdtransport_w2k/kdtransport_pkg/patcher/patch_xp_hal.py) that keeps all standard Windows 2000 patch code completely untouched and separate.

**XP HAL-Specific Fixup:**
The only XP HAL-specific fixup is the `LoaderBlock` retrieval: in `KdPortInitialize`, `EBX` is reused as scratch for `HalpGetResourceSortValue`, so the injected `KdpTransportInitOverride` reads `LoaderBlock` from the caller's stack frame `[caller_ebp + 0x0C]` (`mov eax, [ebp]; mov eax, [eax + 0x0C]`). The Windows 2000 kernel handles everything else identically. PE layout handling (`0x80` alignment, header relocation), `HalpMapPhysicalMemory64` symbol resolution (`0x8001724c` via PDB), and PE checksum recomputation are all standard patching mechanics already supported by `kdpatch.py`.

**Live Validation Results:**
- **COM Mode:** Booted XP HAL with `/DEBUGPORT=COM` -> Connected to KD within 4 seconds.
- **USB Mode:** Booted XP HAL with `/DEBUGPORT=USB` -> Connected to KD on `\\.\pipe\KdUsb` within 13 seconds, successfully reaching full desktop.
- **KD NET Mode:** Booted XP HAL with `/DEBUGPORT=NET` -> Connected to KD via `kdbridge.py` (`\\.\pipe\KdNet`) within 2 seconds (18 RX frames from VM, 2 TX frames to VM).
- **Hardware Capability:** Confirmed EHCI Debug Port capability claimed at MMIO `0xfebf1080` with `DBGP_CLAIM` (`0x58000000`) and device address 127 (`0x00007f01`).

### C. Automated KD NET Test Suite Across All HAL Variants (100% Passing)
Full network kernel debugging (`EtherType 0x88B5` over AMD PCnet to UDP bridge `kdbridge.py` on `\\.\pipe\KdNet`) was verified across all supported HAL variants via `scratch/test_kdnet_variants.py`:

| Variant Binary | Platform / Architecture | VM Disk / CPU | KD NET Result | RX Frames | TX Frames |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `halmacpi_original.dll` | ACPI Multiprocessor (SP4 Rollup) | `win2000-pro-sp4.img` (2 CPU) | **PASSED** (2s) | 22 | 6 |
| `nt51_HALMACPI.DLL` | Windows XP ACPI Multiprocessor (NT 5.1) | `win2000-pro-sp4.img` (2 CPU) | **PASSED** (2s) | 18 | 2 |
| `halmps.dll` | MPS Multiprocessor (Non-ACPI) | `win2000-pro-sp4.img` (2 CPU) | **PASSED** (2s) | 22 | 5 |
| `halaacpi.dll` | ACPI APIC (Uniprocessor) | `win2000-1cpu.img` (1 CPU) | **PASSED** (2s) | 20 | 5 |
| `halacpi.dll` | ACPI PIC (Uniprocessor) | `win2000-1cpu.img` (1 CPU) | **PASSED** (2s) | 22 | 6 |
| `hal.dll` | Standard PC (PIC Uniprocessor) | `win2000-1cpu.img` (1 CPU) | **PASSED** (2s) | 20 | 5 |
| `halapic.dll` | MPS APIC (Uniprocessor Non-ACPI) | `win2000-1cpu.img` (1 CPU) | **PASSED** (2s) | 19 | 5 |

---

## 3. Launchers & Tooling Directory

| Launcher | Target HAL | Virtual Machine | Debugger |
| :--- | :--- | :--- | :--- |
| [launch_xphal_windbg.cmd](file:///c:/Users/Win2000/Downloads/kdtransport_w2k/kdtransport_pkg/launch_xphal_windbg.cmd) | Windows XP HAL (`nt51_HALMACPI.DLL`) | 2-CPU SMP (`win2000-pro-sp4.img`) | Classic WinDbg GUI (`\\.\pipe\KdUsb`) |
| [launch_xphal_windbgx.cmd](file:///c:/Users/Win2000/Downloads/kdtransport_w2k/kdtransport_pkg/launch_xphal_windbgx.cmd) | Windows XP HAL (`nt51_HALMACPI.DLL`) | 2-CPU SMP (`win2000-pro-sp4.img`) | Modern WinDbgX (`\\.\pipe\KdUsb`) |
| [launch_1cpu_windbg.cmd](file:///c:/Users/Win2000/Downloads/kdtransport_w2k/kdtransport_pkg/launch_1cpu_windbg.cmd) | W2K `halaacpi.dll` (ACPI Uni) | 1-CPU (`win2000-1cpu.img`) | Classic WinDbg GUI (`\\.\pipe\KdUsb`) |
| [launch_1cpu_windbgx.cmd](file:///c:/Users/Win2000/Downloads/kdtransport_w2k/kdtransport_pkg/launch_1cpu_windbgx.cmd) | W2K `halaacpi.dll` (ACPI Uni) | 1-CPU (`win2000-1cpu.img`) | Modern WinDbgX (`\\.\pipe\KdUsb`) |
| [launch_all_usb_debug.cmd](file:///c:/Users/Win2000/Downloads/kdtransport_w2k/kdtransport_pkg/launch_all_usb_debug.cmd) | Standard W2K SMP HAL | 2-CPU SMP (`win2000-pro-sp4.img`) | WinDbg USB (`\\.\pipe\KdUsb`) |
| [run_bridge_gui.cmd](file:///c:/Users/Win2000/Downloads/kdtransport_w2k/kdtransport_pkg/run_bridge_gui.cmd) | Any KDNET Patched HAL | VirtualBox / QEMU | GUI Bridge (`\\.\pipe\KdNet`) |

> [!NOTE]
> **EHCI USB Emulation Timing:** Under QEMU TCG software emulation (`accel=tcg`), USB 2.0 transactions require polling MMIO register operations. Initial connection and first break take a short while to stream all USB handshake packets. Please wait patiently during the initial loader and break sequence.

---

## 4. Key Architectural & Operational Rules

1. **Strict Code Isolation:** Never merge XP-specific workarounds into `patcher/kdpatch.py`. Keep XP HAL handling isolated in [patcher/patch_xp_hal.py](file:///c:/Users/Win2000/Downloads/kdtransport_w2k/kdtransport_pkg/patcher/patch_xp_hal.py).
2. **NTFS Resident Attribute Constraint (`boot.ini`):** On `win2000-pro-sp4.img`, `boot.ini` is resident in MFT record 2728 with a maximum capacity of **185 bytes**. Keep operating system entry lines compact:
   ```ini
   multi(0)disk(0)rdisk(0)partition(1)\WINNT="W2K" /DEBUG /DEBUGPORT=USB /BREAK
   ```
3. **QEMU Named Pipe Blocking Semantics:** When `-chardev pipe,id=kdusb,path=KdUsb` is used on Windows, QEMU pauses guest CPU startup until a debugger opens `\\.\pipe\KdUsb`. Debuggers should be launched immediately after QEMU starts.
4. **File Locking:** Always invoke `pe.close()` on `pefile.PE` instances in Python scripts before attempting to overwrite or deploy patched PE images on Windows.
