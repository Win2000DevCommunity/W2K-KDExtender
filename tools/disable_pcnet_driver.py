"""
tools/disable_pcnet_driver.py

Safely disables the PCnet NDIS miniport driver (pcntn5m.sys) inside the VirtualBox VDI
WITHOUT corrupting NTFS file tables, directories, MFT records, or registry hives.

Background & Strategy:
  - In a single-NIC setup, both the HAL KD transport and the Windows 2000 NDIS miniport
    driver (pcntn5m.sys) attempt to control the PCnet Am79C973 hardware.
  - When NDIS initializes pcntn5m.sys, it resets the adapter, changes descriptor rings,
    and initiates DHCP negotiation. This causes contention with the HAL KD transport
    and deadlocks Windows 2000 during boot at "Preparing network connections...".
  - To solve this cleanly for single-NIC setups, we patch the DriverEntry of pcntn5m.sys
    directly in the VDI to return STATUS_UNSUCCESSFUL (0xC0000001).
  - Original 8 bytes at EntryPoint (+0x2E08):
      55 8B EC 83 EC 60 53 33  (push ebp; mov ebp, esp; sub esp, 60h; push ebx; xor ebx, ebx)
  - Patched 8 bytes:
      B8 01 00 00 C0 C2 08 00  (mov eax, 0xC0000001; ret 8)
  - When Windows loads the driver during PnP enumeration, DriverEntry returns STATUS_UNSUCCESSFUL,
    causing the kernel to cleanly abort loading pcntn5m.sys.
  - The HAL KD transport retains exclusive, uncontested access to the hardware.
  - Windows boots seamlessly to the desktop with active kernel debugging!

Usage:
  python tools/disable_pcnet_driver.py [path_to_vdi]
  python tools/disable_pcnet_driver.py [path_to_vdi] --revert
"""

import sys
import os

DEFAULT_VDI_PATH = r"C:\Users\Win2000\VirtualBox VMs\win2000AHCI\win2000AHCI_1.vdi"

TARGET_OFFSETS = [0x5548e00, 0x424a2e00]
EP_OFFSET = 0x2e08

ORIG_BYTES = bytes.fromhex("558BEC83EC605333")
PATCH_BYTES = bytes.fromhex("B8010000C0C20800")

def main():
    args = sys.argv[1:]
    revert = "--revert" in args
    if revert:
        args.remove("--revert")

    vdi_path = args[0] if len(args) > 0 else DEFAULT_VDI_PATH

    if not os.path.exists(vdi_path):
        print(f"[-] Error: VDI file not found: {vdi_path}")
        sys.exit(1)

    print(f"[*] Target VDI: {vdi_path}")
    print(f"[*] Action:     {'REVERT (restore pcntn5m.sys)' if revert else 'DISABLE (patch DriverEntry to STATUS_UNSUCCESSFUL)'}")

    with open(vdi_path, "r+b") as f:
        for base in TARGET_OFFSETS:
            ep_abs = base + EP_OFFSET
            f.seek(ep_abs)
            curr = f.read(8)
            print(f"\n[*] Checking offset {base:#x} (EntryPoint at {ep_abs:#x}):")
            print(f"    Current bytes: {curr.hex()}")

            if revert:
                if curr == ORIG_BYTES:
                    print("    Already in original state, skipping.")
                    continue
                f.seek(ep_abs)
                f.write(ORIG_BYTES)
                print(f"    Restored original bytes: {ORIG_BYTES.hex()}")
            else:
                if curr == PATCH_BYTES:
                    print("    Already patched, skipping.")
                    continue
                if curr != ORIG_BYTES:
                    print(f"[-] Warning: unexpected bytes at {ep_abs:#x}: {curr.hex()} != {ORIG_BYTES.hex()}")
                    print("    Skipping this offset for safety.")
                    continue
                f.seek(ep_abs)
                f.write(PATCH_BYTES)
                print(f"    Wrote patch bytes: {PATCH_BYTES.hex()}")

            # Verify
            f.seek(ep_abs)
            check = f.read(8)
            expected = ORIG_BYTES if revert else PATCH_BYTES
            if check == expected:
                print(f"    Verified successfully: {check.hex()} == {expected.hex()}")
            else:
                print(f"[-] Verification failed at {ep_abs:#x}: got {check.hex()}, expected {expected.hex()}")
                sys.exit(1)

    print("\n[+] Operation completed successfully!")

if __name__ == "__main__":
    main()
