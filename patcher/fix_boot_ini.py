"""Fix boot.ini in VDI to include KD USB, KD NET, KD COM entries."""
import sys
import struct

vdi_path = r"C:\Users\Win2000\VirtualBox VMs\win2000AHCI\win2000AHCI_1.vdi"

# The correct boot.ini content
boot_ini = (
    "[boot loader]\r\n"
    "timeout=0\r\n"
    "default=multi(0)disk(0)rdisk(0)partition(1)\\WINNT\r\n"
    "DefSwitches=/DEBUG /DEBUGPORT=USB /fastdetect\r\n"
    "[operating systems]\r\n"
    'multi(0)disk(0)rdisk(0)partition(1)\\WINNT="Windows 2000 - KD USB" /DEBUG /DEBUGPORT=USB /fastdetect\r\n'
    'multi(0)disk(0)rdisk(0)partition(1)\\winnt="Windows 2000 - KD USB 2" /DEBUG /DEBUGPORT=USB /fastdetect\r\n'
    'multi(0)disk(0)rdisk(0)partition(1)\\WINNT="Windows 2000 - KD NET" /fastdetect /DEBUG /DEBUGPORT=NET\r\n'
    'multi(0)disk(0)rdisk(0)partition(1)\\WINNT="Windows 2000 - KD COM" /fastdetect /DEBUG /DEBUGPORT=COM1 /BAUDRATE=115200\r\n'
    'multi(0)disk(0)rdisk(0)partition(1)\\WINNT="Windows 2000 Professional" /fastdetect\r\n'
).encode("ascii")

print(f"New boot.ini size: {len(boot_ini)} bytes")
print("Content:")
print(boot_ini.decode("ascii"))

# Known boot.ini locations in VDI
search_offsets = [0x450000, 0x67EF00]

with open(vdi_path, "r+b") as f:
    for base_off in search_offsets:
        f.seek(base_off)
        data = f.read(8192)
        idx = data.find(b"[boot loader]")
        if idx < 0:
            print(f"No [boot loader] found near 0x{base_off:X}, skipping")
            continue
        
        exact_off = base_off + idx
        print(f"\nFound [boot loader] at VDI offset 0x{exact_off:X}")
        
        # Find the end of the old boot.ini
        old_boot = data[idx:]
        old_end = old_boot.find(b"\x00")
        if old_end > 0:
            old_size = old_end
        else:
            old_size = 512
        print(f"Old boot.ini size: ~{old_size} bytes")
        
        # Write new boot.ini
        f.seek(exact_off)
        f.write(boot_ini)
        # Null-terminate
        f.write(b"\x00" * 32)
        f.flush()
        
        # Verify
        f.seek(exact_off)
        verify = f.read(len(boot_ini))
        if verify == boot_ini:
            print(f"Verified OK at 0x{exact_off:X}")
        else:
            print(f"VERIFICATION FAILED at 0x{exact_off:X}!")

print("\nDone!")
