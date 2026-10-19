import os
import sys

VDI_PATH = r"C:\Users\Win2000\VirtualBox VMs\win2000AHCI\win2000AHCI_1.vdi"
FIXED_HAL_PATH = r"c:\Users\Win2000\Downloads\kdtransport_w2k\kdtransport_pkg\halmacpi_fixed.dll"

def inject():
    with open(FIXED_HAL_PATH, "rb") as f:
        fixed_hal = f.read()
    assert len(fixed_hal) == 111008, f"Unexpected hal size: {len(fixed_hal)}"

    with open(VDI_PATH, "r+b") as f:
        # 1. Update hal.dll at both known locations
        for off in [0x13d68e00, 0x2c1a0e00]:
            f.seek(off)
            f.write(fixed_hal)
            print(f"[*] Injected fixed hal.dll at offset {hex(off)}")

        # 2. Update boot.ini at 0x67ef40
        f.seek(0x67ef40)
        boot_ini_orig = f.read(420)
        
        new_boot_ini = (
            b"[boot loader]\r\n"
            b"timeout=3\r\n"
            b"default=multi(0)disk(0)rdisk(0)partition(1)\\WINNT\r\n"
            b"[operating systems]\r\n"
            b"multi(0)disk(0)rdisk(0)partition(1)\\WINNT=\"Windows 2000 - KD USB\" /fastdetect /DEBUG /DEBUGPORT=USB\r\n"
            b"multi(0)disk(0)rdisk(0)partition(1)\\WINNT=\"Windows 2000 - KD NET\" /fastdetect /DEBUG /DEBUGPORT=NET\r\n"
            b"multi(0)disk(0)rdisk(0)partition(1)\\WINNT=\"Windows 2000 - KD COM\" /fastdetect /DEBUG /DEBUGPORT=COM1 /BAUDRATE=115200\r\n"
        )
        assert len(new_boot_ini) <= 420
        padded = new_boot_ini.ljust(420, b" ")
        f.seek(0x67ef40)
        f.write(padded)
        print("[*] Successfully set 'Windows 2000 - KD USB' as DEFAULT entry in boot.ini!")

if __name__ == "__main__":
    inject()
