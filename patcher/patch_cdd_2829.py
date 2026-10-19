vdi_path = r"C:\Users\Win2000\VirtualBox VMs\win2000AHCI\win2000AHCI_1.vdi"

old_id = b"pci#ven_8086&dev_2922"
new_id = b"pci#ven_8086&dev_2829"

offsets = [0x5EC783, 0xBDEE70, 0x2634FD8, 0x2CE4FD8]

with open(vdi_path, "r+b") as f:
    for off in offsets:
        f.seek(off)
        cur = f.read(len(old_id))
        print(f"At 0x{off:X}: {cur}")
        if cur == old_id:
            f.seek(off)
            f.write(new_id)
            print(f"[*] Patched to {new_id} at 0x{off:X}")
        else:
            print(f"[-] Unexpected content at 0x{off:X}")

print("Done patching CriticalDeviceDatabase entries!")
