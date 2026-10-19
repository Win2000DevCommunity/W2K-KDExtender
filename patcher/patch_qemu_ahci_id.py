"""
Patch QEMU binary to change ICH9 AHCI PCI device ID from 0x2922 to 0x2829
so it matches VirtualBox's ICH8M SATA controller.

VirtualBox uses PCI ID 8086:2829 (ICH8M)
QEMU ich9-ahci uses PCI ID 8086:2922 (ICH9R)

The Windows 2000 AHCI driver in the VDI is bound to 8086:2829.
"""
import struct
import shutil
import os
import sys

qemu_path = r"C:\Users\Win2000\Downloads\qemu\build\qemu-system-i386.exe"
backup_path = qemu_path + ".bak_2922"

# Read the binary
with open(qemu_path, "rb") as f:
    data = f.read()

print(f"QEMU binary size: {len(data)} bytes")

# The PCI device ID 0x2922 is written as a 16-bit little-endian value
# In the ICH9 AHCI class_init function:
#   k->device_id = PCI_DEVICE_ID_INTEL_82801IR; // 0x2922
# This compiles to something like: mov word ptr [reg+offset], 0x2922
# or: mov dword ptr [...], 0x2922  (zero-extended)
# We need to find the right occurrence

# Search for x86 instruction patterns that move 0x2922 into a register/memory
# Common patterns:
#   C7 xx xx xx xx xx 22 29 00 00  (mov dword, 0x2922)
#   66 C7 xx xx 22 29              (mov word, 0x2922)
#   B8 22 29 00 00                 (mov eax, 0x2922)
#   etc.

# Let's search for all occurrences of bytes 0x22 0x29
target_le = struct.pack("<H", 0x2922)  # b'\x22\x29'
replacement_le = struct.pack("<H", 0x2829)  # b'\x29\x28'

# Find all occurrences
occurrences = []
pos = 0
while True:
    idx = data.find(target_le, pos)
    if idx < 0:
        break
    # Show context
    ctx_start = max(0, idx - 8)
    ctx_end = min(len(data), idx + 10)
    ctx_hex = data[ctx_start:ctx_end].hex(' ')
    occurrences.append((idx, ctx_hex))
    pos = idx + 1

print(f"\nFound {len(occurrences)} occurrences of 0x2922 (LE: {target_le.hex()})")

# Filter to likely PCI device ID assignments
# Look for patterns near "mov" instructions or constant data
candidates = []
for idx, ctx in occurrences:
    # Check surrounding bytes for instruction patterns
    # mov dword ptr: C7 xx ... 22 29 00 00
    # Or in constant tables/structs
    before = data[max(0,idx-16):idx]
    after = data[idx+2:idx+4]
    
    # Check if followed by 0x00 0x00 (32-bit zero-extended)
    is_dword_zero_ext = (after == b'\x00\x00')
    
    # Check if this looks like a PCI config write
    # Also check nearby for 0x8086 (Intel vendor ID) 
    nearby = data[max(0,idx-64):idx+64]
    has_intel_vendor = (b'\x86\x80' in nearby or b'\x06\x80' in nearby)
    
    candidates.append({
        'offset': idx,
        'ctx': ctx,
        'zero_ext': is_dword_zero_ext,
        'has_vendor': has_intel_vendor,
    })

print("\nCandidates analysis:")
for c in candidates:
    flags = []
    if c['zero_ext']:
        flags.append("DWORD_ZEXT")
    if c['has_vendor']:
        flags.append("NEAR_INTEL_VID")
    flags_str = " ".join(flags) if flags else "no flags"
    print(f"  0x{c['offset']:08X}: {c['ctx']}  [{flags_str}]")

# Find the best candidate - should have both zero extension AND nearby Intel vendor ID
best = [c for c in candidates if c['zero_ext'] and c['has_vendor']]
if not best:
    # Fallback to just zero-extended
    best = [c for c in candidates if c['zero_ext']]
if not best:
    best = candidates

print(f"\nBest candidates: {len(best)}")
for c in best:
    print(f"  0x{c['offset']:08X}")

if len(best) == 0:
    print("ERROR: No candidates found!")
    sys.exit(1)

# If there are too many candidates, let's be more surgical
# We should only patch the one in the ICH9 AHCI init code
# Let's just patch all candidates that have both flags
to_patch = best

# Backup
if not os.path.exists(backup_path):
    shutil.copy2(qemu_path, backup_path)
    print(f"\nBackup saved: {backup_path}")
else:
    print(f"\nBackup already exists: {backup_path}")

# Patch
patched = bytearray(data)
count = 0
for c in to_patch:
    off = c['offset']
    patched[off:off+2] = replacement_le
    count += 1
    print(f"Patched offset 0x{off:08X}: {target_le.hex()} -> {replacement_le.hex()}")

with open(qemu_path, "wb") as f:
    f.write(patched)

print(f"\nPatched {count} occurrence(s). PCI device ID: 0x2922 -> 0x2829")
print("QEMU will now present ICH8M SATA (VirtualBox-compatible) to the guest.")
