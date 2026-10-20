#!/usr/bin/env python3
"""
patch_xp_hal.py  --  Dedicated, isolated patcher for Windows XP HAL (NT 5.1) on Windows 2000.
Keeps all working W2K patch code completely untouched and separate.

The only XP HAL-specific fixup is the LoaderBlock retrieval: in the XP HAL's
KdPortInitialize, EBX is reused as scratch for HalpGetResourceSortValue, so the
injected KdpTransportInitOverride reads LoaderBlock from the caller's stack frame
[caller_ebp + 0x0C] instead of from EBX. Everything else (PE layout handling,
symbol resolution, checksum) is standard patching that kdpatch.py already supports.
"""

import sys, os, struct, io, re, ctypes
from ctypes import wintypes
import pefile

# Add patcher directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kdpatch import patch_hal, compute_checksum

def patch_xp_hal(orig_xp_hal, lib_path, out_xp_hal, sym_search_paths=None):
    orig_xp_hal = os.path.abspath(orig_xp_hal)
    lib_path    = os.path.abspath(lib_path)
    out_xp_hal  = os.path.abspath(out_xp_hal)

    print("=" * 70)
    print("   DEDICATED PATCHER FOR WINDOWS XP HAL (NT 5.1) ON WINDOWS 2000")
    print(f" Source: {orig_xp_hal}")
    print(f" Library: {lib_path}")
    print(f" Target: {out_xp_hal}")
    print("=" * 70)

    # Step 1: Run HAL variant patching (links .kdtrans section into the binary)
    patch_hal(orig_xp_hal, lib_path, out_xp_hal, sym_search_paths)

    # Step 2: Fix LoaderBlock retrieval in KdpTransportInitOverride
    # In W2K: mov LoaderBlock, ebx (89 5D FC)
    # In XP:  mov eax, [ebp]; mov eax, [eax + 0x0C] (8B 45 00 8B 40 0C)
    with open(out_xp_hal, 'rb') as f:
        data = bytearray(f.read())

    target = bytes([0x89, 0x5D, 0xFC, 0x8B, 0x45, 0xFC])
    idx = data.find(target)
    if idx == -1:
        print("[-] Error: LoaderBlock instruction pattern not found in patched HAL!")
        return False

    replacement = bytes([0x8B, 0x45, 0x00, 0x8B, 0x40, 0x0C])
    data[idx:idx+6] = replacement
    print(f"[+] Fixed LoaderBlock retrieval at offset {hex(idx)} -> [caller_ebp + 0x0C]")

    # Step 3: Recalculate PE checksum
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    new_csum = compute_checksum(data)
    struct.pack_into('<I', data, pe_off + 24 + 64, new_csum)
    print(f"[+] Recalculated PE checksum: {hex(new_csum)}")

    with open(out_xp_hal, 'wb') as f:
        f.write(data)

    print(f"[+] Successfully wrote patched XP HAL to {out_xp_hal} ({len(data)} bytes)")
    return True

if __name__ == '__main__':
    orig = sys.argv[1] if len(sys.argv) > 1 else r"C:\HAL variants\2000 NT5.1\HALMACPI.DLL"
    lib  = sys.argv[2] if len(sys.argv) > 2 else r"build\obj\i386\kdtransport.lib"
    out  = sys.argv[3] if len(sys.argv) > 3 else r"build\patched_variants\nt51_HALMACPI.DLL"
    patch_xp_hal(orig, lib, out)
