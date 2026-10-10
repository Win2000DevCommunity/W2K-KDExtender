#!/usr/bin/env python3
"""
kdpatch.py  --  Patch halmacpi.dll (KB891861 rollup) to add USB/NET KD transport.

Usage:
    python kdpatch.py <halmacpi_original.dll> <kdtransport.lib> <halmacpi_patched.dll>

Requirements:
    pip install pefile

What it does:
    1. Verifies halmacpi.dll is the KB891861 rollup build we analysed.
    2. Links the COFF .obj records from kdtransport.lib into a flat binary,
       resolving all inter-module references and hardcoding the confirmed
       absolute addresses for HAL-internal functions.
    3. Appends a new '.kdtrans' section to halmacpi.dll containing that binary.
    4. Patches the single CpInitialize call site in KdPortInitialize to call
       KdpTransportInitOverride instead.
    5. Adds a 5-byte JMP trampoline at the head of each of the 5 simple
       KdPort* exports so they check KdActiveTransport before falling through
       to the original code.
    6. Writes the result to the output path.

All addresses are confirmed from analysis of halmacpi.dll KB891861 x86.
See build/hal_addresses.h for the full address list and methodology notes.
"""

import sys, os, struct, io, re
import pefile

# ── Confirmed addresses (halmacpi.dll KB891861 rollup, ImageBase 0x80010000) ──

HAL_BASE            = 0x80010000

# HAL internal functions called by our transport code (RVAs from KB891861 rollup)
HAL_INTERNALS = {
    '_CpInitialize@12':         HAL_BASE + 0x4EB4,
    '_CpSetBaud@8':             HAL_BASE + 0x4EEA,
    '_CpReadLsr@8':             HAL_BASE + 0x501F,
    '_CpGetByte@12':            HAL_BASE + 0x526C,
    '_CpPutByte@8':             HAL_BASE + 0x5208,
    '_CpDoesPortExist@4':       HAL_BASE + 0x532C,
    '_CpSendModemString@8':     HAL_BASE + 0x4F48,
    '_HalGetBusDataByOffset@24':HAL_BASE + 0x6640,
    '_HalpMapPhysicalMemory64@12':HAL_BASE + 0x7182,
    '_MiGetPteAddress@4':       HAL_BASE + 0x6978,
    '_Port':                    HAL_BASE + 0x8C50,
    '_PortInformation':         HAL_BASE + 0x8C70,
    # HAL exports (READ/WRITE_PORT_*) — also reachable by absolute address
    '_READ_PORT_UCHAR@4':       HAL_BASE + 0x80E8,
    '_READ_PORT_USHORT@4':      HAL_BASE + 0x80F4,
    '_READ_PORT_ULONG@4':       HAL_BASE + 0x8100,
    '_WRITE_PORT_UCHAR@8':      HAL_BASE + 0x8150,
    '_WRITE_PORT_USHORT@8':     HAL_BASE + 0x815C,
    '_WRITE_PORT_ULONG@8':      HAL_BASE + 0x816C,
}

# The CpInitialize call site inside KdPortInitialize (RVA 0x70A1)
CALL_CpInit_VA      = HAL_BASE + 0x70A1   # E8 0E DE FF FF
CALL_CpInit_CHECK   = bytes([0xE8, 0x0E, 0xDE, 0xFF, 0xFF])

# KdPort* export entry points
EXPORTS = {
    'KdPortGetByte':   HAL_BASE + 0x7132,
    'KdPortPollByte':  HAL_BASE + 0x7148,
    'KdPortPutByte':   HAL_BASE + 0x715E,
    'KdPortRestore':   HAL_BASE + 0x7170,
    'KdPortSave':      HAL_BASE + 0x717A,
}

# First instruction size at each export (bytes to steal for the trampoline)
# Must be >= 5 (the JMP instruction size) and not split an instruction.
# Verified by disassembly.
STOLEN = {
    'KdPortGetByte':  6,   # 6a 01 push 1 (2) + ff742408 push [esp+8] (4)
    'KdPortPollByte': 6,   # 6a 00 push 0 (2) + ff742408 push [esp+8] (4)
    'KdPortPutByte':  9,   # ff742404 push [esp+4] (4) + 68508c0180 push offset Port (5)
    'KdPortRestore':  9,   # 66 81 25 588c0180 fbff (9 bytes)
    'KdPortSave':     7,   # 80 0d 588c0180 04 (7 bytes)
}

SECTION_ALIGN   = 0x1000   # 4 KB page alignment (kernel mode)
FILE_ALIGN      = 0x200    # 512-byte file alignment

# ── COFF mini-linker ──────────────────────────────────────────────────────────

IMAGE_FILE_MACHINE_I386     = 0x014C
IMAGE_REL_I386_DIR32        = 0x0006   # absolute 32-bit VA fixup
IMAGE_REL_I386_REL32        = 0x0014   # PC-relative 32-bit fixup
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080

def _align(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)

class CoffObj:
    """Minimal COFF .obj parser for x86 objects produced by MSVC/DDK."""
    def __init__(self, data):
        self.data = data
        mach, nsect, _, symoff, nsym, opthdr, flags = struct.unpack_from('<HHIIIHH', data, 0)
        assert mach == IMAGE_FILE_MACHINE_I386, f"Expected i386 COFF, got machine {mach:#06x}"
        self.nsect   = nsect
        self.symoff  = symoff
        self.nsym    = nsym
        self.sections = []
        off = 20 + opthdr   # section headers start after optional header
        for _ in range(nsect):
            name, vsz, vaddr, rawsz, rawoff, reloff, lnoff, nrel, nln, chars = \
                struct.unpack_from('<8sIIIIIIHHI', data, off)
            self.sections.append({
                'name':   name.rstrip(b'\x00').decode(errors='replace'),
                'rawsz':  rawsz,
                'rawoff': rawoff,
                'reloff': reloff,
                'nrel':   nrel,
                'chars':  chars,
            })
            off += 40
        # Symbol table indexed by 0-based symbol index
        self.symbols = [None] * nsym
        soff = symoff
        strtab_off = symoff + nsym * 18
        i = 0
        while i < nsym:
            raw_name = data[soff:soff+8]
            value, sect_idx, sym_type, storage, naux = struct.unpack_from('<IHHBB', data, soff+8)
            if raw_name[:4] == b'\x00\x00\x00\x00':
                name_off = struct.unpack_from('<I', raw_name, 4)[0]
                end = data.index(b'\x00', strtab_off + name_off)
                sym_name = data[strtab_off + name_off:end].decode(errors='replace')
            else:
                sym_name = raw_name.rstrip(b'\x00').decode(errors='replace')
            self.symbols[i] = {'name': sym_name, 'value': value, 'sect': sect_idx, 'storage': storage}
            soff += 18
            i += 1
            for a in range(naux):
                self.symbols[i] = {'name': f'{sym_name}_aux{a}', 'is_aux': True}
                soff += 18
                i += 1

    def section_data(self, idx):
        s = self.sections[idx]
        if s['rawoff'] == 0 or (s['chars'] & IMAGE_SCN_CNT_UNINITIALIZED_DATA):
            return bytearray(s['rawsz'])
        return bytearray(self.data[s['rawoff']:s['rawoff'] + s['rawsz']])

    def relocations(self, idx):
        s = self.sections[idx]
        rels = []
        off = s['reloff']
        for _ in range(s['nrel']):
            va, symidx, reltype = struct.unpack_from('<IIH', self.data, off)
            rels.append((va, symidx, reltype))
            off += 10
        return rels

def link_objs(obj_list, load_va, hal_base=0):
    """
    Link a list of CoffObj instances into a flat binary starting at load_va.
    Returns (binary: bytes, symbol_map: dict[name -> va], dir32_rvas: list[int]).

    dir32_rvas is a list of RVAs (relative to hal_base) of every DIR32 fixup
    applied in the linked binary.  These must be added to the PE .reloc table
    so that osloader can adjust them when HAL is relocated.
    """
    # Pass 1: assign VAs to every .text/.data/.bss section
    sections_by_obj = []   # list of list of (section_idx, va)
    symbol_va = {}
    cursor = load_va

    for obj in obj_list:
        obj_sects = []
        for si, sect in enumerate(obj.sections):
            name = sect['name']
            # Only link code and initialised/uninitialised data sections
            if not (name.startswith('.text') or name.startswith('.data') or
                    name.startswith('.rdata') or name.startswith('.bss')):
                obj_sects.append(None)
                continue
            align_code = (sect['chars'] >> 20) & 0xF
            alignment = (1 << (align_code - 1)) if align_code > 0 else 4
            cursor = _align(cursor, max(alignment, 4))
            obj_sects.append(cursor)
            cursor += max(sect['rawsz'], 1)
        sections_by_obj.append(obj_sects)
        # Register public symbols
        for sym in obj.symbols:
            if sym and not sym.get('is_aux') and sym['storage'] == 2 and sym['sect'] > 0:
                sect_va = obj_sects[sym['sect'] - 1]
                if sect_va is not None:
                    symbol_va[sym['name']] = sect_va + sym['value']

    # Pass 2: build flat binary and apply relocations
    flat_size = cursor - load_va
    flat = bytearray(flat_size)
    dir32_rvas = []   # RVAs (relative to hal_base) of all DIR32 fixups

    for obj_idx, obj in enumerate(obj_list):
        obj_sects = sections_by_obj[obj_idx]
        for si, sect in enumerate(obj.sections):
            va = obj_sects[si]
            if va is None:
                continue
            offset = va - load_va
            raw = obj.section_data(si)
            flat[offset:offset + len(raw)] = raw
            # Apply relocations
            for (rel_off, sym_idx, rel_type) in obj.relocations(si):
                sym = obj.symbols[sym_idx]
                target_va = None
                if sym['sect'] > 0:
                    # Symbol defined within this object
                    sect_target_va = obj_sects[sym['sect'] - 1]
                    if sect_target_va is not None:
                        target_va = sect_target_va + sym['value']
                elif sym['name'] in symbol_va:
                    target_va = symbol_va[sym['name']]
                elif sym['name'] in HAL_INTERNALS:
                    target_va = HAL_INTERNALS[sym['name']]
                else:
                    print(f"  WARNING: unresolved symbol '{sym['name']}' -- zeroed")
                    target_va = 0

                abs_rel_off = offset + rel_off
                if rel_type == IMAGE_REL_I386_DIR32:
                    existing = struct.unpack_from('<I', flat, abs_rel_off)[0]
                    struct.pack_into('<I', flat, abs_rel_off, (target_va + existing) & 0xFFFFFFFF)
                    dir32_rvas.append((load_va - hal_base) + abs_rel_off)
                elif rel_type == IMAGE_REL_I386_REL32:
                    instr_va = va + rel_off + 4
                    existing = struct.unpack_from('<i', flat, abs_rel_off)[0]
                    rel_val  = (target_va + existing - instr_va) & 0xFFFFFFFF
                    struct.pack_into('<I', flat, abs_rel_off, rel_val)
                else:
                    print(f"  WARNING: unsupported relocation type {rel_type:#06x} for '{sym['name']}'")

    return bytes(flat), symbol_va, dir32_rvas

# ── COFF .lib archive reader ──────────────────────────────────────────────────

def read_lib(lib_path):
    """Extract CoffObj instances from a COFF .lib file."""
    objs = []
    with open(lib_path, 'rb') as f:
        sig = f.read(8)
        assert sig == b'!<arch>\n', f"Not a COFF .lib archive: {lib_path}"
        while True:
            hdr = f.read(60)
            if len(hdr) < 60:
                break
            name    = hdr[0:16].rstrip().decode(errors='replace')
            size    = int(hdr[48:58].strip())
            data    = f.read(size)
            if size % 2:
                f.read(1)   # padding
            if data[:2] == bytes([0x4C, 0x01]):
                try:
                    objs.append(CoffObj(data))
                except Exception as e:
                    print(f"  WARNING: failed to parse COFF obj '{name}': {e}")
    return objs

# ── PE patcher ────────────────────────────────────────────────────────────────

def _make_rel32_call(from_va, to_va):
    """Return 5 bytes: E8 <rel32>  calling to_va from from_va."""
    rel = (to_va - (from_va + 5)) & 0xFFFFFFFF
    return bytes([0xE8]) + struct.pack('<I', rel)

def _make_rel32_jmp(from_va, to_va):
    """Return 5 bytes: E9 <rel32>  jumping to to_va from from_va."""
    rel = (to_va - (from_va + 5)) & 0xFFFFFFFF
    return bytes([0xE9]) + struct.pack('<I', rel)

def build_reloc_blocks(rva_list):
    """Build IMAGE_BASE_RELOCATION blocks from a list of RVAs.

    Each RVA is an offset from the PE ImageBase where a 32-bit absolute
    address lives and needs adjustment during relocation.  Returns the
    raw bytes that can be appended to the existing .reloc table.
    """
    pages = {}
    for rva in sorted(set(rva_list)):
        page = rva & ~0xFFF
        off  = rva & 0xFFF
        pages.setdefault(page, []).append(off)
    blob = bytearray()
    for page in sorted(pages.keys()):
        offs = pages[page]
        entries = [(3 << 12) | o for o in offs]   # type 3 = IMAGE_REL_BASED_HIGHLOW
        if len(entries) % 2 == 1:
            entries.append(0)                      # pad to DWORD alignment
        block_size = 8 + len(entries) * 2
        block = struct.pack('<II', page, block_size)
        for e in entries:
            block += struct.pack('<H', e)
        blob += block
    return bytes(blob)

# Stolen-instruction offsets within each export where an absolute address
# (needing a base relocation) resides.  None means no absolute ref.
# These match the original relocs at 0x7163, 0x7173, 0x717c.
STOLEN_ABS_OFFSET = {
    'KdPortGetByte':  None,       # 6a 01 ff742408  -- no abs ref
    'KdPortPollByte': None,       # 6a 00 ff742408  -- no abs ref
    'KdPortPutByte':  5,          # ff742404 68[508c0180]  -- push _Port at offset +5
    'KdPortRestore':  3,          # 6681 25 [588c0180] fbff -- AND at offset +3
    'KdPortSave':     2,          # 800d [588c0180] 04 -- OR at offset +2
}

# Original RVAs of the relocs that now collide with our 5-byte JMPs.
# These must be neutralized (type set to ABSOLUTE/0) so osloader
# doesn't corrupt our JMP displacements.
NEUTRALIZE_RELOC_RVAS = {0x7163, 0x7173, 0x717c}

def compute_checksum(data):
    """Compute Microsoft PE optional header checksum."""
    csum = 0
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    csum_off = pe_off + 24 + 64
    for i in range(0, len(data), 4):
        if i == csum_off:
            continue
        if i + 4 <= len(data):
            val = struct.unpack_from('<I', data, i)[0]
        else:
            val = struct.unpack_from('<H', data[i:].ljust(4, b'\x00'), 0)[0]
        csum += val
        if csum > 0xFFFFFFFF:
            csum = (csum & 0xFFFFFFFF) + (csum >> 32)
    csum = (csum & 0xFFFF) + (csum >> 16)
    csum = (csum & 0xFFFF) + (csum >> 16)
    return (csum + len(data)) & 0xFFFFFFFF

def patch_halmacpi(orig_path, lib_path, out_path):
    print(f"Reading original: {orig_path}")
    pe = pefile.PE(orig_path, fast_load=False)

    global HAL_BASE
    HAL_BASE = pe.OPTIONAL_HEADER.ImageBase
    print(f"  ImageBase: {HAL_BASE:#010x}")

    # ── Verify this is the right binary ──
    call_rva = CALL_CpInit_VA - HAL_BASE
    file_off = pe.get_offset_from_rva(call_rva)
    actual_bytes = pe.__data__[file_off:file_off+5]
    if actual_bytes != CALL_CpInit_CHECK:
        print(f"WARNING: CpInitialize call site bytes don't match.")
        print(f"  Expected: {CALL_CpInit_CHECK.hex()}")
        print(f"  Got:      {actual_bytes.hex()}")
        print(f"  Proceeding anyway -- verify this is KB891861 rollup halmacpi.dll")
    else:
        print("  Binary verified: CpInitialize call site matches KB891861 rollup.")

    # ── Determine where to place the new section ──
    sect_align = pe.OPTIONAL_HEADER.SectionAlignment
    file_align = pe.OPTIONAL_HEADER.FileAlignment
    print(f"  SectionAlignment: {sect_align:#x}, FileAlignment: {file_align:#x}")

    # For Windows 2000 halmacpi.dll, SectionAlignment == FileAlignment == 0x20.
    # The OS loader loads the image flat from disk into memory (ArcRead).
    # Therefore, VirtualAddress MUST EQUAL PointerToRawData for EVERY section.
    # .reloc starts at 0x14020. Placing .kdtrans at 0x16000 leaves 0x1FE0 (8160 bytes)
    # for .reloc, which comfortably holds the reloc data even after __forceinline
    # expanded the transport code and increased the DIR32 fixup count to ~233.
    new_sect_rva = 0x16000
    new_raw_off  = 0x16000
    new_sect_va  = HAL_BASE + new_sect_rva
    print(f"  New section will be at VA {new_sect_va:#010x} (RVA {new_sect_rva:#010x})")

    # ── Dynamically resolve all exports from the target HAL ──
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') and pe.DIRECTORY_ENTRY_EXPORT:
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                ename = exp.name.decode('ascii', errors='replace')
                eva = HAL_BASE + exp.address
                HAL_INTERNALS[ename] = eva
                HAL_INTERNALS['_' + ename] = eva
                for arg_bytes in (0, 4, 8, 12, 16, 20, 24):
                    HAL_INTERNALS[f"_{ename}@{arg_bytes}"] = eva
                    HAL_INTERNALS[f"{ename}@{arg_bytes}"] = eva

    # ── Link the transport library ──
    print(f"Reading library: {lib_path}")
    objs = read_lib(lib_path)
    if not objs:
        sys.exit("ERROR: No COFF objects found in library. Re-run the DDK build.")
    print(f"  Found {len(objs)} COFF object(s).")

    # Reserve the first 4 KB of our section for trampolines and stubs.
    # Transport code starts at new_sect_va + 0x1000.
    transport_va = new_sect_va + 0x1000
    print(f"  Linking transport code at VA {transport_va:#010x} ...")
    transport_bin, symbol_va, dir32_rvas = link_objs(objs, transport_va, HAL_BASE)
    print(f"  Linked: {len(transport_bin)} bytes, {len(symbol_va)} symbols, {len(dir32_rvas)} DIR32 fixups.")

    # Find the key symbol we need to call
    override_sym = None
    for name in ['_KdpTransportInitOverride@12', '_KdpTransportInitOverride@16',
                 '_KdpTransportInitOverride', 'KdpTransportInitOverride']:
        if name in symbol_va:
            override_sym = name
            break
    if not override_sym:
        print(f"  WARNING: Could not find KdpTransportInitOverride in symbols.")
        print(f"  Symbols found: {list(symbol_va.keys())[:20]}")
        sys.exit("ERROR: KdpTransportInitOverride not found. Check build output.")
    override_va = symbol_va[override_sym]
    print(f"  KdpTransportInitOverride ({override_sym}) at VA {override_va:#010x}")

    # ── Build trampoline region (0x1000 bytes at new_sect_va) ──
    tramp_region = bytearray(0x1000)
    tramp_reloc_rvas = []   # RVAs of absolute addresses in trampoline stubs

    # KdActiveTransport VA (global in our code)
    kdat_va = symbol_va.get('_KdActiveTransport', symbol_va.get('KdActiveTransport', 0))
    if kdat_va == 0:
        print("  WARNING: KdActiveTransport symbol not found. Override dispatch may not work.")

    # Per-export override functions
    overrides = {
        'KdPortGetByte':  '_KdpTransportGetByteOverride',
        'KdPortPollByte': '_KdpTransportPollByteOverride',
        'KdPortPutByte':  '_KdpTransportPutByteOverride',
        'KdPortSave':     '_KdpTransportSaveOverride',
        'KdPortRestore':  '_KdpTransportRestoreOverride',
    }

    pe_data = bytearray(pe.__data__)
    orig_stolen = {}
    for exp_name, exp_va in EXPORTS.items():
        n = STOLEN[exp_name]
        rva = exp_va - HAL_BASE
        foff = pe.get_offset_from_rva(rva)
        orig_stolen[exp_name] = bytes(pe_data[foff:foff+n])

    tramp_offset = 0   # byte offset within tramp_region
    export_patches = {}

    for exp_name, exp_va in EXPORTS.items():
        base_ov = overrides[exp_name]
        ov_sym_candidates = [
            base_ov + '@4', base_ov + '@0', base_ov + '@8',
            base_ov, base_ov[1:] if base_ov.startswith('_') else base_ov
        ]
        ov_va = 0
        for c in ov_sym_candidates:
            if c in symbol_va:
                ov_va = symbol_va[c]
                break
        if ov_va == 0:
            print(f"  WARNING: No override symbol for {exp_name}, trampoline will just steal+return")

        stub_va = new_sect_va + tramp_offset
        stub = bytearray()

        if kdat_va != 0 and ov_va != 0:
            # CMP DWORD PTR [kdat_va], 0   (7 bytes: 83 3D <addr32> 00)
            # The 4-byte absolute address of kdat_va is at stub offset +2
            tramp_reloc_rvas.append(new_sect_rva + tramp_offset + len(stub) + 2)
            stub += bytes([0x83, 0x3D]) + struct.pack('<I', kdat_va) + bytes([0x00])
            # JE fallthrough  (short JMP -- will fix offset below)
            je_offset_pos = len(stub) + 1   # +1 for the JE opcode
            stub += bytes([0x74, 0x00])     # placeholder
            # JMP ov_va
            stub += _make_rel32_jmp(stub_va + len(stub), ov_va)
            # fallthrough: fill in the JE short offset
            fallthrough_offset = len(stub) - (je_offset_pos + 1)
            stub[je_offset_pos] = fallthrough_offset & 0xFF
        # Stolen original bytes
        stolen_start_in_stub = len(stub)
        stub += orig_stolen[exp_name]
        # Record relocation for absolute addresses in stolen instructions
        abs_off = STOLEN_ABS_OFFSET.get(exp_name)
        if abs_off is not None:
            tramp_reloc_rvas.append(new_sect_rva + tramp_offset + stolen_start_in_stub + abs_off)
        # JMP back to export_va + stolen_count
        stub += _make_rel32_jmp(stub_va + len(stub), exp_va + STOLEN[exp_name])

        tramp_region[tramp_offset:tramp_offset + len(stub)] = stub
        tramp_offset += _align(len(stub), 16)

        # The JMP to put at the export entry point
        jmp_to_stub = _make_rel32_jmp(exp_va, stub_va)
        export_patches[exp_name] = jmp_to_stub

    # ── Collect all RVAs that need base relocations ──
    all_reloc_rvas = list(dir32_rvas) + list(tramp_reloc_rvas)
    print(f"  Relocation fixups: {len(dir32_rvas)} from transport code, "
          f"{len(tramp_reloc_rvas)} from trampolines = {len(all_reloc_rvas)} total")

    # ── Assemble the full new section ──
    new_sect_data = bytes(tramp_region) + transport_bin
    raw_size = _align(len(new_sect_data), file_align)
    virt_size = len(new_sect_data)
    new_sect_data = new_sect_data.ljust(raw_size, b'\x00')

    # ── Patch the original binary ──
    # 1. CpInitialize call site -> KdpTransportInitOverride
    call_to_override = _make_rel32_call(CALL_CpInit_VA, override_va)
    call_foff = pe.get_offset_from_rva(CALL_CpInit_VA - HAL_BASE)
    pe_data[call_foff:call_foff+5] = call_to_override
    print(f"  Patched CpInitialize call site -> KdpTransportInitOverride")

    # 2. KdPort* export trampolines
    for exp_name, jmp_bytes in export_patches.items():
        rva  = EXPORTS[exp_name] - HAL_BASE
        foff = pe.get_offset_from_rva(rva)
        pe_data[foff:foff+5] = jmp_bytes
        print(f"  Patched {exp_name} -> trampoline")

    # ── Neutralize original relocs that collide with our JMP trampolines ──
    # The 5-byte JMPs at KdPortPutByte/KdPortRestore/KdPortSave overwrite
    # bytes that had original DIR32 relocs.  If osloader applies those relocs
    # to our JMP displacement bytes, the displacement gets corrupted and we
    # jump to unmapped memory -> triple fault.  Set their type to ABSOLUTE (0)
    # so osloader skips them.
    reloc_dir_idx = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC']
    reloc_rva  = pe.OPTIONAL_HEADER.DATA_DIRECTORY[reloc_dir_idx].VirtualAddress
    reloc_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[reloc_dir_idx].Size
    reloc_foff = pe.get_offset_from_rva(reloc_rva)

    cur_off = reloc_foff
    end_off = reloc_foff + reloc_size
    while cur_off < end_off:
        page_rva, block_sz = struct.unpack_from('<II', pe_data, cur_off)
        if block_sz == 0:
            break
        num_entries = (block_sz - 8) // 2
        for i in range(num_entries):
            e_off = cur_off + 8 + i * 2
            entry = struct.unpack_from('<H', pe_data, e_off)[0]
            entry_rva = page_rva + (entry & 0xFFF)
            if entry_rva in NEUTRALIZE_RELOC_RVAS:
                # Set type nibble to 0 (IMAGE_REL_BASED_ABSOLUTE = skip)
                struct.pack_into('<H', pe_data, e_off, entry & 0xFFF)
                print(f"  Neutralized relocation at RVA {entry_rva:#06x}")
        cur_off += block_sz

    # ── Generate new relocation blocks for .kdtrans ──
    new_reloc_blob = build_reloc_blocks(all_reloc_rvas)
    new_total_reloc_sz = reloc_size + len(new_reloc_blob)
    print(f"  New reloc data: {len(new_reloc_blob)} bytes "
          f"(total .reloc size: {reloc_size:#x} -> {new_total_reloc_sz:#x})")

    if reloc_foff + new_total_reloc_sz > new_raw_off:
        sys.exit(f"ERROR: Relocations ({new_total_reloc_sz:#x} bytes) exceed available space before new section ({new_raw_off:#x})!")

    # ── Add new section to PE ──
    pe_hdr_off = struct.unpack_from('<I', pe_data, 0x3C)[0]
    opt_hdr_size = struct.unpack_from('<H', pe_data, pe_hdr_off + 20)[0]
    num_sections = struct.unpack_from('<H', pe_data, pe_hdr_off + 6)[0]
    sect_hdr_start = pe_hdr_off + 24 + opt_hdr_size
    sect_headers_end = sect_hdr_start + num_sections * 40
    first_raw = min(s.PointerToRawData for s in pe.sections if s.PointerToRawData > 0)

    # Check if there is room for another 40-byte section header in the header area
    if first_raw - sect_headers_end < 40:
        # Move NT headers earlier to 0x80 (inside the unused DOS stub)
        new_pe_off = 0x80
        hdr_len = sect_headers_end - pe_hdr_off
        pe_data[new_pe_off:new_pe_off + hdr_len] = pe_data[pe_hdr_off:sect_headers_end]
        struct.pack_into('<I', pe_data, 0x3C, new_pe_off)
        pe_data[new_pe_off + hdr_len:first_raw] = b'\x00' * (first_raw - (new_pe_off + hdr_len))
        pe_hdr_off = new_pe_off
        sect_hdr_start = pe_hdr_off + 24 + opt_hdr_size

    num_sections_off = pe_hdr_off + 6
    num_sections = struct.unpack_from('<H', pe_data, num_sections_off)[0]
    new_num = num_sections + 1
    struct.pack_into('<H', pe_data, num_sections_off, new_num)

    new_sect_hdr_off = sect_hdr_start + num_sections * 40

    # Build the new section header (IMAGE_SECTION_HEADER, 40 bytes)
    sect_name   = b'.kdtrans'          # 8 bytes
    IMAGE_SCN_CNT_CODE            = 0x00000020
    IMAGE_SCN_CNT_INITIALIZED_DATA= 0x00000040
    IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
    IMAGE_SCN_MEM_NOT_PAGED       = 0x08000000
    IMAGE_SCN_MEM_EXECUTE         = 0x20000000
    IMAGE_SCN_MEM_READ            = 0x40000000
    IMAGE_SCN_MEM_WRITE           = 0x80000000
    characteristics = (IMAGE_SCN_CNT_CODE |
                       IMAGE_SCN_CNT_INITIALIZED_DATA |
                       IMAGE_SCN_CNT_UNINITIALIZED_DATA |
                       IMAGE_SCN_MEM_NOT_PAGED |
                       IMAGE_SCN_MEM_EXECUTE |
                       IMAGE_SCN_MEM_READ |
                       IMAGE_SCN_MEM_WRITE)
    new_hdr = struct.pack('<8sIIIIIIHHI',
        sect_name,
        virt_size,      # Misc_VirtualSize
        new_sect_rva,   # VirtualAddress
        raw_size,       # SizeOfRawData
        new_raw_off,    # PointerToRawData
        0, 0, 0, 0,     # relocs/linenos
        characteristics)
    pe_data[new_sect_hdr_off:new_sect_hdr_off+40] = new_hdr

    # ── Update .reloc section header and DATA_DIRECTORY ──
    # Update DATA_DIRECTORY[5].Size
    reloc_dir_off = pe_hdr_off + 24 + 96 + reloc_dir_idx * 8
    struct.pack_into('<I', pe_data, reloc_dir_off + 4, new_total_reloc_sz)

    # Update .reloc section header VirtualSize and SizeOfRawData
    for i in range(num_sections):   # num_sections is still old count (before +1)
        s_off = sect_hdr_start + i * 40
        s_name = pe_data[s_off:s_off+8].rstrip(b'\x00')
        if s_name == b'.reloc':
            # VirtualSize: covers the new total reloc data
            struct.pack_into('<I', pe_data, s_off + 8, new_total_reloc_sz)
            # SizeOfRawData: covers the space between .reloc and .kdtrans
            struct.pack_into('<I', pe_data, s_off + 16, new_raw_off - reloc_rva)
            print(f"  Updated .reloc: VirtualSize={new_total_reloc_sz:#x}  "
                  f"SizeOfRawData={(new_raw_off - reloc_rva):#x}")
            break

    # Update SizeOfImage
    size_of_image_off = pe_hdr_off + 24 + 56
    new_image_size    = _align(new_sect_rva + raw_size, sect_align)
    struct.pack_into('<I', pe_data, size_of_image_off, new_image_size)

    # ── Append relocations and section data cleanly without shifting offsets ──
    # Truncate pe_data to the end of original active relocations
    pe_data = pe_data[:reloc_foff + reloc_size]
    # Append the new reloc blocks
    pe_data += new_reloc_blob
    # Pad with zeroes up to new_raw_off (0x15000)
    if len(pe_data) < new_raw_off:
        pe_data += b'\x00' * (new_raw_off - len(pe_data))
    # Append the new section data (starts at exactly new_raw_off = 0x15000)
    pe_data += new_sect_data
    # Align file end to file_align
    aligned_file_len = _align(len(pe_data), file_align)
    if len(pe_data) < aligned_file_len:
        pe_data += b'\x00' * (aligned_file_len - len(pe_data))

    # Recompute PE Checksum
    new_csum = compute_checksum(pe_data)
    struct.pack_into('<I', pe_data, pe_hdr_off + 24 + 64, new_csum)

    print(f"  Added .kdtrans section: VirtualAddress={new_sect_rva:#x}  PointerToRawData={new_raw_off:#x}")
    print(f"  Section sizes: VirtualSize={virt_size:#x}  RawSize={raw_size:#x}")
    print(f"  SizeOfImage updated to {new_image_size:#010x}")
    print(f"  CheckSum updated to {new_csum:#010x}")

    with open(out_path, 'wb') as f:
        f.write(pe_data)
    print(f"\nDone. Patched DLL written to: {out_path}")
    print(f"  Size: {len(pe_data)} bytes")
    print()
    print("  Deploy by copying to \\system32\\halmacpi.dll on the target.")
    print("  Keep the original as halmacpi_orig.dll for rollback.")
    print("  Set /DEBUGPORT=NET or /DEBUGPORT=USB in boot.ini before rebooting.")

def main():
    if len(sys.argv) != 4:
        print(__doc__)
        sys.exit(1)
    patch_halmacpi(sys.argv[1], sys.argv[2], sys.argv[3])

if __name__ == '__main__':
    main()
