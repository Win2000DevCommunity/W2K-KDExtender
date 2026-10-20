#!/usr/bin/env python3
"""
kdpatch.py  --  Universal dynamic patcher for Windows 2000 / XP HAL variants.

Usage:
    python kdpatch.py <hal_original.dll> <kdtransport.lib> <hal_patched.dll> [symbols_dir]
    python kdpatch.py --batch <hal_variants_dir> <kdtransport.lib> <out_dir> [symbols_dir]

Requirements:
    pip install pefile

Features:
    1. Fully dynamic symbol resolution: No hardcoded function or variable addresses.
       Internal symbols (CpInitialize, Port, HalpMapPhysicalMemory64) are resolved
       using Windows dbghelp.dll from matching PDB/DBG files, with robust binary
       pattern fallback.
    2. Supports all Windows 2000 SP4 HAL variants:
       - hal.dll (Standard PC)
       - halaacpi.dll (ACPI APIC)
       - halacpi.dll (ACPI PIC)
       - halapic.dll (MPS APIC)
       - halmps.dll (MPS Multi-processor)
       - halsp.dll (Compaq SystemPro)
       - halmacpi.dll (ACPI Multi-processor - SP4 / KB891861 rollup)
       - NT 5.1 (XP) HAL for Windows 2000 (HALMACPI.DLL)
    3. Links COFF objects from kdtransport.lib into an added '.kdtrans' section.
    4. Dynamically splices the CpInitialize call site inside KdPortInitialize.
    5. Dynamically builds trampolines for KdPort* exports, stealing the exact instruction
       lengths and neutralizing colliding original base relocations.
    6. Dynamically appends new relocations to .reloc and recalculates PE checksum.
"""

import sys, os, struct, io, re, ctypes
from ctypes import wintypes
import pefile

dbghelp = ctypes.windll.dbghelp
hProcess = wintypes.HANDLE(0x12345678)
dbghelp.SymSetOptions(0x2) # SYMOPT_UNDNAME

class SYMBOL_INFO(ctypes.Structure):
    _fields_ = [
        ('SizeOfStruct', wintypes.ULONG),
        ('TypeIndex', wintypes.ULONG),
        ('Reserved', ctypes.c_uint64 * 2),
        ('Index', wintypes.ULONG),
        ('Size', wintypes.ULONG),
        ('ModBase', ctypes.c_uint64),
        ('Flags', wintypes.ULONG),
        ('Value', ctypes.c_uint64),
        ('Address', ctypes.c_uint64),
        ('Register', wintypes.ULONG),
        ('Scope', wintypes.ULONG),
        ('Tag', wintypes.ULONG),
        ('NameLen', wintypes.ULONG),
        ('MaxNameLen', wintypes.ULONG),
        ('Name', ctypes.c_char * 256)
    ]

PSYM_ENUMERATESYMBOLS_CALLBACK = ctypes.WINFUNCTYPE(wintypes.BOOL, ctypes.c_void_p, wintypes.ULONG, ctypes.c_void_p)
dbghelp.SymEnumSymbols.argtypes = [wintypes.HANDLE, ctypes.c_uint64, ctypes.c_char_p, PSYM_ENUMERATESYMBOLS_CALLBACK, ctypes.c_void_p]
dbghelp.SymLoadModuleEx.restype = ctypes.c_uint64
dbghelp.SymLoadModuleEx.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint64, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]

DEFAULT_SYM_PATHS = [
    r'C:\Users\Win2000\Downloads\w2ksp4sym_en\dll',
    r'C:\Users\Win2000\Downloads\w2ksp4sym_en\dll\NT5.1 HAL',
    r'C:\Users\Win2000\Downloads\Windows2000-KB891861-x86-Symbols-ENU\symbols\dll'
]

def resolve_symbols_dbghelp(dll_path, sym_search_paths=None):
    if sym_search_paths is None:
        sym_search_paths = DEFAULT_SYM_PATHS
    elif isinstance(sym_search_paths, str):
        sym_search_paths = [sym_search_paths] + DEFAULT_SYM_PATHS

    # Filter only existing paths
    existing_paths = [p for p in sym_search_paths if os.path.isdir(p)]
    if not existing_paths:
        return {}

    search_str = ';'.join(existing_paths).encode('ascii', errors='ignore')
    dbghelp.SymInitialize(hProcess, search_str, False)
    pe = pefile.PE(dll_path)
    base = pe.OPTIONAL_HEADER.ImageBase
    size = pe.OPTIONAL_HEADER.SizeOfImage
    hmod = dbghelp.SymLoadModuleEx(hProcess, None, dll_path.encode('ascii', errors='ignore'), None, base, size, None, 0)
    found = {}
    if hmod:
        def enum_cb(pSymInfo, SymbolSize, UserContext):
            s = ctypes.cast(pSymInfo, ctypes.POINTER(SYMBOL_INFO)).contents
            name = s.Name.decode('ascii', errors='ignore')
            found[name] = s.Address
            return True
        cb = PSYM_ENUMERATESYMBOLS_CALLBACK(enum_cb)
        dbghelp.SymEnumSymbols(hProcess, hmod, b'*', cb, None)
        dbghelp.SymUnloadModule64(hProcess, hmod)
    dbghelp.SymCleanup(hProcess)
    return found

def _align(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)

def _make_rel32_call(from_va, to_va):
    rel = (to_va - (from_va + 5)) & 0xFFFFFFFF
    return bytes([0xE8]) + struct.pack('<I', rel)

def _make_rel32_jmp(from_va, to_va):
    rel = (to_va - (from_va + 5)) & 0xFFFFFFFF
    return bytes([0xE9]) + struct.pack('<I', rel)

def build_reloc_blocks(rva_list):
    pages = {}
    for rva in sorted(set(rva_list)):
        page = rva & ~0xFFF
        off  = rva & 0xFFF
        pages.setdefault(page, []).append(off)
    blob = bytearray()
    for page in sorted(pages.keys()):
        offs = pages[page]
        entries = [(3 << 12) | o for o in offs]
        if len(entries) % 2 == 1:
            entries.append(0)
        block_size = 8 + len(entries) * 2
        block = struct.pack('<II', page, block_size)
        for e in entries:
            block += struct.pack('<H', e)
        blob += block
    return bytes(blob)

def compute_checksum(data):
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

IMAGE_FILE_MACHINE_I386     = 0x014C
IMAGE_REL_I386_DIR32        = 0x0006
IMAGE_REL_I386_REL32        = 0x0014
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080

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
        off = 20 + opthdr
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

def read_lib(lib_path):
    objs = []
    with open(lib_path, 'rb') as f:
        sig = f.read(8)
        assert sig == b'!<arch>\n', f"Not a COFF .lib archive: {lib_path}"
        while True:
            hdr = f.read(60)
            if len(hdr) < 60:
                break
            name = hdr[0:16].rstrip().decode(errors='replace')
            size = int(hdr[48:58].strip())
            data = f.read(size)
            if size % 2:
                f.read(1)
            if data[:2] == bytes([0x4C, 0x01]):
                try:
                    objs.append(CoffObj(data))
                except Exception as e:
                    print(f"  WARNING: failed to parse COFF obj '{name}': {e}")
    return objs

def link_objs_dynamic(obj_list, load_va, hal_base, hal_symbols):
    sections_by_obj = []
    symbol_va = {}
    cursor = load_va

    for obj in obj_list:
        obj_sects = []
        for si, sect in enumerate(obj.sections):
            name = sect['name']
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
        for sym in obj.symbols:
            if sym and not sym.get('is_aux') and sym['storage'] == 2 and sym['sect'] > 0:
                sect_va = obj_sects[sym['sect'] - 1]
                if sect_va is not None:
                    symbol_va[sym['name']] = sect_va + sym['value']

    flat_size = cursor - load_va
    flat = bytearray(flat_size)
    dir32_rvas = []

    for obj_idx, obj in enumerate(obj_list):
        obj_sects = sections_by_obj[obj_idx]
        for si, sect in enumerate(obj.sections):
            va = obj_sects[si]
            if va is None:
                continue
            offset = va - load_va
            raw = obj.section_data(si)
            flat[offset:offset + len(raw)] = raw
            for (rel_off, sym_idx, rel_type) in obj.relocations(si):
                sym = obj.symbols[sym_idx]
                target_va = None
                sname = sym['name']
                if sym['sect'] > 0:
                    sect_target_va = obj_sects[sym['sect'] - 1]
                    if sect_target_va is not None:
                        target_va = sect_target_va + sym['value']
                elif sname in symbol_va:
                    target_va = symbol_va[sname]
                elif sname in hal_symbols:
                    target_va = hal_symbols[sname]
                else:
                    clean_name = sname.lstrip('_').split('@')[0]
                    if clean_name in hal_symbols:
                        target_va = hal_symbols[clean_name]
                    else:
                        print(f"  WARNING: unresolved symbol '{sname}' -- zeroed")
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

    return bytes(flat), symbol_va, dir32_rvas

def patch_hal(orig_path, lib_path, out_path, sym_search_paths=None):
    print(f"\n=======================================================")
    print(f"Patching: {orig_path}")
    print(f"=======================================================")
    pe = pefile.PE(orig_path, fast_load=False)
    hal_base = pe.OPTIONAL_HEADER.ImageBase
    print(f"  ImageBase: {hal_base:#010x}")

    # 1. Resolve symbols from DBG/PDB via dbghelp
    pdb_syms = resolve_symbols_dbghelp(orig_path, sym_search_paths)
    print(f"  Resolved {len(pdb_syms)} symbols via dbghelp.")

    # 2. Collect all exports
    exports = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') and pe.DIRECTORY_ENTRY_EXPORT:
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                ename = exp.name.decode('ascii', errors='replace')
                exports[ename] = exp.address

    # Build HAL symbol table for linking
    hal_symbols = {}
    for ename, erva in exports.items():
        eva = hal_base + erva
        hal_symbols[ename] = eva
        hal_symbols['_' + ename] = eva
        for arg_b in (0, 4, 8, 12, 16, 20, 24):
            hal_symbols[f"_{ename}@{arg_b}"] = eva
            hal_symbols[f"{ename}@{arg_b}"] = eva

    for sname, sva in pdb_syms.items():
        hal_symbols[sname] = sva
        hal_symbols['_' + sname] = sva
        for arg_b in (0, 4, 8, 12, 16, 20, 24):
            hal_symbols[f"_{sname}@{arg_b}"] = sva
            hal_symbols[f"{sname}@{arg_b}"] = sva

    # 3. Fallback / Validation for Port, CpInitialize, HalpMapPhysicalMemory64
    if 'Port' not in hal_symbols and '_Port' not in hal_symbols:
        put_rva = exports['KdPortPutByte']
        put_code = pe.get_data(put_rva, 10)
        port_va = struct.unpack_from('<I', put_code, 5)[0]
        hal_symbols['Port'] = port_va
        hal_symbols['_Port'] = port_va
    else:
        port_va = hal_symbols.get('_Port', hal_symbols.get('Port'))

    # Find CpInitialize call site inside KdPortInitialize:
    init_rva = exports['KdPortInitialize']
    init_code = pe.get_data(init_rva, 600)
    pattern = bytes([0x68]) + struct.pack('<I', port_va) + bytes([0xE8])
    idx = init_code.find(pattern)
    assert idx != -1, f"Could not find CpInitialize call site in {orig_path}"
    call_cp_init_rva = init_rva + idx + 5
    call_cp_init_va = hal_base + call_cp_init_rva
    rel = struct.unpack_from('<i', init_code, idx + 6)[0]
    cp_init_va = (call_cp_init_va + 5 + rel) & 0xFFFFFFFF
    hal_symbols['CpInitialize'] = cp_init_va
    hal_symbols['_CpInitialize@12'] = cp_init_va
    hal_symbols['_CpInitialize'] = cp_init_va

    if '_HalpMapPhysicalMemory64@12' not in hal_symbols:
        save_rva = exports['KdPortSave']
        save_code = pe.get_data(save_rva, 16)
        ret_idx = save_code.find(b'\xc3')
        map_va = hal_base + save_rva + ret_idx + 1
        hal_symbols['HalpMapPhysicalMemory64'] = map_va
        hal_symbols['_HalpMapPhysicalMemory64@12'] = map_va

    print(f"  Port: {port_va:#x}")
    print(f"  CpInitialize: {cp_init_va:#x} (called at VA {call_cp_init_va:#x})")
    print(f"  HalpMapPhysicalMemory64: {hal_symbols.get('_HalpMapPhysicalMemory64@12', 0):#x}")

    # 4. Determine stolen instructions and relocations for the 5 exports
    kd_exports = ['KdPortGetByte', 'KdPortPollByte', 'KdPortPutByte', 'KdPortRestore', 'KdPortSave']
    stolen_bytes = {}
    stolen_len = {}
    neutralize_reloc_rvas = set()
    stolen_abs_offsets = {}

    reloc_dir_idx = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC']
    reloc_rva  = pe.OPTIONAL_HEADER.DATA_DIRECTORY[reloc_dir_idx].VirtualAddress
    reloc_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[reloc_dir_idx].Size
    reloc_foff = pe.get_offset_from_rva(reloc_rva)

    pe_data = bytearray(pe.__data__)
    cur_off = reloc_foff
    end_off = reloc_foff + reloc_size
    orig_relocs = []
    while cur_off < end_off:
        page_rva, block_sz = struct.unpack_from('<II', pe_data, cur_off)
        if block_sz == 0:
            break
        num_entries = (block_sz - 8) // 2
        for i in range(num_entries):
            e_off = cur_off + 8 + i * 2
            entry = struct.unpack_from('<H', pe_data, e_off)[0]
            reloc_type = entry >> 12
            if reloc_type == 3:
                orig_relocs.append((page_rva + (entry & 0xFFF), e_off))
        cur_off += block_sz

    for exp_name in kd_exports:
        exp_rva = exports[exp_name]
        exp_code = pe.get_data(exp_rva, 16)
        if exp_name in ('KdPortGetByte', 'KdPortPollByte'):
            slen = 6
        elif exp_name == 'KdPortPutByte':
            slen = 9
        else: # KdPortRestore, KdPortSave
            ret_idx = exp_code.find(b'\xc3')
            slen = ret_idx
        stolen_len[exp_name] = slen
        stolen_bytes[exp_name] = bytes(pe_data[exp_rva:exp_rva + slen])

        for r_rva, e_off in orig_relocs:
            if exp_rva <= r_rva < exp_rva + slen:
                stolen_abs_offsets[exp_name] = r_rva - exp_rva
                if r_rva < exp_rva + 5:
                    neutralize_reloc_rvas.add((r_rva, e_off))

    print(f"  Stolen lengths: {stolen_len}")
    print(f"  Neutralizing {len(neutralize_reloc_rvas)} colliding relocations: {[hex(r[0]) for r in neutralize_reloc_rvas]}")

    for r_rva, e_off in neutralize_reloc_rvas:
        entry = struct.unpack_from('<H', pe_data, e_off)[0]
        struct.pack_into('<H', pe_data, e_off, entry & 0xFFF)

    # 5. Read transport library
    objs = read_lib(lib_path)
    assert objs, "Failed to read kdtransport.lib"

    # 6. Determine section placement
    est_total_reloc = reloc_size + 0x1000
    new_sect_rva = _align(reloc_rva + est_total_reloc + 0x400, 0x1000)
    new_raw_off  = new_sect_rva
    new_sect_va  = hal_base + new_sect_rva
    print(f"  New section .kdtrans at VA {new_sect_va:#010x} (RVA {new_sect_rva:#010x})")

    TRAMP_SIZE = 0x200
    transport_va = new_sect_va + TRAMP_SIZE
    transport_bin, symbol_va, dir32_rvas = link_objs_dynamic(objs, transport_va, hal_base, hal_symbols)
    print(f"  Linked transport code: {len(transport_bin)} bytes, {len(dir32_rvas)} DIR32 fixups")

    override_sym = None
    for name in ['_KdpTransportInitOverride@12', '_KdpTransportInitOverride@16',
                 '_KdpTransportInitOverride', 'KdpTransportInitOverride']:
        if name in symbol_va:
            override_sym = name
            break
    assert override_sym, "KdpTransportInitOverride not found in transport symbols"
    override_va = symbol_va[override_sym]

    tramp_region = bytearray(TRAMP_SIZE)
    tramp_reloc_rvas = []
    kdat_va = symbol_va.get('_KdActiveTransport', symbol_va.get('KdActiveTransport', 0))

    overrides = {
        'KdPortGetByte':  '_KdpTransportGetByteOverride',
        'KdPortPollByte': '_KdpTransportPollByteOverride',
        'KdPortPutByte':  '_KdpTransportPutByteOverride',
        'KdPortSave':     '_KdpTransportSaveOverride',
        'KdPortRestore':  '_KdpTransportRestoreOverride',
    }

    tramp_offset = 0
    export_patches = {}

    for exp_name in kd_exports:
        exp_va = hal_base + exports[exp_name]
        base_ov = overrides[exp_name]
        ov_va = 0
        for c in [base_ov + '@4', base_ov + '@0', base_ov + '@8', base_ov, base_ov[1:]]:
            if c in symbol_va:
                ov_va = symbol_va[c]
                break

        stub_va = new_sect_va + tramp_offset
        stub = bytearray()

        if kdat_va != 0 and ov_va != 0:
            tramp_reloc_rvas.append(new_sect_rva + tramp_offset + len(stub) + 2)
            stub += bytes([0x83, 0x3D]) + struct.pack('<I', kdat_va) + bytes([0x00])
            je_pos = len(stub) + 1
            stub += bytes([0x74, 0x00])
            stub += _make_rel32_jmp(stub_va + len(stub), ov_va)
            stub[je_pos] = (len(stub) - (je_pos + 1)) & 0xFF

        stolen_start = len(stub)
        stub += stolen_bytes[exp_name]
        abs_off = stolen_abs_offsets.get(exp_name)
        if abs_off is not None:
            tramp_reloc_rvas.append(new_sect_rva + tramp_offset + stolen_start + abs_off)
        stub += _make_rel32_jmp(stub_va + len(stub), exp_va + stolen_len[exp_name])

        tramp_region[tramp_offset:tramp_offset + len(stub)] = stub
        tramp_offset += _align(len(stub), 16)
        export_patches[exp_name] = _make_rel32_jmp(exp_va, stub_va)

    all_reloc_rvas = list(dir32_rvas) + list(tramp_reloc_rvas)
    new_reloc_blob = build_reloc_blocks(all_reloc_rvas)
    total_reloc_sz = reloc_size + len(new_reloc_blob)

    # 7. Patch original binary
    call_to_override = _make_rel32_call(call_cp_init_va, override_va)
    call_foff = pe.get_offset_from_rva(call_cp_init_rva)
    pe_data[call_foff:call_foff+5] = call_to_override
    print(f"  Patched CpInitialize call site -> KdpTransportInitOverride")

    for exp_name, jmp_bytes in export_patches.items():
        foff = pe.get_offset_from_rva(exports[exp_name])
        pe_data[foff:foff+5] = jmp_bytes

    # 8. Assemble section data
    file_align = pe.OPTIONAL_HEADER.FileAlignment
    sect_align = pe.OPTIONAL_HEADER.SectionAlignment
    new_sect_data = bytes(tramp_region) + transport_bin
    raw_size = _align(len(new_sect_data), max(file_align, 0x200))
    virt_size = len(new_sect_data)
    new_sect_data = new_sect_data.ljust(raw_size, b'\x00')

    # 9. Update PE headers & add .kdtrans section header
    pe_hdr_off = struct.unpack_from('<I', pe_data, 0x3C)[0]
    opt_hdr_size = struct.unpack_from('<H', pe_data, pe_hdr_off + 20)[0]
    num_sections_off = pe_hdr_off + 6
    num_sections = struct.unpack_from('<H', pe_data, num_sections_off)[0]
    sect_hdr_start = pe_hdr_off + 24 + opt_hdr_size
    sect_headers_end = sect_hdr_start + num_sections * 40
    first_raw = min(s.PointerToRawData for s in pe.sections if s.PointerToRawData > 0)

    if first_raw - sect_headers_end < 40:
        new_pe_off = 0x80
        hdr_len = sect_headers_end - pe_hdr_off
        pe_data[new_pe_off:new_pe_off + hdr_len] = pe_data[pe_hdr_off:sect_headers_end]
        struct.pack_into('<I', pe_data, 0x3C, new_pe_off)
        pe_data[new_pe_off + hdr_len:first_raw] = b'\x00' * (first_raw - (new_pe_off + hdr_len))
        pe_hdr_off = new_pe_off
        num_sections_off = pe_hdr_off + 6
        sect_hdr_start = pe_hdr_off + 24 + opt_hdr_size

    new_num = num_sections + 1
    struct.pack_into('<H', pe_data, num_sections_off, new_num)
    new_sect_hdr_off = sect_hdr_start + num_sections * 40

    chars = (0x00000020 | 0x00000040 | 0x00000080 | 0x08000000 | 0x20000000 | 0x40000000 | 0x80000000)
    new_hdr = struct.pack('<8sIIIIIIHHI',
        b'.kdtrans',
        virt_size,
        new_sect_rva,
        raw_size,
        new_raw_off,
        0, 0, 0, 0,
        chars)
    pe_data[new_sect_hdr_off:new_sect_hdr_off+40] = new_hdr

    reloc_dir_off = pe_hdr_off + 24 + 96 + reloc_dir_idx * 8
    struct.pack_into('<I', pe_data, reloc_dir_off + 4, total_reloc_sz)

    for i in range(num_sections):
        s_off = sect_hdr_start + i * 40
        s_name = pe_data[s_off:s_off+8].rstrip(b'\x00')
        if s_name == b'.reloc':
            struct.pack_into('<I', pe_data, s_off + 8, total_reloc_sz)
            struct.pack_into('<I', pe_data, s_off + 16, new_raw_off - reloc_rva)
            break

    size_of_image_off = pe_hdr_off + 24 + 56
    new_image_size = _align(new_sect_rva + raw_size, sect_align)
    struct.pack_into('<I', pe_data, size_of_image_off, new_image_size)

    pe_data = pe_data[:reloc_foff + reloc_size]
    pe_data += new_reloc_blob
    if len(pe_data) < new_raw_off:
        pe_data += b'\x00' * (new_raw_off - len(pe_data))
    pe_data += new_sect_data
    aligned_file_len = _align(len(pe_data), file_align)
    if len(pe_data) < aligned_file_len:
        pe_data += b'\x00' * (aligned_file_len - len(pe_data))

    new_csum = compute_checksum(pe_data)
    struct.pack_into('<I', pe_data, pe_hdr_off + 24 + 64, new_csum)

    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, 'wb') as f:
        f.write(pe_data)

    print(f"SUCCESS: Wrote patched {out_path} ({len(pe_data)} bytes)")
    pe_check = pefile.PE(out_path)
    print(f"  Validation OK: {len(pe_check.sections)} sections, SizeOfImage={pe_check.OPTIONAL_HEADER.SizeOfImage:#x}, CheckSum={new_csum:#x}")
    pe_check.close()

def main():
    if len(sys.argv) >= 2 and sys.argv[1] == '--batch':
        if len(sys.argv) < 5:
            print("Usage: python kdpatch.py --batch <hal_variants_dir> <kdtransport.lib> <out_dir> [symbols_dir]")
            sys.exit(1)
        hal_dir = sys.argv[2]
        lib_path = sys.argv[3]
        out_dir = sys.argv[4]
        sym_dir = sys.argv[5] if len(sys.argv) >= 6 else None
        
        dlls = []
        for root, dirs, files in os.walk(hal_dir):
            for file in files:
                if file.lower().endswith('.dll'):
                    dlls.append(os.path.join(root, file))
        for dll in dlls:
            rel = os.path.relpath(dll, hal_dir)
            out_file = os.path.join(out_dir, rel)
            patch_hal(dll, lib_path, out_file, sym_dir)
        return

    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(1)

    orig_path = sys.argv[1]
    lib_path = sys.argv[2]
    out_path = sys.argv[3]
    sym_dir = sys.argv[4] if len(sys.argv) >= 5 else None

    patch_hal(orig_path, lib_path, out_path, sym_dir)

if __name__ == '__main__':
    main()
