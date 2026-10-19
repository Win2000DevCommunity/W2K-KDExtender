#!/usr/bin/env python3
"""
patch_raw_img.py -- Find and patch halmacpi.dll and boot.ini in a raw NTFS disk image.

Usage:
    python patch_raw_img.py <disk.img> [--hal <patched_hal.dll>] [--boot-ini] [--extract-hal <output.dll>]

Steps:
    1. Parse MBR to find NTFS partition
    2. Parse NTFS boot sector for MFT location
    3. Walk MFT to find target files
    4. Read/write file data via NTFS data runs
"""

import sys, struct, os, argparse

# ── NTFS constants ──
ATTR_STANDARD_INFO = 0x10
ATTR_FILENAME      = 0x30
ATTR_DATA          = 0x80
ATTR_INDEX_ROOT    = 0x90
ATTR_INDEX_ALLOC   = 0xA0

FILE_RECORD_MAGIC  = b'FILE'

class NtfsVolume:
    """Minimal NTFS volume reader for raw disk images."""
    
    def __init__(self, img_path):
        self.img_path = img_path
        self.f = open(img_path, 'r+b')
        self._parse_mbr()
        self._parse_boot_sector()
    
    def close(self):
        self.f.close()
    
    def _parse_mbr(self):
        """Find the first NTFS partition in the MBR."""
        self.f.seek(0)
        mbr = self.f.read(512)
        for i in range(4):
            off = 0x1BE + i * 16
            ptype = mbr[off + 4]
            lba_start = struct.unpack_from('<I', mbr, off + 8)[0]
            lba_size = struct.unpack_from('<I', mbr, off + 12)[0]
            if ptype == 0x07:  # NTFS
                self.part_offset = lba_start * 512
                self.part_sectors = lba_size
                print(f"NTFS partition at LBA {lba_start} (offset {self.part_offset:#x}), {lba_size} sectors")
                return
        raise ValueError("No NTFS partition found in MBR")
    
    def _parse_boot_sector(self):
        """Parse NTFS boot sector parameters."""
        self.f.seek(self.part_offset)
        bs = self.f.read(512)
        oem = bs[3:11]
        if not oem.startswith(b'NTFS'):
            raise ValueError(f"Not an NTFS volume: OEM={oem}")
        
        self.bytes_per_sector = struct.unpack_from('<H', bs, 11)[0]
        self.sectors_per_cluster = bs[13]
        self.bytes_per_cluster = self.bytes_per_sector * self.sectors_per_cluster
        self.total_sectors = struct.unpack_from('<Q', bs, 0x28)[0]
        self.mft_lcn = struct.unpack_from('<Q', bs, 0x30)[0]
        
        clusters_per_mft = struct.unpack_from('<b', bs, 0x40)[0]
        if clusters_per_mft < 0:
            self.mft_record_size = 2 ** (-clusters_per_mft)
        else:
            self.mft_record_size = clusters_per_mft * self.bytes_per_cluster
        
        self.mft_offset = self.part_offset + self.mft_lcn * self.bytes_per_cluster
        
        print(f"  BPS={self.bytes_per_sector} SPC={self.sectors_per_cluster} "
              f"BytesPerCluster={self.bytes_per_cluster}")
        print(f"  MFT at LCN {self.mft_lcn} (abs offset {self.mft_offset:#x})")
        print(f"  MFT record size: {self.mft_record_size} bytes")
    
    def lcn_to_offset(self, lcn):
        """Convert a Logical Cluster Number to absolute file offset."""
        return self.part_offset + lcn * self.bytes_per_cluster
    
    def read_mft_record(self, record_num):
        """Read and fixup an MFT record by its record number."""
        # For simplicity, assume MFT is contiguous for the first ~1000 records
        # (which it almost always is for a fresh Win2K install)
        offset = self.mft_offset + record_num * self.mft_record_size
        self.f.seek(offset)
        data = bytearray(self.f.read(self.mft_record_size))
        
        if data[:4] != FILE_RECORD_MAGIC:
            return None
        
        # Apply fixup array
        fixup_off = struct.unpack_from('<H', data, 4)[0]
        fixup_count = struct.unpack_from('<H', data, 6)[0]
        if fixup_count > 1:
            signature = struct.unpack_from('<H', data, fixup_off)[0]
            for i in range(1, fixup_count):
                sector_end = i * self.bytes_per_sector - 2
                fixup_val = struct.unpack_from('<H', data, fixup_off + i * 2)[0]
                struct.pack_into('<H', data, sector_end, fixup_val)
        
        return data
    
    def parse_attributes(self, record):
        """Parse all attributes from an MFT record. Returns list of (type, attr_data)."""
        if record is None:
            return []
        
        attr_off = struct.unpack_from('<H', record, 0x14)[0]
        flags = struct.unpack_from('<H', record, 0x16)[0]
        attrs = []
        
        off = attr_off
        while off + 4 <= len(record):
            attr_type = struct.unpack_from('<I', record, off)[0]
            if attr_type == 0xFFFFFFFF:
                break
            attr_len = struct.unpack_from('<I', record, off + 4)[0]
            if attr_len < 16 or off + attr_len > len(record):
                break
            attrs.append((attr_type, bytes(record[off:off + attr_len])))
            off += attr_len
        
        return attrs
    
    def get_filename(self, record):
        """Extract the filename from an MFT record."""
        attrs = self.parse_attributes(record)
        names = []
        for attr_type, attr_data in attrs:
            if attr_type == ATTR_FILENAME:
                non_res = attr_data[8]
                if non_res == 0:  # resident
                    content_off = struct.unpack_from('<H', attr_data, 0x14)[0]
                    # Filename attribute structure
                    fn_off = content_off
                    name_len = attr_data[fn_off + 0x40]
                    name_ns = attr_data[fn_off + 0x41]  # namespace
                    name_bytes = attr_data[fn_off + 0x42 : fn_off + 0x42 + name_len * 2]
                    name = name_bytes.decode('utf-16-le', errors='replace')
                    names.append((name_ns, name))
        
        # Prefer Win32 (namespace 1 or 3) over DOS (namespace 2)
        for ns, name in names:
            if ns in (1, 3):  # Win32 or Win32+DOS
                return name
        for ns, name in names:
            if ns == 2:  # DOS
                return name
        if names:
            return names[0][1]
        return None
    
    def get_parent_ref(self, record):
        """Extract parent directory MFT reference from filename attribute."""
        attrs = self.parse_attributes(record)
        for attr_type, attr_data in attrs:
            if attr_type == ATTR_FILENAME:
                non_res = attr_data[8]
                if non_res == 0:
                    content_off = struct.unpack_from('<H', attr_data, 0x14)[0]
                    parent_ref = struct.unpack_from('<Q', attr_data, content_off)[0]
                    return parent_ref & 0xFFFFFFFFFFFF  # lower 48 bits = record number
        return None
    
    def decode_data_runs(self, attr_data):
        """Decode NTFS data runs from a non-resident attribute."""
        runs = []
        mapping_off = struct.unpack_from('<H', attr_data, 0x20)[0]
        off = mapping_off
        current_lcn = 0
        
        while off < len(attr_data):
            header = attr_data[off]
            if header == 0:
                break
            
            len_size = header & 0x0F
            off_size = (header >> 4) & 0x0F
            off += 1
            
            if off + len_size > len(attr_data):
                break
            
            # Read run length (unsigned)
            run_len = int.from_bytes(attr_data[off:off + len_size], 'little', signed=False)
            off += len_size
            
            if off_size > 0:
                if off + off_size > len(attr_data):
                    break
                # Read run offset (signed, relative to previous LCN)
                run_off = int.from_bytes(attr_data[off:off + off_size], 'little', signed=True)
                off += off_size
                current_lcn += run_off
                runs.append((current_lcn, run_len))
            else:
                # Sparse run
                runs.append((None, run_len))
        
        return runs
    
    def get_data_attr(self, record):
        """Get the $DATA attribute from an MFT record."""
        attrs = self.parse_attributes(record)
        for attr_type, attr_data in attrs:
            if attr_type == ATTR_DATA:
                return attr_data
        return None
    
    def read_file_data(self, record):
        """Read all data from a file's $DATA attribute."""
        data_attr = self.get_data_attr(record)
        if data_attr is None:
            return None
        
        non_res = data_attr[8]
        if non_res == 0:
            # Resident data
            content_off = struct.unpack_from('<H', data_attr, 0x14)[0]
            content_len = struct.unpack_from('<I', data_attr, 0x10)[0]
            return bytes(data_attr[content_off:content_off + content_len])
        else:
            # Non-resident data
            real_size = struct.unpack_from('<Q', data_attr, 0x30)[0]
            runs = self.decode_data_runs(data_attr)
            result = bytearray()
            for lcn, length in runs:
                if lcn is None:
                    result += b'\x00' * (length * self.bytes_per_cluster)
                else:
                    abs_off = self.lcn_to_offset(lcn)
                    self.f.seek(abs_off)
                    result += self.f.read(length * self.bytes_per_cluster)
            return bytes(result[:real_size])
    
    def write_file_data(self, record, new_data, record_num=None):
        """Write data to a file's $DATA attribute. Only supports non-resident files
        where the new data fits in the existing allocation."""
        data_attr = self.get_data_attr(record)
        if data_attr is None:
            raise ValueError("No $DATA attribute found")
        
        non_res = data_attr[8]
        if non_res == 0:
            # Resident data - need to handle differently
            raise ValueError("Cannot write to resident $DATA attribute (file too small). "
                           "Use write_resident_data instead.")
        
        # Non-resident
        alloc_size = struct.unpack_from('<Q', data_attr, 0x28)[0]
        real_size = struct.unpack_from('<Q', data_attr, 0x30)[0]
        init_size = struct.unpack_from('<Q', data_attr, 0x38)[0]
        
        if len(new_data) > alloc_size:
            raise ValueError(f"New data ({len(new_data)} bytes) exceeds allocation "
                           f"({alloc_size} bytes). Cannot extend in-place.")
        
        runs = self.decode_data_runs(data_attr)
        
        # Write data to the data runs
        remaining = new_data
        for lcn, length in runs:
            if lcn is None:
                continue
            chunk_size = length * self.bytes_per_cluster
            write_size = min(len(remaining), chunk_size)
            abs_off = self.lcn_to_offset(lcn)
            self.f.seek(abs_off)
            self.f.write(remaining[:write_size])
            # Zero-fill rest of cluster if needed
            if write_size < chunk_size:
                self.f.write(b'\x00' * (chunk_size - write_size))
            remaining = remaining[write_size:]
            if not remaining:
                break
        
        # Update real_size and init_size in the MFT record
        if record_num is not None:
            self._update_data_sizes(record_num, len(new_data))
        
        self.f.flush()
        print(f"  Written {len(new_data)} bytes to file data runs")
    
    def _update_data_sizes(self, record_num, new_size):
        """Update the real_size and init_size fields in the MFT record's $DATA attribute."""
        offset = self.mft_offset + record_num * self.mft_record_size
        self.f.seek(offset)
        raw_record = bytearray(self.f.read(self.mft_record_size))
        
        if raw_record[:4] != FILE_RECORD_MAGIC:
            return
        
        # Apply fixups to work with the record
        fixup_off = struct.unpack_from('<H', raw_record, 4)[0]
        fixup_count = struct.unpack_from('<H', raw_record, 6)[0]
        fixup_sig = struct.unpack_from('<H', raw_record, fixup_off)[0]
        
        # Save original sector-end bytes, apply fixups
        saved_ends = []
        for i in range(1, fixup_count):
            sector_end = i * self.bytes_per_sector - 2
            saved_ends.append(struct.unpack_from('<H', raw_record, sector_end)[0])
            fixup_val = struct.unpack_from('<H', raw_record, fixup_off + i * 2)[0]
            struct.pack_into('<H', raw_record, sector_end, fixup_val)
        
        # Find $DATA attribute and update sizes
        attr_off = struct.unpack_from('<H', raw_record, 0x14)[0]
        off = attr_off
        while off + 4 <= len(raw_record):
            attr_type = struct.unpack_from('<I', raw_record, off)[0]
            if attr_type == 0xFFFFFFFF:
                break
            attr_len = struct.unpack_from('<I', raw_record, off + 4)[0]
            if attr_len < 16:
                break
            if attr_type == ATTR_DATA:
                non_res = raw_record[off + 8]
                if non_res != 0:
                    # Update real_size (offset 0x30) and init_size (offset 0x38)
                    struct.pack_into('<Q', raw_record, off + 0x30, new_size)
                    struct.pack_into('<Q', raw_record, off + 0x38, new_size)
                    break
            off += attr_len
        
        # Reapply fixup signature before writing back
        new_fixup_sig = (fixup_sig + 1) & 0xFFFF
        if new_fixup_sig == 0:
            new_fixup_sig = 1
        struct.pack_into('<H', raw_record, fixup_off, new_fixup_sig)
        for i in range(1, fixup_count):
            sector_end = i * self.bytes_per_sector - 2
            # Store current byte in fixup array
            struct.pack_into('<H', raw_record, fixup_off + i * 2,
                           struct.unpack_from('<H', raw_record, sector_end)[0])
            # Write signature at sector end
            struct.pack_into('<H', raw_record, sector_end, new_fixup_sig)
        
        # Write back
        self.f.seek(offset)
        self.f.write(raw_record)
        self.f.flush()
    
    def write_resident_data(self, record_num, new_data):
        """Write data to a resident $DATA attribute in-place.
        The new data must fit within the existing attribute size."""
        offset = self.mft_offset + record_num * self.mft_record_size
        self.f.seek(offset)
        raw_record = bytearray(self.f.read(self.mft_record_size))
        
        if raw_record[:4] != FILE_RECORD_MAGIC:
            raise ValueError("Invalid MFT record")
        
        # Apply fixups
        fixup_off = struct.unpack_from('<H', raw_record, 4)[0]
        fixup_count = struct.unpack_from('<H', raw_record, 6)[0]
        fixup_sig = struct.unpack_from('<H', raw_record, fixup_off)[0]
        
        for i in range(1, fixup_count):
            sector_end = i * self.bytes_per_sector - 2
            fixup_val = struct.unpack_from('<H', raw_record, fixup_off + i * 2)[0]
            struct.pack_into('<H', raw_record, sector_end, fixup_val)
        
        # Find $DATA attribute
        attr_off = struct.unpack_from('<H', raw_record, 0x14)[0]
        off = attr_off
        while off + 4 <= len(raw_record):
            attr_type = struct.unpack_from('<I', raw_record, off)[0]
            if attr_type == 0xFFFFFFFF:
                break
            attr_len = struct.unpack_from('<I', raw_record, off + 4)[0]
            if attr_len < 16:
                break
            if attr_type == ATTR_DATA:
                non_res = raw_record[off + 8]
                if non_res == 0:
                    content_off = struct.unpack_from('<H', raw_record, off + 0x14)[0]
                    content_len = struct.unpack_from('<I', raw_record, off + 0x10)[0]
                    if len(new_data) > content_len:
                        raise ValueError(f"New data ({len(new_data)}) exceeds resident "
                                       f"attribute capacity ({content_len})")
                    abs_content_off = off + content_off
                    # Zero out old content
                    raw_record[abs_content_off:abs_content_off + content_len] = b'\x00' * content_len
                    # Write new content
                    raw_record[abs_content_off:abs_content_off + len(new_data)] = new_data
                    # Update content length
                    struct.pack_into('<I', raw_record, off + 0x10, len(new_data))
                    break
            off += attr_len
        
        # Reapply fixups for write-back
        new_fixup_sig = (fixup_sig + 1) & 0xFFFF
        if new_fixup_sig == 0:
            new_fixup_sig = 1
        struct.pack_into('<H', raw_record, fixup_off, new_fixup_sig)
        for i in range(1, fixup_count):
            sector_end = i * self.bytes_per_sector - 2
            struct.pack_into('<H', raw_record, fixup_off + i * 2,
                           struct.unpack_from('<H', raw_record, sector_end)[0])
            struct.pack_into('<H', raw_record, sector_end, new_fixup_sig)
        
        self.f.seek(offset)
        self.f.write(raw_record)
        self.f.flush()
        print(f"  Written {len(new_data)} bytes to resident $DATA attribute")
    
    def scan_mft_for_files(self, target_names, max_records=50000):
        """Scan the MFT looking for files by name (case-insensitive).
        Returns dict of {lowercase_name: (record_num, record_data)}"""
        target_lower = {n.lower() for n in target_names}
        found = {}
        
        print(f"Scanning MFT for: {target_names} ...")
        for rec_num in range(max_records):
            try:
                record = self.read_mft_record(rec_num)
                if record is None:
                    continue
                name = self.get_filename(record)
                if name and name.lower() in target_lower:
                    parent = self.get_parent_ref(record)
                    print(f"  Found '{name}' at MFT record #{rec_num} (parent=#{parent})")
                    found[name.lower()] = (rec_num, record)
            except Exception as e:
                continue  # Skip corrupt/unreadable records
            
            if len(found) == len(target_lower):
                break
        
        return found


def find_system32_hal(vol, hal_name='halmacpi.dll'):
    """Find halmacpi.dll in WINNT\\system32 by scanning MFT."""
    # First, find the file by name
    results = vol.scan_mft_for_files([hal_name, 'hal.dll', 'boot.ini'])
    
    # We might find multiple files with the same name; filter by path
    candidates = {}
    for name, (rec_num, record) in results.items():
        parent_ref = vol.get_parent_ref(record)
        # Read parent record to check if it's 'system32'
        parent_rec = vol.read_mft_record(parent_ref)
        if parent_rec:
            parent_name = vol.get_filename(parent_rec)
            if parent_name:
                candidates[name] = {
                    'rec_num': rec_num,
                    'record': record,
                    'parent_name': parent_name,
                    'parent_ref': parent_ref
                }
                print(f"  {name}: parent='{parent_name}' (MFT #{parent_ref})")
    
    return candidates


def main():
    parser = argparse.ArgumentParser(description='Patch halmacpi.dll and boot.ini in raw NTFS disk image')
    parser.add_argument('disk_img', help='Path to raw disk image')
    parser.add_argument('--extract-hal', metavar='OUTPUT', help='Extract halmacpi.dll to file')
    parser.add_argument('--hal', metavar='PATCHED_HAL', help='Replace halmacpi.dll with patched version')
    parser.add_argument('--boot-ini', action='store_true', help='Patch boot.ini for KD debug options')
    parser.add_argument('--scan', action='store_true', help='Just scan and report files found')
    args = parser.parse_args()
    
    vol = NtfsVolume(args.disk_img)
    
    try:
        candidates = find_system32_hal(vol)
        
        if args.scan:
            print("\n=== Scan Results ===")
            for name, info in candidates.items():
                data = vol.read_file_data(info['record'])
                print(f"  {name}: {len(data) if data else 0} bytes, "
                      f"parent='{info['parent_name']}' (MFT #{info['parent_ref']})")
            return
        
        # Extract HAL
        if args.extract_hal:
            hal_info = candidates.get('halmacpi.dll') or candidates.get('hal.dll')
            if not hal_info:
                sys.exit("ERROR: halmacpi.dll/hal.dll not found in disk image")
            data = vol.read_file_data(hal_info['record'])
            if data:
                with open(args.extract_hal, 'wb') as f:
                    f.write(data)
                print(f"\nExtracted {len(data)} bytes -> {args.extract_hal}")
            else:
                sys.exit("ERROR: Could not read file data")
        
        # Replace HAL
        if args.hal:
            hal_info = candidates.get('halmacpi.dll') or candidates.get('hal.dll')
            if not hal_info:
                sys.exit("ERROR: halmacpi.dll/hal.dll not found in disk image")
            
            with open(args.hal, 'rb') as f:
                new_data = f.read()
            print(f"\nReplacing HAL with {len(new_data)} bytes from {args.hal}")
            
            data_attr = vol.get_data_attr(hal_info['record'])
            non_res = data_attr[8]
            if non_res == 0:
                vol.write_resident_data(hal_info['rec_num'], new_data)
            else:
                vol.write_file_data(hal_info['record'], new_data, hal_info['rec_num'])
            print("HAL replaced successfully!")
        
        # Patch boot.ini
        if args.boot_ini:
            boot_info = candidates.get('boot.ini')
            if not boot_info:
                sys.exit("ERROR: boot.ini not found in disk image")
            
            old_data = vol.read_file_data(boot_info['record'])
            print(f"\nCurrent boot.ini ({len(old_data)} bytes):")
            print(old_data.decode('ascii', errors='replace'))
            
            # Build new boot.ini
            new_boot_ini = (
                "[boot loader]\r\n"
                "timeout=10\r\n"
                "default=multi(0)disk(0)rdisk(0)partition(1)\\WINNT\r\n"
                "[operating systems]\r\n"
                'multi(0)disk(0)rdisk(0)partition(1)\\WINNT="Windows 2000 - KD USB" '
                '/DEBUG /DEBUGPORT=USB /fastdetect\r\n'
                'multi(0)disk(0)rdisk(0)partition(1)\\WINNT="Windows 2000 - KD NET" '
                '/fastdetect /DEBUG /DEBUGPORT=NET\r\n'
                'multi(0)disk(0)rdisk(0)partition(1)\\WINNT="Windows 2000 - KD COM" '
                '/fastdetect /DEBUG /DEBUGPORT=COM1 /BAUDRATE=115200\r\n'
                'multi(0)disk(0)rdisk(0)partition(1)\\WINNT="Windows 2000 Professional" '
                '/fastdetect\r\n'
            ).encode('ascii')
            
            data_attr = vol.get_data_attr(boot_info['record'])
            non_res = data_attr[8]
            
            if len(new_boot_ini) > len(old_data):
                print(f"WARNING: New boot.ini ({len(new_boot_ini)}) is larger than old ({len(old_data)})!")
                if non_res == 0:
                    print("  Resident attribute -- checking capacity...")
                else:
                    alloc_size = struct.unpack_from('<Q', data_attr, 0x28)[0]
                    if len(new_boot_ini) > alloc_size:
                        sys.exit(f"  ERROR: New boot.ini exceeds allocation ({alloc_size} bytes)")
            
            if non_res == 0:
                vol.write_resident_data(boot_info['rec_num'], new_boot_ini)
            else:
                vol.write_file_data(boot_info['record'], new_boot_ini, boot_info['rec_num'])
            
            print(f"\nNew boot.ini ({len(new_boot_ini)} bytes):")
            print(new_boot_ini.decode('ascii'))
            print("boot.ini patched successfully!")
    
    finally:
        vol.close()


if __name__ == '__main__':
    main()
