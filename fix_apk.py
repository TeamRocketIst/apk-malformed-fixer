#!/usr/bin/env python
import zipfile, sys, argparse
from struct import pack, unpack

# --- GLOBAL SETTINGS ---
DEBUG = True

def dprint(msg):
    if DEBUG:
        print(msg)

kEOCDLen = 22

class EOCDR(object):    
    def __init__(self, zf):
        super(EOCDR, self).__init__()
        self.signature = zf.read(4)
        self.disk_number = u16(zf.read(2))
        self.disk_with_central_dir = u16(zf.read(2))
        self.disk_entries = u16(zf.read(2))
        self.total_num_entries = u16(zf.read(2))
        self.central_dir_size = u32(zf.read(4))
        self.central_dir_offset = u32(zf.read(4))
        self.comment_size = u16(zf.read(2))
        self.file_comment = zf.read(self.comment_size)
        assert(self.signature == b'\x50\x4b\x05\x06')

def u16(x): return unpack('<H', x)[0]
def p16(x): return pack('<H', x)
def u32(x): return unpack('<I', x)[0]
def p32(x): return pack('<I', x)

def EOCDR_parse(zf, offset_eodr):
    zf.seek(offset_eodr)
    return EOCDR(zf)

def CDR(zf, cp_type):
    global scan_buff
    signature = zf.read(4)
    while (signature == b'\x50\x4b\x01\x02'):
        version = zf.read(2)
        version_needed = zf.read(2)
        
        flags_off = zf.tell()
        flags = zf.read(2)
        flags_val = u16(flags)

        comp_type_off = zf.tell()
        comp_type = u16(zf.read(2))
        
        mod_time = zf.read(2)
        mod_date = zf.read(2)
        crc_32 = zf.read(4)

        comp_size_off = zf.tell()
        compressed_size = u32(zf.read(4))
        uncompressed_size = u32(zf.read(4))
        
        entry_name_length = u16(zf.read(2))
        extra_field_length = u16(zf.read(2))

        file_comm = zf.read(2)
        file_comm_length = u16(file_comm)
        
        disk_start = zf.read(2)
        internal_attr = zf.read(2)
        external_attr = zf.read(4)
        off_localh = u32(zf.read(4))
        
        entry_name_off = zf.tell()
        current_entry_name = zf.read(entry_name_length)
        decoded_name = current_entry_name.decode('utf-8', 'ignore')
        
        extra_field_off = zf.tell()
        _ = zf.read(extra_field_length)
        _ = zf.read(file_comm_length)
        
        # Process Local File Header FIRST
        temp_offset = zf.tell()
        zf.seek(off_localh)
        LFH(zf, cp_type, compressed_size, uncompressed_size, decoded_name)
        zf.seek(temp_offset)
        
        # TRICK 1: Clear the fake password bit
        if flags_val & 1:
            scan_buff[flags_off:flags_off+2] = p16(flags_val & 0xFFFE)
            dprint(f"[!] CDR: Cleared fake password bit on {decoded_name}")

        # TRICK 2: Correct completely invalid compression types
        if comp_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            scan_buff[comp_type_off:comp_type_off+2] = p16(cp_type)
            dprint(f"[!] CDR: Fixed Invalid Compression (0x{comp_type:04X}) on {decoded_name}")
            comp_type = cp_type # Crucial: Update local variable
            
        # TRICK 3: Fix files marked as DEFLATED but are physically STORED
        elif comp_type == zipfile.ZIP_DEFLATED and compressed_size == uncompressed_size and compressed_size > 0:
            scan_buff[comp_type_off:comp_type_off+2] = p16(zipfile.ZIP_STORED)
            dprint(f"[!] CDR: Fixed Fake DEFLATED -> STORED on {decoded_name}")
            comp_type = zipfile.ZIP_STORED # Crucial: Update local variable

        # TRICK 4: Fix File Truncation (Mismatching Sizes on STORED files)
        if comp_type == zipfile.ZIP_STORED and compressed_size != uncompressed_size:
            real_size = max(compressed_size, uncompressed_size)
            scan_buff[comp_size_off : comp_size_off+8] = p32(real_size) + p32(real_size)
            dprint(f"[!] CDR: Fixed Truncation on {decoded_name} -> Sizes leveled to {real_size}")

        # TRICK 5: Neutralize ZIP Path Collisions
        targets = [b'classes.dex/', b'AndroidManifest.xml/', b'resources.arsc/']
        for target in targets:
            if current_entry_name.startswith(target):
                new_target = target.replace(b'.', b'_')
                new_name = new_target + current_entry_name[len(target):]
                scan_buff[entry_name_off:entry_name_off + entry_name_length] = new_name
                dprint(f"[!] CDR: Neutralized phantom folder -> {new_name.decode('utf-8', 'ignore')}")
                break
                
        # TRICK 6: Sanitize Malformed Extra Fields
        if extra_field_length >= 4:
            dummy_header = p16(0x9999) + p16(extra_field_length - 4)
            scan_buff[extra_field_off : extra_field_off + 4] = dummy_header
            if extra_field_length > 4:
                scan_buff[extra_field_off + 4 : extra_field_off + extra_field_length] = b'\x00' * (extra_field_length - 4)
                
        signature = zf.read(4)

def LFH(zf, cp_type, cdr_csize, cdr_ucsize, decoded_name):
    global scan_buff
    signature = zf.read(4)
    if signature != b'\x50\x4b\x03\x04':
        dprint(f"[-] LFH: Invalid signature for {decoded_name}")
        return
    version = zf.read(2)
    
    flags_off = zf.tell()
    flags = zf.read(2)
    flags_val = u16(flags)

    comp_type_off = zf.tell()
    comp_type = u16(zf.read(2))

    mod_time = zf.read(2)
    mod_date = zf.read(2)
    crc_32 = zf.read(4)
    
    comp_size_off = zf.tell()
    compressed_size = u32(zf.read(4))
    uncompressed_size = u32(zf.read(4))

    entry_name_length = u16(zf.read(2))
    extra_field_length = u16(zf.read(2))
    
    entry_name_off = zf.tell()
    current_entry_name = zf.read(entry_name_length)
    
    extra_field_off = zf.tell()
    _ = zf.read(extra_field_length)
    
    # TRICK 1: Clear the fake password bit
    if flags_val & 1:
        scan_buff[flags_off:flags_off+2] = p16(flags_val & 0xFFFE)

    # TRICK 2: Correct completely invalid compression types
    if comp_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        scan_buff[comp_type_off:comp_type_off+2] = p16(cp_type)
        comp_type = cp_type
    
    # TRICK 3: Fix files marked as DEFLATED but are physically STORED    
    elif comp_type == zipfile.ZIP_DEFLATED and compressed_size == uncompressed_size and compressed_size > 0:
        scan_buff[comp_type_off:comp_type_off+2] = p16(zipfile.ZIP_STORED)
        comp_type = zipfile.ZIP_STORED

    # TRICK 4: Fix File Truncation in Local File Header
    # We use max() across both LFH and CDR sizes to guarantee we capture the full payload length
    if comp_type == zipfile.ZIP_STORED:
        if (flags_val & 8) == 0:  # Only patch if sizes aren't relegated to the Data Descriptor
            real_size = max(compressed_size, uncompressed_size, cdr_csize, cdr_ucsize)
            if compressed_size != real_size or uncompressed_size != real_size:
                scan_buff[comp_size_off : comp_size_off+8] = p32(real_size) + p32(real_size)
                dprint(f"[!] LFH: Fixed Truncation on {decoded_name} -> Sizes leveled to {real_size}")

    # TRICK 5: Neutralize ZIP Path Collisions
    targets = [b'classes.dex/', b'AndroidManifest.xml/', b'resources.arsc/']
    for target in targets:
        if current_entry_name.startswith(target):
            new_target = target.replace(b'.', b'_')
            new_name = new_target + current_entry_name[len(target):]
            scan_buff[entry_name_off:entry_name_off + entry_name_length] = new_name
            break

    # TRICK 6: Sanitize Malformed Extra Fields
    if extra_field_length >= 4:
        dummy_header = p16(0x9999) + p16(extra_field_length - 4)
        scan_buff[extra_field_off : extra_field_off + 4] = dummy_header
        if extra_field_length > 4:
            scan_buff[extra_field_off + 4 : extra_field_off + extra_field_length] = b'\x00' * (extra_field_length - 4)

def fix_apk(apk_name, apk_output, cp_type):
    print(f"[*] Analyzing ZIP structures inside: {apk_name}")
    with open(apk_name, 'r+b') as zf:
        global scan_buff
        scan_buff = bytearray(zf.read()) 
        file_size = len(scan_buff)
        for i in range(file_size-kEOCDLen, -1, -1):
            if scan_buff[i] == 0x50 and scan_buff[i:i+4] == b'\x50\x4b\x05\x06':
                break
        assert(i > 0 and scan_buff[i:i+4] == b'\x50\x4b\x05\x06')
        eocdr = EOCDR_parse(zf, i)
        zf.seek(eocdr.central_dir_offset)
        CDR(zf, cp_type)

    with open(apk_output, 'wb+') as f:
        f.write(scan_buff)
    print(f"[+] Fixed APK saved to {apk_output}")


def main():
    parser = argparse.ArgumentParser(description='Fix malformed APKs')
    parser.add_argument('-i', '--input', required=True, help='Input APK file')
    parser.add_argument('-o', '--output', required=True, help='Output APK file')
    parser.add_argument(
        '-c',
        '--compression',
        choices=['zipstored', 'zipdeflated'],
        default='zipstored',
        help='Compression type to replace on invalid type entries'
    )
    args = parser.parse_args()
    types_comp = {
        'zipstored': zipfile.ZIP_STORED,
        'zipdeflated': zipfile.ZIP_DEFLATED
    }
    fix_apk(args.input, args.output, types_comp[args.compression])


if __name__ == '__main__':
    main()
