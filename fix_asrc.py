import sys
import struct
import os

# --- GLOBAL SETTINGS ---
DEBUG = True

def dprint(msg):
    if DEBUG:
        print(msg)

# Standard ARSC Chunk Types
RES_TABLE_TYPE = 0x0002
RES_STRING_POOL_TYPE = 0x0001
RES_TABLE_PACKAGE_TYPE = 0x0200
RES_TABLE_TYPE_TYPE = 0x0201
RES_TABLE_TYPE_SPEC_TYPE = 0x0202
RES_TABLE_LIBRARY_TYPE = 0x0203

VALID_ARSC_CHUNKS = {
    RES_STRING_POOL_TYPE,
    RES_TABLE_PACKAGE_TYPE,
    RES_TABLE_TYPE_TYPE,
    RES_TABLE_TYPE_SPEC_TYPE,
    RES_TABLE_LIBRARY_TYPE,
    0x0204, 0x0205, 0x0206
}

CHUNK_NAMES = {
    0x0001: "RES_STRING_POOL",
    0x0002: "RES_TABLE",
    0x0200: "RES_TABLE_PACKAGE",
    0x0201: "RES_TABLE_TYPE",
    0x0202: "RES_TABLE_TYPE_SPEC",
    0x0203: "RES_TABLE_LIBRARY",
    0x0204: "RES_TABLE_OVERLAYABLE",
    0x0205: "RES_TABLE_OVERLAYABLE_POLICY",
    0x0206: "RES_TABLE_STAGED_ALIAS"
}

def fix_arsc(file_path, out_path):
    print(f"\n[*] Processing ARSC: {file_path}")
    with open(file_path, 'rb') as f:
        data = bytearray(f.read())

    file_size = len(data)
    dprint(f"[DEBUG] Physical file size on disk: {file_size} bytes")
    
    if file_size < 12:
        print("[-] File is too small to be an ARSC.")
        return

    # 1. Parse ARSC Header (12 bytes)
    arsc_type, header_size, total_size, package_count = struct.unpack('<HHII', data[0:12])
    dprint(f"[DEBUG] Header -> Magic: 0x{arsc_type:04X} | HSize: {header_size} | Declared Total: {total_size} | Packages: {package_count}")
    
    if arsc_type != RES_TABLE_TYPE:
        print(f"[-] Invalid ARSC magic (Found 0x{arsc_type:04X}). Skipping.")
        return

    fixed_count = 0

    # The Header Padding Exploit (JADX Offset 0xE fix)
    if header_size > 12:
        excess = header_size - 12
        print(f"[!] Trap Detected: Spoofed header_size ({header_size}). Slicing out {excess} bytes of garbage padding...")
        
        del data[12 : header_size]
        file_size -= excess
        
        # Rewrite Global Size & Header Size back to standard 12
        data[4:8] = struct.pack('<I', file_size)
        data[2:4] = struct.pack('<H', 12)
        
        header_size = 12
        fixed_count += 1

    # 2. Chunk Walker
    offset = header_size
    current_package_offset = -1

    while offset < file_size:
        if offset + 8 > file_size:
            dprint(f"[DEBUG] Offset 0x{offset:X} is too close to EOF. Stopping walk.")
            break

        chunk_type, chunk_header_size, chunk_size = struct.unpack('<HHI', data[offset:offset+8])
        chunk_name = CHUNK_NAMES.get(chunk_type, "UNKNOWN")
        
        # Condensed 1-line Debug Output
        dprint(f"[DEBUG] @ 0x{offset:08X} | {chunk_name} (0x{chunk_type:04X}) | HSize: {chunk_header_size} | CSize: {chunk_size}")
        
        # Kill 0-byte chunk infinite loops
        if chunk_size < 8:
            print(f"[!] Trap Detected at 0x{offset:X}: Corrupted 0-size chunk. Erasing...")
            del data[offset : offset + 8]
            file_size -= 8
            data[4:8] = struct.pack('<I', file_size)
            fixed_count += 1
            continue

        # TRICK 0: Step INTO Package Containers
        if chunk_type == RES_TABLE_PACKAGE_TYPE:
            current_package_offset = offset
            offset += chunk_header_size
            continue

        # TRICK 1: Handle Unknown / Junk Chunks
        if chunk_type not in VALID_ARSC_CHUNKS:
            print(f"[!] TRICK 1: Trap Detected at 0x{offset:X}. Junk Chunk Type 0x{chunk_type:04X}. Erasing...")
            delete_size = min(chunk_size, file_size - offset)
            del data[offset : offset + delete_size]
            file_size -= delete_size
            data[4:8] = struct.pack('<I', file_size)
            fixed_count += 1
            continue 

        # TRICK 2: Process String Pool Chunk (Bad Offsets)
        if chunk_type == RES_STRING_POOL_TYPE:
            sp_header_offset = offset + 8
            str_count, style_count, flags, str_start, style_start = struct.unpack(
                '<IIIII', data[sp_header_offset:sp_header_offset+20]
            )

            if style_count == 0 and style_start != 0:
                print(f"[!] TRICK 2: Trap Detected at 0x{offset:X}. Fake style_start {style_start}. Forcing to 0...")
                data[sp_header_offset+16 : sp_header_offset+20] = struct.pack('<I', 0)
                style_start = 0
                fixed_count += 1

            max_str_offset = (style_start - str_start) if (style_count > 0 and style_start > str_start) else (chunk_size - str_start)
            offsets_array_start = offset + chunk_header_size
            bad_offsets = 0

            for i in range(str_count):
                ptr = offsets_array_start + (i * 4)
                if ptr + 4 > file_size: break
                offset_val = struct.unpack('<i', data[ptr:ptr+4])[0]

                if offset_val < 0 or offset_val >= max_str_offset:
                    data[ptr:ptr+4] = struct.pack('<i', 0)
                    bad_offsets += 1
                    fixed_count += 1
            
            if bad_offsets > 0:
                print(f"[!] TRICK 2: Neutralized {bad_offsets} out-of-bounds String Pool offsets at 0x{offset:X}")
            
            offset += chunk_size

        # TRICK 3: The Config Size Patcher (Byte Injector)
        elif chunk_type == RES_TABLE_TYPE_TYPE:
            if offset + 24 <= file_size:
                config_size_ptr = offset + 20
                config_size = struct.unpack('<I', data[config_size_ptr:config_size_ptr+4])[0]
                
                if config_size < 28:
                    missing_bytes = 28 - config_size
                    print(f"[!] TRICK 3: Trap Detected at 0x{offset:X}. Config size < 28. Injecting {missing_bytes} padding bytes...")
                    
                    insertion_point = offset + 20 + config_size
                    data[insertion_point : insertion_point] = b'\x00' * missing_bytes
                    
                    data[config_size_ptr:config_size_ptr+4] = struct.pack('<I', 28)
                    
                    header_size_ptr = offset + 2
                    old_header_size = struct.unpack('<H', data[header_size_ptr:header_size_ptr+2])[0]
                    data[header_size_ptr:header_size_ptr+2] = struct.pack('<H', old_header_size + missing_bytes)
                    
                    chunk_size_ptr = offset + 4
                    old_chunk_size = struct.unpack('<I', data[chunk_size_ptr:chunk_size_ptr+4])[0]
                    new_chunk_size = old_chunk_size + missing_bytes
                    data[chunk_size_ptr:chunk_size_ptr+4] = struct.pack('<I', new_chunk_size)
                    
                    entries_start_ptr = offset + 16
                    old_entries_start = struct.unpack('<I', data[entries_start_ptr:entries_start_ptr+4])[0]
                    data[entries_start_ptr:entries_start_ptr+4] = struct.pack('<I', old_entries_start + missing_bytes)
                    
                    if current_package_offset != -1:
                        pkg_size_ptr = current_package_offset + 4
                        old_pkg_size = struct.unpack('<I', data[pkg_size_ptr:pkg_size_ptr+4])[0]
                        data[pkg_size_ptr:pkg_size_ptr+4] = struct.pack('<I', old_pkg_size + missing_bytes)
                    
                    global_size_ptr = 4
                    old_global_size = struct.unpack('<I', data[global_size_ptr:global_size_ptr+4])[0]
                    data[global_size_ptr:global_size_ptr+4] = struct.pack('<I', old_global_size + missing_bytes)
                    
                    file_size += missing_bytes
                    chunk_size = new_chunk_size
                    fixed_count += 1

            offset += chunk_size
        else:
            offset += chunk_size

    if fixed_count > 0:
        with open(out_path, 'wb') as f:
            f.write(data)
        print(f"\n[+] Successfully neutralized {fixed_count} ARSC traps. Saved to: {out_path}")
    else:
        print("\n[+] No traps detected. ARSC file is clean.")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python fix_arsc.py <resources.arsc>")
    else:
        target = sys.argv[1]
        fix_arsc(target, target)