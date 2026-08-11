import argparse
import os
import struct

# --- GLOBAL SETTINGS ---
DEBUG = False

def dprint(msg):
    if DEBUG:
        print(f"[DEBUG] {msg}")

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

RESOURCE_TYPE_NAMES = (
    'anim', 'animator', 'attr', 'bool', 'color', 'dimen', 'drawable', 'font',
    'id', 'integer', 'interpolator', 'layout', 'menu', 'mipmap', 'plurals',
    'string', 'style', 'transition', 'xml'
)


def restore_type_names(data, package_offset):
    type_strings = struct.unpack_from('<I', data, package_offset + 0x10C)[0]
    pool_offset = package_offset + type_strings
    chunk_type, header_size, chunk_size = struct.unpack_from(
        '<HHI', data, pool_offset
    )
    if chunk_type != RES_STRING_POOL_TYPE:
        return False

    string_count, style_count, flags, strings_start, _ = struct.unpack_from(
        '<IIIII', data, pool_offset + 8
    )
    capacity = (strings_start - header_size) // 4
    if style_count != 0 or flags & 0x100 or capacity != len(RESOURCE_TYPE_NAMES):
        return False
    if string_count < len(RESOURCE_TYPE_NAMES):
        return False

    offsets = [
        struct.unpack_from('<I', data, pool_offset + header_size + index * 4)[0]
        for index in range(len(RESOURCE_TYPE_NAMES))
    ]
    values = []
    for relative in offsets:
        string_offset = pool_offset + strings_start + relative
        length = struct.unpack_from('<H', data, string_offset)[0]
        if length & 0x8000:
            return False
        start = string_offset + 2
        values.append(data[start:start + length * 2].decode('utf-16le'))
    if not all(value.startswith('##') for value in values):
        return False

    strings_size = chunk_size - strings_start
    for index, name in enumerate(RESOURCE_TYPE_NAMES):
        start = offsets[index]
        end = offsets[index + 1] if index + 1 < len(offsets) else strings_size
        encoded = struct.pack('<H', len(name)) + name.encode('utf-16le') + b'\x00\x00'
        if len(encoded) > end - start:
            raise ValueError(f"Resource type name {name!r} does not fit")
        string_offset = pool_offset + strings_start + start
        data[string_offset:string_offset + end - start] = (
            encoded + b'\x00' * (end - start - len(encoded))
        )
    return True


def fix_arsc(file_path, out_path):
    dprint(f"Processing ARSC: {file_path}")
    with open(file_path, 'rb') as f:
        data = bytearray(f.read())

    file_size = len(data)
    dprint(f"Physical file size on disk: {file_size} bytes")
    
    if file_size < 12:
        print("[-] File is too small to be an ARSC.")
        return

    # 1. Parse ARSC Header (12 bytes)
    arsc_type, header_size, total_size, package_count = struct.unpack('<HHII', data[0:12])
    dprint(f"Header -> Magic: 0x{arsc_type:04X} | HSize: {header_size} | Declared Total: {total_size} | Packages: {package_count}")
    
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
            dprint(f"Offset 0x{offset:X} is too close to EOF. Stopping walk.")
            break

        chunk_type, chunk_header_size, chunk_size = struct.unpack('<HHI', data[offset:offset+8])
        chunk_name = CHUNK_NAMES.get(chunk_type, "UNKNOWN")
        
        # Condensed 1-line Debug Output
        dprint(f"@ 0x{offset:08X} | {chunk_name} (0x{chunk_type:04X}) | HSize: {chunk_header_size} | CSize: {chunk_size}")
        
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
            standard_header_size = 0x120
            if chunk_header_size > standard_header_size:
                excess = chunk_header_size - standard_header_size
                child_offset = offset + chunk_header_size
                package_end = offset + chunk_size
                if child_offset + 8 > package_end or package_end > file_size:
                    raise ValueError(f"Invalid package bounds at 0x{offset:X}")
                child_type, child_header_size, child_size = struct.unpack(
                    '<HHI', data[child_offset:child_offset+8]
                )
                if (
                    child_type not in VALID_ARSC_CHUNKS or
                    child_header_size < 8 or child_size < child_header_size or
                    child_offset + child_size > package_end
                ):
                    raise ValueError(f"Invalid package child at 0x{child_offset:X}")
                for field_offset in (0x10C, 0x114):
                    field = offset + field_offset
                    value = struct.unpack('<I', data[field:field+4])[0]
                    if standard_header_size < value < chunk_header_size:
                        raise ValueError(
                            f"Package pointer enters padded header at 0x{field:X}"
                        )
                    if value >= chunk_header_size:
                        data[field:field+4] = struct.pack('<I', value - excess)
                del data[offset+standard_header_size:child_offset]
                chunk_header_size = standard_header_size
                chunk_size -= excess
                file_size -= excess
                data[offset+2:offset+4] = struct.pack('<H', chunk_header_size)
                data[offset+4:offset+8] = struct.pack('<I', chunk_size)
                data[4:8] = struct.pack('<I', file_size)
                fixed_count += 1
                print(
                    f"[!] Normalized package header at 0x{offset:X}: "
                    f"removed {excess} bytes"
                )
            if restore_type_names(data, current_package_offset):
                fixed_count += 1
                print(f"[!] Restored {len(RESOURCE_TYPE_NAMES)} resource type names")
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

            # string and style offset arrays must fit in the region between the
            # string-pool header and stringsStart.  Clamp a forged count before
            # walking the array so string payload bytes are never overwritten.
            offsets_bytes = str_start - chunk_header_size
            if offsets_bytes < 0:
                raise ValueError(
                    f"String pool at 0x{offset:X} has stringsStart before its header"
                )
            offsets_capacity = offsets_bytes // 4
            required_offsets = str_count + style_count
            if required_offsets > offsets_capacity:
                fixed_str_count = max(0, offsets_capacity - style_count)
                print(
                    f"[!] TRICK 2: Clamped forged stringCount at 0x{offset:X}: "
                    f"{str_count} -> {fixed_str_count}"
                )
                data[sp_header_offset:sp_header_offset+4] = struct.pack(
                    '<I', fixed_str_count
                )
                str_count = fixed_str_count
                fixed_count += 1

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
        dprint("No ARSC traps detected")


def main():
    parser = argparse.ArgumentParser(description='Fix malformed ARSC files')
    parser.add_argument('target', help='resources.arsc file')
    args = parser.parse_args()
    fix_arsc(args.target, args.target)


if __name__ == '__main__':
    main()
