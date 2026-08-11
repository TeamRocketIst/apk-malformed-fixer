import argparse
import os
import struct

# --- GLOBAL SETTINGS ---
DEBUG = False

def dprint(msg):
    if DEBUG:
        print(f"[DEBUG] {msg}")

# Standard AXML Chunk Types Whitelist
RES_XML_TYPE = 0x0003
RES_STRING_POOL_TYPE = 0x0001
RES_XML_RESOURCE_MAP_TYPE = 0x0180
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104

VALID_CHUNK_TYPES = {
    RES_STRING_POOL_TYPE, RES_XML_RESOURCE_MAP_TYPE, 
    RES_XML_START_NAMESPACE_TYPE, RES_XML_END_NAMESPACE_TYPE, 
    RES_XML_START_ELEMENT_TYPE, RES_XML_END_ELEMENT_TYPE, RES_XML_CDATA_TYPE
}

CHUNK_NAMES = {
    0x0003: "RES_XML_HEADER",
    0x0001: "RES_STRING_POOL",
    0x0180: "RES_XML_RESOURCE_MAP",
    0x0100: "RES_XML_START_NAMESPACE",
    0x0101: "RES_XML_END_NAMESPACE",
    0x0102: "RES_XML_START_ELEMENT",
    0x0103: "RES_XML_END_ELEMENT",
    0x0104: "RES_XML_CDATA"
}

ANDROID_ATTRIBUTE_NAMES = {
    0x01010000: 'theme',
    0x01010001: 'label',
    0x01010002: 'icon',
    0x01010003: 'name',
    0x01010006: 'permission',
    0x0101000D: 'persistent',
    0x0101000E: 'enabled',
    0x0101000F: 'debuggable',
    0x01010010: 'exported',
    0x01010017: 'excludeFromRecents',
    0x01010018: 'authorities',
    0x0101001C: 'priority',
    0x0101001D: 'launchMode',
    0x01010024: 'value',
    0x01010025: 'resource',
    0x01010027: 'scheme',
    0x0101020C: 'minSdkVersion',
    0x0101021B: 'versionCode',
    0x0101021C: 'versionName',
    0x0101022D: 'noHistory',
    0x01010270: 'targetSdkVersion',
    0x01010280: 'allowBackup',
    0x010102D3: 'hardwareAccelerated',
    0x0101035A: 'largeHeap',
    0x010103AF: 'supportsRtl',
    0x010104EB: 'fullBackupContent',
    0x010104EC: 'usesCleartextTraffic',
    0x01010505: 'directBootAware',
    0x01010572: 'compileSdkVersion',
    0x01010573: 'compileSdkVersionCodename',
    0x0101057A: 'appComponentFactory',
    0x01010599: 'foregroundServiceType',
    0x01010603: 'requestLegacyExternalStorage'
}


def decode_length8(data, offset):
    value = data[offset]
    if value & 0x80:
        return ((value & 0x7F) << 8) | data[offset + 1], 2
    return value, 1


def decode_length16(data, offset):
    value = struct.unpack_from('<H', data, offset)[0]
    if value & 0x8000:
        low = struct.unpack_from('<H', data, offset + 2)[0]
        return ((value & 0x7FFF) << 16) | low, 4
    return value, 2


def encode_length8(value):
    if value > 0x7FFF:
        raise ValueError("UTF-8 string is too long")
    if value > 0x7F:
        return bytes((0x80 | (value >> 8), value & 0xFF))
    return bytes((value,))


def encode_length16(value):
    if value > 0x7FFFFFFF:
        raise ValueError("UTF-16 string is too long")
    if value > 0x7FFF:
        return struct.pack('<HH', 0x8000 | (value >> 16), value & 0xFFFF)
    return struct.pack('<H', value)


def read_pool_strings(data, offset, header_size, string_count, flags, strings_start):
    values = []
    for index in range(string_count):
        relative = struct.unpack_from(
            '<I', data, offset + header_size + index * 4
        )[0]
        cursor = offset + strings_start + relative
        if flags & 0x100:
            _, size = decode_length8(data, cursor)
            cursor += size
            byte_length, size = decode_length8(data, cursor)
            cursor += size
            values.append(data[cursor:cursor + byte_length].decode('utf-8', 'replace'))
        else:
            char_length, size = decode_length16(data, cursor)
            cursor += size
            values.append(
                data[cursor:cursor + char_length * 2].decode('utf-16le', 'replace')
            )
    return values


def encode_pool_string(value, utf8):
    if utf8:
        encoded = value.encode('utf-8')
        return (
            encode_length8(len(value))
            + encode_length8(len(encoded))
            + encoded
            + b'\x00'
        )
    encoded = value.encode('utf-16le')
    return encode_length16(len(value)) + encoded + b'\x00\x00'


def restore_attribute_names(
    data, offset, header_size, chunk_size, string_count, style_count,
    flags, strings_start
):
    if style_count != 0:
        return chunk_size, 0, [], None
    map_offset = offset + chunk_size
    if map_offset + 8 > len(data):
        return chunk_size, 0, [], None
    map_type, _, map_size = struct.unpack_from('<HHI', data, map_offset)
    if map_type != RES_XML_RESOURCE_MAP_TYPE or map_size < 8:
        return chunk_size, 0, [], None

    values = read_pool_strings(
        data, offset, header_size, string_count, flags, strings_start
    )
    resource_ids = [
        struct.unpack_from('<I', data, map_offset + 8 + index * 4)[0]
        for index in range((map_size - 8) // 4)
    ]
    namespace_uri = 'http://schemas.android.com/apk/res/android'
    namespace_index = values.index(namespace_uri) if namespace_uri in values else None
    restored = 0
    for index, resource_id in enumerate(resource_ids[:len(values)]):
        replacement = ANDROID_ATTRIBUTE_NAMES.get(resource_id)
        if not values[index] and replacement:
            values[index] = replacement
            restored += 1
    if restored == 0:
        return chunk_size, 0, resource_ids, namespace_index

    encoded_strings = bytearray()
    offsets = []
    utf8 = bool(flags & 0x100)
    for value in values:
        offsets.append(len(encoded_strings))
        encoded_strings.extend(encode_pool_string(value, utf8))
    while len(encoded_strings) % 4:
        encoded_strings.append(0)

    strings_start = header_size + string_count * 4
    new_size = strings_start + len(encoded_strings)
    header = bytearray(data[offset:offset + header_size])
    header[4:8] = struct.pack('<I', new_size)
    header[20:24] = struct.pack('<I', strings_start)
    header[24:28] = struct.pack('<I', 0)
    rebuilt = header
    rebuilt.extend(b''.join(struct.pack('<I', value) for value in offsets))
    rebuilt.extend(encoded_strings)
    data[offset:offset + chunk_size] = rebuilt
    return new_size, restored, resource_ids, namespace_index


def fix_axml(file_path, out_path):
    dprint(f"Processing AXML: {file_path}")
    with open(file_path, 'rb') as f:
        data = bytearray(f.read())

    file_size = len(data)
    dprint(f"Physical file size on disk: {file_size} bytes")
    
    if file_size < 8:
        print("[-] File is too small to be an AXML.")
        return

    # 1. Parse AXML Header
    axml_type, header_size, total_size = struct.unpack('<HHI', data[0:8])
    dprint(f"Header -> Magic: 0x{axml_type:04X} | HSize: {header_size} | Declared Total: {total_size}")
    
    if axml_type != RES_XML_TYPE:
        print(f"[-] Invalid AXML magic. Skipping.")
        return

    # 2. Chunk Walker
    offset = header_size
    fixed_count = 0
    string_count = None
    resource_ids = []
    android_namespace_index = None
    namespace_fixed = 0

    while offset < file_size:
        if offset + 8 > file_size:
            dprint(f"Offset 0x{offset:X} is too close to EOF. Stopping walk.")
            break

        chunk_type, chunk_header_size, chunk_size = struct.unpack('<HHI', data[offset:offset+8])
        chunk_name = CHUNK_NAMES.get(chunk_type, "UNKNOWN")
        
        # Condensed 1-line Debug Output
        dprint(f"@ 0x{offset:04X} | {chunk_name} (0x{chunk_type:04X}) | HSize: {chunk_header_size} | CSize: {chunk_size}")
        
        if chunk_size < 8:
            print(f"[!] Corrupted chunk size at 0x{offset:X}. Stopping walk.")
            break

        # TRICK 1: Handle Unknown / Junk Chunks
        if chunk_type not in VALID_CHUNK_TYPES:
            print(f"[!] TRICK 1: Trap Detected at 0x{offset:X}. Junk Chunk Type 0x{chunk_type:04X}. Erasing {chunk_size} bytes...")
            delete_size = min(chunk_size, file_size - offset)
            del data[offset : offset + delete_size]
            
            file_size -= delete_size
            data[4:8] = struct.pack('<I', file_size)
            fixed_count += 1
            continue # Do not advance offset; next chunk shifted down

        # TRICK 2: Process String Pool Chunk (Bad Offsets)
        if chunk_type == RES_STRING_POOL_TYPE:
            sp_header_offset = offset + 8
            str_count, style_count, flags, str_start, style_start = struct.unpack(
                '<IIIII', data[sp_header_offset:sp_header_offset+20]
            )

            # The offset arrays live between header_size and stringsStart.  A
            # forged stringCount can make parsers interpret the string bytes as
            # offsets (the protection used by this sample).  Repair the count
            # before inspecting any offsets; zeroing the apparent "bad offsets"
            # would otherwise destroy the actual strings.
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

            string_count = str_count

            if style_count > 0 and style_start > str_start:
                max_str_offset = style_start - str_start
            else:
                max_str_offset = chunk_size - str_start

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

            old_size = chunk_size
            (
                chunk_size,
                restored,
                resource_ids,
                android_namespace_index
            ) = restore_attribute_names(
                data, offset, chunk_header_size, chunk_size,
                str_count, style_count, flags, str_start
            )
            if restored:
                file_size += chunk_size - old_size
                data[4:8] = struct.pack('<I', file_size)
                fixed_count += 1
                print(f"[!] Restored {restored} Android attribute names")

        # TRICK 3: The Attribute De-Puffer (JADX Alignment Fix)
        elif chunk_type == RES_XML_START_ELEMENT_TYPE:
            ext_ptr = offset + chunk_header_size
            
            if ext_ptr + 16 <= file_size:
                attr_start, attr_size, attr_count = struct.unpack('<HHH', data[ext_ptr+8 : ext_ptr+14])
                
                if attr_size > 20: # 20 bytes (0x14) is the Android standard
                    excess = attr_size - 20
                    print(f"[!] TRICK 3: Trap Detected at 0x{offset:X}. attributeSize is {attr_size} bytes. Slicing out {excess} bytes of padding per attribute ({attr_count} attributes total)...")
                    
                    # Delete the physical padding from each attribute
                    for i in reversed(range(attr_count)):
                        attr_base = ext_ptr + attr_start + (i * attr_size)
                        del_start = attr_base + 20
                        del_end = del_start + excess
                        del data[del_start : del_end]
                        
                    # 1. Patch the attributeSize header back to 20
                    data[ext_ptr+10 : ext_ptr+12] = struct.pack('<H', 20)
                    
                    # 2. Mathematically shrink the chunk_size
                    new_chunk_size = chunk_size - (attr_count * excess)
                    data[offset+4 : offset+8] = struct.pack('<I', new_chunk_size)
                    
                    # 3. Mathematically shrink the global file size
                    file_size -= (attr_count * excess)
                    data[4:8] = struct.pack('<I', file_size)
                    
                    # 4. IMPORTANT: Update our local chunk_size variable so the walker jumps correctly!
                    dprint(f"Shrunk Element Chunk from {chunk_size} -> {new_chunk_size} bytes")
                    chunk_size = new_chunk_size
                    fixed_count += 1

                # Drop attributes whose raw or typed string index is outside the repaired pool.
                if string_count is not None:
                    attr_start, attr_size, attr_count = struct.unpack(
                        '<HHH', data[ext_ptr+8 : ext_ptr+14]
                    )
                    invalid = []
                    for i in range(attr_count):
                        attr_base = ext_ptr + attr_start + (i * attr_size)
                        if attr_base + 20 > offset + chunk_size:
                            raise ValueError(
                                f"Attribute {i} at 0x{offset:X} exceeds its chunk"
                            )
                        raw_value = struct.unpack(
                            '<I', data[attr_base+8:attr_base+12]
                        )[0]
                        value_type = data[attr_base+15]
                        value_data = struct.unpack(
                            '<I', data[attr_base+16:attr_base+20]
                        )[0]
                        bad_raw = raw_value != 0xFFFFFFFF and raw_value >= string_count
                        bad_typed = value_type == 0x03 and value_data >= string_count
                        if bad_raw or bad_typed:
                            invalid.append(i)

                    if invalid:
                        id_index, class_index, style_index = struct.unpack(
                            '<HHH', data[ext_ptr+14:ext_ptr+20]
                        )
                        special = [id_index, class_index, style_index]
                        for i in reversed(invalid):
                            attr_base = ext_ptr + attr_start + (i * attr_size)
                            del data[attr_base:attr_base + attr_size]
                            one_based = i + 1
                            special = [
                                0 if value == one_based else
                                value - 1 if value > one_based else value
                                for value in special
                            ]
                        removed_size = len(invalid) * attr_size
                        attr_count -= len(invalid)
                        data[ext_ptr+12:ext_ptr+14] = struct.pack('<H', attr_count)
                        data[ext_ptr+14:ext_ptr+20] = struct.pack('<HHH', *special)
                        chunk_size -= removed_size
                        data[offset+4:offset+8] = struct.pack('<I', chunk_size)
                        file_size -= removed_size
                        data[4:8] = struct.pack('<I', file_size)
                        fixed_count += len(invalid)
                        print(
                            f"[!] Removed {len(invalid)} attribute(s) with "
                            f"out-of-range string references at 0x{offset:X}"
                        )

                attr_start, attr_size, attr_count = struct.unpack(
                    '<HHH', data[ext_ptr+8:ext_ptr+14]
                )
                if android_namespace_index is not None:
                    for i in range(attr_count):
                        attr_base = ext_ptr + attr_start + i * attr_size
                        namespace, name_index = struct.unpack_from(
                            '<II', data, attr_base
                        )
                        if (
                            namespace == 0xFFFFFFFF and
                            name_index < len(resource_ids) and
                            resource_ids[name_index] in ANDROID_ATTRIBUTE_NAMES
                        ):
                            struct.pack_into(
                                '<I', data, attr_base, android_namespace_index
                            )
                            namespace_fixed += 1
                            fixed_count += 1

                attr_start, attr_size, attr_count = struct.unpack(
                    '<HHH', data[ext_ptr+8:ext_ptr+14]
                )
                attributes_end = (
                    chunk_header_size
                    + attr_start
                    + attr_size * attr_count
                )
                trailing_size = chunk_size - attributes_end
                trailing_start = offset + attributes_end
                trailing = data[trailing_start:offset+chunk_size]
                if (
                    8 <= trailing_size <= 28 and trailing_size % 4 == 0 and
                    not any(trailing[4:])
                ):
                    del data[trailing_start:offset+chunk_size]
                    chunk_size -= trailing_size
                    data[offset+4:offset+8] = struct.pack('<I', chunk_size)
                    file_size -= trailing_size
                    data[4:8] = struct.pack('<I', file_size)
                    fixed_count += 1
                    print(
                        f"[!] Removed {trailing_size} forged element tail bytes "
                        f"at 0x{offset:X}"
                    )

        # Jump to the next chunk
        offset += chunk_size

    if namespace_fixed:
        print(f"[!] Restored {namespace_fixed} Android attribute namespaces")

    if fixed_count > 0:
        with open(out_path, 'wb') as f:
            f.write(data)
        print(f"[+] Successfully neutralized {fixed_count} total traps. Saved to: {out_path}")
    else:
        dprint("No AXML traps detected")


def main():
    parser = argparse.ArgumentParser(description='Fix malformed binary XML files')
    parser.add_argument('target', help='Binary XML file or directory')
    args = parser.parse_args()
    if os.path.isdir(args.target):
        for root, _, files in os.walk(args.target):
            for file in files:
                if file.endswith('.xml'):
                    full_path = os.path.join(root, file)
                    fix_axml(full_path, full_path)
    else:
        fix_axml(args.target, args.target)


if __name__ == '__main__':
    main()
