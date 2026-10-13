#!/usr/bin/env python3
"""
safe_extractor.py - Static SFX & Obfuscated 7z Payload Extractor
Extracts all payloads from Advanced Installer SFX droppers without executing any code.
"""

import os
import sys
import struct
import argparse
import py7zr

ADVINSTSFX_SIG = b'ADVINSTSFX'
OBFUSCATION_XOR_LEN = 512  # Exact length discovered via Ghidra FUN_0053aa50 (0x200 bytes)


def parse_sfx_trailer(f):
    f.seek(0, 2)
    file_size = f.tell()
    if file_size < 256:
        raise ValueError("File is too small to be a valid SFX container.")

    # Search for ADVINSTSFX in the trailing 512 bytes
    search_len = min(512, file_size)
    f.seek(file_size - search_len)
    tail_buf = f.read(search_len)

    idx = tail_buf.find(ADVINSTSFX_SIG)
    if idx == -1:
        raise ValueError("ADVINSTSFX trailer signature not found.")

    sig_file_pos = file_size - search_len + idx
    trailer_pos = sig_file_pos - 60  # sizeof(SFXTrailer) - 10 bytes signature
    f.seek(trailer_pos)

    trailer_raw = f.read(70)
    table_end, num_files, flags, table_end2, table_start, archive_start, hash_val, trailer_size, sig = struct.unpack(
        '<IIIIII32sI10s', trailer_raw
    )

    if not sig.startswith(ADVINSTSFX_SIG):
        raise ValueError("Invalid trailer signature verification.")

    return {
        'num_files': num_files,
        'table_start': table_start,
        'table_end': table_end,
        'archive_start': archive_start,
    }


def parse_file_table(f, table_start, num_files):
    f.seek(table_start)
    entries = []
    for i in range(num_files):
        hdr = f.read(24)
        if len(hdr) < 24:
            break
        flags, unk1, method, size, offset, name_len = struct.unpack('<IIIIII', hdr)
        wname = f.read(name_len * 2).decode('utf-16le', errors='ignore')
        entries.append({
            'name': wname,
            'offset': offset,
            'size': size,
            'method': method,
            'flags': flags
        })
    return entries


def deobfuscate_stream(data, method):
    """
    Method 2 in Advanced Installer SFX inverts the first 512 bytes (0x200)
    as implemented in FUN_0053aa50.
    """
    buf = bytearray(data)
    if method == 2:
        invert_len = min(OBFUSCATION_XOR_LEN, len(buf))
        for i in range(invert_len):
            buf[i] ^= 0xFF
    return bytes(buf)


def extract_container(exe_path, output_dir, unpack_inner_7z=True):
    print("=" * 70)
    print(" Safe Static SFX Container & Payload Extractor (Defensive Security Tool)")
    print(" Extracts trojanized installers safely without executing ANY code")
    print("=" * 70)

    if not os.path.isfile(exe_path):
        print(f"[-] Error: File not found: {exe_path}")
        return False

    os.makedirs(output_dir, exist_ok=True)
    raw_payloads_dir = os.path.join(output_dir, "raw_payloads")
    unpacked_dir = os.path.join(output_dir, "unpacked_contents")
    os.makedirs(raw_payloads_dir, exist_ok=True)

    with open(exe_path, 'rb') as f:
        print(f"[*] Reading container: {exe_path}")
        try:
            trailer = parse_sfx_trailer(f)
        except Exception as e:
            print(f"[-] Error parsing SFX trailer: {e}")
            return False

        print(f"[+] Found ADVINSTSFX trailer:")
        print(f"    Total Stored Files:  {trailer['num_files']}")
        print(f"    File Table Offset:   0x{trailer['table_start']:08X}")
        print(f"    Archive Base Offset: 0x{trailer['archive_start']:08X}")

        entries = parse_file_table(f, trailer['table_start'], trailer['num_files'])
        extracted_7z_archives = []

        print(f"\n[*] Extracting {len(entries)} container payloads...")
        for i, entry in enumerate(entries, 1):
            target_path = os.path.join(raw_payloads_dir, entry['name'].replace('/', '\\'))
            os.makedirs(os.path.dirname(target_path), exist_ok=True)

            f.seek(entry['offset'])
            data = f.read(entry['size'])

            is_obfuscated = (entry['method'] == 2)
            clean_data = deobfuscate_stream(data, entry['method'])

            with open(target_path, 'wb') as out_f:
                out_f.write(clean_data)

            status = "Decoded 512-byte obfuscation" if is_obfuscated else "Clean stream"
            print(f"  [{i}/{len(entries)}] {entry['name']} ({entry['size']} bytes) -> {status}")

            if entry['name'].lower().endswith('.7z'):
                extracted_7z_archives.append((entry['name'], target_path))

    if unpack_inner_7z and extracted_7z_archives:
        print(f"\n[*] Recursively unpacking inner 7z archives without running any executables...")
        os.makedirs(unpacked_dir, exist_ok=True)

        for name, archive_path in extracted_7z_archives:
            archive_sub_dir = os.path.join(unpacked_dir, os.path.splitext(os.path.basename(name))[0])
            os.makedirs(archive_sub_dir, exist_ok=True)
            print(f"  [*] Unpacking: {name} -> {archive_sub_dir}")

            try:
                with py7zr.SevenZipFile(archive_path, mode='r') as z:
                    names = z.getnames()
                    print(f"      Contents ({len(names)} items): {', '.join(names[:5])}{'...' if len(names) > 5 else ''}")
                    z.extractall(path=archive_sub_dir)
                print(f"      [+] Successfully unpacked cleanly!")
            except Exception as e:
                print(f"      [-] Warning unpacking {name}: {e}")

    print("\n" + "=" * 70)
    print(f"[+] EXTRACTION COMPLETE!")
    print(f"[+] Output Directory: {output_dir}")
    print(f"    - Raw decoded payloads: {raw_payloads_dir}")
    print(f"    - Unpacked files:       {unpacked_dir}")
    print("=" * 70)
    return True


def main():
    parser = argparse.ArgumentParser(description="Static Advanced Installer SFX Payload Extractor")
    parser.add_argument("installer", help="Path to suspicious/trojanized installer executable")
    parser.add_argument("-o", "--output", default="safe_extracted_payloads", help="Output directory path")
    parser.add_argument("--no-unpack", action="store_true", help="Do not unpack inner 7z archives, only dump payloads")
    args = parser.parse_args()

    success = extract_container(args.installer, args.output, unpack_inner_7z=not args.no_unpack)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
