#!/usr/bin/env python3
"""
safe_extractor.py - Static SFX & Obfuscated Payload Extractor (Defensive Security Tool)
Extracts both:
 1. Advanced Installer SFX droppers (ADVINSTSFX - e.g. Step 3 - Setup_Install_Game.exe)
 2. Setup Factory disguised game installers (e.g. Data_xe.bin / main.exe / irsetup.exe)
Completely safe: unpacks all payloads and genuine game files without executing ANY code.
"""

import os
import sys
import struct
import argparse
import py7zr

# Optional dependencies for Setup Factory (irsetup) extraction
try:
    import pefile
    from sfextract import setupfactory8, setupfactory7
    HAS_SFEXTRACT = True
except ImportError:
    HAS_SFEXTRACT = False

ADVINSTSFX_SIG = b'ADVINSTSFX'
OBFUSCATION_XOR_LEN = 512  # Discovered via Ghidra FUN_0053aa50 (0x200 bytes)
SETUP_FACTORY_SIG = b'\xe0\xe0\xe1\xe1\xe2\xe2\xe3\xe3\xe4\xe4\xe5\xe5\xe6\xe6\xe7\xe7'


def is_setup_factory(file_path):
    """Checks if file contains the Setup Factory runtime overlay."""
    if not os.path.isfile(file_path) or os.path.getsize(file_path) < 1024:
        return False
    try:
        with open(file_path, 'rb') as f:
            head = f.read(256 * 1024)
            if b'Setup Factory' in head:
                return True
            # Search for overlay signature in first 512 KB
            if SETUP_FACTORY_SIG in head:
                return True
    except Exception:
        pass
    return False


def is_advinstsfx(file_path):
    """Checks if file contains the ADVINSTSFX trailer signature."""
    if not os.path.isfile(file_path) or os.path.getsize(file_path) < 256:
        return False
    try:
        with open(file_path, 'rb') as f:
            f.seek(0, 2)
            size = f.tell()
            search_len = min(512, size)
            f.seek(size - search_len)
            tail = f.read(search_len)
            return ADVINSTSFX_SIG in tail
    except Exception:
        return False


def parse_sfx_trailer(f):
    f.seek(0, 2)
    file_size = f.tell()
    if file_size < 256:
        raise ValueError("File is too small to be a valid SFX container.")

    search_len = min(512, file_size)
    f.seek(file_size - search_len)
    tail_buf = f.read(search_len)

    idx = tail_buf.find(ADVINSTSFX_SIG)
    if idx == -1:
        raise ValueError("ADVINSTSFX trailer signature not found.")

    sig_file_pos = file_size - search_len + idx
    trailer_pos = sig_file_pos - 60
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
    as implemented in Ghidra FUN_0053aa50.
    """
    buf = bytearray(data)
    if method == 2:
        invert_len = min(OBFUSCATION_XOR_LEN, len(buf))
        for i in range(invert_len):
            buf[i] ^= 0xFF
    return bytes(buf)


def extract_advinst_container(exe_path, output_dir, unpack_inner_7z=True):
    """Extracts an Advanced Installer SFX container and its payloads."""
    print("=" * 70)
    print(" [1/2] Processing Advanced Installer SFX Dropper Container")
    print("=" * 70)

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

    print(f"\n[+] SFX Dropper Extraction Complete! Payloads saved to: {output_dir}")
    return True


def extract_setup_factory_container(bin_path, output_dir):
    """Extracts genuine game files from Setup Factory archives (Data_xe.bin / irsetup.exe)."""
    print("=" * 70)
    print(" [2/2] Processing Disguised Setup Factory Game Archive (Data_xe.bin)")
    print("=" * 70)

    if not HAS_SFEXTRACT:
        print("[-] Error: 'pefile' or 'sfextract' not installed.")
        print("    Install them with: pip install pefile sfextract")
        return False

    print(f"[*] Analyzing Setup Factory executable: {bin_path}")
    os.makedirs(output_dir, exist_ok=True)

    try:
        pe = pefile.PE(bin_path, fast_load=True)
        extractor = setupfactory8.get_extractor(pe) or setupfactory7.get_extractor(pe)

        if not extractor:
            print("[-] Could not identify Setup Factory version for this file.")
            return False

        version_str = ".".join(str(x) for x in extractor.version)
        print(f"[+] Identified: Setup Factory {version_str} Run-time installer")
        print(f"[*] Extracting all genuine game files to: {output_dir}")
        print("    (This unpacks irsetup.exe, audio, models, animations, and game exe)")

        extractor.extract_files(output_dir)

        print(f"\n[+] SUCCESS: Extracted {len(extractor.files)} clean game files!")
        # Print sample of extracted files
        for f in extractor.files[:10]:
            fname = f.name.decode('utf-8', errors='ignore') if isinstance(f.name, bytes) else str(f.name)
            print(f"    - {fname} ({f.unpacked_size} bytes)")
        if len(extractor.files) > 10:
            print(f"    ... and {len(extractor.files) - 10} more files.")

        return True
    except Exception as e:
        print(f"[-] Error extracting Setup Factory archive: {e}")
        return False


def process_target(target_path, output_dir, unpack_inner_7z=True):
    print("======================================================================")
    print(" OceanofGames Safe Defensive Extractor & Analysis Tool")
    print(" Static, zero-execution extractor for droppers and disguised game data")
    print("======================================================================\n")

    if not os.path.exists(target_path):
        print(f"[-] Target path not found: {target_path}")
        return False

    # Scenario A: Target is a directory (e.g. Grand_Theft_Auto_III download directory)
    if os.path.isdir(target_path):
        print(f"[*] Target is a directory. Scanning for malware dropper and game data in: {target_path}")
        found_any = False

        # Check for CheckSums_xe.txt and Data_xe.bin
        data_bin_path = os.path.join(target_path, "Data_xe.bin")
        checksum_path = os.path.join(target_path, "CheckSums_xe.txt")
        if os.path.isfile(checksum_path):
            with open(checksum_path, 'r', errors='ignore') as cf:
                real_name = cf.read().strip()
            print(f"[!] Discovered bait-and-switch mapping: CheckSums_xe.txt points to '{real_name}'")

        if os.path.isfile(data_bin_path):
            print(f"[+] Found disguised game archive: Data_xe.bin ({os.path.getsize(data_bin_path)} bytes)")
            game_out = os.path.join(output_dir, "Clean_Game_Files")
            extract_setup_factory_container(data_bin_path, game_out)
            found_any = True

        # Search for Step 3 - Setup_Install_Game.exe or any ADVINSTSFX
        for root, dirs, files in os.walk(target_path):
            for file in files:
                full_p = os.path.join(root, file)
                if is_advinstsfx(full_p):
                    print(f"\n[+] Found ADVINSTSFX malware dropper: {file}")
                    sfx_out = os.path.join(output_dir, "Malware_Dropper_Payloads")
                    extract_advinst_container(full_p, sfx_out, unpack_inner_7z=unpack_inner_7z)
                    found_any = True

        return found_any

    # Scenario B: Target is an ADVINSTSFX executable (Step 3 - Setup_Install_Game.exe)
    if is_advinstsfx(target_path):
        print(f"[*] Target recognized as an Advanced Installer SFX Container.")
        return extract_advinst_container(target_path, output_dir, unpack_inner_7z=unpack_inner_7z)

    # Scenario C: Target is a Setup Factory file (Data_xe.bin / main.exe)
    if is_setup_factory(target_path) or target_path.lower().endswith('.bin'):
        print(f"[*] Target recognized as a Setup Factory installer package.")
        return extract_setup_factory_container(target_path, output_dir)

    print(f"[-] Unrecognized container format for file: {target_path}")
    return False


def main():
    parser = argparse.ArgumentParser(description="Static Malware SFX & Disguised Game Extractor")
    parser.add_argument("target", help="Path to installer executable (Step 3), Data_xe.bin, or download folder")
    parser.add_argument("-o", "--output", default="safe_extracted_output", help="Output directory path")
    parser.add_argument("--no-unpack", action="store_true", help="Do not unpack inner 7z archives, only dump payloads")
    args = parser.parse_args()

    success = process_target(args.target, args.output, unpack_inner_7z=not args.no_unpack)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
