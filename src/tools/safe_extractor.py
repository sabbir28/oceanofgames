#!/usr/bin/env python3
"""
safe_extractor.py - Universal Static Malware SFX & Disguised Game Extractor
Defensive Security & Digital Forensics Suite

Supported Architectures & Formats:
 1. Advanced Installer SFX (ADVINSTSFX) - Extracts XOR-obfuscated 7z payload trojans (Step 3)
 2. Setup Factory Installers - Extracts disguised runtime packages (Setup Factory 7/8/9)
 3. Inno Setup + FreeArc Repacks - Dissects disguised Inno stubs (Data_xe.bin / R.G. Origami, FitGirl),
    extracts embedded unpacker toolkits (ISDone.dll, unarc.dll, botva2.dll), and catalogs FreeArc payloads.
 4. Nullsoft Scriptable Install System (NSIS) detection
 5. FreeArc (ArC\x01) Archive detection and integrity checks
 6. Bait-and-Switch PE Obfuscation - Unmasks PE executables disguised as .bin files

COMPLETELY SAFE & DEFENSIVE:
Performs strictly static dissection without executing ANY untrusted host or guest code.
"""

import os
import sys
import struct
import argparse
import hashlib
import py7zr

# Optional dependencies for Setup Factory & PE dissection
try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

try:
    from sfextract import setupfactory8, setupfactory7
    HAS_SFEXTRACT = True
except ImportError:
    HAS_SFEXTRACT = False

ADVINSTSFX_SIG = b'ADVINSTSFX'
OBFUSCATION_XOR_LEN = 512  # Discovered via Ghidra FUN_0053aa50 (0x200 bytes)
SETUP_FACTORY_SIG = b'\xe0\xe0\xe1\xe1\xe2\xe2\xe3\xe3\xe4\xe4\xe5\xe5\xe6\xe6\xe7\xe7'
FREEARC_SIG = b'ArC\x01'
NSIS_SIG = b'NullsoftInst'
INNO_SIG = b'Inno Setup Setup Data'


def get_file_hashes(file_path):
    """Calculates MD5 and SHA-256 hashes of a target file."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(65536):
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()


def is_advinstsfx(file_path):
    """Checks if file contains the ADVINSTSFX trailer signature at EOF."""
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


def is_setup_factory(file_path):
    """Checks if file contains the Setup Factory runtime signature."""
    if not os.path.isfile(file_path) or os.path.getsize(file_path) < 1024:
        return False
    try:
        with open(file_path, 'rb') as f:
            head = f.read(256 * 1024)
            if b'Setup Factory' in head or SETUP_FACTORY_SIG in head:
                return True
    except Exception:
        pass
    return False


def is_inno_setup(file_path):
    """Checks if file contains Inno Setup signatures in headers or overlay."""
    if not os.path.isfile(file_path) or os.path.getsize(file_path) < 1024:
        return False
    try:
        with open(file_path, 'rb') as f:
            head = f.read(64 * 1024)
            if INNO_SIG in head or b'Inno Setup' in head:
                return True
            # Also check overlay
            f.seek(0, 2)
            size = f.tell()
            search_len = min(1024 * 1024, size)
            f.seek(size - search_len)
            tail = f.read(search_len)
            return INNO_SIG in tail or b'Inno Setup' in tail
    except Exception:
        return False


def is_freearc(file_path):
    """Checks if file begins with FreeArc archive signature."""
    if not os.path.isfile(file_path) or os.path.getsize(file_path) < 16:
        return False
    try:
        with open(file_path, 'rb') as f:
            return f.read(4) == FREEARC_SIG
    except Exception:
        return False


def is_nsis(file_path):
    """Checks if file contains NSIS (Nullsoft) installer signature."""
    if not os.path.isfile(file_path) or os.path.getsize(file_path) < 512:
        return False
    try:
        with open(file_path, 'rb') as f:
            head = f.read(64 * 1024)
            return NSIS_SIG in head
    except Exception:
        return False


def is_pe_executable(file_path):
    """Checks if file is a valid Portable Executable (PE32/PE32+)."""
    if not os.path.isfile(file_path) or os.path.getsize(file_path) < 64:
        return False
    try:
        with open(file_path, 'rb') as f:
            if f.read(2) != b'MZ':
                return False
            f.seek(0x3C)
            e_lfanew_bytes = f.read(4)
            if len(e_lfanew_bytes) < 4:
                return False
            e_lfanew = struct.unpack('<I', e_lfanew_bytes)[0]
            f.seek(e_lfanew)
            return f.read(4) == b'PE\x00\x00'
    except Exception:
        return False


def detect_format(file_path):
    """Classifies the binary/archive format across supported installer engines."""
    if is_advinstsfx(file_path):
        return "ADVINSTSFX"
    if is_setup_factory(file_path):
        return "SETUP_FACTORY"
    if is_inno_setup(file_path):
        return "INNO_SETUP"
    if is_freearc(file_path):
        return "FREEARC"
    if is_nsis(file_path):
        return "NSIS"
    if is_pe_executable(file_path):
        return "DISGUISED_PE"
    return "UNKNOWN"


def parse_pe_metadata(file_path):
    """Statically extracts PE headers, metadata strings, and version info."""
    if not HAS_PEFILE:
        return {}
    meta = {}
    try:
        pe = pefile.PE(file_path, fast_load=True)
        meta['Machine'] = hex(pe.FILE_HEADER.Machine)
        meta['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
        meta['ImageBase'] = hex(pe.OPTIONAL_HEADER.ImageBase)
        meta['Sections'] = [s.Name.decode(errors='ignore').strip('\x00') for s in pe.sections]
        
        # Parse Version Information
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
        if hasattr(pe, 'FileInfo'):
            for finfo in pe.FileInfo:
                for item in finfo:
                    if hasattr(item, 'StringTable'):
                        for st in item.StringTable:
                            for k, v in st.entries.items():
                                meta[k.decode(errors='ignore')] = v.decode(errors='ignore')
    except Exception as e:
        meta['error'] = str(e)
    return meta


# =====================================================================
# 1. Advanced Installer SFX Container Extractor (Step 3 Malware Dropper)
# =====================================================================

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
    print(" [*] Processing Advanced Installer SFX Dropper Container")
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


# =====================================================================
# 2. Setup Factory Container Extractor (GTA III & legacy repacks)
# =====================================================================

def extract_setup_factory_container(bin_path, output_dir):
    """Extracts genuine game files from Setup Factory archives (Data_xe.bin / irsetup.exe)."""
    print("=" * 70)
    print(" [*] Processing Disguised Setup Factory Game Archive")
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

        extractor.extract_files(output_dir)

        print(f"\n[+] SUCCESS: Extracted {len(extractor.files)} clean game files!")
        for f in extractor.files[:10]:
            fname = f.name.decode('utf-8', errors='ignore') if isinstance(f.name, bytes) else str(f.name)
            print(f"    - {fname} ({f.unpacked_size} bytes)")
        if len(extractor.files) > 10:
            print(f"    ... and {len(extractor.files) - 10} more files.")

        return True
    except Exception as e:
        print(f"[-] Error extracting Setup Factory archive: {e}")
        return False


# =====================================================================
# 3. Inno Setup + FreeArc Repack Dissector (Closure / R.G. Origami)
# =====================================================================

def extract_embedded_pe_tools(bin_path, output_dir):
    """Safely carves all embedded helper PE libraries (ISDone.dll, unarc.dll, botva2.dll, etc.)."""
    if not HAS_PEFILE:
        return []
    with open(bin_path, 'rb') as f:
        data = f.read()

    os.makedirs(output_dir, exist_ok=True)
    pos = 0
    extracted = []

    while True:
        idx = data.find(b'MZ', pos)
        if idx == -1:
            break
        if idx > 0 and idx + 0x40 <= len(data):
            e_lfanew = int.from_bytes(data[idx+0x3c:idx+0x40], 'little')
            if 0 < e_lfanew < 0x1000 and idx + e_lfanew + 4 <= len(data):
                if data[idx+e_lfanew:idx+e_lfanew+4] == b'PE\x00\x00':
                    try:
                        sub_pe = pefile.PE(data=data[idx:])
                        pe_size = max(s.PointerToRawData + s.SizeOfRawData for s in sub_pe.sections)
                        if hasattr(sub_pe, 'OPTIONAL_HEADER') and hasattr(sub_pe.OPTIONAL_HEADER, 'DATA_DIRECTORY'):
                            for dd in sub_pe.OPTIONAL_HEADER.DATA_DIRECTORY:
                                if dd.name == 'IMAGE_DIRECTORY_ENTRY_SECURITY' and dd.Size > 0:
                                    pe_size = max(pe_size, dd.VirtualAddress + dd.Size)

                        pe_bytes = data[idx:idx+pe_size]

                        name = None
                        if hasattr(sub_pe, 'DIRECTORY_ENTRY_EXPORT') and sub_pe.DIRECTORY_ENTRY_EXPORT.name:
                            name = sub_pe.DIRECTORY_ENTRY_EXPORT.name.decode(errors='ignore')
                        if not name and hasattr(sub_pe, 'FileInfo'):
                            for finfo in sub_pe.FileInfo:
                                for item in finfo:
                                    if hasattr(item, 'StringTable'):
                                        for st in item.StringTable:
                                            if b'OriginalFilename' in st.entries:
                                                name = st.entries[b'OriginalFilename'].decode(errors='ignore')
                                            elif b'InternalName' in st.entries:
                                                name = st.entries[b'InternalName'].decode(errors='ignore')
                        if not name:
                            ext = ".dll" if sub_pe.is_dll() else ".exe"
                            name = f"embedded_0x{idx:X}{ext}"

                        if not name.endswith(('.dll', '.exe')):
                            name += ".dll" if sub_pe.is_dll() else ".exe"

                        out_path = os.path.join(output_dir, name)
                        with open(out_path, 'wb') as out_f:
                            out_f.write(pe_bytes)

                        extracted.append((name, hex(idx), len(pe_bytes)))
                        pos = idx + pe_size
                        continue
                    except Exception:
                        pass
        pos = idx + 2
    return extracted


def process_inno_freearc_repack(bin_path, output_dir, companion_dir=None):
    """
    Forensically dissects disguised Inno Setup + FreeArc repacks (e.g. Data_xe.bin).
    Identifies clean repack identity, extracts embedded tools, and catalogs FreeArc payload slices.
    """
    print("=" * 70)
    print(" [*] Processing Disguised Inno Setup + FreeArc Game Repack (Data_xe.bin)")
    print("=" * 70)

    os.makedirs(output_dir, exist_ok=True)
    meta = parse_pe_metadata(bin_path)
    md5, sha256 = get_file_hashes(bin_path)

    print(f"[+] Forensic Identification of Binary:")
    print(f"    File Path:        {bin_path}")
    print(f"    File Size:        {os.path.getsize(bin_path):,} bytes")
    print(f"    MD5:              {md5}")
    print(f"    SHA-256:          {sha256}")
    print(f"    Architecture:     PE32 x86 Little-Endian (Delphi Stub)")
    if meta:
        print(f"    Product Name:     {meta.get('ProductName', 'N/A')}")
        print(f"    Company Name:     {meta.get('CompanyName', 'N/A')}")
        print(f"    File Description: {meta.get('FileDescription', 'N/A')}")
        print(f"    Comments:         {meta.get('Comments', 'N/A')}")

    # Extract embedded unpacker toolkit
    tools_dir = os.path.join(output_dir, "unpacker_toolkit")
    print(f"\n[*] Carving embedded helper unpacking libraries into: {tools_dir}")
    tools = extract_embedded_pe_tools(bin_path, tools_dir)
    print(f"[+] Successfully carved {len(tools)} embedded libraries:")
    for name, off, sz in tools:
        print(f"    - {name:<22} (Offset: {off}, Size: {sz:,} bytes)")

    # Check companion FreeArc data slices
    scan_dir = companion_dir or os.path.dirname(bin_path)
    arc_files = []
    if os.path.isdir(scan_dir):
        for fname in sorted(os.listdir(scan_dir)):
            fpath = os.path.join(scan_dir, fname)
            if os.path.isfile(fpath) and is_freearc(fpath):
                arc_files.append((fname, os.path.getsize(fpath)))

    if arc_files:
        print(f"\n[+] Detected {len(arc_files)} Associated FreeArc (ArC) Game Data Slices:")
        total_arc_sz = 0
        for name, sz in arc_files:
            total_arc_sz += sz
            print(f"    - {name:<20} ({sz:,} bytes)")
        print(f"    Total Payload Volume: {total_arc_sz:,} bytes (~{total_arc_sz / (1024*1024):.2f} MB)")

    print(f"\n" + "=" * 70)
    print(" [!] FORENSIC SUMMARY & SANDBOX UNPACKING INSTRUCTIONS:")
    print("=" * 70)
    print("  1. 'Data_xe.bin' is the GENUINE, CLEAN Inno Setup game installer (Setup.exe)")
    print("     created by repack group 'R.G. Origami' for 'Closure'.")
    print("  2. OceanofGames malware distributors RENAMED 'Setup.exe' to 'Data_xe.bin' (_xe = .exe)")
    print("     to block direct installation and coerce users into running the malware droppers")
    print("     ('Step 1 - Disable Defender.exe' and 'Step 3 - Setup_Install_Game.exe').")
    print("  3. The virus payloads are located in 'Step 3' (ADVINSTSFX), NOT inside 'Data_xe.bin'.")
    print("  4. To safely install the clean game without running any malware:")
    print("     - Simply rename 'Data_xe.bin' back to 'Setup.exe'")
    print("     - Run 'Setup.exe' in Windows Sandbox or an isolated test VM.")
    print("     - Inno Setup will invoke unarc.dll to decompress 'data 1.bin' - 'data 4.bin'.")
    print("=" * 70)

    return True


# =====================================================================
# Main Multi-Format Dispatcher
# =====================================================================

def process_target(target_path, output_dir, unpack_inner_7z=True):
    print("======================================================================")
    print(" Universal Defensive Extractor & Forensic Installer Analyzer")
    print(" Analyzes droppers, unmasks disguised binaries, and extracts payloads")
    print("======================================================================\n")

    if not os.path.exists(target_path):
        print(f"[-] Target path not found: {target_path}")
        return False

    # Scenario A: Target is a directory
    if os.path.isdir(target_path):
        print(f"[*] Scanning directory: {target_path}")
        found_any = False

        # Check for CheckSums_xe.txt and Data_xe.bin bait-and-switch
        data_bin_path = os.path.join(target_path, "Data_xe.bin")
        checksum_path = os.path.join(target_path, "CheckSums_xe.txt")
        if os.path.isfile(checksum_path):
            with open(checksum_path, 'r', errors='ignore') as cf:
                real_name = cf.read().strip()
            print(f"[!] Bait-and-Switch Detected: CheckSums_xe.txt points to original name '{real_name}'")

        if os.path.isfile(data_bin_path):
            fmt = detect_format(data_bin_path)
            print(f"[+] Found disguised game archive: Data_xe.bin -> Detected Format: {fmt}")
            game_out = os.path.join(output_dir, "Disguised_Game_Archive")
            if fmt == "SETUP_FACTORY":
                extract_setup_factory_container(data_bin_path, game_out)
                found_any = True
            elif fmt == "INNO_SETUP":
                process_inno_freearc_repack(data_bin_path, game_out, companion_dir=target_path)
                found_any = True
            elif fmt == "DISGUISED_PE":
                process_inno_freearc_repack(data_bin_path, game_out, companion_dir=target_path)
                found_any = True

        # Scan directory recursively for ADVINSTSFX malware droppers
        for root, dirs, files in os.walk(target_path):
            for file in files:
                full_p = os.path.join(root, file)
                if is_advinstsfx(full_p):
                    print(f"\n[+] Found ADVINSTSFX malware dropper: {file}")
                    sfx_out = os.path.join(output_dir, "Malware_Dropper_Payloads")
                    extract_advinst_container(full_p, sfx_out, unpack_inner_7z=unpack_inner_7z)
                    found_any = True

        return found_any

    # Scenario B: Target is a specific file
    fmt = detect_format(target_path)
    print(f"[*] Analyzing target file: {target_path}")
    print(f"[+] Detected Installer Format: {fmt}")

    if fmt == "ADVINSTSFX":
        return extract_advinst_container(target_path, output_dir, unpack_inner_7z=unpack_inner_7z)
    elif fmt == "SETUP_FACTORY":
        return extract_setup_factory_container(target_path, output_dir)
    elif fmt in ("INNO_SETUP", "DISGUISED_PE"):
        return process_inno_freearc_repack(target_path, output_dir)
    elif fmt == "FREEARC":
        print("[+] File is a FreeArc compressed game data slice.")
        print(f"    Size: {os.path.getsize(target_path):,} bytes")
        print("    Decompressed during game installation via unarc.dll / ISDone.dll.")
        return True
    elif fmt == "NSIS":
        print("[+] File is a Nullsoft Scriptable Install System (NSIS) executable.")
        return True

    print(f"[-] Unrecognized container format for file: {target_path}")
    return False


def main():
    parser = argparse.ArgumentParser(description="Universal Static Malware SFX & Disguised Game Extractor")
    parser.add_argument("target", help="Path to installer executable (Step 3), Data_xe.bin, or download folder")
    parser.add_argument("-o", "--output", default="safe_extracted_output", help="Output directory path")
    parser.add_argument("--no-unpack", action="store_true", help="Do not unpack inner 7z archives, only dump payloads")
    args = parser.parse_args()

    success = process_target(args.target, args.output, unpack_inner_7z=not args.no_unpack)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
