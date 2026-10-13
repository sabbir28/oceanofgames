# Malware Forensics & Reverse Engineering Report: Decoder.dll & SFX Dropper

[**[বাংলা সংস্করণ / Bengali Version]**](file:///F:/Project/skill/decoder/docs/README_BN.md) | [**[When & Why Decoder.dll is Called (English)]**](file:///F:/Project/skill/decoder/docs/DECODER_CALL_ANALYSIS.md) | [**[কল অ্যানালাইসিস রিপোর্ট (বাংলা)]**](file:///F:/Project/skill/decoder/docs/DECODER_CALL_ANALYSIS_BN.md)

---

## 1. Executive Summary & Forensic Context

This repository hosts the reverse engineering documentation, clean-room C/C++ re-implementation, and defensive extraction tools for **`decoder.dll`** and obfuscated **Advanced Installer SFX** containers.

`decoder.dll` was recovered and analyzed from a trojanized installer bundle (`Step 3 - Setup_Install_Game.exe`, distributed under the "OceanofGames" repacking umbrella). Threat actors and repacking distributors use Advanced Installer SFX containers to encapsulate legitimate game installers alongside hidden malicious payloads, such as privilege escalation tools, background services, and persistence scripts.

### Key Forensic Discoveries:
1. **Container Architecture**: Advanced Installer SFX (Self-Extracting Executable) container terminated by an `ADVINSTSFX` trailer.
2. **Stream Obfuscation (Method 2)**: Embedded 7z payload streams have their first **512 bytes (`0x200`)** bitwise inverted (`^ 0xFF`). This defeats antivirus heuristic scanners and causes standard decompression tools to report `Data Error` / `Corrupt input data`.
3. **Role of `decoder.dll`**: The SFX stub drops `decoder.dll` into `%TEMP%` and dynamically binds its 4 exported ABI functions to decompress the obfuscated 7z streams in-process without spawning external tools like `7z.exe` or `cmd.exe`.
4. **Discovered Malicious Payloads in `326FA02\FILES.7z`**:
   - `LocalAppDataFolder\Updates\Run.vbs`: Obfuscated VBScript configuring startup and services.
   - `LocalAppDataFolder\Updates\import.reg`: Registry modification payload disabling security configurations.
   - `LocalAppDataFolder\Updates\WindowsService.exe`: Masqueraded Windows service binary.
   - `System64Folder\NSudo.exe`: Well-known administrative and TrustedInstaller privilege elevation tool.
   - `System64Folder\fidelity.exe`: Dropped secondary executable payload.

> [!CAUTION]
> Running the original installer executes malicious payloads with elevated privileges. **Do NOT run the original installer directly.** Instead, use the defensive extraction tools provided here (`safe_extractor.py` or `standalone_extractor.exe`) to statically unpack all files without executing any binary code.

---

## 2. Documentation Index

- [**Forensic Analysis: Infection & Game Delivery Chain (English)**](file:///F:/Project/skill/decoder/docs/MALWARE_CHAIN_ANALYSIS.md)
- [**ইনফেকশন ও আসল গেম ডেলিভারি চেইন বিশ্লেষণ (বাংলা)**](file:///F:/Project/skill/decoder/docs/MALWARE_CHAIN_ANALYSIS_BN.md)
- [**When, Why, and How Decoder.dll is Invoked (English)**](file:///F:/Project/skill/decoder/docs/DECODER_CALL_ANALYSIS.md)
- [**কখন, কেন এবং কীভাবে Decoder.dll কল করা হয় (বাংলা)**](file:///F:/Project/skill/decoder/docs/DECODER_CALL_ANALYSIS_BN.md)
- [**Container Architecture & XOR Inversion Deep Dive**](file:///F:/Project/skill/decoder/docs/ARCHITECTURE.md)
- [**C/C++ Exported ABI & DecoderContext API Reference**](file:///F:/Project/skill/decoder/docs/API.md)
- [**বাংলা ম্যালওয়্যার বিশ্লেষণ ও টেকনিক্যাল রিপোর্ট**](file:///F:/Project/skill/decoder/docs/README_BN.md)

---

## 3. Defensive Extraction Tools

### Option A: `safe_extractor.py` (Recommended Python Unpacker)
Recursively unpacks the SFX container and all nested 7-Zip archives safely:
```cmd
python F:\Project\skill\decoder\src\tools\safe_extractor.py "path\to\installer.exe" -o "output_dir"
```

### Option B: `standalone_extractor.exe` (Self-Contained C Tool)
Extracts container payloads with full 512-byte header de-obfuscation:
```cmd
F:\Project\skill\decoder\bin\x64\standalone_extractor.exe -o "output_dir" "path\to\installer.exe"
```

### Option C: `test_decoder.exe` with Reimplemented `decoder.dll`
Validates in-process extraction via the exact original ABI:
```cmd
F:\Project\skill\decoder\bin\x64\test_decoder.exe -d bin\x64\decoder.dll -f "installer.exe" -o 0x381400 -s 5298970 -t "output_dir"
```
