# OceanofGames / Advanced Installer SFX Decoder

> 📖 **Comprehensive Documentation / বিস্তারিত ডকুমেন্টেশন**:  
> • 🇬🇧 [**English Forensic & Technical Report**](file:///F:/Project/skill/decoder/docs/README.md)  
> • 🇧🇩 [**বাংলা ম্যালওয়্যার বিশ্লেষণ ও টেকনিক্যাল রিপোর্ট**](file:///F:/Project/skill/decoder/docs/README_BN.md)

A professional, reverse-engineered C/C++ suite and ABI-compatible replacement library for decoding and unpacking obfuscated 7-Zip payload archives embedded inside **Advanced Installer SFX** containers (widely used in OceanofGames repackaging).

---

## Features

- **Drop-in ABI Replacement (`decoder.dll`)**: Implements the identical binary interface (`InitExtraction`, `GetTotalFilesSize`, `ExtractAllFiles`, `EndExtraction`) required by Advanced Installer SFX stubs.
- **Standalone Container Unpacker (`standalone_extractor.exe`)**: Parses the `ADVINSTSFX` container trailer and embedded file tables directly without requiring external COM components.
- **Automated Header De-obfuscation**: Transparently detects and reverses the bitwise XOR (`0xFF`) obfuscation applied to 7-Zip archive headers (`7z\xBC\xAF\x27\x1C`).
- **Dual Architecture Support**: Full support for both **x86 (32-bit)** and **x64 (64-bit)** targets.
- **Modern Build System**: Built with modern CMake (3.15+) and direct MSVC script support.
- **Zero In-Tree Clutter**: Clean separation of public headers, source modules, tests, samples, build scripts, and compiled binaries.

---

## Directory Structure

```
decoder/
├── CMakeLists.txt                 # Modern root CMake configuration
├── README.md                      # Primary project overview and instructions
├── LICENSE                        # MIT License
├── .gitignore                     # Git ignore rules for MSVC, CMake, and build artifacts
│
├── include/                       # Public API header files
│   ├── decoder.h                  # Convenience forwarding header
│   └── decoder/
│       ├── decoder.h              # Public C API & DecoderContext definitions
│       └── export.h               # Cross-platform symbol export/import macros
│
├── src/                           # Source implementations
│   ├── lib/                       # Core decoder.dll implementation
│   │   ├── CMakeLists.txt
│   │   ├── decoder.cpp            # 7-Zip COM virtual stream & inverted-header decoder
│   │   └── decoder.def            # Module definition file for exact export ABI
│   └── tools/                     # Command-line tools
│       ├── CMakeLists.txt
│       ├── standalone_extractor.c # Self-contained ADVINSTSFX container extractor
│       └── gof_extractor.c        # Enhanced extractor driving decoder.dll with extensive telemetry
│
├── tests/                         # Integration test harness
│   ├── CMakeLists.txt
│   └── test_decoder.c             # Test runner verifying ABI exports and extraction
│
├── scripts/                       # Developer automation scripts
│   ├── build.bat                  # One-click dual-architecture (x86 & x64) MSVC build
│   ├── build.ps1                  # PowerShell build automation script
│   └── run_tests.bat              # Test suite verification runner
│
├── bin/                           # Ready-to-use compiled binaries
│   ├── x64/                       # 64-bit binaries (decoder.dll, standalone_extractor.exe, gof_extractor.exe, test_decoder.exe)
│   └── x86/                       # 32-bit binaries (decoder.dll, standalone_extractor.exe, gof_extractor.exe, test_decoder.exe)
│
├── samples/                       # Reference payloads and extracted sample data
│   ├── README.md
│   └── payloads/
│       ├── original_installer_decoder.dll
│       ├── Step 3 - Setup_Install_Game.ini
│       └── 326FA02/               # Extracted clean payload archives
│
└── docs/                          # In-depth architectural & API documentation
    ├── ARCHITECTURE.md            # Deep dive into container layout and XOR inversion
    └── API.md                     # Comprehensive C API documentation and examples
```

---

## Quick Start

### 1. Extracting an Installer Executable (CLI)

To unpack all embedded payloads from an OceanofGames installer directly:

```powershell
.\bin\x64\standalone_extractor.exe "Step 3 - Setup_Install_Game.exe" -o "Extracted_Payloads"
```

Output:
```
===================================================================
 ADVINST SFX Container Extractor & Decoder                         
 Decodes obfuscated Advanced Installer 7z streams & payloads       
===================================================================

[+] Target Container:   Step 3 - Setup_Install_Game.exe (9610844 bytes)
[+] SFX Archive Start:  0x0034E000
[+] File Table Offset:  0x0092A4F4
[+] Total Stored Files: 4
[+] Output Directory:   Extracted_Payloads

[1/4] decoder.dll (Offset: 0x0034E000, Size: 209920 bytes, Method: 0)
    [+] Extracted clean payload:       Extracted_Payloads\decoder.dll (209920 bytes)
[2/4] 326FA02\FILES.7z (Offset: 0x00381400, Size: 5298970 bytes, Method: 2)
    [+] Decoded obfuscated 7z archive: Extracted_Payloads\326FA02\FILES.7z (5298970 bytes)
[3/4] 326FA02\OceanofGames-Top-Games-EXE.7z (Offset: 0x0088EF1A, Size: 635574 bytes, Method: 2)
    [+] Decoded obfuscated 7z archive: Extracted_Payloads\326FA02\OceanofGames-Top-Games-EXE.7z (635574 bytes)
[4/4] Step 3 - Setup_Install_Game.ini (Offset: 0x0092A1D0, Size: 804 bytes, Method: 0)
    [+] Extracted clean payload:       Extracted_Payloads\Step 3 - Setup_Install_Game.ini (804 bytes)

[+] Finished: Successfully extracted 4 of 4 payload files into 'Extracted_Payloads'.
```

### 2. Full Extraction & Inner Archive Unpacking with Detailed Logging (`gof_extractor`)

For deep forensics analysis, real-time un-inversion telemetry, and automatic unpacking of inner `.7z` archives using `decoder.dll`:

```powershell
.\bin\x64\gof_extractor.exe "Step 3 - Setup_Install_Game.exe" -o "Extracted_Payloads" --unzip -l "extraction.log"
```

Features:
- **Timestamped Diagnostic Telemetry**: Logs offsets, signature verification, hex bytes, and throughput speeds.
- **Decoder DLL Integration**: Dynamically binds `decoder.dll` and drives `InitExtraction` / `ExtractAllFiles` to unpack inner archives directly into subfolders.
- **Log Duplication**: Simultaneously logs to standard output with colored levels (`INFO`, `STEP`, `DEBUG`, `TRACE`, `SUCCESS`, `WARN`) and to an output file (`-l <log_file>`).

### 3. Verifying the DLL ABI Exports

Run the automated test suite to verify symbol export resolution:

```cmd
scripts\run_tests.bat
```

Or run the test harness manually against a custom build:

```powershell
.\bin\x64\test_decoder.exe -d .\bin\x64\decoder.dll
.\bin\x86\test_decoder.exe -d .\bin\x86\decoder.dll
```

---

## Building from Source

### Option A: Using the Automated Build Script (Recommended)

Run the included batch script to compile both **x86** and **x64** configurations using MSVC:

```cmd
scripts\build.bat
```

Or using PowerShell:

```powershell
.\scripts\build.ps1 -Arch x64 -Configuration Release
.\scripts\build.ps1 -Arch x86 -Configuration Release
```

### Option B: Using CMake Directly

```powershell
# Configure for x64
cmake -B build/x64 -S . -A x64 -DCMAKE_BUILD_TYPE=Release

# Build all targets
cmake --build build/x64 --config Release

# Run tests
ctest --test-dir build/x64 -C Release --output-on-failure
```

For 32-bit (x86):
```powershell
cmake -B build/x86 -S . -A Win32 -DCMAKE_BUILD_TYPE=Release
cmake --build build/x86 --config Release
```

---

## Documentation

- **[Architecture Deep Dive](docs/ARCHITECTURE.md)**: Container layout, trailer specification, and XOR obfuscation mechanics.
- **[API Reference](docs/API.md)**: Function signatures, return codes, and context structures.
- **[Sample Payloads Guide](samples/README.md)**: Information about reference assets and reverse-engineering artifacts.
- **[বাংলা সংস্করণ (Bengali Report)](docs/README_BN.md)**: ম্যালওয়্যার ফরেনসিক্স এবং রিভার্স ইঞ্জিনিয়ারিং বিশ্লেষণ প্রতিবেদন।

---

## License

This project is licensed under the [MIT License](LICENSE).
