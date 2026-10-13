# OceanofGames / Advanced Installer SFX Decoder Architecture

## 1. Overview

This project provides a complete reverse-engineered implementation and toolchain for decoding, unpacking, and extracting obfuscated 7-Zip payload archives embedded inside **Advanced Installer SFX** (Self-Extracting Executable) containers commonly distributed by OceanofGames and similar packaging systems.

It consists of two complementary components:
1. **`decoder.dll`**: A dynamic link library re-implementing the exact ABI exported by the proprietary `decoder.dll` used by SFX stub installers (`InitExtraction`, `GetTotalFilesSize`, `ExtractAllFiles`, `EndExtraction`).
2. **`standalone_extractor.exe`**: A self-contained CLI tool that parses SFX container trailers and table-of-contents directly, de-obfuscates embedded archives on the fly, and extracts clean, standard 7-Zip archives without requiring external dependencies.

---

## 2. ADVINSTSFX Container Layout

Advanced Installer packages append payload archives directly to the end of a PE executable stub. The overall binary layout is structured as follows:

```
+-------------------------------------------------------------+
| PE Executable Stub (Installer UI & Runner)                  |
+-------------------------------------------------------------+
| Embedded Archive #1 (e.g., decoder.dll)                     |
+-------------------------------------------------------------+
| Embedded Archive #2 (e.g., FILES.7z) [Obfuscated]           |
+-------------------------------------------------------------+
| Embedded Archive #3 (e.g., Payload.7z) [Obfuscated]         |
+-------------------------------------------------------------+
| Embedded Archive #4 (e.g., Setup.ini)                       |
+-------------------------------------------------------------+
| File Table of Contents (Entries with name, size, offset)    |
+-------------------------------------------------------------+
| SFX Trailer (Contains signature "ADVINSTSFX" & TOC offset)  |
+-------------------------------------------------------------+
```

### 2.1 The SFX Trailer

The trailing 512 bytes of the container contain the `SFXTrailer` structure, terminated by the ASCII signature `ADVINSTSFX`:

```c
#pragma pack(push, 1)
typedef struct {
    DWORD table_end_offset;       // Offset where table of contents ends
    DWORD num_files;              // Total number of embedded files
    DWORD flags;                  // Container flags
    DWORD table_end_offset2;      // Redundant table end offset
    DWORD table_start_offset;     // File offset where TOC begins
    DWORD archive_start_offset;   // File offset of first embedded archive
    char  hash[32];               // Integrity hash
    DWORD trailer_size;           // Size of the trailer block
    char  signature[10];          // ASCII "ADVINSTSFX"
} SFXTrailer;
#pragma pack(pop)
```

### 2.2 Table of Contents & File Entries

At `table_start_offset`, an array of `num_files` entries is stored. Each entry begins with a 24-byte header followed by a UTF-16LE filename:

```c
#pragma pack(push, 1)
typedef struct {
    DWORD magic_or_flags;   // Flags
    DWORD unk1;             // Internal metadata
    DWORD method;           // Compression / obfuscation method:
                            //   0 = Plain / uncompressed
                            //   2 = Obfuscated inverted 7z
    DWORD size;             // Size of file stream in bytes
    DWORD offset;           // Absolute offset of stream within PE file
    DWORD name_len;         // Number of UTF-16 characters in filename
} SFXFileEntryHeader;
#pragma pack(pop)
```

Immediately following `SFXFileEntryHeader`, `name_len * sizeof(WCHAR)` bytes encode the relative output path (e.g., `326FA02\FILES.7z`).

---

## 3. XOR Obfuscation Mechanism

When `method == 2`, the embedded 7z archive is intentionally obfuscated to prevent standard archive utilities (7-Zip, WinRAR) and antivirus heuristic scanners from detecting the payload.

### Obfuscation Signature

Standard 7-Zip archives begin with the magic bytes:
`37 7A BC AF 27 1C` (`'7' 'z' 0xBC 0xAF 0x27 0x1C`)

The obfuscated archive stores the bitwise inverted (`XOR 0xFF`) representation of the first **512 bytes (`0x200`)**:
```
Original:    37 7A BC AF 27 1C ...
Inverted:    C8 85 43 50 D8 E3 ...
```

### De-obfuscation Routine (Ghidra `FUN_0053aa50`)

Reverse engineering of the stream filter object (`FUN_0053aa50` at offset `0x00518e2c`) established that the obfuscation is exactly `0x200` (512) bytes long. Inverting only 32 bytes causes LZMA2 decompression failures ("Data Error"). Inverting the entire 512-byte block restores the archive completely:

1. Check if bytes `[0..5]` match `C8 85 43 50 D8 E3`.
2. Apply `byte ^= 0xFF` to the first **512 bytes** of the stream.
3. Stream the remaining bytes un-inverted.

```c
if (isInverted7z && isFirstBlock) {
    size_t bytesToInvert = (bytesRead < 512) ? bytesRead : 512;
    for (size_t i = 0; i < bytesToInvert; i++) {
        buffer[i] ^= 0xFF; // Restore valid 7z header & compressed stream block
    }
    isFirstBlock = 0;
}
```

---

## 4. `decoder.dll` ABI & Interception Layer

The custom `decoder.dll` operates as an in-memory virtual file system bridge between the installer executable and `7z.dll` COM interfaces.

```
+--------------------------------------------------------------+
|                    Installer Executable                      |
+--------------------------------------------------------------+
                               |
                               | Calls InitExtraction(DecoderContext*)
                               v
+--------------------------------------------------------------+
|                        decoder.dll                           |
|  - Manages DecoderContext state                              |
|  - Instantiates CInFileStream virtual 7z reader              |
|  - Un-inverts obfuscated header dynamically during Read()    |
|  - Implements IArchiveExtractCallback for file writing       |
+--------------------------------------------------------------+
                               |
                               | Loads COM interfaces via CreateObject
                               v
+--------------------------------------------------------------+
|                          7z.dll                              |
|  - IInArchive: Parses 7z tables and LZMA/LZMA2 streams       |
+--------------------------------------------------------------+
```

### 4.1 `DecoderContext` Memory Layout

The installer allocates a 0x260-byte structure (`DecoderContext`) on its stack or heap and passes it by pointer:

```c
#pragma pack(push, 1)
typedef struct DecoderContext {
    HANDLE       hFile;              // [0x00] Open handle to container PE file
    UINT64       archiveOffset;      // [0x08] Byte offset of 7z archive in hFile
    UINT64       archiveSize;        // [0x10] Size in bytes of the archive slice
    WCHAR        outputDir[260];     // [0x18] Target output directory path (Unicode)
    WCHAR       *pOutputDir;         // [0x220] Pointer to outputDir
    void        *pInternalState;     // [0x224] Decoder internal state pointer
    void        *pProgressCallback;  // [0x228] Optional progress callback
    void        *pProgressContext;   // [0x22C] Optional progress user context
    BYTE         reserved[0x30];     // [0x230] Reserved padding to >= 0x260
} DecoderContext;
#pragma pack(pop)
```

### 4.2 Exported ABI Functions

All functions use the `__cdecl` calling convention and plain C undecorated names:

| Export | Signature | Description |
|---|---|---|
| `InitExtraction` | `int (DecoderContext *ctx)` | Opens archive slice, inverts header, reads item count |
| `GetTotalFilesSize` | `UINT64 (DecoderContext *ctx)` | Returns sum of all uncompressed item sizes |
| `ExtractAllFiles` | `int (DecoderContext *ctx)` | Extracts all files in archive to target folder |
| `EndExtraction` | `void (DecoderContext *ctx)` | Closes archive, releases streams, cleans state |
