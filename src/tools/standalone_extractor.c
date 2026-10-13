/**
 * @file standalone_extractor.c
 * @brief Standalone SFX Decoder & Extractor for Advanced Installer SFX containers.
 *
 * Directly parses the ADVINSTSFX trailer, reads embedded table-of-contents,
 * detects obfuscated / inverted 7z streams, and extracts clean payload archives.
 */

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ADVINSTSFX_SIG     "ADVINSTSFX"
#define ADVINSTSFX_SIG_LEN 10
#define BUFFER_CHUNK_SIZE  65536

#pragma pack(push, 1)

typedef struct {
    DWORD magic_or_flags;   // 0x00
    DWORD unk1;             // 0x04
    DWORD method;           // 0x08: 0 = plain, 2 = obfuscated 7z
    DWORD size;             // 0x0C: File size in bytes
    DWORD offset;           // 0x10: File offset in container executable
    DWORD name_len;         // 0x14: Length of Unicode filename (characters)
} SFXFileEntryHeader;

typedef struct {
    DWORD table_end_offset;
    DWORD num_files;
    DWORD flags;
    DWORD table_end_offset2;
    DWORD table_start_offset;
    DWORD archive_start_offset;
    char  hash[32];
    DWORD trailer_size;
    char  signature[10];    // "ADVINSTSFX"
} SFXTrailer;

#pragma pack(pop)

static void PrintBanner(void) {
    printf("===================================================================\n");
    printf(" ADVINST SFX Container Extractor & Decoder                         \n");
    printf(" Decodes obfuscated Advanced Installer 7z streams & payloads       \n");
    printf("===================================================================\n\n");
}

static void PrintUsage(const char *progName) {
    printf("Usage:\n");
    printf("  %s <installer_path> [options]\n\n", progName);
    printf("Options:\n");
    printf("  -o, --output <dir>    Set output extraction folder (default: Extracted_Payloads)\n");
    printf("  -v, --verbose         Enable detailed stream decoding logs\n");
    printf("  -h, --help            Show this help manual\n\n");
    printf("Example:\n");
    printf("  %s \"Step 3 - Setup_Install_Game.exe\" -o \"output_folder\"\n", progName);
}

static void CreateDirRecursive(const char *dirPath) {
    char temp[MAX_PATH];
    strncpy(temp, dirPath, sizeof(temp) - 1);
    temp[sizeof(temp) - 1] = '\0';
    size_t len = strlen(temp);
    if (len > 0 && (temp[len - 1] == '/' || temp[len - 1] == '\\')) {
        temp[len - 1] = '\0';
    }

    for (char *p = temp + 1; *p; p++) {
        if (*p == '/' || *p == '\\') {
            *p = '\0';
            CreateDirectoryA(temp, NULL);
            *p = '\\';
        }
    }
    CreateDirectoryA(temp, NULL);
}

static int ExtractEntry(FILE *fIn, DWORD offset, DWORD size, DWORD method, const char *outPath, int verbose) {
    char parentDir[MAX_PATH];
    strncpy(parentDir, outPath, sizeof(parentDir) - 1);
    parentDir[sizeof(parentDir) - 1] = '\0';
    char *lastSlash = strrchr(parentDir, '\\');
    if (!lastSlash) lastSlash = strrchr(parentDir, '/');
    if (lastSlash) {
        *lastSlash = '\0';
        CreateDirRecursive(parentDir);
    }

    FILE *fOut = fopen(outPath, "wb");
    if (!fOut) {
        fprintf(stderr, "[-] Failed to create output file: %s\n", outPath);
        return 0;
    }

    if (fseek(fIn, offset, SEEK_SET) != 0) {
        fprintf(stderr, "[-] Failed to seek to offset 0x%08X\n", offset);
        fclose(fOut);
        return 0;
    }

    // Check for bitwise-inverted 7z header (0xC8 0x85 0x43 0x50 0xD8 0xE3)
    BYTE header[32];
    size_t headerRead = fread(header, 1, sizeof(header), fIn);
    fseek(fIn, offset, SEEK_SET);

    int isInverted7z = 0;
    if (headerRead >= 8 &&
        header[0] == 0xC8 && header[1] == 0x85 &&
        header[2] == 0x43 && header[3] == 0x50 &&
        header[4] == 0xD8 && header[5] == 0xE3) {
        isInverted7z = 1;
    }

    BYTE buffer[BUFFER_CHUNK_SIZE];
    DWORD remaining = size;
    int isFirstBlock = 1;

    while (remaining > 0) {
        DWORD toRead = (remaining < sizeof(buffer)) ? remaining : (DWORD)sizeof(buffer);
        size_t bytesRead = fread(buffer, 1, toRead, fIn);
        if (bytesRead == 0) break;

        if (isInverted7z && isFirstBlock) {
            size_t bytesToInvert = (bytesRead < 512) ? bytesRead : 512;
            for (size_t i = 0; i < bytesToInvert; i++) {
                buffer[i] ^= 0xFF; // Invert first 512 bytes (0x200) to restore clean 7z stream
            }
            isFirstBlock = 0;
        }

        fwrite(buffer, 1, bytesRead, fOut);
        remaining -= (DWORD)bytesRead;
    }

    fclose(fOut);

    if (isInverted7z) {
        printf("    [+] Decoded obfuscated 7z archive: %s (%u bytes)\n", outPath, size);
    } else {
        printf("    [+] Extracted clean payload:       %s (%u bytes)\n", outPath, size);
    }
    return 1;
}

int main(int argc, char *argv[]) {
    PrintBanner();

    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }

    const char *exePath = NULL;
    char outDir[MAX_PATH] = "Extracted_Payloads";
    int verbose = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            PrintUsage(argv[0]);
            return 0;
        } else if ((strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) && i + 1 < argc) {
            strncpy(outDir, argv[++i], sizeof(outDir) - 1);
            outDir[sizeof(outDir) - 1] = '\0';
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        } else if (argv[i][0] != '-') {
            exePath = argv[i];
        }
    }

    if (!exePath) {
        fprintf(stderr, "[-] Error: No input file specified.\n");
        PrintUsage(argv[0]);
        return 1;
    }

    FILE *fIn = fopen(exePath, "rb");
    if (!fIn) {
        fprintf(stderr, "[-] Error: Cannot open file: %s\n", exePath);
        return 1;
    }

    fseek(fIn, 0, SEEK_END);
    long fileSize = ftell(fIn);
    if (fileSize < 256) {
        fprintf(stderr, "[-] Error: File too small.\n");
        fclose(fIn);
        return 1;
    }

    // Search for ADVINSTSFX trailer signature in trailing 512 bytes
    long searchStart = (fileSize > 512) ? (fileSize - 512) : 0;
    fseek(fIn, searchStart, SEEK_SET);
    BYTE tailBuf[512];
    size_t tailRead = fread(tailBuf, 1, sizeof(tailBuf), fIn);

    long sigOffsetInBuf = -1;
    for (size_t i = 0; i + ADVINSTSFX_SIG_LEN <= tailRead; i++) {
        if (memcmp(tailBuf + i, ADVINSTSFX_SIG, ADVINSTSFX_SIG_LEN) == 0) {
            sigOffsetInBuf = (long)i;
            break;
        }
    }

    if (sigOffsetInBuf < 0) {
        fprintf(stderr, "[-] Error: 'ADVINSTSFX' trailer signature not found in %s\n", exePath);
        fclose(fIn);
        return 1;
    }

    long sigFileOffset = searchStart + sigOffsetInBuf;
    long trailerOffset = sigFileOffset - (sizeof(SFXTrailer) - ADVINSTSFX_SIG_LEN);
    fseek(fIn, trailerOffset, SEEK_SET);

    SFXTrailer trailer;
    if (fread(&trailer, 1, sizeof(SFXTrailer), fIn) != sizeof(SFXTrailer)) {
        fprintf(stderr, "[-] Error reading SFX trailer structure.\n");
        fclose(fIn);
        return 1;
    }

    printf("[+] Target Container:   %s (%ld bytes)\n", exePath, fileSize);
    printf("[+] SFX Archive Start:  0x%08X\n", trailer.archive_start_offset);
    printf("[+] File Table Offset:  0x%08X\n", trailer.table_start_offset);
    printf("[+] Total Stored Files: %u\n", trailer.num_files);
    printf("[+] Output Directory:   %s\n\n", outDir);

    CreateDirRecursive(outDir);

    fseek(fIn, trailer.table_start_offset, SEEK_SET);
    DWORD extractedCount = 0;

    for (DWORD i = 0; i < trailer.num_files; i++) {
        SFXFileEntryHeader entry;
        if (fread(&entry, 1, sizeof(SFXFileEntryHeader), fIn) != sizeof(SFXFileEntryHeader)) {
            fprintf(stderr, "[-] Failed reading file entry header #%u\n", i);
            break;
        }

        WCHAR wFileName[MAX_PATH];
        DWORD charsToRead = (entry.name_len < MAX_PATH - 1) ? entry.name_len : (MAX_PATH - 1);
        if (fread(wFileName, sizeof(WCHAR), charsToRead, fIn) != charsToRead) {
            fprintf(stderr, "[-] Failed reading filename #%u\n", i);
            break;
        }
        wFileName[charsToRead] = L'\0';

        char relPath[MAX_PATH];
        WideCharToMultiByte(CP_UTF8, 0, wFileName, -1, relPath, sizeof(relPath), NULL, NULL);

        char outFilePath[MAX_PATH];
        snprintf(outFilePath, sizeof(outFilePath), "%s\\%s", outDir, relPath);

        printf("[%u/%u] %s (Offset: 0x%08X, Size: %u bytes, Method: %u)\n",
               i + 1, trailer.num_files, relPath, entry.offset, entry.size, entry.method);

        long savePos = ftell(fIn);
        if (ExtractEntry(fIn, entry.offset, entry.size, entry.method, outFilePath, verbose)) {
            extractedCount++;
        }
        fseek(fIn, savePos, SEEK_SET);
    }

    fclose(fIn);

    printf("\n[+] Finished: Successfully extracted %u of %u payload files into '%s'.\n",
           extractedCount, trailer.num_files, outDir);
    return (extractedCount == trailer.num_files) ? 0 : 2;
}
