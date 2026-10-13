/**
 * @file gof_extractor.c
 * @brief GOF Advanced SFX Container Extractor & Decoder DLL Integration Engine.
 *
 * Fully unpacks Advanced Installer SFX containers, safely de-obfuscates embedded
 * 7-Zip payload streams, loads and drives decoder.dll to unpack inner archives,
 * and emits extensive diagnostic and forensics telemetry logs.
 */

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "decoder/decoder.h"

#define ADVINSTSFX_SIG         "ADVINSTSFX"
#define ADVINSTSFX_SIG_LEN     10
#define BUFFER_CHUNK_SIZE      65536
#define MAX_LOG_LINE           2048

/* Global logging options */
static int   g_verbose = 1;
static FILE *g_logFile = NULL;

/* Color constants for Windows Console */
#define COLOR_RESET   7
#define COLOR_RED     12
#define COLOR_GREEN   10
#define COLOR_YELLOW  14
#define COLOR_CYAN    11
#define COLOR_MAGENTA 13
#define COLOR_GRAY    8
#define COLOR_WHITE   15

static void SetConsoleColor(WORD color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

/* Precise Timestamped Logging Helper */
static void LogMsg(WORD color, const char *level, const char *fmt, ...) {
    SYSTEMTIME st;
    GetLocalTime(&st);

    char timeBuf[64];
    snprintf(timeBuf, sizeof(timeBuf), "[%04d-%02d-%02d %02d:%02d:%02d.%03d]",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    char msgBuf[MAX_LOG_LINE];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msgBuf, sizeof(msgBuf), fmt, args);
    va_end(args);

    // Print to console with color
    SetConsoleColor(COLOR_GRAY);
    printf("%s ", timeBuf);
    SetConsoleColor(color);
    printf("[%s] ", level);
    SetConsoleColor(COLOR_RESET);
    printf("%s\n", msgBuf);

    // Also write to log file if enabled
    if (g_logFile) {
        fprintf(g_logFile, "%s [%s] %s\n", timeBuf, level, msgBuf);
        fflush(g_logFile);
    }
}

#define LOG_INFO(...)    LogMsg(COLOR_CYAN,    "INFO",    __VA_ARGS__)
#define LOG_SUCCESS(...) LogMsg(COLOR_GREEN,   "SUCCESS", __VA_ARGS__)
#define LOG_WARN(...)    LogMsg(COLOR_YELLOW,  "WARN",    __VA_ARGS__)
#define LOG_ERROR(...)   LogMsg(COLOR_RED,     "ERROR",   __VA_ARGS__)
#define LOG_DEBUG(...)   do { if (g_verbose) LogMsg(COLOR_GRAY, "DEBUG", __VA_ARGS__); } while(0)
#define LOG_TRACE(...)   do { if (g_verbose) LogMsg(COLOR_MAGENTA, "TRACE", __VA_ARGS__); } while(0)
#define LOG_STEP(...)    LogMsg(COLOR_WHITE,   "STEP",    __VA_ARGS__)

#pragma pack(push, 1)

typedef struct {
    DWORD magic_or_flags;   // 0x00
    DWORD unk1;             // 0x04
    DWORD method;           // 0x08: 0 = plain, 2 = obfuscated 7z
    DWORD size;             // 0x0C: File size in bytes
    DWORD offset;           // 0x10: File offset in executable
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

typedef int    (DECODER_CALL *fnInitExtraction)(DecoderContext *ctx);
typedef UINT64 (DECODER_CALL *fnGetTotalFilesSize)(DecoderContext *ctx);
typedef int    (DECODER_CALL *fnExtractAllFiles)(DecoderContext *ctx);
typedef void   (DECODER_CALL *fnEndExtraction)(DecoderContext *ctx);

typedef struct {
    HMODULE             hDll;
    char                dllPath[MAX_PATH];
    fnInitExtraction    InitExt;
    fnGetTotalFilesSize GetTotal;
    fnExtractAllFiles   ExtractAll;
    fnEndExtraction     EndExt;
} DecoderDllEngine;

static void PrintBanner(void) {
    SetConsoleColor(COLOR_CYAN);
    printf("===============================================================================\n");
    printf(" GOF Advanced SFX Container Extractor & Decoder DLL Integration Engine        \n");
    printf(" Reverse-Engineering & Forensics Unpacker with Extensive Diagnostic Telemetry  \n");
    printf("===============================================================================\n\n");
    SetConsoleColor(COLOR_RESET);
}

static void PrintUsage(const char *progName) {
    printf("Usage:\n");
    printf("  %s <path_to_installer.exe> [options]\n\n", progName);
    printf("Options:\n");
    printf("  -o, --output <dir>     Output directory for extracted payloads (default: Extracted_Payloads)\n");
    printf("  -d, --dll <path>       Custom path to decoder.dll (auto-discovered if omitted)\n");
    printf("  -u, --unzip            Unpack extracted .7z archives using decoder.dll (default: enabled)\n");
    printf("      --no-unzip         Extract raw payloads only; skip inner 7z unzipping\n");
    printf("  -l, --log <file>       Write execution logs to a file\n");
    printf("  -q, --quiet            Disable verbose debug output\n");
    printf("  -h, --help             Show this help screen\n\n");
    printf("Example:\n");
    printf("  %s \"Step 3 - Setup_Install_Game.exe\" -o \"Extracted\" --unzip -l \"extraction.log\"\n\n", progName);
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

/* Dynamically locate and bind decoder.dll */
static int LoadDecoderDllEngine(DecoderDllEngine *engine, const char *userDllPath, const char *outDir) {
    memset(engine, 0, sizeof(DecoderDllEngine));

    const char *candidatePaths[8];
    int numCandidates = 0;

    if (userDllPath && userDllPath[0]) {
        candidatePaths[numCandidates++] = userDllPath;
    }

    char outDirDll[MAX_PATH];
    snprintf(outDirDll, sizeof(outDirDll), "%s\\decoder.dll", outDir);
    candidatePaths[numCandidates++] = outDirDll;

    candidatePaths[numCandidates++] = "decoder.dll";
    candidatePaths[numCandidates++] = "bin\\x64\\decoder.dll";
    candidatePaths[numCandidates++] = "bin\\x86\\decoder.dll";
    candidatePaths[numCandidates++] = "..\\bin\\x64\\decoder.dll";
    candidatePaths[numCandidates++] = "samples\\payloads\\original_installer_decoder.dll";

    LOG_DEBUG("Searching for compatible decoder.dll engine...");
    for (int i = 0; i < numCandidates; i++) {
        const char *cand = candidatePaths[i];
        LOG_TRACE("Testing candidate DLL path: %s", cand);
        HMODULE h = LoadLibraryA(cand);
        if (h) {
            strncpy(engine->dllPath, cand, sizeof(engine->dllPath) - 1);
            engine->hDll = h;
            LOG_INFO("Successfully loaded DLL module: %s (HMODULE: 0x%p)", cand, (void*)h);
            break;
        }
    }

    if (!engine->hDll) {
        LOG_WARN("Could not load decoder.dll automatically. DLL unpacking step will be skipped.");
        return 0;
    }

    engine->InitExt    = (fnInitExtraction)GetProcAddress(engine->hDll, "InitExtraction");
    engine->GetTotal   = (fnGetTotalFilesSize)GetProcAddress(engine->hDll, "GetTotalFilesSize");
    engine->ExtractAll = (fnExtractAllFiles)GetProcAddress(engine->hDll, "ExtractAllFiles");
    engine->EndExt     = (fnEndExtraction)GetProcAddress(engine->hDll, "EndExtraction");

    LOG_DEBUG("Resolving export symbols from %s:", engine->dllPath);
    LOG_DEBUG("  -> InitExtraction:    0x%p", (void*)engine->InitExt);
    LOG_DEBUG("  -> GetTotalFilesSize: 0x%p", (void*)engine->GetTotal);
    LOG_DEBUG("  -> ExtractAllFiles:   0x%p", (void*)engine->ExtractAll);
    LOG_DEBUG("  -> EndExtraction:     0x%p", (void*)engine->EndExt);

    if (!engine->InitExt || !engine->ExtractAll || !engine->EndExt) {
        LOG_WARN("DLL %s is missing required exports (Init=%p, Extract=%p, End=%p)",
                 engine->dllPath, engine->InitExt, engine->ExtractAll, engine->EndExt);
        FreeLibrary(engine->hDll);
        engine->hDll = NULL;
        return 0;
    }

    LOG_SUCCESS("Decoder DLL engine successfully initialized and verified!");
    return 1;
}

static void FreeDecoderDllEngine(DecoderDllEngine *engine) {
    if (engine && engine->hDll) {
        LOG_DEBUG("Unloading Decoder DLL engine (0x%p)", (void*)engine->hDll);
        FreeLibrary(engine->hDll);
        engine->hDll = NULL;
    }
}

/* Extract raw payload entry from container */
static int ExtractEntry(FILE *fIn, DWORD offset, DWORD size, DWORD method, const char *outPath, int *outIsInverted7z) {
    *outIsInverted7z = 0;

    char parentDir[MAX_PATH];
    strncpy(parentDir, outPath, sizeof(parentDir) - 1);
    parentDir[sizeof(parentDir) - 1] = '\0';
    char *lastSlash = strrchr(parentDir, '\\');
    if (!lastSlash) lastSlash = strrchr(parentDir, '/');
    if (lastSlash) {
        *lastSlash = '\0';
        CreateDirRecursive(parentDir);
    }

    LOG_DEBUG("Opening output destination: %s", outPath);
    FILE *fOut = fopen(outPath, "wb");
    if (!fOut) {
        LOG_ERROR("Failed to create destination file: %s", outPath);
        return 0;
    }

    LOG_TRACE("Seeking input stream to container offset: 0x%08X (%u bytes)", offset, offset);
    if (fseek(fIn, offset, SEEK_SET) != 0) {
        LOG_ERROR("Failed to seek to offset 0x%08X in container", offset);
        fclose(fOut);
        return 0;
    }

    // Inspect first 32 bytes for bitwise-inverted 7z signature
    BYTE header[32];
    size_t headerRead = fread(header, 1, sizeof(header), fIn);
    fseek(fIn, offset, SEEK_SET);

    int isInverted7z = 0;
    if (headerRead >= 8) {
        LOG_TRACE("Examining header bytes [0..7]: %02X %02X %02X %02X %02X %02X %02X %02X",
                  header[0], header[1], header[2], header[3],
                  header[4], header[5], header[6], header[7]);

        if (header[0] == 0xC8 && header[1] == 0x85 &&
            header[2] == 0x43 && header[3] == 0x50 &&
            header[4] == 0xD8 && header[5] == 0xE3) {
            isInverted7z = 1;
            *outIsInverted7z = 1;
            LOG_INFO("Detected obfuscated inverted 7z header (0xC8 0x85 0x43 0x50 0xD8 0xE3)");
            LOG_INFO("Initiating real-time bitwise XOR 0xFF un-inversion on first 512 bytes (Ghidra FUN_0053aa50)...");
        } else if (header[0] == 0x37 && header[1] == 0x7A &&
                   header[2] == 0xBC && header[3] == 0xAF &&
                   header[4] == 0x27 && header[5] == 0x1C) {
            LOG_INFO("Payload already possesses standard 7z magic signature (7z\\xBC\\xAF\\x27\\x1C)");
        }
    }

    BYTE buffer[BUFFER_CHUNK_SIZE];
    DWORD remaining = size;
    int isFirstBlock = 1;
    DWORD totalWritten = 0;

    clock_t startClock = clock();

    while (remaining > 0) {
        DWORD toRead = (remaining < sizeof(buffer)) ? remaining : (DWORD)sizeof(buffer);
        size_t bytesRead = fread(buffer, 1, toRead, fIn);
        if (bytesRead == 0) {
            LOG_WARN("Premature EOF encountered at %u of %u bytes", totalWritten, size);
            break;
        }

        if (isInverted7z && isFirstBlock) {
            size_t bytesToInvert = (bytesRead < 512) ? bytesRead : 512;
            for (size_t b = 0; b < bytesToInvert; b++) {
                buffer[b] ^= 0xFF;
            }
            LOG_DEBUG("Successfully inverted %zu signature bytes back to valid 7z stream", bytesToInvert);
            LOG_TRACE("Restored header bytes [0..5]: %c%c \\x%02X \\x%02X \\x%02X \\x%02X",
                      buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5]);
            isFirstBlock = 0;
        }

        fwrite(buffer, 1, bytesRead, fOut);
        totalWritten += (DWORD)bytesRead;
        remaining -= (DWORD)bytesRead;
    }

    fclose(fOut);

    clock_t endClock = clock();
    double elapsedSec = (double)(endClock - startClock) / CLOCKS_PER_SEC;
    double mbSec = (elapsedSec > 0.001) ? ((double)totalWritten / (1024.0 * 1024.0)) / elapsedSec : 0.0;

    if (isInverted7z) {
        LOG_SUCCESS("Decoded obfuscated archive -> %s (%u bytes, %.2f MB/s)", outPath, totalWritten, mbSec);
    } else {
        LOG_SUCCESS("Extracted clean payload      -> %s (%u bytes, %.2f MB/s)", outPath, totalWritten, mbSec);
    }

    return (totalWritten == size);
}

/* Unzip an archive using the loaded decoder.dll engine */
static int UnpackArchiveWithDll(DecoderDllEngine *engine, const char *containerExePath,
                                DWORD archiveOffset, DWORD archiveSize, const char *targetUnpackDir) {
    if (!engine || !engine->hDll || !engine->InitExt) {
        LOG_WARN("Cannot unpack archive via DLL: Engine not loaded.");
        return 0;
    }

    LOG_STEP("Engaging decoder.dll engine to unpack archive slice (Offset: 0x%08X, Size: %u bytes)...",
             archiveOffset, archiveSize);
    LOG_INFO("Destination directory: %s", targetUnpackDir);

    CreateDirRecursive(targetUnpackDir);

    HANDLE hFile = CreateFileA(containerExePath, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LOG_ERROR("Failed to open container file '%s' for DLL extraction (Win32 Error: %lu)",
                  containerExePath, GetLastError());
        return 0;
    }

    WCHAR wOutDir[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, targetUnpackDir, -1, wOutDir, MAX_PATH);

    DecoderContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.hFile = hFile;
    ctx.archiveOffset = (UINT64)archiveOffset;
    ctx.archiveSize = (UINT64)archiveSize;
    wcsncpy(ctx.outputDir, wOutDir, 258);
    size_t len = wcslen(ctx.outputDir);
    if (len > 0 && ctx.outputDir[len - 1] != L'\\' && ctx.outputDir[len - 1] != L'/') {
        wcscat(ctx.outputDir, L"\\");
    }
    ctx.pOutputDir = ctx.outputDir;

    LOG_DEBUG("Calling InitExtraction(&ctx) [hFile=%p, Offset=0x%I64X, Size=%I64u]...",
              ctx.hFile, ctx.archiveOffset, ctx.archiveSize);

    int initRes = engine->InitExt(&ctx);
    LOG_DEBUG("InitExtraction returned code: %d", initRes);

    if (initRes != DECODER_SUCCESS) {
        LOG_WARN("InitExtraction returned non-zero code %d", initRes);
        CloseHandle(hFile);
        return 0;
    }

    if (engine->GetTotal) {
        UINT64 totalUncompBytes = engine->GetTotal(&ctx);
        LOG_INFO("Total uncompressed payload size reported by archive: %I64u bytes (%.2f MB)",
                 totalUncompBytes, (double)totalUncompBytes / (1024.0 * 1024.0));
    }

    LOG_STEP("Calling ExtractAllFiles(&ctx) to unpack all items...");
    int extRes = engine->ExtractAll(&ctx);
    LOG_DEBUG("ExtractAllFiles returned code: %d", extRes);

    LOG_DEBUG("Calling EndExtraction(&ctx)...");
    engine->EndExt(&ctx);
    CloseHandle(hFile);

    if (extRes == DECODER_SUCCESS) {
        LOG_SUCCESS("All files from archive successfully unpacked into '%s'!", targetUnpackDir);
        return 1;
    } else {
        LOG_WARN("ExtractAllFiles reported code %d for this archive slice.", extRes);
        return 0;
    }
}

int main(int argc, char *argv[]) {
    PrintBanner();

    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }

    const char *exePath = NULL;
    char outDir[MAX_PATH] = "Extracted_Payloads";
    char customDllPath[MAX_PATH] = "";
    char logFilePath[MAX_PATH] = "";
    int enableUnzip = 1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            PrintUsage(argv[0]);
            return 0;
        } else if ((strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) && i + 1 < argc) {
            strncpy(outDir, argv[++i], sizeof(outDir) - 1);
            outDir[sizeof(outDir) - 1] = '\0';
        } else if ((strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--dll") == 0) && i + 1 < argc) {
            strncpy(customDllPath, argv[++i], sizeof(customDllPath) - 1);
            customDllPath[sizeof(customDllPath) - 1] = '\0';
        } else if ((strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--log") == 0) && i + 1 < argc) {
            strncpy(logFilePath, argv[++i], sizeof(logFilePath) - 1);
            logFilePath[sizeof(logFilePath) - 1] = '\0';
        } else if (strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--unzip") == 0) {
            enableUnzip = 1;
        } else if (strcmp(argv[i], "--no-unzip") == 0) {
            enableUnzip = 0;
        } else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0) {
            g_verbose = 0;
        } else if (argv[i][0] != '-') {
            exePath = argv[i];
        }
    }

    if (!exePath) {
        LOG_ERROR("No input installer executable specified.");
        PrintUsage(argv[0]);
        return 1;
    }

    if (logFilePath[0]) {
        g_logFile = fopen(logFilePath, "w");
        if (g_logFile) {
            LOG_INFO("Logging initialized. Output will be duplicated to: %s", logFilePath);
        } else {
            LOG_WARN("Could not create log file: %s", logFilePath);
        }
    }

    LOG_STEP("Starting extraction workflow for target container: %s", exePath);

    FILE *fIn = fopen(exePath, "rb");
    if (!fIn) {
        LOG_ERROR("Cannot open target file: %s (Check path or permissions)", exePath);
        if (g_logFile) fclose(g_logFile);
        return 1;
    }

    fseek(fIn, 0, SEEK_END);
    long fileSize = ftell(fIn);
    LOG_INFO("File opened successfully. Total container size: %ld bytes (%.2f MB)",
             fileSize, (double)fileSize / (1024.0 * 1024.0));

    if (fileSize < 256) {
        LOG_ERROR("File size (%ld bytes) is smaller than minimum required header size.", fileSize);
        fclose(fIn);
        if (g_logFile) fclose(g_logFile);
        return 1;
    }

    // Search trailing 512 bytes for ADVINSTSFX signature
    long searchStart = (fileSize > 512) ? (fileSize - 512) : 0;
    LOG_TRACE("Scanning container tail (offset 0x%08lX to 0x%08lX) for '%s' signature...",
              searchStart, fileSize, ADVINSTSFX_SIG);

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
        LOG_ERROR("Container signature '%s' not found! This executable is not an Advanced Installer SFX package.",
                  ADVINSTSFX_SIG);
        fclose(fIn);
        if (g_logFile) fclose(g_logFile);
        return 1;
    }

    long sigFileOffset = searchStart + sigOffsetInBuf;
    LOG_SUCCESS("Located '%s' signature at file offset: 0x%08lX", ADVINSTSFX_SIG, sigFileOffset);

    long trailerOffset = sigFileOffset - (sizeof(SFXTrailer) - ADVINSTSFX_SIG_LEN);
    LOG_DEBUG("Calculated SFXTrailer start offset: 0x%08lX (%ld bytes)", trailerOffset, sizeof(SFXTrailer));
    fseek(fIn, trailerOffset, SEEK_SET);

    SFXTrailer trailer;
    if (fread(&trailer, 1, sizeof(SFXTrailer), fIn) != sizeof(SFXTrailer)) {
        LOG_ERROR("Failed reading SFXTrailer structure at offset 0x%08lX", trailerOffset);
        fclose(fIn);
        if (g_logFile) fclose(g_logFile);
        return 1;
    }

    LOG_INFO("Trailer Verification:");
    LOG_INFO("  -> Archive Start Offset: 0x%08X", trailer.archive_start_offset);
    LOG_INFO("  -> TOC Table Start:      0x%08X", trailer.table_start_offset);
    LOG_INFO("  -> TOC Table End:        0x%08X", trailer.table_end_offset);
    LOG_INFO("  -> Total Files Stored:   %u", trailer.num_files);
    LOG_INFO("  -> Trailer Block Size:   %u bytes", trailer.trailer_size);
    LOG_INFO("  -> Output Base Directory:%s", outDir);

    CreateDirRecursive(outDir);

    // Track 7z payload entries for optional DLL unpacking
    typedef struct {
        char  relPath[MAX_PATH];
        char  fullPath[MAX_PATH];
        DWORD offset;
        DWORD size;
        DWORD method;
        int   isInverted7z;
    } ExtractedPayload;

    ExtractedPayload *payloadList = (ExtractedPayload*)malloc(sizeof(ExtractedPayload) * trailer.num_files);
    DWORD extractedCount = 0;

    fseek(fIn, trailer.table_start_offset, SEEK_SET);

    LOG_STEP("Iterating and extracting %u embedded table entries...", trailer.num_files);

    for (DWORD i = 0; i < trailer.num_files; i++) {
        SFXFileEntryHeader entryHdr;
        if (fread(&entryHdr, 1, sizeof(entryHdr), fIn) != sizeof(entryHdr)) {
            LOG_ERROR("Failed to read header for file entry #%u", i + 1);
            break;
        }

        if (entryHdr.name_len == 0 || entryHdr.name_len > MAX_PATH) {
            LOG_ERROR("Invalid filename length (%u) encountered in entry #%u", entryHdr.name_len, i + 1);
            break;
        }

        WCHAR wFileName[MAX_PATH];
        DWORD charsToRead = (entryHdr.name_len < MAX_PATH - 1) ? entryHdr.name_len : (MAX_PATH - 1);
        if (fread(wFileName, sizeof(WCHAR), charsToRead, fIn) != charsToRead) {
            LOG_ERROR("Failed reading filename characters for entry #%u", i + 1);
            break;
        }
        wFileName[charsToRead] = L'\0';

        char relPath[MAX_PATH];
        WideCharToMultiByte(CP_UTF8, 0, wFileName, -1, relPath, sizeof(relPath), NULL, NULL);

        char fullOutPath[MAX_PATH];
        snprintf(fullOutPath, sizeof(fullOutPath), "%s\\%s", outDir, relPath);

        LOG_INFO("[%u/%u] Payload: %s", i + 1, trailer.num_files, relPath);
        LOG_INFO("       Offset: 0x%08X | Size: %u bytes (%.2f KB) | Method: %u",
                 entryHdr.offset, entryHdr.size, (double)entryHdr.size / 1024.0, entryHdr.method);

        long savePos = ftell(fIn);
        int isInverted = 0;
        if (ExtractEntry(fIn, entryHdr.offset, entryHdr.size, entryHdr.method, fullOutPath, &isInverted)) {
            strncpy(payloadList[extractedCount].relPath, relPath, MAX_PATH - 1);
            strncpy(payloadList[extractedCount].fullPath, fullOutPath, MAX_PATH - 1);
            payloadList[extractedCount].offset = entryHdr.offset;
            payloadList[extractedCount].size = entryHdr.size;
            payloadList[extractedCount].method = entryHdr.method;
            payloadList[extractedCount].isInverted7z = isInverted;
            extractedCount++;
        }
        fseek(fIn, savePos, SEEK_SET);
    }

    fclose(fIn);

    LOG_SUCCESS("Raw extraction complete: Successfully extracted %u of %u payloads into '%s'.",
                extractedCount, trailer.num_files, outDir);

    // =========================================================================
    // Optional Inner DLL Unpacking Phase
    // =========================================================================
    if (enableUnzip) {
        LOG_STEP("Starting secondary unpacking phase (driving decoder.dll to unpack archives)...");

        DecoderDllEngine engine;
        int engineReady = LoadDecoderDllEngine(&engine, customDllPath, outDir);

        if (engineReady) {
            DWORD unzippedArchives = 0;

            for (DWORD p = 0; p < extractedCount; p++) {
                const char *pPath = payloadList[p].relPath;
                size_t pLen = strlen(pPath);

                // Unpack any file ending in .7z or marked with method 2
                if ((pLen > 3 && _stricmp(pPath + pLen - 3, ".7z") == 0) || payloadList[p].method == 2) {
                    char unpackFolder[MAX_PATH];
                    snprintf(unpackFolder, sizeof(unpackFolder), "%s\\unpacked_%u", outDir, p + 1);

                    LOG_INFO("Found compressed archive payload: %s", pPath);
                    LOG_INFO("Target folder for unpacked contents: %s", unpackFolder);

                    if (UnpackArchiveWithDll(&engine, exePath, payloadList[p].offset, payloadList[p].size, unpackFolder)) {
                        unzippedArchives++;
                    }
                }
            }

            LOG_SUCCESS("Secondary archive unpacking finished: %u archives processed via decoder.dll.",
                        unzippedArchives);
            FreeDecoderDllEngine(&engine);
        } else {
            LOG_WARN("Skipping secondary unpacking: decoder.dll engine could not be bound.");
        }
    } else {
        LOG_INFO("Secondary archive unpacking skipped as requested (--no-unzip).");
    }

    free(payloadList);

    printf("\n===============================================================================\n");
    SetConsoleColor(COLOR_GREEN);
    printf("[+] ALL OPERATIONS FINISHED SUCCESSFULLY!\n");
    SetConsoleColor(COLOR_RESET);
    printf("    Target output directory: %s\n", outDir);
    if (logFilePath[0]) {
        printf("    Diagnostic telemetry log: %s\n", logFilePath);
    }
    printf("===============================================================================\n");

    if (g_logFile) {
        fclose(g_logFile);
        g_logFile = NULL;
    }

    return 0;
}
