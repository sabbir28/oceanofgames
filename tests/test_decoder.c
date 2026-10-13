/**
 * @file test_decoder.c
 * @brief Integration Test Harness for decoder.dll ABI and extraction engine.
 */

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "decoder/decoder.h"

typedef int    (DECODER_CALL *fnInitExtraction)(DecoderContext *ctx);
typedef UINT64 (DECODER_CALL *fnGetTotalFilesSize)(DecoderContext *ctx);
typedef int    (DECODER_CALL *fnExtractAllFiles)(DecoderContext *ctx);
typedef void   (DECODER_CALL *fnEndExtraction)(DecoderContext *ctx);

static void PrintUsage(const char *progName) {
    printf("Usage:\n");
    printf("  %s [options]\n\n", progName);
    printf("Options:\n");
    printf("  -d, --dll <path>       Path to decoder.dll (default: decoder.dll)\n");
    printf("  -f, --file <path>      Path to container / installer .exe\n");
    printf("  -o, --offset <offset>  Archive byte offset in hex or decimal (e.g. 0x88EF1A)\n");
    printf("  -s, --size <bytes>     Archive byte size (e.g. 635574)\n");
    printf("  -t, --target <dir>     Output directory for extracted files (default: test_output)\n");
    printf("  -h, --help             Show this help screen\n");
}

int main(int argc, char *argv[]) {
    printf("====================================================\n");
    printf(" Decoder Test Harness - Verification Suite          \n");
    printf("====================================================\n\n");

    const char *dllPath = "decoder.dll";
    const char *targetFile = NULL;
    UINT64 offset = 0;
    UINT64 size   = 0;
    const char *outDirStr = "test_output";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            PrintUsage(argv[0]);
            return 0;
        } else if ((strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--dll") == 0) && i + 1 < argc) {
            dllPath = argv[++i];
        } else if ((strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--file") == 0) && i + 1 < argc) {
            targetFile = argv[++i];
        } else if ((strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--offset") == 0) && i + 1 < argc) {
            offset = _strtoui64(argv[++i], NULL, 0);
        } else if ((strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--size") == 0) && i + 1 < argc) {
            size = _strtoui64(argv[++i], NULL, 0);
        } else if ((strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--target") == 0) && i + 1 < argc) {
            outDirStr = argv[++i];
        }
    }

    printf("[1/3] Loading Decoder DLL: %s\n", dllPath);
    HMODULE hDll = LoadLibraryA(dllPath);
    if (!hDll) {
        // Fallback search in bin directories
        char fallbackPath[MAX_PATH];
        snprintf(fallbackPath, sizeof(fallbackPath), "bin\\x64\\%s", dllPath);
        hDll = LoadLibraryA(fallbackPath);
        if (hDll) {
            printf("[+] Found DLL in fallback path: %s\n", fallbackPath);
            dllPath = fallbackPath;
        } else {
            fprintf(stderr, "[-] Failed to load %s (Win32 Error: %lu)\n", dllPath, GetLastError());
            return 1;
        }
    }
    printf("[+] Successfully loaded library: %s\n", dllPath);

    printf("[2/3] Resolving ABI export addresses...\n");
    fnInitExtraction    InitExt   = (fnInitExtraction)GetProcAddress(hDll, "InitExtraction");
    fnGetTotalFilesSize GetTotal  = (fnGetTotalFilesSize)GetProcAddress(hDll, "GetTotalFilesSize");
    fnExtractAllFiles   Extract   = (fnExtractAllFiles)GetProcAddress(hDll, "ExtractAllFiles");
    fnEndExtraction     EndExt    = (fnEndExtraction)GetProcAddress(hDll, "EndExtraction");

    if (!InitExt || !GetTotal || !Extract || !EndExt) {
        fprintf(stderr, "[-] ABI verification failed: Missing required exports!\n");
        fprintf(stderr, "    InitExtraction:    %p\n", InitExt);
        fprintf(stderr, "    GetTotalFilesSize: %p\n", GetTotal);
        fprintf(stderr, "    ExtractAllFiles:   %p\n", Extract);
        fprintf(stderr, "    EndExtraction:     %p\n", EndExt);
        FreeLibrary(hDll);
        return 1;
    }
    printf("[+] All 4 ABI exports successfully resolved!\n");
    printf("    -> InitExtraction:    0x%p\n", (void*)InitExt);
    printf("    -> GetTotalFilesSize: 0x%p\n", (void*)GetTotal);
    printf("    -> ExtractAllFiles:   0x%p\n", (void*)Extract);
    printf("    -> EndExtraction:     0x%p\n", (void*)EndExt);

    if (!targetFile) {
        printf("\n[*] No container file specified with -f. Export ABI test PASSED.\n");
        printf("    To run full archive extraction test, supply: -f <file> -o <offset> -s <size>\n");
        FreeLibrary(hDll);
        return 0;
    }

    printf("\n[3/3] Executing extraction workflow on container...\n");
    HANDLE hFile = CreateFileA(targetFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[-] Failed to open container file: %s (Error: %lu)\n", targetFile, GetLastError());
        FreeLibrary(hDll);
        return 1;
    }
    printf("[+] Opened container file: %s\n", targetFile);
    printf("[*] Target slice: offset 0x%I64X, size %I64u bytes\n", offset, size);

    WCHAR wOutDir[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, outDirStr, -1, wOutDir, MAX_PATH);
    CreateDirectoryW(wOutDir, NULL);

    DecoderContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.hFile = hFile;
    ctx.archiveOffset = offset;
    ctx.archiveSize = size;
    wcsncpy(ctx.outputDir, wOutDir, 259);
    ctx.pOutputDir = ctx.outputDir;

    printf("[*] Calling InitExtraction(&ctx)...\n");
    int resInit = InitExt(&ctx);
    printf("[+] InitExtraction result: %d\n", resInit);
    if (resInit != 0) {
        fprintf(stderr, "[-] InitExtraction failed with error code %d\n", resInit);
        CloseHandle(hFile);
        FreeLibrary(hDll);
        return 1;
    }

    UINT64 totalSize = GetTotal(&ctx);
    printf("[+] Total uncompressed size: %I64u bytes (%.2f MB)\n", totalSize, (double)totalSize / (1024.0 * 1024.0));

    printf("[*] Calling ExtractAllFiles(&ctx)...\n");
    int resExtract = Extract(&ctx);
    printf("[+] ExtractAllFiles result: %d\n", resExtract);

    printf("[*] Calling EndExtraction(&ctx)...\n");
    EndExt(&ctx);
    printf("[+] EndExtraction finished.\n");

    CloseHandle(hFile);
    FreeLibrary(hDll);

    if (resExtract == 0) {
        printf("\n[+] Integration test SUCCEEDED.\n");
        return 0;
    } else {
        fprintf(stderr, "\n[-] Extraction returned failure code %d.\n", resExtract);
        return 2;
    }
}
