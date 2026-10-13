# Decoder C/C++ API Reference

The `decoder.dll` exports a lightweight C interface for embedding into installers and extraction utilities.

## Header Inclusion

```c
#include "decoder/decoder.h"
```

---

## Data Structures

### `DecoderContext`

```c
typedef struct DecoderContext {
    HANDLE       hFile;
    UINT64       archiveOffset;
    UINT64       archiveSize;
    WCHAR        outputDir[260];
    WCHAR       *pOutputDir;
    void        *pInternalState;
    void        *pProgressCallback;
    void        *pProgressContext;
    BYTE         reserved[0x30];
} DecoderContext;
```

#### Fields:
- `hFile`: Open `HANDLE` to the container PE executable (`GENERIC_READ` and `FILE_SHARE_READ`).
- `archiveOffset`: 64-bit byte offset where the embedded archive slice starts.
- `archiveSize`: Size in bytes of the archive data stream.
- `outputDir`: Destination directory buffer (null-terminated Unicode string).
- `pOutputDir`: Pointer to `outputDir` (or an alternate target buffer).
- `pInternalState`: Opaque pointer managed by `decoder.dll` (set to `NULL` before initialization).
- `pProgressCallback`: Reserved for progress reporting function.
- `pProgressContext`: User data passed to progress callback.

---

## Status and Error Codes

```c
#define DECODER_SUCCESS                 0
#define DECODER_ERR_INVALID_CONTEXT     1
#define DECODER_ERR_ARCHIVE_OPEN_FAILED 2
#define DECODER_ERR_EXTRACTION_FAILED   3
```

---

## API Functions

### `InitExtraction`

```c
DECODER_API int DECODER_CALL InitExtraction(DecoderContext *ctx);
```

Initializes an extraction session:
1. Validates `ctx` and open `ctx->hFile`.
2. Locates and loads `7z.dll`.
3. Creates a `CInFileStream` spanning `[archiveOffset .. archiveOffset + archiveSize]`.
4. Inspects header bytes for XOR inversion and transparently reverses it.
5. Invokes 7-Zip's `IInArchive::Open`.
6. Queries archive item count and uncompressed byte size.

**Returns:**
- `0`: Initialization succeeded.
- `1`: Invalid context parameters or failed to locate `7z.dll`.
- `2`: Archive signature verification or `Open()` call failed.

---

### `GetTotalFilesSize`

```c
DECODER_API UINT64 DECODER_CALL GetTotalFilesSize(DecoderContext *ctx);
```

Computes and returns the sum of uncompressed sizes of all non-directory items in the archive.

**Returns:**
- Total uncompressed size in bytes, or `0` if context is uninitialized.

---

### `ExtractAllFiles`

```c
DECODER_API int DECODER_CALL ExtractAllFiles(DecoderContext *ctx);
```

Extracts all items in the archive into the folder specified by `ctx->outputDir` (or `ctx->pOutputDir`). Directory hierarchies are created automatically.

**Returns:**
- `0`: Extraction completed successfully.
- `1`: Invalid context or uninitialized state.
- `3`: Extraction failed (corrupted block or write failure).

---

### `EndExtraction`

```c
DECODER_API void DECODER_CALL EndExtraction(DecoderContext *ctx);
```

Closes the archive, frees COM streams, unloads `7z.dll`, and frees `ctx->pInternalState`.

---

## Integration Example

```c
#include <windows.h>
#include <stdio.h>
#include "decoder/decoder.h"

int main(void) {
    HANDLE hFile = CreateFileA("installer.exe", GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 1;

    DecoderContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.hFile = hFile;
    ctx.archiveOffset = 0x88EF1A;
    ctx.archiveSize = 635574;
    wcscpy(ctx.outputDir, L"C:\\extracted_files\\");
    ctx.pOutputDir = ctx.outputDir;

    if (InitExtraction(&ctx) == DECODER_SUCCESS) {
        UINT64 totalBytes = GetTotalFilesSize(&ctx);
        printf("Total uncompressed size: %llu bytes\n", totalBytes);

        if (ExtractAllFiles(&ctx) == DECODER_SUCCESS) {
            printf("Extraction completed successfully!\n");
        }
        EndExtraction(&ctx);
    }

    CloseHandle(hFile);
    return 0;
}
```
