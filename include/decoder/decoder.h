/**
 * @file decoder.h
 * @brief Public interface and data structures for the Advanced Installer / OceanofGames Decoder DLL.
 *
 * This header defines the exact ABI compatibility layer used by SFX installers
 * expecting `decoder.dll` (or `decoder_x86.dll`).
 */

#ifndef DECODER_H
#define DECODER_H

#include <windows.h>
#include "export.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Status and Error Codes returned by Decoder API */
#define DECODER_SUCCESS                 0
#define DECODER_ERR_INVALID_CONTEXT     1
#define DECODER_ERR_ARCHIVE_OPEN_FAILED 2
#define DECODER_ERR_EXTRACTION_FAILED   3

#pragma pack(push, 1)

/**
 * @struct DecoderContext
 * @brief Context structure passed between the installer and decoder.dll.
 *
 * Maintains the file stream handle, archive offsets, extraction target path,
 * and internal decoding state. Must match the exact byte layout expected by
 * Advanced Installer SFX payloads.
 */
typedef struct DecoderContext {
    HANDLE       hFile;              /**< [0x00] Handle to container file / installer executable */
    UINT64       archiveOffset;      /**< [0x08] Byte offset of 7z archive within hFile */
    UINT64       archiveSize;        /**< [0x10] Size in bytes of the archive slice */
    WCHAR        outputDir[260];     /**< [0x18] Target output directory path (Unicode null-terminated) */
    WCHAR       *pOutputDir;         /**< [0x220] Pointer to outputDir */
    void        *pInternalState;     /**< [0x224] Internal decoder state container pointer */
    void        *pProgressCallback;  /**< [0x228] Optional progress callback function */
    void        *pProgressContext;   /**< [0x22C] Optional progress callback user data */
    BYTE         reserved[0x30];     /**< Padding to ensure context buffer >= 0x260 bytes */
} DecoderContext;

#pragma pack(pop)

/**
 * @brief Initializes the extraction session and parses the embedded archive.
 *
 * Locates the 7z decoding engine (7z.dll), binds the stream wrapper around
 * the container file slice at @p ctx->archiveOffset, detects and inverts any
 * obfuscated header bytes, and computes total file size.
 *
 * @param ctx Pointer to an allocated and initialized DecoderContext structure.
 * @return DECODER_SUCCESS (0) on success, or an error code > 0 on failure.
 */
DECODER_API int DECODER_CALL InitExtraction(DecoderContext *ctx);

/**
 * @brief Retrieves the total uncompressed size of all files contained in the archive.
 *
 * @param ctx Pointer to an active DecoderContext initialized with InitExtraction.
 * @return Total uncompressed size in bytes.
 */
DECODER_API UINT64 DECODER_CALL GetTotalFilesSize(DecoderContext *ctx);

/**
 * @brief Extracts all files from the archive to the specified output directory.
 *
 * @param ctx Pointer to an active DecoderContext.
 * @return DECODER_SUCCESS (0) on success, non-zero on failure.
 */
DECODER_API int DECODER_CALL ExtractAllFiles(DecoderContext *ctx);

/**
 * @brief Finalizes the extraction session and frees all allocated resources.
 *
 * Closes the archive, releases stream wrappers, unloads 7z.dll if loaded,
 * and clears internal state allocated on @p ctx.
 *
 * @param ctx Pointer to the DecoderContext to release.
 */
DECODER_API void DECODER_CALL EndExtraction(DecoderContext *ctx);

#ifdef __cplusplus
}
#endif

#endif // DECODER_H
