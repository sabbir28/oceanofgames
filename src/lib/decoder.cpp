#define _CRT_SECURE_NO_WARNINGS
#define DECODER_BUILD_SHARED

#include <windows.h>
#include <ole2.h>
#include <stdio.h>
#include <stdlib.h>
#include "decoder/decoder.h"

#if defined(DECODER_DEBUG) || defined(_DEBUG)
    #define LOG_DEBUG(...) do { printf("[decoder] " __VA_ARGS__); } while(0)
#else
    #define LOG_DEBUG(...) do { } while(0)
#endif

static HINSTANCE g_hModule = NULL;

typedef unsigned int UInt32;
typedef unsigned __int64 UInt64;
typedef __int64 Int64;
typedef int Int32;

// 7-Zip COM Interface definitions
static const GUID CLSID_CFormat7z = 
    { 0x23170F69, 0x40C1, 0x278A, { 0x10, 0x00, 0x00, 0x01, 0x10, 0x07, 0x00, 0x00 } };

static const GUID IID_IInArchive = 
    { 0x23170F69, 0x40C1, 0x278A, { 0x00, 0x00, 0x00, 0x06, 0x00, 0x60, 0x00, 0x00 } };

static const GUID IID_IArchiveExtractCallback = 
    { 0x23170F69, 0x40C1, 0x278A, { 0x00, 0x00, 0x00, 0x06, 0x00, 0x20, 0x00, 0x00 } };

enum {
    kpidPath = 3,
    kpidIsDir = 6,
    kpidSize = 7,
    kpidPosition = 8,
    kpidAttrib = 9,
    kpidEncrypted = 18,
    kpidComment = 19
};

enum {
    kAskExtract = 0,
    kAskTest = 1,
    kAskSkip = 2
};

enum {
    kExtractResultOK = 0,
    kExtractResultUnSupportedMethod = 1,
    kExtractResultDataError = 2,
    kExtractResultCrcError = 3
};

MIDL_INTERFACE("23170F69-40C1-278A-0000-000400010000")
ISequentialInStream : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE Read(void *data, UInt32 size, UInt32 *processedSize) = 0;
};

MIDL_INTERFACE("23170F69-40C1-278A-0000-000400030000")
IInStream : public ISequentialInStream {
    virtual HRESULT STDMETHODCALLTYPE Seek(Int64 offset, UInt32 seekOrigin, UInt64 *newPosition) = 0;
};

MIDL_INTERFACE("23170F69-40C1-278A-0000-000400020000")
ISequentialOutStream : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE Write(const void *data, UInt32 size, UInt32 *processedSize) = 0;
};

MIDL_INTERFACE("23170F69-40C1-278A-0000-000600200000")
IArchiveExtractCallback : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE SetTotal(UInt64 total) = 0;
    virtual HRESULT STDMETHODCALLTYPE SetCompleted(const UInt64 *completeValue) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetStream(UInt32 index, ISequentialOutStream **outStream, Int32 askExtractMode) = 0;
    virtual HRESULT STDMETHODCALLTYPE PrepareOperation(Int32 askExtractMode) = 0;
    virtual HRESULT STDMETHODCALLTYPE SetOperationResult(Int32 resultEOperationResult) = 0;
};

MIDL_INTERFACE("23170F69-40C1-278A-0000-000600600000")
IInArchive : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE Open(IInStream *stream, const UInt64 *maxCheckStartPosition, void *openArchiveCallback) = 0;
    virtual HRESULT STDMETHODCALLTYPE Close() = 0;
    virtual HRESULT STDMETHODCALLTYPE GetNumberOfItems(UInt32 *numItems) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetProperty(UInt32 index, PROPID propID, PROPVARIANT *value) = 0;
    virtual HRESULT STDMETHODCALLTYPE Extract(const UInt32 *indices, UInt32 numItems, Int32 testMode, IArchiveExtractCallback *extractCallback) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetArchiveProperty(PROPID propID, PROPVARIANT *value) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetNumberOfProperties(UInt32 *numProperties) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetPropertyInfo(UInt32 index, BSTR *name, PROPID *propID, VARTYPE *varType) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetNumberOfArchiveProperties(UInt32 *numProperties) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetArchivePropertyInfo(UInt32 index, BSTR *name, PROPID *propID, VARTYPE *varType) = 0;
};

typedef HRESULT (WINAPI *Func_CreateObject)(const GUID *clsID, const GUID *interfaceID, void **outObject);

// ---------------------------------------------------------------------------
// File Stream Implementations
// ---------------------------------------------------------------------------

class CInFileStream : public IInStream {
    LONG m_refCount;
    HANDLE m_hFile;
    UINT64 m_baseOffset;
    UINT64 m_size;
    UINT64 m_curPos;
    bool m_isInverted7z;

public:
    CInFileStream(HANDLE hFile, UINT64 baseOffset, UINT64 size)
        : m_refCount(1), m_hFile(hFile), m_baseOffset(baseOffset), m_size(size), m_curPos(0), m_isInverted7z(false)
    {
        // Detect if the first 32 bytes are bitwise inverted 7z header (0xC8 0x85 0x43 0x50 0xD8 0xE3)
        LARGE_INTEGER li;
        li.QuadPart = (LONGLONG)m_baseOffset;
        if (SetFilePointerEx(m_hFile, li, NULL, FILE_BEGIN)) {
            BYTE hdr[32];
            DWORD readBytes = 0;
            if (ReadFile(m_hFile, hdr, sizeof(hdr), &readBytes, NULL) && readBytes >= 8) {
                if (hdr[0] == 0xC8 && hdr[1] == 0x85 && hdr[2] == 0x43 &&
                    hdr[3] == 0x50 && hdr[4] == 0xD8 && hdr[5] == 0xE3) {
                    m_isInverted7z = true;
                    LOG_DEBUG("Detected obfuscated inverted 7z header signature.\n");
                }
            }
        }
        Seek(0, STREAM_SEEK_SET, NULL);
    }

    virtual ~CInFileStream() {}

    // IUnknown
    STDMETHOD(QueryInterface)(REFIID iid, void **ppv) {
        if (!ppv) return E_POINTER;
        if (iid == IID_IUnknown || iid == __uuidof(ISequentialInStream) || iid == __uuidof(IInStream)) {
            *ppv = static_cast<IInStream*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = NULL;
        return E_NOINTERFACE;
    }

    STDMETHOD_(ULONG, AddRef)() { return InterlockedIncrement(&m_refCount); }
    STDMETHOD_(ULONG, Release)() {
        ULONG count = InterlockedDecrement(&m_refCount);
        if (count == 0) delete this;
        return count;
    }

    // ISequentialInStream
    STDMETHOD(Read)(void *data, UInt32 size, UInt32 *processedSize) {
        if (processedSize) *processedSize = 0;
        if (m_size > 0 && m_curPos >= m_size) {
            LOG_DEBUG("[Stream] EOF at m_curPos=%llu, m_size=%llu\n", m_curPos, m_size);
            return S_OK;
        }

        UInt32 toRead = size;
        if (m_size > 0 && m_curPos + toRead > m_size) {
            toRead = (UInt32)(m_size - m_curPos);
        }

        LARGE_INTEGER li;
        li.QuadPart = (LONGLONG)(m_baseOffset + m_curPos);
        if (!SetFilePointerEx(m_hFile, li, NULL, FILE_BEGIN)) {
            LOG_DEBUG("[Stream] SetFilePointerEx failed pos=%lld, err=%lu\n", li.QuadPart, GetLastError());
            return HRESULT_FROM_WIN32(GetLastError());
        }

        DWORD bytesRead = 0;
        if (!ReadFile(m_hFile, data, toRead, &bytesRead, NULL)) {
            LOG_DEBUG("[Stream] ReadFile failed, err=%lu\n", GetLastError());
            return HRESULT_FROM_WIN32(GetLastError());
        }

        // Bitwise un-invert obfuscated block (first 512 bytes / 0x200 bytes as decoded by FUN_0053aa50)
        if (m_isInverted7z && m_curPos < 512 && bytesRead > 0) {
            BYTE *p = (BYTE*)data;
            for (DWORD i = 0; i < bytesRead && (m_curPos + i) < 512; i++) {
                p[i] ^= 0xFF;
            }
        }

        LOG_DEBUG("[Stream] Read curPos=%llu, toRead=%u, bytesRead=%u\n", m_curPos, toRead, bytesRead);
        m_curPos += bytesRead;
        if (processedSize) *processedSize = bytesRead;
        return S_OK;
    }

    // IInStream
    STDMETHOD(Seek)(Int64 offset, UInt32 seekOrigin, UInt64 *newPosition) {
        Int64 targetPos = 0;
        switch (seekOrigin) {
            case STREAM_SEEK_SET: targetPos = offset; break;
            case STREAM_SEEK_CUR: targetPos = (Int64)m_curPos + offset; break;
            case STREAM_SEEK_END: targetPos = (Int64)m_size + offset; break;
            default: return STG_E_INVALIDFUNCTION;
        }

        if (targetPos < 0) return HRESULT_FROM_WIN32(ERROR_NEGATIVE_SEEK);
        m_curPos = (UINT64)targetPos;
        LOG_DEBUG("[Stream] Seek origin=%u, offset=%lld -> curPos=%llu\n", seekOrigin, offset, m_curPos);
        if (newPosition) *newPosition = m_curPos;
        return S_OK;
    }
};

class COutFileStream : public ISequentialOutStream {
    LONG m_refCount;
    HANDLE m_hFile;

public:
    COutFileStream(HANDLE hFile) : m_refCount(1), m_hFile(hFile) {}
    virtual ~COutFileStream() {
        if (m_hFile != INVALID_HANDLE_VALUE && m_hFile != NULL) {
            CloseHandle(m_hFile);
            m_hFile = INVALID_HANDLE_VALUE;
        }
    }

    STDMETHOD(QueryInterface)(REFIID iid, void **ppv) {
        if (!ppv) return E_POINTER;
        if (iid == IID_IUnknown || iid == __uuidof(ISequentialOutStream)) {
            *ppv = static_cast<ISequentialOutStream*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = NULL;
        return E_NOINTERFACE;
    }

    STDMETHOD_(ULONG, AddRef)() { return InterlockedIncrement(&m_refCount); }
    STDMETHOD_(ULONG, Release)() {
        ULONG count = InterlockedDecrement(&m_refCount);
        if (count == 0) delete this;
        return count;
    }

    STDMETHOD(Write)(const void *data, UInt32 size, UInt32 *processedSize) {
        if (processedSize) *processedSize = 0;
        DWORD bytesWritten = 0;
        if (!WriteFile(m_hFile, data, size, &bytesWritten, NULL)) {
            return HRESULT_FROM_WIN32(GetLastError());
        }
        if (processedSize) *processedSize = bytesWritten;
        return S_OK;
    }
};

// ---------------------------------------------------------------------------
// Extraction Callback Implementation
// ---------------------------------------------------------------------------

class CExtractCallback : public IArchiveExtractCallback {
    LONG m_refCount;
    IInArchive *m_archive;
    WCHAR m_outDir[MAX_PATH];
    COutFileStream *m_curOutStream;

    void CreateDirRecursive(const WCHAR *path) {
        WCHAR temp[MAX_PATH];
        wcsncpy(temp, path, MAX_PATH - 1);
        temp[MAX_PATH - 1] = L'\0';
        size_t len = wcslen(temp);
        if (len > 0 && (temp[len - 1] == L'/' || temp[len - 1] == L'\\')) temp[len - 1] = L'\0';

        for (WCHAR *p = temp + 1; *p; p++) {
            if (*p == L'/' || *p == L'\\') {
                *p = L'\0';
                CreateDirectoryW(temp, NULL);
                *p = L'\\';
            }
        }
        CreateDirectoryW(temp, NULL);
    }

public:
    CExtractCallback(IInArchive *archive, const WCHAR *outDir)
        : m_refCount(1), m_archive(archive), m_curOutStream(NULL)
    {
        wcsncpy(m_outDir, outDir, MAX_PATH - 2);
        m_outDir[MAX_PATH - 2] = L'\0';
        size_t len = wcslen(m_outDir);
        if (len > 0 && m_outDir[len - 1] != L'\\' && m_outDir[len - 1] != L'/') {
            wcscat(m_outDir, L"\\");
        }
        CreateDirRecursive(m_outDir);
    }

    virtual ~CExtractCallback() {
        if (m_curOutStream) {
            m_curOutStream->Release();
            m_curOutStream = NULL;
        }
    }

    STDMETHOD(QueryInterface)(REFIID iid, void **ppv) {
        if (!ppv) return E_POINTER;
        if (iid == IID_IUnknown || iid == IID_IArchiveExtractCallback) {
            *ppv = static_cast<IArchiveExtractCallback*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = NULL;
        return E_NOINTERFACE;
    }

    STDMETHOD_(ULONG, AddRef)() { return InterlockedIncrement(&m_refCount); }
    STDMETHOD_(ULONG, Release)() {
        ULONG count = InterlockedDecrement(&m_refCount);
        if (count == 0) delete this;
        return count;
    }

    STDMETHOD(SetTotal)(UInt64 total) { return S_OK; }
    STDMETHOD(SetCompleted)(const UInt64 *completeValue) { return S_OK; }
    STDMETHOD(PrepareOperation)(Int32 askExtractMode) { return S_OK; }

    STDMETHOD(SetOperationResult)(Int32 resultEOperationResult) {
        LOG_DEBUG("[Callback] SetOperationResult: %d\n", resultEOperationResult);
        if (m_curOutStream) {
            m_curOutStream->Release();
            m_curOutStream = NULL;
        }
        return (resultEOperationResult == kExtractResultOK) ? S_OK : E_FAIL;
    }

    STDMETHOD(GetStream)(UInt32 index, ISequentialOutStream **outStream, Int32 askExtractMode) {
        LOG_DEBUG("[Callback] GetStream index=%u, askExtractMode=%d\n", index, askExtractMode);
        if (!outStream) return E_POINTER;
        *outStream = NULL;

        if (askExtractMode != kAskExtract) return S_OK;

        PROPVARIANT propPath;
        PropVariantInit(&propPath);
        PROPVARIANT propIsDir;
        PropVariantInit(&propIsDir);

        m_archive->GetProperty(index, kpidPath, &propPath);
        m_archive->GetProperty(index, kpidIsDir, &propIsDir);

        bool isDir = (propIsDir.vt == VT_BOOL && propIsDir.boolVal != VARIANT_FALSE);
        const WCHAR *relPath = (propPath.vt == VT_BSTR) ? propPath.bstrVal : L"";
        LOG_DEBUG("[Callback] Item: relPath='%ls', isDir=%d\n", relPath, (int)isDir);

        WCHAR fullPath[MAX_PATH];
        _snwprintf(fullPath, MAX_PATH, L"%s%s", m_outDir, relPath);
        fullPath[MAX_PATH - 1] = L'\0';

        if (isDir) {
            CreateDirRecursive(fullPath);
            PropVariantClear(&propPath);
            PropVariantClear(&propIsDir);
            return S_OK;
        }

        // Ensure parent directory exists
        WCHAR parentDir[MAX_PATH];
        wcsncpy(parentDir, fullPath, MAX_PATH - 1);
        parentDir[MAX_PATH - 1] = L'\0';
        WCHAR *pSlash = wcsrchr(parentDir, L'\\');
        if (!pSlash) pSlash = wcsrchr(parentDir, L'/');
        if (pSlash) {
            *pSlash = L'\0';
            CreateDirRecursive(parentDir);
        }

        HANDLE hOutFile = CreateFileW(fullPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hOutFile == INVALID_HANDLE_VALUE) {
            LOG_DEBUG("[Callback] Failed to create %ls, err=%lu\n", fullPath, GetLastError());
            PropVariantClear(&propPath);
            PropVariantClear(&propIsDir);
            return HRESULT_FROM_WIN32(GetLastError());
        }

        m_curOutStream = new COutFileStream(hOutFile);
        *outStream = m_curOutStream;
        (*outStream)->AddRef();

        PropVariantClear(&propPath);
        PropVariantClear(&propIsDir);
        return S_OK;
    }
};

// ---------------------------------------------------------------------------
// Decoder Internal State Container
// ---------------------------------------------------------------------------

struct InternalState {
    HMODULE        h7zDll;
    IInArchive    *pArchive;
    CInFileStream *pInStream;
    UINT64         totalFilesSize;
    WCHAR          outDir[MAX_PATH];
};

static HMODULE Load7zDll() {
    // 1. Try directory next to current decoder.dll module
    if (g_hModule) {
        WCHAR modPath[MAX_PATH];
        if (GetModuleFileNameW(g_hModule, modPath, MAX_PATH)) {
            WCHAR *lastSlash = wcsrchr(modPath, L'\\');
            if (lastSlash) {
                *(lastSlash + 1) = L'\0';
                wcscat(modPath, L"7z.dll");
                HMODULE h = LoadLibraryW(modPath);
                if (h) return h;
            }
        }
    }

    // 2. Try current working directory
    HMODULE h = LoadLibraryA("7z.dll");
    if (h) return h;

    // 3. Try standard 64-bit and 32-bit 7-Zip installation paths
    h = LoadLibraryA("C:\\Program Files\\7-Zip\\7z.dll");
    if (h) return h;

    h = LoadLibraryA("C:\\Program Files (x86)\\7-Zip\\7z.dll");
    if (h) return h;

    return NULL;
}

// ---------------------------------------------------------------------------
// Exported API Functions
// ---------------------------------------------------------------------------

extern "C" {

DECODER_API int DECODER_CALL InitExtraction(DecoderContext *ctx) {
    if (!ctx || ctx->hFile == INVALID_HANDLE_VALUE || ctx->hFile == NULL) {
        return DECODER_ERR_INVALID_CONTEXT;
    }

    HMODULE h7z = Load7zDll();
    if (!h7z) {
        return DECODER_ERR_INVALID_CONTEXT;
    }

    Func_CreateObject createObj = (Func_CreateObject)GetProcAddress(h7z, "CreateObject");
    if (!createObj) {
        FreeLibrary(h7z);
        return DECODER_ERR_INVALID_CONTEXT;
    }

    IInArchive *archive = NULL;
    HRESULT hr = createObj(&CLSID_CFormat7z, &IID_IInArchive, (void**)&archive);
    if (FAILED(hr) || !archive) {
        FreeLibrary(h7z);
        return DECODER_ERR_ARCHIVE_OPEN_FAILED;
    }

    CInFileStream *inStream = new CInFileStream(ctx->hFile, ctx->archiveOffset, ctx->archiveSize);
    UInt64 maxCheck = 0x100000; // Scan up to 1 MB like original Decoder.dll
    hr = archive->Open(inStream, &maxCheck, NULL);
    if (FAILED(hr)) {
        inStream->Release();
        archive->Release();
        FreeLibrary(h7z);
        return DECODER_ERR_ARCHIVE_OPEN_FAILED;
    }

    InternalState *state = new InternalState();
    state->h7zDll = h7z;
    state->pArchive = archive;
    state->pInStream = inStream;
    state->totalFilesSize = 0;

    const WCHAR *dest = (ctx->pOutputDir && ctx->pOutputDir[0]) ? ctx->pOutputDir : ctx->outputDir;
    wcsncpy(state->outDir, dest, MAX_PATH - 1);
    state->outDir[MAX_PATH - 1] = L'\0';

    // Calculate total uncompressed size of all files
    UInt32 numItems = 0;
    if (SUCCEEDED(archive->GetNumberOfItems(&numItems))) {
        for (UInt32 i = 0; i < numItems; i++) {
            PROPVARIANT propIsDir, propSize;
            PropVariantInit(&propIsDir);
            PropVariantInit(&propSize);
            archive->GetProperty(i, kpidIsDir, &propIsDir);
            archive->GetProperty(i, kpidSize, &propSize);

            bool isDir = (propIsDir.vt == VT_BOOL && propIsDir.boolVal != VARIANT_FALSE);
            if (!isDir && propSize.vt == VT_UI8) {
                state->totalFilesSize += propSize.uhVal.QuadPart;
            }
            PropVariantClear(&propIsDir);
            PropVariantClear(&propSize);
        }
    }

    ctx->pInternalState = state;
    return DECODER_SUCCESS;
}

DECODER_API UINT64 DECODER_CALL GetTotalFilesSize(DecoderContext *ctx) {
    if (!ctx || !ctx->pInternalState) return 0;
    InternalState *state = (InternalState*)ctx->pInternalState;
    return state->totalFilesSize;
}

DECODER_API int DECODER_CALL ExtractAllFiles(DecoderContext *ctx) {
    if (!ctx || !ctx->pInternalState) return DECODER_ERR_INVALID_CONTEXT;
    InternalState *state = (InternalState*)ctx->pInternalState;
    if (!state->pArchive) return DECODER_ERR_INVALID_CONTEXT;

    CExtractCallback *callback = new CExtractCallback(state->pArchive, state->outDir);
    HRESULT hr = state->pArchive->Extract(NULL, (UInt32)-1, 0, callback);
    LOG_DEBUG("Extract returned hr=0x%08lX\n", hr);
    callback->Release();

    return SUCCEEDED(hr) ? DECODER_SUCCESS : DECODER_ERR_EXTRACTION_FAILED;
}

DECODER_API void DECODER_CALL EndExtraction(DecoderContext *ctx) {
    if (!ctx || !ctx->pInternalState) return;
    InternalState *state = (InternalState*)ctx->pInternalState;

    if (state->pArchive) {
        state->pArchive->Close();
        state->pArchive->Release();
        state->pArchive = NULL;
    }
    if (state->pInStream) {
        state->pInStream->Release();
        state->pInStream = NULL;
    }
    if (state->h7zDll) {
        FreeLibrary(state->h7zDll);
        state->h7zDll = NULL;
    }

    delete state;
    ctx->pInternalState = NULL;
}

} // extern "C"

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        g_hModule = hinstDLL;
        DisableThreadLibraryCalls(hinstDLL);
    }
    return TRUE;
}
