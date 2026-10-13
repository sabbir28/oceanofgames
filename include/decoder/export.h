/**
 * @file export.h
 * @brief Macro definitions for DLL symbol export and import visibility.
 */

#ifndef DECODER_EXPORT_H
#define DECODER_EXPORT_H

#if defined(_WIN32) || defined(__CYGWIN__)
    #if defined(DECODER_BUILD_SHARED)
        #define DECODER_API __declspec(dllexport)
    #elif defined(DECODER_USE_SHARED)
        #define DECODER_API __declspec(dllimport)
    #else
        #define DECODER_API
    #endif
    #define DECODER_CALL __cdecl
#else
    #if defined(DECODER_BUILD_SHARED) && defined(__GNUC__) && __GNUC__ >= 4
        #define DECODER_API __attribute__((visibility("default")))
    #else
        #define DECODER_API
    #endif
    #define DECODER_CALL
#endif

#endif // DECODER_EXPORT_H
