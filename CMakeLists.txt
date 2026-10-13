cmake_minimum_required(VERSION 3.15)
project(OceanofGamesDecoder VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Default output locations for compiled binaries
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Multi-configuration generator output support (e.g. Debug/Release subfolders)
foreach(OUTPUTCONFIG ${CMAKE_CONFIGURATION_TYPES})
    string(TOUPPER ${OUTPUTCONFIG} OUTPUTCONFIG)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${OUTPUTCONFIG} ${CMAKE_BINARY_DIR}/bin)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${OUTPUTCONFIG} ${CMAKE_BINARY_DIR}/bin)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${OUTPUTCONFIG} ${CMAKE_BINARY_DIR}/lib)
endforeach()

option(DECODER_ENABLE_DEBUG_LOGS "Enable verbose console logging inside decoder.dll" OFF)
option(BUILD_TESTING "Build the test verification suite" ON)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

add_subdirectory(src/lib)
add_subdirectory(src/tools)

if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()

# Installation & Packaging Rules
install(TARGETS decoder standalone_extractor gof_extractor
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION bin
    ARCHIVE DESTINATION lib
)

install(DIRECTORY include/ DESTINATION include)

# CPack packaging configuration
set(CPACK_PACKAGE_NAME "oceanofgames-decoder")
set(CPACK_PACKAGE_VENDOR "sabbir28")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Reverse-engineered ABI decoder library and safe extraction toolchain")
set(CPACK_PACKAGE_VERSION "1.0.0")
set(CPACK_GENERATOR "ZIP")
include(CPack)
