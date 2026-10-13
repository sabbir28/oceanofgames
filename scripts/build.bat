@echo off
setlocal enabledelayedexpansion

echo ===================================================================
echo  OceanofGames Decoder - MSVC Direct Build System (x86 and x64)
echo ===================================================================

set "VS_PATH=C:\Program Files\Microsoft Visual Studio\18\Community"
set "VCVARS=%VS_PATH%\VC\Auxiliary\Build\vcvarsall.bat"

if not exist "%VCVARS%" (
    echo [-] Error: vcvarsall.bat not found at "%VCVARS%"
    exit /b 1
)

for %%I in ("%~dp0..") do set "ROOT_DIR=%%~fI"

set "SRC_LIB=%ROOT_DIR%\src\lib"
set "SRC_TOOLS=%ROOT_DIR%\src\tools"
set "SRC_TESTS=%ROOT_DIR%\tests"
set "INC_DIR=%ROOT_DIR%\include"
set "BIN_X86=%ROOT_DIR%\bin\x86"
set "BIN_X64=%ROOT_DIR%\bin\x64"
set "OBJ_X86=%ROOT_DIR%\build\obj\x86"
set "OBJ_X64=%ROOT_DIR%\build\obj\x64"

if not exist "%BIN_X86%" mkdir "%BIN_X86%"
if not exist "%BIN_X64%" mkdir "%BIN_X64%"
if not exist "%OBJ_X86%" mkdir "%OBJ_X86%"
if not exist "%OBJ_X64%" mkdir "%OBJ_X64%"

:: =====================================================================
:: 1. Build x86 (32-bit) Targets
:: =====================================================================
echo.
echo [*] Initializing MSVC x86 build environment...
call "%VCVARS%" x86 >nul 2>&1
if errorlevel 1 (
    echo [-] Failed to initialize x86 environment.
    exit /b 1
)

echo [*] Compiling x86 decoder.dll...
cl.exe /nologo /O2 /EHsc /LD /I"%INC_DIR%" ^
    "%SRC_LIB%\decoder.cpp" /DEF:"%SRC_LIB%\decoder.def" ^
    /Fe:"%BIN_X86%\decoder.dll" /Fo:"%OBJ_X86%\decoder.obj" ^
    ole32.lib oleaut32.lib user32.lib
if errorlevel 1 (
    echo [-] x86 decoder.dll compilation failed!
    exit /b 1
)
echo [+] Built: %BIN_X86%\decoder.dll

echo [*] Compiling x86 test_decoder.exe...
cl.exe /nologo /O2 /I"%INC_DIR%" ^
    "%SRC_TESTS%\test_decoder.c" ^
    /Fe:"%BIN_X86%\test_decoder.exe" /Fo:"%OBJ_X86%\test_decoder.obj"
if errorlevel 1 (
    echo [-] x86 test_decoder.exe compilation failed!
    exit /b 1
)
echo [+] Built: %BIN_X86%\test_decoder.exe

echo [*] Compiling x86 standalone_extractor.exe...
cl.exe /nologo /O2 /I"%INC_DIR%" ^
    "%SRC_TOOLS%\standalone_extractor.c" ^
    /Fe:"%BIN_X86%\standalone_extractor.exe" /Fo:"%OBJ_X86%\standalone_extractor.obj"
if errorlevel 1 (
    echo [-] x86 standalone_extractor.exe compilation failed!
    exit /b 1
)
echo [+] Built: %BIN_X86%\standalone_extractor.exe

echo [*] Compiling x86 gof_extractor.exe...
cl.exe /nologo /O2 /I"%INC_DIR%" ^
    "%SRC_TOOLS%\gof_extractor.c" ^
    /Fe:"%BIN_X86%\gof_extractor.exe" /Fo:"%OBJ_X86%\gof_extractor.obj"
if errorlevel 1 (
    echo [-] x86 gof_extractor.exe compilation failed!
    exit /b 1
)
echo [+] Built: %BIN_X86%\gof_extractor.exe

:: =====================================================================
:: 2. Build x64 (64-bit) Targets
:: =====================================================================
echo.
echo [*] Initializing MSVC x64 build environment...
call "%VCVARS%" x64 >nul 2>&1
if errorlevel 1 (
    echo [-] Failed to initialize x64 environment.
    exit /b 1
)

echo [*] Compiling x64 decoder.dll...
cl.exe /nologo /O2 /EHsc /LD /I"%INC_DIR%" ^
    "%SRC_LIB%\decoder.cpp" /DEF:"%SRC_LIB%\decoder.def" ^
    /Fe:"%BIN_X64%\decoder.dll" /Fo:"%OBJ_X64%\decoder.obj" ^
    ole32.lib oleaut32.lib user32.lib
if errorlevel 1 (
    echo [-] x64 decoder.dll compilation failed!
    exit /b 1
)
echo [+] Built: %BIN_X64%\decoder.dll

echo [*] Compiling x64 test_decoder.exe...
cl.exe /nologo /O2 /I"%INC_DIR%" ^
    "%SRC_TESTS%\test_decoder.c" ^
    /Fe:"%BIN_X64%\test_decoder.exe" /Fo:"%OBJ_X64%\test_decoder.obj"
if errorlevel 1 (
    echo [-] x64 test_decoder.exe compilation failed!
    exit /b 1
)
echo [+] Built: %BIN_X64%\test_decoder.exe

echo [*] Compiling x64 standalone_extractor.exe...
cl.exe /nologo /O2 /I"%INC_DIR%" ^
    "%SRC_TOOLS%\standalone_extractor.c" ^
    /Fe:"%BIN_X64%\standalone_extractor.exe" /Fo:"%OBJ_X64%\standalone_extractor.obj"
if errorlevel 1 (
    echo [-] x64 standalone_extractor.exe compilation failed!
    exit /b 1
)
echo [+] Built: %BIN_X64%\standalone_extractor.exe

echo [*] Compiling x64 gof_extractor.exe...
cl.exe /nologo /O2 /I"%INC_DIR%" ^
    "%SRC_TOOLS%\gof_extractor.c" ^
    /Fe:"%BIN_X64%\gof_extractor.exe" /Fo:"%OBJ_X64%\gof_extractor.obj"
if errorlevel 1 (
    echo [-] x64 gof_extractor.exe compilation failed!
    exit /b 1
)
echo [+] Built: %BIN_X64%\gof_extractor.exe

:: Optional: Copy 64-bit 7z.dll next to x64 output if available
if exist "C:\Program Files\7-Zip\7z.dll" (
    copy /Y "C:\Program Files\7-Zip\7z.dll" "%BIN_X64%\7z.dll" >nul
    echo [+] Copied C:\Program Files\7-Zip\7z.dll to %BIN_X64%\7z.dll
)

:: Clean up link .exp and .lib from bin if not needed, or keep .lib
del /q "%BIN_X86%\*.exp" "%BIN_X64%\*.exp" >nul 2>&1

echo.
echo ===================================================================
echo  BUILD COMPLETE!
echo  x86 Binaries: %BIN_X86%
echo  x64 Binaries: %BIN_X64%
echo ===================================================================
endlocal
