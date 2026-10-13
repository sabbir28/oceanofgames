@echo off
setlocal

echo ===================================================================
echo  OceanofGames Decoder - Running Verification Tests
echo ===================================================================

set TEST_EXE=bin\x64\test_decoder.exe
if not exist %TEST_EXE% (
    set TEST_EXE=build\x64\bin\Release\test_decoder.exe
)

if not exist %TEST_EXE% (
    echo [-] Error: Test binary not found. Please build the project first.
    exit /b 1
)

echo [*] Testing ABI Exports via %TEST_EXE%...
%TEST_EXE%
if errorlevel 1 (
    echo [-] ABI test failed!
    exit /b 1
)

echo.
echo [+] All tests completed successfully!
endlocal
