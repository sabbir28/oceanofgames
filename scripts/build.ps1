<#
.SYNOPSIS
    Builds the OceanofGames Decoder project for x64 or x86.
.PARAMETER Arch
    Target architecture (x64 or x86). Default: x64
.PARAMETER Configuration
    Build configuration (Release or Debug). Default: Release
#>

param(
    [ValidateSet("x64", "x86")]
    [string]$Arch = "x64",

    [ValidateSet("Release", "Debug")]
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"

Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host " OceanofGames Decoder - PowerShell Build Script                    " -ForegroundColor Cyan
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host "[*] Architecture:   $Arch"
Write-Host "[*] Configuration:  $Configuration"

$vcvars = "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat"
$cmake = "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"

if (-not (Test-Path $cmake)) {
    $cmake = "cmake.exe"
}

$buildDir = "build\$Arch"

Write-Host "[*] Configuring CMake..." -ForegroundColor Yellow
$archFlag = if ($Arch -eq "x86") { "Win32" } else { "x64" }
& cmd.exe /c "`"$vcvars`" $Arch >nul 2>&1 && `"$cmake`" -B $buildDir -S . -DCMAKE_BUILD_TYPE=$Configuration -A $archFlag"

if ($LASTEXITCODE -ne 0) {
    Write-Error "[-] CMake configuration failed."
    exit $LASTEXITCODE
}

Write-Host "[*] Compiling..." -ForegroundColor Yellow
& cmd.exe /c "`"$vcvars`" $Arch >nul 2>&1 && `"$cmake`" --build $buildDir --config $Configuration"

if ($LASTEXITCODE -ne 0) {
    Write-Error "[-] Build failed."
    exit $LASTEXITCODE
}

Write-Host "[+] Build succeeded!" -ForegroundColor Green
Write-Host "[+] Binaries available at: $buildDir\bin\$Configuration\" -ForegroundColor Green
