@echo off
REM rop_scanner — Windows build script
REM
REM Usage:
REM   windows_build.bat                 :: Release build in .\build
REM   windows_build.bat my_build_dir    :: custom build dir
REM
REM Requires:
REM   - Visual Studio 2019+ (Community / Pro / Enterprise / Build Tools)
REM   - cmake + ninja  (uses the ones shipped with VS if not on PATH)

setlocal EnableDelayedExpansion

cd /d "%~dp0"

REM ---- find Visual Studio ----------------------------------------------
set "VS_ROOT="
for %%E in (Community Professional Enterprise BuildTools) do (
    if not defined VS_ROOT (
        if exist "C:\Program Files\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat" (
            set "VS_ROOT=C:\Program Files\Microsoft Visual Studio\2022\%%E"
        )
    )
)
for %%E in (Community Professional Enterprise BuildTools) do (
    if not defined VS_ROOT (
        if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\%%E\VC\Auxiliary\Build\vcvars64.bat" (
            set "VS_ROOT=C:\Program Files (x86)\Microsoft Visual Studio\2019\%%E"
        )
    )
)

if not defined VS_ROOT (
    echo [-] Visual Studio not found.
    echo     Install VS 2022 / 2019 Community or VS Build Tools with "Desktop development with C++" workload.
    exit /b 1
)

echo [+] Using Visual Studio at: !VS_ROOT!

REM ---- vcvars64 ---------------------------------------------------------
call "!VS_ROOT!\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 (
    echo [-] vcvars64.bat failed
    exit /b 1
)

REM ---- pick CMake / Ninja: prefer system, fall back to VS-shipped -------
where cmake >nul 2>nul
if errorlevel 1 (
    set "VS_CMAKE=!VS_ROOT!\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin"
    if exist "!VS_CMAKE!\cmake.exe" set "PATH=!VS_CMAKE!;!PATH!"
)

where ninja >nul 2>nul
if errorlevel 1 (
    set "VS_NINJA=!VS_ROOT!\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja"
    if exist "!VS_NINJA!\ninja.exe" set "PATH=!VS_NINJA!;!PATH!"
)

where cmake >nul 2>nul || (echo [-] cmake not found ^& exit /b 1)

REM ---- build dir --------------------------------------------------------
set "BUILD_DIR=%~1"
if "%BUILD_DIR%"=="" set "BUILD_DIR=build"

for /f "tokens=*" %%v in ('cmake --version 2^>nul') do (
    echo [+] %%v
    goto :_cmake_done
)
:_cmake_done

cl 2>nul >nul
for /f "tokens=*" %%v in ('cl 2^>^&1 ^| findstr /R "Microsoft.*Compiler"') do (
    echo [+] %%v
    goto :_cl_done
)
:_cl_done

echo [+] target:   %BUILD_DIR% (Release)
echo.

REM ---- configure --------------------------------------------------------
echo [+] Configuring
cmake -S . -B %BUILD_DIR% -G Ninja -DCMAKE_BUILD_TYPE=Release
if errorlevel 1 (echo [-] Configure failed ^& exit /b 2)

REM ---- build ------------------------------------------------------------
echo.
echo [+] Building
cmake --build %BUILD_DIR%
if errorlevel 1 (echo [-] Build failed ^& exit /b 3)

REM ---- verify -----------------------------------------------------------
if not exist "%BUILD_DIR%\bin\rop_scanner.exe" (
    echo [-] Binary not found at %BUILD_DIR%\bin\rop_scanner.exe
    exit /b 4
)

echo.
echo [+] OK -^> %BUILD_DIR%\bin\rop_scanner.exe
"%BUILD_DIR%\bin\rop_scanner.exe" --help | findstr /B "rop_scanner Usage:"
exit /b 0
