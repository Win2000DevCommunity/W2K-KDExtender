@echo off
setlocal EnableDelayedExpansion
title Replace QEMU in Program Files (DISABLED)

echo ========================================================
echo   [PROTECTED] DO NOT OVERWRITE PROGRAM FILES QEMU
echo ========================================================
echo   The official QEMU in Program Files is reserved for kernel
echo   rewriting with Claude. The custom EHCI DBGP QEMU is run
echo   directly from C:\Users\Win2000\Downloads\qemu\build.
echo.
echo   Use 'run_qemu_w2k_dbgp.cmd' to run the custom QEMU directly!
echo ========================================================
pause
exit /b 0


:: Check for Administrator elevation
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo ========================================================
    echo   ELEVATION REQUIRED
    echo ========================================================
    echo   Modifying 'D:\Program Files\qemu' requires Administrator rights.
    echo   Launching UAC prompt...
    echo.
    powershell -Command "Start-Process cmd -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

echo ========================================================
echo   Upgrading QEMU at D:\Program Files\qemu
echo   With Custom EHCI DBGP Build (QEMU 11.1.50)
echo ========================================================
echo.

set "TARGET_DIR=D:\Program Files\qemu"
set "SRC_EXE=C:\Users\Win2000\Downloads\qemu\build\qemu-system-i386.exe"
set "MINGW_BIN=C:\Users\Win2000\msys64\mingw64\bin"

if not exist "%TARGET_DIR%" (
    echo [ERROR] Target directory not found: %TARGET_DIR%
    pause
    exit /b 1
)

if not exist "%SRC_EXE%" (
    echo [ERROR] Source executable not found: %SRC_EXE%
    pause
    exit /b 1
)

:: 1. Backup original executable if not already backed up
if not exist "%TARGET_DIR%\qemu-system-i386.exe.orig.bak" (
    echo [*] Creating backup: %TARGET_DIR%\qemu-system-i386.exe.orig.bak
    copy /Y "%TARGET_DIR%\qemu-system-i386.exe" "%TARGET_DIR%\qemu-system-i386.exe.orig.bak" >nul
)

:: 2. Copy the new custom qemu-system-i386.exe
echo [*] Installing custom qemu-system-i386.exe ...
copy /Y "%SRC_EXE%" "%TARGET_DIR%\qemu-system-i386.exe"
if %errorlevel% neq 0 (
    echo [ERROR] Failed to copy qemu-system-i386.exe!
    pause
    exit /b 1
)

:: 3. Copy updated MinGW runtime DLLs required by QEMU 11.1.50
echo [*] Updating runtime DLL dependencies from MinGW-w64 ...
set "DLL_LIST=libbz2-1.dll libfdt-1.dll libffi-8.dll libgio-2.0-0.dll libglib-2.0-0.dll libgmodule-2.0-0.dll libgobject-2.0-0.dll libiconv-2.dll libintl-8.dll libncursesw6.dll libpcre2-8-0.dll libpixman-1-0.dll libwinpthread-1.dll libzstd.dll zlib1.dll"

for %%F in (%DLL_LIST%) do (
    if exist "%MINGW_BIN%\%%F" (
        copy /Y "%MINGW_BIN%\%%F" "%TARGET_DIR%\%%F" >nul
    )
)

echo.
echo ========================================================
echo   Verification:
echo ========================================================
"%TARGET_DIR%\qemu-system-i386.exe" --version
if %errorlevel% equ 0 (
    echo.
    echo [SUCCESS] QEMU in 'D:\Program Files\qemu' successfully replaced!
) else (
    echo.
    echo [WARNING] QEMU exited with code %errorlevel%.
)

echo.
pause
