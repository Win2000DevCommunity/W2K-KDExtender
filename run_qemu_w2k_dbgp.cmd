@echo off
setlocal EnableDelayedExpansion
title QEMU - Windows 2000 AHCI (EHCI Debug Port)
echo ========================================================
echo   Starting QEMU with Windows 2000 AHCI ^& EHCI DBGP
echo   Source: C:\Users\Win2000\Downloads\qemu\build\qemu-system-i386.exe
echo   Named Pipe: \\.\pipe\KdUsb
echo   VNC Display: 127.0.0.1:5900
echo ========================================================
echo.

:: Add MinGW64 to PATH for modified QEMU runtime dependencies
set "PATH=C:\Users\Win2000\msys64\mingw64\bin;%PATH%"

:: Explicitly use the modified QEMU build from the Downloads folder
set "QEMU=C:\Users\Win2000\Downloads\qemu\build\qemu-system-i386.exe"
set "DISK=C:\Users\Win2000\VirtualBox VMs\win2000AHCI\win2000AHCI_1.vdi"
set "VNC_VIEWER=D:\Program Files\TightVNC\tvnviewer.exe"

if not exist "%QEMU%" (
    echo [ERROR] Modified QEMU build not found at:
    echo         %QEMU%
    echo Please make sure the build is present in Downloads\qemu\build.
    pause
    exit /b 1
)

if not exist "%DISK%" (
    if exist "C:\Users\Win2000\Desktop\win2000AHCI_repaired.vdi" (
        set "DISK=C:\Users\Win2000\Desktop\win2000AHCI_repaired.vdi"
    ) else if exist "C:\Users\Win2000\VirtualBox VMs\win2000AHCI\win2000AHCI.vdi" (
        set "DISK=C:\Users\Win2000\VirtualBox VMs\win2000AHCI\win2000AHCI.vdi"
    )
)

echo [*] Target Disk: %DISK%
echo.

:: 1. Launch QEMU core process in background
echo [*] Launching QEMU core engine...
start "QEMU Core" "%QEMU%" -M pc -m 512M -cpu pentium3 -device ich9-ahci,id=ahci -drive "file=%DISK%,format=vdi,if=none,id=disk0" -device ide-hd,drive=disk0,bus=ahci.0 -chardev pipe,id=kdusb,path=KdUsb -device usb-ehci,id=ehci,chardev=kdusb -nic none -vnc :0 -monitor telnet:127.0.0.1:4445,server=on,wait=off -boot order=c

:: 2. Launch WinDbg USB to connect to \\.\pipe\KdUsb
:: Note: QEMU's named pipe chardev blocks until the debugger connects to \\.\pipe\KdUsb.
echo [*] Starting WinDbg to connect to \\.\pipe\KdUsb...
start "WinDbg USB" cmd /c "%~dp0run_windbg_usb.cmd"

:: 3. Wait for VNC port 5900 to become active once the pipe is connected
echo [*] Waiting for QEMU VNC server (127.0.0.1:5900) to initialize...
python -c "import socket, time, sys; [sys.exit(0) for _ in range(40) if time.sleep(0.5) is None and (lambda s: (s.connect_ex(('127.0.0.1', 5900)) == 0 and s.close() is None))(socket.socket())]; sys.exit(1)"

if %ERRORLEVEL% equ 0 (
    if exist "%VNC_VIEWER%" (
        echo [*] Opening graphical VM display via TightVNC...
        start "Windows 2000 VM Display" "%VNC_VIEWER%" 127.0.0.1:5900
    ) else (
        echo [*] QEMU VNC server listening at 127.0.0.1:5900.
    )
    echo.
    echo [SUCCESS] VM and Debugger are active and running!
) else (
    echo.
    echo [NOTICE] QEMU is waiting for debugger pipe connection on \\.\pipe\KdUsb.
    echo          Once WinDbg attaches, VNC server will activate on 127.0.0.1:5900.
)

echo.
