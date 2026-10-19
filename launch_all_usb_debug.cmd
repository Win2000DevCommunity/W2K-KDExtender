@echo off
setlocal

set "QEMU_CMD=C:\Users\Win2000\Documents\QEMU\Windows2000-Pro-SP4\start-win2000-debug.cmd"
set "WINDBG_CMD=%~dp0run_windbg_usb.cmd"

echo =======================================================
echo  Starting Windows 2000 SP4 VM with KD USB Transport
echo =======================================================

start "Windows 2000 VM (QEMU)" cmd /c "%QEMU_CMD%"
timeout /t 2 /nobreak >nul

start "WinDbg" cmd /c "%WINDBG_CMD%"

echo.
echo [OK] QEMU VM and WinDbg launched!
echo Connect your VNC viewer to 127.0.0.1:5900 to view the VM desktop.
echo WinDbg will automatically attach over \\.\pipe\KdUsb.
