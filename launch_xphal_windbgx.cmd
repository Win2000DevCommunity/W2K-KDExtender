@echo off
setlocal

set "QEMU_LAUNCHER=C:\Users\Win2000\Documents\QEMU\Windows2000-Pro-SP4\start-win2000-debug.cmd"
set "WINDBGX_EXE=C:\Users\Win2000\AppData\Local\Microsoft\WindowsApps\WinDbgX.exe"
set "SYMBOLS=C:\Users\Win2000\Downloads\w2ksp4sym_en\exe;C:\Users\Win2000\Downloads\w2ksp4sym_en\dll;C:\Users\Win2000\Downloads\w2ksp4sym_en\sys;C:\Users\Win2000\Downloads\Windows2000-KB891861-x86-Symbols-ENU\symbols\exe;C:\Users\Win2000\Downloads\Windows2000-KB891861-x86-Symbols-ENU\symbols\dll;C:\Users\Win2000\Downloads\Windows2000-KB891861-x86-Symbols-ENU\symbols\sys"

echo ========================================================
echo  Windows 2000 SP4 (2-CPU SMP) - Modern WinDbgX Session
echo ========================================================
echo  HAL Variant : Windows XP HAL (NT 5.1 HALMACPI.DLL)
echo  Debug Port  : USB (EHCI Named Pipe \\.\pipe\KdUsb)
echo  VM Disk     : win2000-pro-sp4.img (2 CPUs, ACPI Multiprocessor)
echo  Symbols     : %SYMBOLS%
echo ========================================================
echo.
echo  [*] Note: Under QEMU EHCI USB emulation, the initial
echo      connection and breakpoint may take 1-2 minutes to
echo      stream all USB handshake packets. Please wait for it.
echo ========================================================

:: Clean reset of any previous QEMU and debugger processes
echo [*] Cleaning up previous QEMU and debugger processes...
taskkill /F /IM qemu-system-i386.exe /IM windbg.exe /IM DbgX.Shell.exe /IM WinDbgX.exe /IM EngHost.exe /IM kd.exe >nul 2>&1
ping 127.0.0.1 -n 2 >nul

:: Launch QEMU VM
echo [*] Starting Windows 2000 SMP VM with Windows XP HAL...
start "Windows 2000 SMP - XP HAL (QEMU)" cmd /c "%QEMU_LAUNCHER%"

:: Wait for QEMU to create the named pipe
echo [*] Waiting 3 seconds for named pipe creation...
ping 127.0.0.1 -n 4 >nul

:: Launch Modern WinDbgX
echo [*] Launching Modern WinDbgX...
start "WinDbgX - XP HAL on W2K" "%WINDBGX_EXE%" -y "%SYMBOLS%" -k com:pipe,port=\\.\pipe\KdUsb,resets=0,reconnect

echo.
echo [OK] Both QEMU and Modern WinDbgX launched!
echo  - Connect your VNC viewer to 127.0.0.1:5900 to see the VM screen.
echo  - In WinDbgX, click 'Break' (or press Ctrl+Break) to halt the kernel.
echo  - Run your KD commands (.version, r, kv, !pcr, !process 0 0, etc.)
echo  - Click 'Go' (or press F5) to resume execution!
echo ========================================================
