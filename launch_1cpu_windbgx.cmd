@echo off
setlocal

set "QEMU_LAUNCHER=C:\Users\Win2000\Documents\QEMU\Windows2000-Pro-SP4\start-win2000-1cpu-debug.cmd"
set "WINDBGX_EXE=C:\Users\Win2000\AppData\Local\Microsoft\WindowsApps\WinDbgX.exe"
set "SYMBOLS=C:\Users\Win2000\Downloads\w2ksp4sym_en\exe;C:\Users\Win2000\Downloads\w2ksp4sym_en\dll;C:\Users\Win2000\Downloads\w2ksp4sym_en\sys;C:\Users\Win2000\Downloads\Windows2000-KB891861-x86-Symbols-ENU\symbols\exe;C:\Users\Win2000\Downloads\Windows2000-KB891861-x86-Symbols-ENU\symbols\dll;C:\Users\Win2000\Downloads\Windows2000-KB891861-x86-Symbols-ENU\symbols\sys"

echo ========================================================
echo  Windows 2000 SP4 (1-CPU) - Modern WinDbgX Session
echo ========================================================
echo  HAL Variant : halaacpi.dll (ACPI Uniprocessor PC)
echo  Debug Port  : USB (EHCI Named Pipe \\.\pipe\KdUsb)
echo  Symbols     : %SYMBOLS%
echo ========================================================

:: Clean reset of any previous QEMU and debugger processes
echo [*] Cleaning up previous QEMU and debugger processes...
taskkill /F /IM qemu-system-i386.exe /IM windbg.exe /IM DbgX.Shell.exe /IM WinDbgX.exe /IM EngHost.exe /IM kd.exe >nul 2>&1
ping 127.0.0.1 -n 2 >nul

:: Launch QEMU VM
echo [*] Starting Windows 2000 (1-CPU) QEMU VM...
start "Windows 2000 1-CPU (QEMU)" cmd /c "%QEMU_LAUNCHER%"

:: Wait for QEMU to create the named pipe
echo [*] Waiting 3 seconds for named pipe creation...
ping 127.0.0.1 -n 4 >nul

:: Launch Modern WinDbgX
echo [*] Launching Modern WinDbgX...
start "WinDbgX" "%WINDBGX_EXE%" -y "%SYMBOLS%" -k com:pipe,port=\\.\pipe\KdUsb,resets=0,reconnect

echo.
echo [OK] Both QEMU and Modern WinDbgX launched!
echo  - Connect your VNC viewer to 127.0.0.1:5900 to see the VM screen.
echo  - In WinDbgX, click 'Break' at any time to break into the kernel!
echo  - Run your KD commands (.version, r, kv, !pcr, !process, etc.)
echo  - Click 'Go' (or press F5) to resume execution!
echo ========================================================
