@echo off
setlocal

set "WINDBGX=C:\Users\Win2000\AppData\Local\Microsoft\WindowsApps\WinDbgX.exe"
set "_NT_SYMBOL_PATH=C:\Users\Win2000\Downloads\Windows2000-KB891861-x86-Symbols-ENU\symbols"

:: Ensure no lingering debugger or engine host process holds the named pipe
taskkill /F /IM windbg.exe /IM DbgX.Shell.exe /IM WinDbgX.exe /IM EngHost.exe /IM kd.exe >nul 2>&1
ping 127.0.0.1 -n 2 >nul

if not exist "%WINDBGX%" (
    echo WinDbgX executable not found: "%WINDBGX%"
    pause
    exit /b 1
)

echo ========================================================
echo  Modern WinDbgX (WinDbg Preview) - Windows 2000 KD USB
echo ========================================================
echo Symbol Path: %_NT_SYMBOL_PATH%
echo Target Pipe: \\.\pipe\KdUsb
echo.
echo WinDbgX will attach when the VM reaches KdInitSystem.
echo Press 'Go' (or F5, or type 'g' and Enter) in WinDbgX to resume boot!
echo ========================================================

start "WinDbgX Modern" "%WINDBGX%" -y "%_NT_SYMBOL_PATH%" -k com:pipe,port=\\.\pipe\KdUsb,resets=0,reconnect
