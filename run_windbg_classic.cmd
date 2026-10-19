@echo off
setlocal

set "WINDBG=D:\WinDDK\7600.16385.1\Debuggers\windbg.exe"
set "_NT_SYMBOL_PATH=C:\Users\Win2000\Downloads\Windows2000-KB891861-x86-Symbols-ENU\symbols"

if not exist "%WINDBG%" (
    echo WinDbg executable not found: "%WINDBG%"
    pause
    exit /b 1
)

echo ========================================================
echo  Classic WinDbg (WDK 7600) - Windows 2000 KD USB
echo ========================================================
echo Symbol Path: %_NT_SYMBOL_PATH%
echo Target Pipe: \\.\pipe\KdUsb
echo.
echo WinDbg will attach when the VM reaches KdInitSystem.
echo Press F5 (or type 'g' and Enter) in WinDbg to resume boot!
echo ========================================================

start "WinDbg Classic" "%WINDBG%" -y "%_NT_SYMBOL_PATH%" -k com:pipe,port=\\.\pipe\KdUsb,resets=0,reconnect
