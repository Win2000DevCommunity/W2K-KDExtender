@echo off
setlocal

set "WINDBG=D:\WinDDK\7600.16385.1\Debuggers\windbg.exe"
set "_NT_SYMBOL_PATH=C:\Users\Win2000\Downloads\Windows2000-KB891861-x86-Symbols-ENU\symbols"

if not exist "%WINDBG%" (
    echo WinDbg not found at: "%WINDBG%"
    pause
    exit /b 1
)

echo Symbol path set to: %_NT_SYMBOL_PATH%
echo Starting WinDbg attached to KD USB named pipe \\.\pipe\KdUsb ...
start "WinDbg - Windows 2000 KD USB" "%WINDBG%" -y "%_NT_SYMBOL_PATH%" -k com:pipe,port=\\.\pipe\KdUsb,resets=0,reconnect -g
