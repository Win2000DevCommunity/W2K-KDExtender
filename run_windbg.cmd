@echo off
title WinDbg - Windows 2000 NET KD
echo Connecting WinDbg to \\.\pipe\KdNet ...
if exist "D:\WinDDK\7600.16385.1\Debuggers\windbg.exe" (
    "D:\WinDDK\7600.16385.1\Debuggers\windbg.exe" -k com:pipe,port=\\.\pipe\KdNet,resets=0,reconnect
) else if exist "C:\Program Files (x86)\Debugging Tools for Windows (x86)\windbg.exe" (
    "C:\Program Files (x86)\Debugging Tools for Windows (x86)\windbg.exe" -k com:pipe,port=\\.\pipe\KdNet,resets=0,reconnect
) else (
    windbg.exe -k com:pipe,port=\\.\pipe\KdNet,resets=0,reconnect
)
