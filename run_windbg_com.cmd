@echo off
title WinDbg - Windows 2000 COM KD (COM1 \\.\pipe\com_1)
echo Connecting WinDbg to VirtualBox COM1 pipe (\\.\pipe\com_1) ...
"D:\WinDDK\7600.16385.1\Debuggers\windbg.exe" -k com:pipe,port=\\.\pipe\com_1,resets=0,reconnect
