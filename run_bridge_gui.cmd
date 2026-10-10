@echo off
title KDTransport GUI Bridge
cd /d "%~dp0"
echo Starting KDTransport Graphical Bridge...
python bridge\kdbridge_gui.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Bridge exited with error code %ERRORLEVEL%.
    pause
)
