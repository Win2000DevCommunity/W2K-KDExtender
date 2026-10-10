@echo off
:: ============================================================
:: build_w2k.cmd
:: Builds kdtransport.lib targeting Windows 2000 using DDK 3790.1830
:: ============================================================

if "%DDK%"=="" set DDK=C:\WINDDK\3790.1830

if not exist "%DDK%\bin\setenv.bat" (
    echo ERROR: DDK not found at %DDK%
    echo        Edit DDK= in this script to point to your DDK root.
    exit /b 1
)

:: --- Free (release) build ---
echo.
echo ====== Building FREE (release) for W2K x86 ======
call "%DDK%\bin\setenv.bat" %DDK% fre W2K
cd /d "%~dp0..\src"
build -cZ

if errorlevel 1 (
    echo.
    echo BUILD FAILED.  Check build log in src\buildfre_w2K_x86.log
    exit /b 1
)

:: The sources file outputs to ..\build\obj -- check there
if exist "%~dp0obj\i386\kdtransport.lib" (
    echo.
    echo ====== Build complete ======
    echo Output: %~dp0obj\i386\kdtransport.lib
) else (
    echo.
    echo WARNING: kdtransport.lib not found in expected output location.
    echo          Check src\buildfre_w2K_x86.log for details.
)

echo.
echo Next step: run  patcher\kdpatch.py  against halmacpi.dll
echo See README.md for full instructions.
