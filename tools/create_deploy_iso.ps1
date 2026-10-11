# tools\create_deploy_iso.ps1
# Creates deploy_hal.iso containing HAL.DLL and automated DEPLOY.BAT for Windows 2000

$baseDir = Split-Path -Parent $PSScriptRoot
$isoRoot = Join-Path $baseDir "build\iso_root"
$isoPath = Join-Path $baseDir "deploy_hal.iso"
$halPath = Join-Path $baseDir "halmacpi_fixed.dll"

if (-not (Test-Path $isoRoot)) {
    New-Item -ItemType Directory -Force -Path $isoRoot | Out-Null
}

# Copy the fixed HAL
Copy-Item $halPath (Join-Path $isoRoot "HAL.DLL") -Force

# Create automated DEPLOY.BAT
$batchContent = @"
@echo off
title KDTransport HAL Deployment
echo ========================================================
echo   KDTransport HAL Deployment for Windows 2000
echo ========================================================
echo.
echo [1/3] Backing up original HAL...
if not exist C:\WINNT\system32\hal_backup.dll (
    copy /y C:\WINNT\system32\hal.dll C:\WINNT\system32\hal_backup.dll
    echo       Saved backup to C:\WINNT\system32\hal_backup.dll
) else (
    echo       Backup already exists at C:\WINNT\system32\hal_backup.dll
)

echo.
echo [2/3] Installing Patched HAL...
copy /y HAL.DLL C:\WINNT\system32\hal.dll
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to copy HAL.DLL! Make sure you run with Administrator privileges.
    pause
    goto :eof
)
echo       Patched HAL copied successfully!

echo.
echo [3/3] Updating C:\boot.ini...
attrib -r -s -h C:\boot.ini
findstr /i "DEBUGPORT=USB" C:\boot.ini >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo       DEBUGPORT=USB entry already present in C:\boot.ini!
) else (
    echo multi(0)disk(0)rdisk(0)partition(1)\WINNT="Windows 2000 - KD USB" /fastdetect /DEBUG /DEBUGPORT=USB >> C:\boot.ini
    echo       Added "Windows 2000 - KD USB" to C:\boot.ini
)
attrib +r +s +h C:\boot.ini

echo.
echo ========================================================
echo   Deployment Complete!
echo   You can now restart Windows 2000 and select:
echo   "Windows 2000 - KD USB" from the boot menu.
echo ========================================================
pause
"@
Set-Content -Path (Join-Path $isoRoot "DEPLOY.BAT") -Value $batchContent -Encoding Ascii

# Create autorun.inf for seamless execution
$autorunContent = @"
[autorun]
open=DEPLOY.BAT
icon=HAL.DLL,0
label=KDTransport Deploy
"@
Set-Content -Path (Join-Path $isoRoot "AUTORUN.INF") -Value $autorunContent -Encoding Ascii

# C# helper to read COM IStream to file
$code = @"
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;

public static class IsoHelper {
    public static void SaveImage(object comStream, string destPath) {
        IStream stream = (IStream)comStream;
        using (FileStream fs = new FileStream(destPath, FileMode.Create, FileAccess.Write)) {
            byte[] buf = new byte[65536];
            IntPtr pcbRead = Marshal.AllocHGlobal(sizeof(int));
            try {
                while (true) {
                    stream.Read(buf, buf.Length, pcbRead);
                    int read = Marshal.ReadInt32(pcbRead);
                    if (read <= 0) break;
                    fs.Write(buf, 0, read);
                }
            } finally {
                Marshal.FreeHGlobal(pcbRead);
            }
        }
    }
}
"@
Add-Type -TypeDefinition $code

$fsi = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
$fsi.ChooseImageDefaultsForMediaType(12)
$fsi.FileSystemsToCreate = 1 + 2 # ISO9660 + Joliet
$fsi.VolumeName = "KD_DEPLOY"
$fsi.Root.AddTree($isoRoot, $false)

$resultImage = $fsi.CreateResultImage()
[IsoHelper]::SaveImage($resultImage.ImageStream, $isoPath)

$item = Get-Item $isoPath
Write-Host "Created ISO: $($item.FullName) ($($item.Length) bytes)"
