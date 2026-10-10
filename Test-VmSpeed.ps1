# ==============================================================================
# Test-VmSpeed.ps1 - Virtual Machine Speed & Synchronization Diagnostic Tool
# ==============================================================================
# Tests hypervisor status, CPU emulation speed, VM-exit overhead, and disk latency
# ==============================================================================

[CmdletBinding()]
param (
    [switch]$SkipQemu,
    [switch]$SkipDiskBench
)

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "       VM SPEED & LOW-LEVEL SYNCHRONIZATION DIAGNOSTIC TOOL       " -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host ""

# ------------------------------------------------------------------------------
# 1. Host Hypervisor & VT-x Status Check
# ------------------------------------------------------------------------------
Write-Host "[1/4] Checking Host Virtualization & Hypervisor Status..." -ForegroundColor Yellow

$compSystem = Get-CimInstance Win32_ComputerSystem
$hypervisorRunning = [bool]$compSystem.HypervisorPresent

$vbsStatus = (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue).VirtualizationBasedSecurityStatus
$cpuInfo = Get-CimInstance Win32_Processor | Select-Object -First 1 Name, NumberOfCores, NumberOfLogicalProcessors

Write-Host "  CPU Detected:            $($cpuInfo.Name) ($($cpuInfo.NumberOfCores) cores / $($cpuInfo.NumberOfLogicalProcessors) threads)" -ForegroundColor Gray
Write-Host "  VBS (Core Isolation):    $(if ($vbsStatus -eq 2) { 'RUNNING (Active)' } else { 'Disabled or Inactive' })" -ForegroundColor $(if ($vbsStatus -eq 2) { 'Red' } else { 'Green' })
Write-Host "  Hyper-V Kernel Status:   $(if ($hypervisorRunning) { 'ACTIVE in memory' } else { 'DISABLED (Direct VT-x available)' })" -ForegroundColor $(if ($hypervisorRunning) { 'Yellow' } else { 'Green' })

if ($hypervisorRunning) {
    Write-Host ""
    Write-Host "  [IMPORTANT NOTE ON 'bcdedit /set hypervisorlaunchtype off']" -ForegroundColor Magenta
    Write-Host "  The Hyper-V hypervisor is STILL RUNNING in memory right now." -ForegroundColor Magenta
    Write-Host "  -> 'bcdedit /set hypervisorlaunchtype off' REQUIRES A FULL PC REBOOT to take effect." -ForegroundColor Magenta
    Write-Host "  -> Until rebooted, VirtualBox and VMware remain forced into slow NEM/WHPX mode." -ForegroundColor Magenta
}

Write-Host ""

# ------------------------------------------------------------------------------
# 2. VirtualBox Execution Engine & Exit Storm Analysis
# ------------------------------------------------------------------------------
Write-Host "[2/4] Checking VirtualBox VM Configuration & Trap Statistics..." -ForegroundColor Yellow

$vboxLogPath = "$env:USERPROFILE\VirtualBox VMs\win2000AHCI\Logs\VBox.log"
if (Test-Path $vboxLogPath) {
    Write-Host "  Analyzing most recent VirtualBox log (win2000AHCI)..." -ForegroundColor Gray
    
    $nemFound = Select-String -Path $vboxLogPath -Pattern "Attempting fall back to NEM" -SimpleMatch | Select-Object -First 1
    $apicV = Select-String -Path $vboxLogPath -Pattern "fVirtApicRegsEnabled=false" -SimpleMatch | Select-Object -First 1
    $unmapped = Select-String -Path $vboxLogPath -Pattern "/NEM/CPU0/ExitMemUnmapped" -SimpleMatch | Select-Object -First 1
    $portIo = Select-String -Path $vboxLogPath -Pattern "/NEM/CPU0/ExitPortIo" -SimpleMatch | Select-Object -First 1
    
    if ($nemFound) {
        Write-Host "  Execution Engine:        NEM (Native Execution Mode / Green Turtle Mode) - SLOW" -ForegroundColor Red
    } else {
        Write-Host "  Execution Engine:        HM (Native VT-x Hardware Mode) - FAST" -ForegroundColor Green
    }
    
    if ($apicV) {
        Write-Host "  APIC-v Hardware Accel:   DISABLED (Hardware APIC-v hidden by Hyper-V)" -ForegroundColor Red
    } else {
        Write-Host "  APIC-v Hardware Accel:   ENABLED" -ForegroundColor Green
    }
    
    if ($unmapped) {
        $countUnmapped = ($unmapped.Line -split '\s+')[-2]
        Write-Host "  ExitMemUnmapped (APIC):  $countUnmapped exits recorded" -ForegroundColor Yellow
    }
    if ($portIo) {
        $countPortIo = ($portIo.Line -split '\s+')[-2]
        Write-Host "  ExitPortIo (Serial/PIT): $countPortIo exits recorded" -ForegroundColor Yellow
    }
} else {
    Write-Host "  No win2000AHCI log found at $vboxLogPath" -ForegroundColor Gray
}

Write-Host ""

# ------------------------------------------------------------------------------
# 3. Disk I/O Latency Benchmark (QEMU Image Benchmark)
# ------------------------------------------------------------------------------
if (-not $SkipDiskBench) {
    Write-Host "[3/4] Benchmarking Virtual Disk I/O Latency..." -ForegroundColor Yellow
    $qemuImg = "D:\Program Files\qemu\qemu-img.exe"
    $testDisk = "$env:TEMP\speedtest_disk.qcow2"

    if (Test-Path $qemuImg) {
        try {
            Write-Host "  Creating temporary 1GB benchmark disk ($testDisk)..." -ForegroundColor Gray
            & $qemuImg create -f qcow2 $testDisk 1G > $null

            # Benchmark 1: Uncached synchronous write (Slow mode)
            Write-Host "  [Test A] Synchronous Disk Write (default unbuffered cache)..." -ForegroundColor Gray
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $benchSync = & $qemuImg bench -w -c 500 -s 4k -t writethrough $testDisk 2>&1
            $sw.Stop()
            $syncTime = $sw.ElapsedMilliseconds
            Write-Host "           Time: $syncTime ms" -ForegroundColor $(if ($syncTime -gt 1500) { 'Red' } else { 'Yellow' })

            # Benchmark 2: Writeback cached write (Optimized mode)
            Write-Host "  [Test B] Writeback Cached Write (cache=writeback)..." -ForegroundColor Gray
            $sw.Restart()
            $benchWb = & $qemuImg bench -w -c 500 -s 4k -t writeback $testDisk 2>&1
            $sw.Stop()
            $wbTime = $sw.ElapsedMilliseconds
            Write-Host "           Time: $wbTime ms" -ForegroundColor Green

            if ($syncTime -gt 0 -and $wbTime -gt 0) {
                $speedup = [math]::Round($syncTime / $wbTime, 1)
                Write-Host "  --> Disk caching provides a ${speedup}x speedup for VM disk writes!" -ForegroundColor Cyan
            }
        } finally {
            if (Test-Path $testDisk) { Remove-Item -Force $testDisk -ErrorAction SilentlyContinue }
        }
    } else {
        Write-Host "  qemu-img not found at $qemuImg, skipping disk bench." -ForegroundColor Gray
    }
    Write-Host ""
}

# ------------------------------------------------------------------------------
# 4. CPU Emulation & VM-Exit Micro-Benchmark (QEMU Test Micro-VM)
# ------------------------------------------------------------------------------
if (-not $SkipQemu) {
    Write-Host "[4/4] Running Live VM CPU Execution & Trap Speed Test..." -ForegroundColor Yellow
    $qemuBin = "D:\Program Files\qemu\qemu-system-x86_64.exe"

    if (Test-Path $qemuBin) {
        # Construct a synthetic 512-byte raw bootsector that executes 50 million iterations
        $testBoot = "$env:TEMP\test_bootsector.bin"
        $rawAsm = [byte[]](
            0xFA,                               # cli
            0x31, 0xC0,                         # xor ax, ax
            0x8E, 0xD8,                         # mov ds, ax
            0x66, 0xB9, 0x80, 0xE9, 0xFB, 0x02, # mov ecx, 50,000,000 (50M loop iterations)
            0x66, 0x49,                         # dec ecx
            0x75, 0xFC,                         # jnz -4
            0xBA, 0xF4, 0x00,                   # mov dx, 0xf4 (QEMU isa-debug-exit port)
            0xB0, 0x01,                         # mov al, 1
            0xEE,                               # out dx, al
            0xF4                                # hlt
        )
        $bootSector = New-Object byte[] 512
        [Array]::Copy($rawAsm, $bootSector, $rawAsm.Length)
        $bootSector[510] = 0x55
        $bootSector[511] = 0xAA
        [IO.File]::WriteAllBytes($testBoot, $bootSector)

        try {
            # Test 1: TCG Software Emulation
            Write-Host "  [Run 1] Testing QEMU TCG (Pure Software Emulation - 50M iterations)..." -ForegroundColor Gray
            $swTcg = [Diagnostics.Stopwatch]::StartNew()
            $procTcg = Start-Process -FilePath $qemuBin -ArgumentList "-M pc -accel tcg -drive format=raw,file=`"$testBoot`" -device isa-debug-exit,iobase=0xf4,iosize=0x04 -display none -no-reboot" -NoNewWindow -PassThru -Wait
            $swTcg.Stop()
            $tcgMs = $swTcg.ElapsedMilliseconds
            Write-Host "          TCG Time: $tcgMs ms (Exit code: $($procTcg.ExitCode))" -ForegroundColor Yellow

            # Test 2: WHPX Hardware Acceleration
            Write-Host "  [Run 2] Testing QEMU WHPX (Windows Hypervisor Platform)..." -ForegroundColor Gray
            $swWhpx = [Diagnostics.Stopwatch]::StartNew()
            $procWhpx = Start-Process -FilePath $qemuBin -ArgumentList "-M pc -accel whpx -drive format=raw,file=`"$testBoot`" -device isa-debug-exit,iobase=0xf4,iosize=0x04 -display none -no-reboot" -NoNewWindow -PassThru -Wait
            $swWhpx.Stop()
            $whpxMs = $swWhpx.ElapsedMilliseconds
            Write-Host "          WHPX Time: $whpxMs ms (Exit code: $($procWhpx.ExitCode))" -ForegroundColor Green

            Write-Host ""
            Write-Host "  Benchmark Summary:" -ForegroundColor Cyan
            Write-Host "    TCG (Software Emulation):      $tcgMs ms" -ForegroundColor Gray
            Write-Host "    WHPX (Hypervisor Hardware):    $whpxMs ms" -ForegroundColor Gray
        } finally {
            if (Test-Path $testBoot) { Remove-Item -Force $testBoot -ErrorAction SilentlyContinue }
        }
    } else {
        Write-Host "  qemu-system-x86_64.exe not found at $qemuBin." -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "                        DIAGNOSTIC SUMMARY                        " -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan
if ($hypervisorRunning) {
    Write-Host "[!] ACTION NEEDED TO RECOVER 100% NATIVE SPEED:" -ForegroundColor Red
    Write-Host "    1. You executed 'bcdedit /set hypervisorlaunchtype off', BUT you must" -ForegroundColor Yellow
    Write-Host "       RESTART YOUR COMPUTER for Windows to unload the hypervisor." -ForegroundColor Yellow
    Write-Host "    2. After restarting, run this script again: 'Hyper-V Kernel Status'" -ForegroundColor Yellow
    Write-Host "       will show 'DISABLED', and VirtualBox will run in full hardware VT-x mode." -ForegroundColor Yellow
    Write-Host "    3. In VirtualBox, ensure 'win2000AHCI' is set to 1 vCPU and remove" -ForegroundColor Yellow
    Write-Host "       or disconnect the COM1 pipe (\\.\pipe\com_1) to stop the 2.9M port exits." -ForegroundColor Yellow
} else {
    Write-Host "[OK] Hypervisor is disabled! VirtualBox and VMware can now use direct VT-x hardware." -ForegroundColor Green
}
Write-Host "==================================================================" -ForegroundColor Cyan
