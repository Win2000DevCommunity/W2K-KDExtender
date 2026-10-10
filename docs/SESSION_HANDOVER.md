# KDTransport — Session Handover & State Summary

**Date:** October 10, 2026  
**Repository:** [https://github.com/Win2000DevCommunity/W2K-KDExtender](https://github.com/Win2000DevCommunity/W2K-KDExtender)  
**Branch:** `main` (tracked, clean working tree)  
**Latest Commit:** `ece7dc4` — *"docs: add GUI bridge monitor screenshot and update guide title"*

---

## 1. Project Overview & Working Architecture

KDTransport implements a high-speed kernel debugging transport layer injected directly into Windows 2000 SP4 `halmacpi.dll` (`.kdtrans` section). It routes Microsoft DbgKd serial packets over raw Ethernet (EtherType `0x88B5`) to a host-side Python bridge that feeds standard Windows debuggers via a Named Pipe (`\\.\pipe\KdNet`).

```
Target VM (W2K) [ntoskrnl <-> halmacpi.dll (.kdtrans) <-> PCnet]
       |
  Raw Ethernet (0x88B5) over VirtualBox UDPTunnel (sport=40000, dport=40001)
       v
Host Bridge [kdbridge.py / kdbridge_gui.py]
       |
  Windows Named Pipe (\\.\pipe\KdNet)
       v
Debugger [WinDbgX (Modern) / kd.exe / WinDbg Classic]
```

---

## 2. Completed Milestones & Implemented Components

### A. Core HAL Transport (`src/`)
- `kdport_wrappers.c`: Intercepts `KdPortInitialize`, `KdPortGetByte`, `KdPortPollByte`, `KdPortPutByte`, `KdPortSave`, `KdPortRestore`. Parses `/DEBUGPORT=NET`, `/DEBUGPORT=USB`, `/DEBUGPORT=COMx`.
- `kdtransport_net.c`: Implements PCnet Am79C973 and RTL8168 network drivers, raw Ethernet framing (`0x88B5`), and the low-overhead `PcnetRearm` dynamic hardware coexistence engine.
- `kdtransport_usb.c`: Intel EHCI USB 2.0 debug port capability driver (**Implemented — Not Yet Tested on bare metal**).
- `kdtransport_serial.c`: 16550 UART serial fallback (preserves original Microsoft code for COM ports).

### B. Host Bridge Utilities (`bridge/`)
- `kdbridge.py`: CLI daemon listening on UDP :40001 (RX from VM), transmitting to UDP :40000 (TX to VM), bridging to `\\.\pipe\KdNet`, with remote break control on UDP :40002.
- `kdbridge_gui.py`: Full Tkinter GUI monitor with real-time RX/TX packet & byte counters, learned MAC address, status badges, Reset VM, Break ('b'), Go ('g'), and Auto-Go pulser.
- `run_bridge_gui.cmd`: One-click desktop launcher for the GUI bridge.
- `auto_kd.py`: Background automation feeder for classic `kd.exe` that suppresses initial module breaks (`sxd *`) and pulses `g`.
- `send_break.py`: Standalone CLI utility to send break-in packets to port 40002.

### C. Tools & VDI Patching (`tools/`)
- `disable_pcnet_driver.py`: In-place VDI binary patcher that neutralizes `pcntn5m.sys` DriverEntry (returns `STATUS_UNSUCCESSFUL` `0xC0000001`), completely eliminating single-NIC contention and boot freezes without touching MFT or registry. Supports `--revert`.

### D. Documentation & Visuals (`README.md`, `docs/images/`)
- `docs/images/bridge_architecture.jpg`: High-res technical architecture flow diagram embedded in Architecture Overview.
- `docs/images/bridge_gui.png`: Real running screenshot of the GUI monitor embedded in the Graphical Bridge Monitor section.
- Table of Contents and Title updated to professional *"Step-by-Step Guide: VirtualBox"*.
- Explicit status notice marking USB EHCI 2.0 as **Implemented — Not Yet Tested**.
- Step-by-step instructions for using **Modern WinDbg (WinDbgX)** without requiring extra scripts or GUI buttons.

---

## 3. Verified Verification Results

- **Boot Test:** Windows 2000 boots cleanly to desktop in seconds with active KDNET traffic.
- **Debugger Connection:** Modern WinDbg (`WinDbgX`) connects seamlessly over `\\.\pipe\KdNet`.
- **Break-In & Resume:** Remote break ('b') halts target; `g` resumes execution smoothly.
- **Git State:** Clean git repository initialized, remote configured to `https://Win2000DevCommunity@github.com/Win2000DevCommunity/W2K-KDExtender.git`, all commits pushed to branch `main`.

---

## 4. Quick Resume Commands for Next Session

1. **Start the GUI Bridge:**
   ```cmd
   run_bridge_gui.cmd
   ```
2. **Attach Modern WinDbg:**
   ```cmd
   WinDbgX.exe -k com:pipe,port=\\.\pipe\KdNet,resets=0,reconnect
   ```
3. **Boot VM in VirtualBox:**
   Select **"Windows 2000 - KD NET"** from the boot loader menu.
