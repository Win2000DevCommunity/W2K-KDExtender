/*
 * kdtransport_usb.c
 *
 * EHCI hardware debug-port backend. Confirmed on this target: Intel
 * 8086:265C EHCI controller (generic, no vendor quirks), PCI bus 0 device
 * 11 function 0, debug port number 1.
 *
 * Protocol below is written from reading Linux's drivers/usb/early/
 * ehci-dbgp.c (GPL-2.0) for understanding, then re-expressed here against
 * this HAL's idioms -- this is NOT a port of that file, and several things
 * it does are Linux-specific plumbing with no equivalent here (the KGDB/
 * console/kthread integration, all dropped) or are replaced with the
 * primitives already confirmed for this HAL (HalGetBusDataByOffset instead
 * of Linux's early_pci accessors). The actual wire protocol -- register
 * layout, PID values, the claim/reset/enable sequence, the address-127
 * convention -- is dictated by the EHCI and USB2 Debug Device
 * specifications, not by Linux's implementation of them, and has to match
 * regardless of which OS is driving it.
 *
 * Deliberately simplified relative to the reference: no vendor-specific
 * debug-port remapping (nvidia_set_debug_port and friends -- not needed for
 * a confirmed generic Intel controller), no retry-across-every-port search
 * loop (this target's port is confirmed as 1), no BIOS EHCI-ownership
 * handoff (separate concern from the debug port itself, can be added if it
 * turns out to matter here). If the simple path below doesn't come up, that
 * handoff step is the first thing to add back.
 */

#include "kdtransport.h"

#define PCI_CLASS_SERIAL_USB_EHCI 0x0C0320   /* class/subclass/prog-if, from PCI_CLASS_REVISION */
#define PCI_CAP_ID_EHCI_DEBUG     0x0A       /* capability ID in the PCI capability list */

#define USB_DEBUG_DEVNUM   127   /* spec-mandated address a debug device gets moved to */
#define DBGP_MAX_PACKET    8     /* debug port's fixed max transfer size */
#define DBGP_LOOPS         1000  /* retry budget for a single NAK'd transaction */

/* EHCI capability registers (memory-mapped, read-only) */
typedef struct _EHCI_CAP_REGS {
    UCHAR  CapLength;        /* low byte of HcCapBase -- length of this cap block, i.e. offset to operational regs */
    UCHAR  Reserved;
    USHORT HciVersion;
    ULONG  HcsParams;        /* bits 0-3 = N_PORTS, bits 20-23 = debug port number */
    ULONG  HccParams;
} EHCI_CAP_REGS, *PEHCI_CAP_REGS;

#define EHCI_HCS_N_PORTS(p)     ((p) & 0xF)
#define EHCI_HCS_DEBUG_PORT(p)  (((p) >> 20) & 0xF)

/* EHCI operational registers (memory-mapped, base = cap regs + CapLength) */
typedef struct _EHCI_OP_REGS {
    ULONG Command;
    ULONG Status;
    ULONG IntrEnable;
    ULONG FrameIndex;
    ULONG SegmentSelector;
    ULONG FrameListBase;
    ULONG AsyncListAddr;
    ULONG Reserved[9];
    ULONG ConfigFlag;
    ULONG PortStatus[1];   /* [0] is port 1 -- indexed as PortStatus[port - 1] */
} EHCI_OP_REGS, *PEHCI_OP_REGS;

#define EHCI_CMD_RUN    0x00000001
#define EHCI_CMD_RESET  0x00000002
#define EHCI_STS_HALT   0x00001000
#define EHCI_STS_PORT_CHANGE 0x00000004
#define EHCI_CONFIGFLAG_ROUTE_TO_EHCI 0x1

#define EHCI_PORT_CONNECT    0x00000001
#define EHCI_PORT_ENABLE     0x00000004
#define EHCI_PORT_RESET      0x00000100

/* The debug port's own register block -- location is NOT fixed, it's given
   by the PCI debug-port capability DWORD (bar selector + MMIO offset). */
typedef struct _EHCI_DBGP_REGS {
    ULONG Control;
    ULONG Pids;
    ULONG Address;
    ULONG Data03;
    ULONG Data47;
} EHCI_DBGP_REGS, *PEHCI_DBGP_REGS;

#define DBGP_CTRL_OWNER    0x40000000
#define DBGP_CTRL_ENABLED  0x10000000
#define DBGP_CTRL_INUSE    0x08000000
#define DBGP_CTRL_DONE     0x00010000
#define DBGP_CTRL_OUT      0x00040000  /* direction: set = OUT, clear = IN */
#define DBGP_CTRL_GO       0x00080000
#define DBGP_CTRL_ERROR    0x00100000
#define DBGP_CTRL_LEN(x)   ((x) & 0x0F)
#define DBGP_CTRL_SET_LEN(ctrl, len) (((ctrl) & ~0x0F) | ((len) & 0x0F))
#define DBGP_CLAIM (DBGP_CTRL_OWNER | DBGP_CTRL_ENABLED | DBGP_CTRL_INUSE)

/* Packet IDs -- USB spec token/handshake/data values, not Linux's */
#define USB_PID_OUT    0xE1
#define USB_PID_IN     0x69
#define USB_PID_SETUP  0x2D
#define USB_PID_DATA0  0xC3
#define USB_PID_DATA1  0x4B
#define USB_PID_NAK    0x5A

#define DBGP_PID_GET(pids)        ((pids) & 0xFF)
#define DBGP_PID_SET(data, token) ((((ULONG)(data)) << 8) | ((token) & 0xFF))
#define DBGP_EPADDR(dev, ep)      ((((ULONG)(dev)) << 8) | ((ep) & 0x0F))

/* USB spec "Debug Descriptor" (type 0x0A) -- what GET_DESCRIPTOR returns
   for a debug device, telling us which two endpoints are the debug pipes. */
typedef struct _USB_DEBUG_DESCRIPTOR {
    UCHAR Length;
    UCHAR DescriptorType;
    UCHAR DebugInEndpoint;
    UCHAR DebugOutEndpoint;
} USB_DEBUG_DESCRIPTOR, *PUSB_DEBUG_DESCRIPTOR;

/*
 * PARTIALLY CONFIRMED: dt nt!_PCI_SLOT_NUMBER shows the type exists (one
 * field, an anonymous union WinDbg didn't expand) but didn't hand over the
 * actual bit layout the way dt on _LOADER_PARAMETER_BLOCK did. The packing
 * below is now the standard, long-documented PCI_SLOT_NUMBER layout
 * (function number in bits 0-2, device number in bits 3-7) rather than the
 * (slot<<16)|func placeholder from before -- solid from general WDK
 * knowledge, just not independently verified against this exact build the
 * way the rest of this file's assumptions have been. Fill in `dt
 * nt!_PCI_SLOT_NUMBER.u` (or expand the anonymous member some other way) to
 * close this out the same way the others were closed.
 */
#ifndef PCI_SLOT_NUMBER_MAKE
#define PCI_SLOT_NUMBER_MAKE(device, function) (((device) & 0x1F) | (((function) & 0x7) << 5))
#endif
/* CONFIRMED: dt -b nt!_PCI_SLOT_NUMBER shows DeviceNumber at Pos 0 (5 bits),
   FunctionNumber at Pos 5 (3 bits). Verified: EHCI device 11 func 0 gives
   AsULONG=0xb=11 = (11 & 0x1F) | (0 << 5). Previous macro had these
   reversed and was wrong for any non-zero function number. */

static PEHCI_CAP_REGS  EhciCaps;
static PEHCI_OP_REGS   EhciOps;
static PEHCI_DBGP_REGS EhciDbg;
static ULONG           DbgpPort;          /* 1-based physical port number */
static UCHAR           DbgpEndpointOut;
static UCHAR           DbgpEndpointIn;
static UCHAR           DbgpDataToggleOut = USB_PID_DATA1;   /* flips each OUT, per spec */

/* Direct PCI Configuration Mechanism #1 (ports 0xCF8 / 0xCFC).
 * Phase-0 safe: does NOT call HalGetBusDataByOffset. */
static __forceinline ULONG PciReadConfig32(ULONG Bus, ULONG Slot, ULONG Func, ULONG Offset)
{
    ULONG address = 0x80000000UL | ((Bus & 0xFF) << 16) | ((Slot & 0x1F) << 11) | ((Func & 0x7) << 8) | (Offset & 0xFC);
    WRITE_PORT_ULONG((PULONG)0xCF8, address);
    return READ_PORT_ULONG((PULONG)0xCFC);
}

static __forceinline UCHAR PciReadConfig8(ULONG Bus, ULONG Slot, ULONG Func, ULONG Offset)
{
    ULONG val = PciReadConfig32(Bus, Slot, Func, Offset);
    return (UCHAR)((val >> ((Offset & 3) * 8)) & 0xFF);
}

/*
 * Locate the debug-port PCI capability. Uses direct PCI ports 0xCF8/0xCFC (Phase 0 safe).
 */
static __forceinline BOOLEAN
FindDebugPortCapability(OUT PULONG Bus, OUT PULONG Slot, OUT PULONG Func, OUT PULONG CapOffset)
{
    ULONG bus, slot, func;
    ULONG classCode;
    UCHAR capPtr, capId;

    for (bus = 0; bus < 8; bus++) {
        for (slot = 0; slot < 32; slot++) {
            for (func = 0; func < 8; func++) {
                ULONG idReg = PciReadConfig32(bus, slot, func, 0x00);
                if (idReg == 0xFFFFFFFF || idReg == 0) continue;

                classCode = PciReadConfig32(bus, slot, func, 0x08);
                if ((classCode >> 8) != PCI_CLASS_SERIAL_USB_EHCI) {
                    continue;
                }

                capPtr = PciReadConfig8(bus, slot, func, 0x34);   /* PCI_CAPABILITY_LIST */
                while (capPtr >= 0x40 && capPtr < 0xFF) {
                    capId = PciReadConfig8(bus, slot, func, capPtr);
                    if (capId == PCI_CAP_ID_EHCI_DEBUG) {
                        *Bus = bus; *Slot = slot; *Func = func; *CapOffset = capPtr;
                        return TRUE;
                    }
                    capPtr = PciReadConfig8(bus, slot, func, capPtr + 1);   /* next pointer */
                }
            }
        }
    }
    return FALSE;
}


/*
 * CONFIRMED via full `uf`. ret 0xC = 3 stack slots, which is exactly
 * PHYSICAL_ADDRESS (2 slots, low+high -- the "64" in the name) plus
 * NumberOfPages (1 slot): [ebp+8]/[ebp+0xc] get walked 0x1000 at a time
 * with add/adc (the classic split-64-bit-increment idiom), shifted right
 * by 12 via _allshr to get a page frame number, which goes into
 * HalpSetPageFrameNumber; [ebp+0x10] is decremented once per loop until it
 * hits 0, confirming NumberOfPages. So the declaration guessed earlier was
 * actually already right at the C level -- PHYSICAL_ADDRESS-by-value on x86
 * stdcall naturally decomposes into those same two stack slots. What was
 * actually missing was the prototype itself, added below.
 *
 * Side note, not needed for this file but explains the memory model: HAL
 * keeps growing HalpHeapStart forever for these mappings rather than ever
 * reclaiming it -- fine for a handful of one-time early-boot mappings,
 * meaning this should be called once per device at Initialize time, not
 * repeatedly, since there's no unmap facility visible here.
 */
PVOID NTAPI HalpMapPhysicalMemory64(IN PHYSICAL_ADDRESS PhysicalAddress, IN ULONG NumberOfPages);

/* Forward declarations for functions defined later in this file */
static LONG UsbBulkWrite(IN ULONG DevNum, IN ULONG Endpoint, IN PCHAR Bytes, IN ULONG Size);
static LONG UsbBulkRead(IN ULONG DevNum, IN ULONG Endpoint, OUT PVOID Data, IN ULONG Size, IN LONG Loops);
static LONG UsbControlMessage(IN ULONG DevNum, IN BOOLEAN DirectionIn, IN UCHAR Request,
                              IN USHORT Value, IN USHORT Index, OUT PVOID Data, IN ULONG Size);

static __forceinline PVOID
MapPhysicalMemory(IN ULONG PhysicalAddress, IN ULONG SizeInBytes)
{
    ULONG pages = (SizeInBytes + 0xFFF) / 0x1000;
    PHYSICAL_ADDRESS pa;
    pa.QuadPart = PhysicalAddress;
    return HalpMapPhysicalMemory64(pa, pages);
}

static BOOLEAN
UsbInitialize(
    IN OUT PPORT_DESCRIPTOR Port,
    IN ULONG Unused1,
    IN ULONG BaudRate
    )
{
    ULONG bus, slot, func, capOffset;
    ULONG capDword, barOffset, mmioOffset, barValue;
    ULONG hcsParams;
    ULONG loop;
    USB_DEBUG_DESCRIPTOR debugDesc;   /* GET_DESCRIPTOR(Debug Descriptor) result -- endpoint numbers live here */
    ULONG devnum;

    UNREFERENCED_PARAMETER(Port);
    UNREFERENCED_PARAMETER(Unused1);
    UNREFERENCED_PARAMETER(BaudRate);   /* debug port has no baud rate concept */

    if (!FindDebugPortCapability(&bus, &slot, &func, &capOffset)) {
        return FALSE;   /* shouldn't happen on this target -- already confirmed present -- but stay honest */
    }

    capDword = PciReadConfig32(bus, slot, func, capOffset);
    barOffset = 0x10 + (((capDword >> 29) & 0x7) * 4);   /* PCI_BASE_ADDRESS_0 + n*4 */
    mmioOffset = (capDword >> 16) & 0xFFF;

    barValue = PciReadConfig32(bus, slot, func, barOffset);
    if (barValue & 0x1) {
        return FALSE;   /* I/O-space BAR, not the simple 32-bit MMIO case handled here */
    }


    EhciCaps = (PEHCI_CAP_REGS)MapPhysicalMemory(barValue & ~0xFUL, 0x1000);
    if (EhciCaps == NULL) {
        return FALSE;
    }
    EhciOps = (PEHCI_OP_REGS)((PUCHAR)EhciCaps + EhciCaps->CapLength);
    EhciDbg = (PEHCI_DBGP_REGS)((PUCHAR)EhciCaps + mmioOffset);

    hcsParams = EhciCaps->HcsParams;
    DbgpPort = EHCI_HCS_DEBUG_PORT(hcsParams);   /* confirmed via UsbView as 1 on this target; re-derived
                                                     here too so this keeps working if it's ever wrong */
    if (DbgpPort == 0) {
        return FALSE;
    }

    /* Reset the controller if it isn't already configured and running. */
    if (!(EhciOps->ConfigFlag & EHCI_CONFIGFLAG_ROUTE_TO_EHCI)) {
        EhciOps->Command |= EHCI_CMD_RESET;
        for (loop = 250000; (EhciOps->Command & EHCI_CMD_RESET) && loop; loop--) {
            ;
        }
        if (loop == 0) {
            return FALSE;
        }
    }

    /* Claim ownership of the debug port before enabling it. */
    EhciDbg->Control = (EhciDbg->Control | DBGP_CTRL_OWNER) & ~(DBGP_CTRL_ENABLED | DBGP_CTRL_INUSE);

    EhciOps->Command = (EhciOps->Command & ~EHCI_CMD_RESET) | EHCI_CMD_RUN;
    EhciOps->ConfigFlag = EHCI_CONFIGFLAG_ROUTE_TO_EHCI;
    for (loop = 1000; (EhciOps->Status & EHCI_STS_HALT) && loop; loop--) {
        ;
    }
    if (loop == 0) {
        return FALSE;
    }

    /* Wait for the debug cable's far end to show up, then reset that port
       so it belongs to the debug controller rather than a normal driver. */
    for (loop = 300; !(EhciOps->Status & EHCI_STS_PORT_CHANGE) && loop; loop--) {
        ;
    }
    EhciOps->PortStatus[DbgpPort - 1] = (EhciOps->PortStatus[DbgpPort - 1] & ~EHCI_PORT_ENABLE) | EHCI_PORT_RESET;
    for (loop = 50000; (EhciOps->PortStatus[DbgpPort - 1] & EHCI_PORT_RESET) && loop; loop--) {
        ;
    }
    if (!(EhciOps->PortStatus[DbgpPort - 1] & EHCI_PORT_CONNECT)) {
        return FALSE;   /* nothing plugged in */
    }

    EhciDbg->Control |= DBGP_CLAIM;
    if ((EhciDbg->Control & DBGP_CLAIM) != DBGP_CLAIM) {
        return FALSE;   /* device didn't accept the claim */
    }
    EhciOps->PortStatus[DbgpPort - 1] &= ~EHCI_PORT_ENABLE;   /* fully hand the port to the debug controller */

    /* Find the debug device (spec default: address 0 until told otherwise)
       and read its Debug Descriptor for the real bulk endpoint numbers. */
    for (devnum = 0; devnum <= 127; devnum++) {
        if (UsbControlMessage(devnum, TRUE, /* GET_DESCRIPTOR */ 0x06,
                               (0x0A /* USB_DT_DEBUG */ << 8), 0,
                               &debugDesc, sizeof(debugDesc)) > 0) {
            break;
        }
    }
    if (devnum > 127) {
        return FALSE;
    }
    DbgpEndpointOut = debugDesc.DebugOutEndpoint;
    DbgpEndpointIn  = debugDesc.DebugInEndpoint;

    if (devnum != USB_DEBUG_DEVNUM) {
        if (UsbControlMessage(devnum, FALSE, /* SET_ADDRESS */ 0x05, USB_DEBUG_DEVNUM, 0, NULL, 0) < 0) {
            return FALSE;
        }
    }
    if (UsbControlMessage(USB_DEBUG_DEVNUM, FALSE, /* SET_FEATURE */ 0x03, /* DEBUG_MODE */ 6, 0, NULL, 0) < 0) {
        return FALSE;
    }

    /* Throwaway 1-byte write, matching the reference -- syncs the data
       toggle state before real traffic starts. */
    UsbBulkWrite(USB_DEBUG_DEVNUM, DbgpEndpointOut, " ", 1);

    return TRUE;
}

/* Common tail for a bulk transaction: program address+pids, kick GO,
   poll for DONE, retry once on NAK (a device legitimately not being ready
   yet isn't a real error). Returns transferred byte count, or -1. */
static LONG
DbgpRunTransaction(IN ULONG DevNum, IN ULONG Endpoint, IN ULONG Token, IN ULONG Size)
{
    ULONG ctrl, pids;
    LONG loop = DBGP_LOOPS;

retry:
    EhciDbg->Address = DBGP_EPADDR(DevNum, Endpoint);

    pids = DBGP_PID_GET(EhciDbg->Pids);
    if (Token == USB_PID_OUT) {
        DbgpDataToggleOut ^= (USB_PID_DATA1 ^ USB_PID_DATA0);   /* flip DATA0/DATA1 each OUT, per spec */
        pids = DBGP_PID_SET(DbgpDataToggleOut, Token);
    } else {
        pids = DBGP_PID_SET(USB_PID_DATA0, Token);   /* IN/SETUP always request DATA0 here -- device's own toggle governs the reply */
    }
    EhciDbg->Pids = pids;

    ctrl = DBGP_CTRL_SET_LEN(EhciDbg->Control, Size);
    ctrl = (Token == USB_PID_OUT) ? (ctrl | DBGP_CTRL_OUT) : (ctrl & ~(ULONG)DBGP_CTRL_OUT);
    ctrl |= DBGP_CTRL_GO;
    EhciDbg->Control = ctrl;

    while (!(EhciDbg->Control & DBGP_CTRL_DONE) && loop--) {
        ;
    }
    if (loop <= 0) {
        return -1;
    }
    ctrl = EhciDbg->Control;
    EhciDbg->Control = ctrl | DBGP_CTRL_DONE;   /* write-1-to-clear */

    if (ctrl & DBGP_CTRL_ERROR) {
        return -1;
    }
    if (DBGP_PID_GET(EhciDbg->Pids) == USB_PID_NAK) {
        if (loop > 0) {
            goto retry;
        }
        return -1;
    }
    return (LONG)DBGP_CTRL_LEN(ctrl);
}

static LONG
UsbBulkWrite(IN ULONG DevNum, IN ULONG Endpoint, IN PCHAR Bytes, IN ULONG Size)
{
    if (Size > DBGP_MAX_PACKET) {
        return -1;
    }
    EhciDbg->Data03 = *(PULONG)(Bytes);
    EhciDbg->Data47 = (Size > 4) ? *(PULONG)(Bytes + 4) : 0;
    return DbgpRunTransaction(DevNum, Endpoint, USB_PID_OUT, Size);
}

static LONG
UsbBulkRead(IN ULONG DevNum, IN ULONG Endpoint, OUT PVOID Data, IN ULONG Size, IN LONG Loops)
{
    LONG ret = DbgpRunTransaction(DevNum, Endpoint, USB_PID_IN, Size);
    if (ret > 0) {
        ((PULONG)Data)[0] = EhciDbg->Data03;
        if (Size > 4) {
            ((PULONG)Data)[1] = EhciDbg->Data47;
        }
    }
    UNREFERENCED_PARAMETER(Loops);   /* retry budget is DbgpRunTransaction's own DBGP_LOOPS today, not per-call yet */
    return ret;
}

static LONG
UsbControlMessage(IN ULONG DevNum, IN BOOLEAN DirectionIn, IN UCHAR Request,
                   IN USHORT Value, IN USHORT Index, OUT PVOID Data, IN ULONG Size)
{
    UCHAR setupPacket[8];
    LONG ret;

    setupPacket[0] = (UCHAR)(DirectionIn ? 0x80 : 0x00) | 0x00 /* type=standard, recip=device */;
    setupPacket[1] = Request;
    setupPacket[2] = (UCHAR)(Value & 0xFF);
    setupPacket[3] = (UCHAR)(Value >> 8);
    setupPacket[4] = (UCHAR)(Index & 0xFF);
    setupPacket[5] = (UCHAR)(Index >> 8);
    setupPacket[6] = (UCHAR)(Size & 0xFF);
    setupPacket[7] = (UCHAR)(Size >> 8);

    EhciDbg->Pids = DBGP_PID_SET(USB_PID_DATA0, USB_PID_SETUP);   /* SETUP stage is always DATA0 */
    ret = UsbBulkWrite(DevNum, 0, (PCHAR)setupPacket, sizeof(setupPacket));
    if (ret < 0) {
        return ret;
    }
    if (!DirectionIn || Size == 0) {
        return 0;
    }
    return UsbBulkRead(DevNum, 0, Data, Size, DBGP_LOOPS);
}

static ULONG
UsbGetByte(IN PPORT_DESCRIPTOR Port, OUT PUCHAR Byte, IN BOOLEAN Wait)
{
    UCHAR buf[DBGP_MAX_PACKET];
    LONG  received;

    UNREFERENCED_PARAMETER(Port);

    received = UsbBulkRead(USB_DEBUG_DEVNUM, DbgpEndpointIn, buf, 1, Wait ? DBGP_LOOPS : 1);
    if (received <= 0) {
        return 1UL;   /* CP_GET_NODATA: 1 on timeout/no-data allows KdpReceivePacketLeader to return timeout */
    }
    *Byte = buf[0];
    return 0UL;
}

static VOID
UsbPutByte(IN PPORT_DESCRIPTOR Port, IN UCHAR Byte)
{
    UNREFERENCED_PARAMETER(Port);
    UsbBulkWrite(USB_DEBUG_DEVNUM, DbgpEndpointOut, (PCHAR)&Byte, 1);
}

static VOID UsbSave(IN PPORT_DESCRIPTOR Port)    { UNREFERENCED_PARAMETER(Port); }
static VOID UsbRestore(IN PPORT_DESCRIPTOR Port) { UNREFERENCED_PARAMETER(Port); }

KD_TRANSPORT KdUsbTransport = {
    "USB",
    UsbInitialize,
    UsbGetByte,
    UsbPutByte,
    UsbSave,
    UsbRestore
};
