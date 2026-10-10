/*
 * kdtransport.h
 *
 * Pluggable byte-transport layer for the Windows 2000 HAL's kernel-debugger
 * port interface (KdPortInitialize / KdPortGetByte / KdPortPutByte /
 * KdPortPollByte / KdPortSave / KdPortRestore), reverse-engineered from
 * halmacpi.dll (KB891861 rollup) and cross-checked instruction-for-instruction
 * against a live "hal!" build via WinDbg.
 *
 * GOAL: ntoskrnl.exe and osloader.exe keep importing exactly the same six
 * names, same calling convention, from HAL.dll -- nothing above the HAL
 * changes. Below those six exports, the ORIGINAL serial Cp*() routines are
 * untouched, byte-for-byte -- see the CpReadLsr note further down for why.
 * KdActiveTransport is NULL by default, meaning "run the original code,
 * unmodified." It's only ever set to something when boot.ini explicitly
 * asks for USB or NET, at which point the relevant export's small prepended
 * check diverts to that transport instead of falling through.
 *
 * CONFIRMED FROM DISASSEMBLY, now cross-checked against the real hal! (x
 * hal!Cp*, x hal!Kd*, uf on all three) and against nt!KdInitSystem, the
 * actual caller:
 *
 *   KdPortGetByte(OUT PUCHAR Byte)  -> USHORT status   (internally Wait=TRUE)
 *   KdPortPollByte(OUT PUCHAR Byte) -> USHORT status   (internally Wait=FALSE)
 *     -- same CpGetByte call, differing only in the Wait argument. Byte is
 *        written through the out-pointer, status is the return value.
 *   KdPortPutByte(IN UCHAR Byte)    -> VOID
 *
 *   CpGetByte(Port, OUT PUCHAR Byte, BOOLEAN Wait) -> USHORT
 *       0 = byte written, success
 *       1 = Port->IoBase was 0 (never initialized)
 *       2 = no data available (only reachable when Wait == FALSE)
 *   CpPutByte(Port, UCHAR Byte) -> VOID
 *   CpInitialize(Port, IoBase, BaudRate) -> VOID. Real body, confirmed:
 *       Port->Reserved1 = 0; Port->IoBase = IoBase; CpSetBaud(Port, BaudRate);
 *       WRITE_PORT_UCHAR(IoBase+4, 3);   -- MCR: DTR+RTS asserted
 *       WRITE_PORT_UCHAR(IoBase+1, 0);   -- IER: all UART interrupts off
 *   CpSetBaud(Port, BaudRate), CpReadLsr(Port, Mask), CpDoesPortExist(IoBase)
 *     are real, separately-named functions (confirmed via `x hal!Cp*`) --
 *     CpReadLsr is what this file's SerialGetByte/PutByte polling loops
 *     were inlining as a nameless helper; CpSetBaud does the divisor/DLAB
 *     sequence; CpDoesPortExist is what KdPortInitialize itself uses to
 *     probe COM2-then-COM1 when nothing else resolved a port. None of
 *     their three bodies are disassembled yet -- next thing to pull.
 *
 *   Port+0x00 = IoBase (confirmed), Port+0x04 = BaudRate -- CORRECTED, was
 *   wrong two messages ago (said +0x24). Port+0x08 = Flags, low byte only:
 *   bit 0x2 = flow-control-check enable, bit 0x4 = Save/Restore toggle.
 *   Port+0x28 = 1 in the live dump -- new, meaning not yet known.
 *
 *   IMPORTANT CORRECTION: what I was calling "Port+0x20/+0x24" two messages
 *   back is NOT part of this struct at all -- `hal!PortInformation` is a
 *   SEPARATE global that happens to sit 0x20 bytes after Port in memory
 *   (confirmed by its own symbol name in the KdPortInitialize disassembly).
 *   It's KdPortInitialize's own staging pair for whichever io_base/baud it
 *   resolved, mirrored there before the real CpInitialize call -- CpGetByte/
 *   CpPutByte never read it. Nothing here should reference it.
 *
 * FULLY RESOLVED, this round:
 *
 *   LoaderBlock->LoadOptions really is at +0x44 -- `dt
 *   nt!_LOADER_PARAMETER_BLOCK` confirmed it directly, and independently
 *   ConfigurationRoot at +0x30 matches the `[ebx+0x30]` KeFindConfigurationEntry
 *   calls in KdPortInitialize. The splice in kdport_wrappers.c was right.
 *
 *   The full DEBUGPORT= parsing chain, traced through nt!KdInitSystem:
 *   LoadOptions gets _strupr()'d, then searched for "DEBUGPORT". If found,
 *   it searches (from that point on, not from the start of the string) for
 *   "COM" and atol()'s three characters past the match straight into
 *   KdDebugParameters[0] -- confirmed by the live dd (KdDebugParameters[0]
 *   was 1, matching a boot.ini of COM1). A SEPARATE, unconditional search
 *   for "BAUDRATE" (8 chars, matching the `add esi,8` before the atol in
 *   the disassembly) fills KdDebugParameters[4] with the baud. Nothing
 *   about this cares what's between "DEBUGPORT=" and "COM" or whether "COM"
 *   is even there -- boot.ini'ing /DEBUGPORT=USB today would simply fail
 *   the "COM" search and leave KdDebugParameters[0] at 0, which
 *   KdPortInitialize already treats as "no explicit port, auto-detect."
 *   Nothing breaks; it just silently falls back to ACPI-table/probe
 *   detection. The USB/NET check in kdport_wrappers.c is what turns that
 *   from a silent no-op into an actual branch.
 *
 *   CpSetBaud, confirmed: divisor = 0x1C200 / baud, exactly as assumed. One
 *   correction -- the DLAB-set LCR write is read-modify-write
 *   (existing_LCR | 0x80), not a flat 0x83; the final LCR write (DLAB
 *   clear) is a flat 3, matching what was already here. Fixed in
 *   kdtransport_serial.c.
 *
 * DESIGN CHANGE, this round -- CpReadLsr:
 *
 *   This is NOT a simple masked LSR poll the way SerialReadLsr() modeled
 *   it. The real function -- called as CpReadLsr(Port, Mask) -- also: counts
 *   consecutive all-1s LSR reads and disables the port entirely past a
 *   threshold (cable-unplugged detection), tracks individual framing/
 *   parity/overrun error bits into separate counters, polls the Modem
 *   Status Register against Port->Flags and a real-time-clock timestamp to
 *   detect a stale connection and re-send a modem init string
 *   (CpSendModemString -- this HAL has actual dial-up modem KD support
 *   bundled into the same poll loop), and calls HalpCheckPowerButton on the
 *   way through. None of that is something a from-scratch reconstruction
 *   should silently drop.
 *
 *   Consequence: kdtransport_serial.c is being DEMOTED to reference/
 *   documentation only. It is not what the patch uses for the serial path.
 *   The actual patch leaves CpInitialize/CpGetByte/CpPutByte/CpReadLsr/
 *   CpSetBaud's compiled code completely untouched, and is additive-only:
 *   each of the five simple KdPort* exports gets a small prepended check
 *   ("if a non-serial transport is active, call it and return; otherwise
 *   fall through to the original instructions, unmodified"), and
 *   KdPortInitialize keeps the same single-call-site splice as before. This
 *   is safer than replacing working, more-subtle-than-expected code with a
 *   reconstruction that's one poll loop and misses cable-detection, error
 *   counters, and modem retraining. See kdport_wrappers.c.
 *
 * Still open, lower priority: the literal bytes of the "COM" search string
 * (nt!KdUpdateDataBlock+0x32) haven't been read directly -- inferred with
 * high confidence from behavior (3-char skip, atol matches the known COM
 * number) but not confirmed byte-for-byte like "DEBUGPORT" was.
 */

#ifndef _KDTRANSPORT_H_
#define _KDTRANSPORT_H_

#include <ntddk.h>

/*
 * This is the HAL's existing static global -- we never allocate, resize,
 * or reinterpret it, and we don't add fields to it. Only IoBase, Flags,
 * and BaudRate are confirmed; everything else is unmapped padding.
 */
typedef struct _PORT_DESCRIPTOR {
    ULONG  IoBase;          /* +0x00 -- confirmed */
    ULONG  BaudRate;        /* +0x04 -- confirmed (corrected from +0x24) */
    USHORT Flags;           /* +0x08 -- confirmed, low byte only */
    UCHAR  Unknown_0A[30];  /* +0x0A -- not mapped. +0x28 reads back as 1
                               live; meaning unknown. Size here is only
                               enough to reach +0x28, still a guess past that. */
} PORT_DESCRIPTOR, *PPORT_DESCRIPTOR;

#define PORT_FLAG_CHECK_FLOW_CONTROL 0x2
#define PORT_FLAG_SAVE_RESTORE_BIT   0x4

typedef struct _KD_TRANSPORT {

    PCSTR Name;  /* matched case-insensitively against the boot.ini DEBUGPORT= value */

    /*
     * DeviceSelector: serial gets the classic io_base (0x3F8 et al.);
     * USB/NET get 0 today and probe for their own hardware. Parameter is
     * BaudRate for serial, unused so far for USB/NET.
     */
    BOOLEAN (*Initialize)(IN OUT PPORT_DESCRIPTOR Port, IN ULONG DeviceSelector, IN ULONG Parameter);

    /* Match the real CpGetByte signature: returns ULONG (0=success, 1=not init, 2=nodata). */
    ULONG (*GetByte)(IN PPORT_DESCRIPTOR Port, OUT PUCHAR Byte, IN BOOLEAN Wait);

    /* Exact match to the real CpPutByte signature. */
    VOID (*PutByte)(IN PPORT_DESCRIPTOR Port, IN UCHAR Byte);

    /* The original Save/Restore just toggle Port+0x8 bit 2, which
       CpReadLsr's flow-control/modem-timing logic reads. Meaningless to
       USB/NET, which never go through CpReadLsr -- both can no-op. */
    VOID (*Save)(IN PPORT_DESCRIPTOR Port);
    VOID (*Restore)(IN PPORT_DESCRIPTOR Port);

} KD_TRANSPORT, *PKD_TRANSPORT;

extern KD_TRANSPORT KdUsbTransport;     /* kdtransport_usb.c -- EHCI debug-port, stub pending hardware check */
extern KD_TRANSPORT KdNetTransport;     /* kdtransport_net.c -- raw NIC, stub pending chipset choice */

/*
 * NULL = run the original, untouched HAL code (serial or whatever
 * KdPortInitialize's own ACPI/probe logic found). Non-NULL = boot.ini
 * asked for USB or NET; each patched export diverts to it instead of
 * falling through to the original instructions.
 */
extern PKD_TRANSPORT KdActiveTransport;

#ifndef PCI_SLOT_NUMBER_MAKE
#define PCI_SLOT_NUMBER_MAKE(device, function) (((device) & 0x1F) | (((function) & 0x7) << 5))
#endif

/* HAL internal functions called by transport code and wrappers */
BOOLEAN NTAPI CpInitialize(IN OUT PPORT_DESCRIPTOR Port, IN ULONG ResolvedIoBase, IN ULONG BaudRate);
ULONG NTAPI MiGetPteAddress(IN ULONG VirtualAddress);

#endif /* _KDTRANSPORT_H_ */

