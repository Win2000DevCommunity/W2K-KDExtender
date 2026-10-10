/*
 * kdtransport_serial.c -- REFERENCE / DOCUMENTATION ONLY, not part of the
 * patch.
 *
 * CpReadLsr turned out to bundle cable-detection (consecutive-0xFF
 * counting), per-bit error counters, MSR/RTC-timestamp-based modem
 * retraining (CpSendModemString), and a power-button check -- see
 * kdtransport.h. A from-scratch poll-loop reconstruction would silently
 * drop all of that, so the actual patch leaves CpInitialize/CpGetByte/
 * CpPutByte/CpReadLsr/CpSetBaud's compiled code completely untouched
 * (kdport_wrappers.c is additive-only now) rather than routing serial
 * traffic through this file. Kept here as a readable account of what the
 * simple, non-modem, non-error-tracking happy path does -- useful for
 * understanding the algorithm, not for building against.
 */

#include "kdtransport.h"

/*
 * No COM1-4 string table here anymore -- KdPortInitialize's own ACPI-table/
 * KeFindConfigurationEntry/CpDoesPortExist-probe logic (untouched by the
 * patch, see kdport_wrappers.c) still does that resolution exactly as
 * before, and hands this file the already-resolved io_base directly.
 */

/*
 * CpSetBaud's own body isn't disassembled yet -- the divisor/DLAB sequence
 * below is carried over from before as the standard 16550 approach and is
 * very likely what it does, but treat it as one notch less certain than
 * everything else in this file until `uf hal!CpSetBaud` confirms it.
 */
/* Confirmed via `uf hal!CpSetBaud` -- matches exactly except the DLAB-set
   write, which is read-modify-write (preserves the existing LCR bits and
   ORs in 0x80), not a flat 0x83 the way this first assumed. */
static VOID
SerialSetBaud(IN ULONG IoBase, IN ULONG BaudRate)
{
    USHORT divisor = (USHORT)(115200 / BaudRate);
    UCHAR existingLcr = READ_PORT_UCHAR((PUCHAR)(IoBase + 3));
    WRITE_PORT_UCHAR((PUCHAR)(IoBase + 3), existingLcr | 0x80);       /* DLAB set, other bits preserved */
    WRITE_PORT_UCHAR((PUCHAR)(IoBase + 1), (UCHAR)(divisor >> 8));    /* divisor MSB -- real order is MSB then LSB */
    WRITE_PORT_UCHAR((PUCHAR)(IoBase + 0), (UCHAR)(divisor & 0xFF));  /* divisor LSB */
    WRITE_PORT_UCHAR((PUCHAR)(IoBase + 3), 0x03);                     /* DLAB clear, flat 8N1 -- confirmed */
}

static BOOLEAN
SerialInitialize(
    IN OUT PPORT_DESCRIPTOR Port,
    IN ULONG IoBase,
    IN ULONG BaudRate
    )
{
    if (IoBase == 0 || BaudRate == 0) {
        return FALSE;
    }

    /* confirmed sequence, from `uf hal!CpInitialize`: */
    Port->BaudRate = 0;         /* Port+0x4 zeroed first (disassembly: and dword ptr [esi+4],0) */
    Port->IoBase = IoBase;      /* +0x00 -- confirmed */
    SerialSetBaud(IoBase, BaudRate);   /* CpSetBaud(Port, BaudRate) -- also the thing that ends up
                                           leaving BaudRate readable back at Port+0x4, per the live dd */
    Port->BaudRate = BaudRate;
    WRITE_PORT_UCHAR((PUCHAR)(IoBase + 4), 0x03);   /* MCR: DTR+RTS asserted -- confirmed, wasn't in the first pass */
    WRITE_PORT_UCHAR((PUCHAR)(IoBase + 1), 0x00);   /* IER: interrupts off -- confirmed, explicit in the real code */

    Port->Flags = 0;
    return TRUE;
}

/*
 * Named to match the confirmed hal!CpReadLsr(Port, Mask) -- real signature
 * is 2 args (8 bytes per `x hal!Cp*`), consistent with (Port, MaskToTestFor)
 * rather than taking IoBase directly the way this stand-in does; body still
 * not disassembled, this is the same LSR-bit-poll both GetByte and PutByte
 * were already separately inlining, just named and shared now.
 */
static UCHAR
SerialReadLsr(IN ULONG IoBase)
{
    return READ_PORT_UCHAR((PUCHAR)(IoBase + 5));
}

static ULONG
SerialGetByte(
    IN PPORT_DESCRIPTOR Port,
    OUT PUCHAR Byte,
    IN BOOLEAN Wait
    )
{
    ULONG retries = Wait ? 0x32000 : 1;   /* confirmed constant: 0x31FFF + 1 in the disassembly */

    if (Port->IoBase == 0) {
        return 1UL;   /* confirmed: "never initialized" status */
    }

    if (Port->Flags & PORT_FLAG_CHECK_FLOW_CONTROL) {
        UCHAR msr = READ_PORT_UCHAR((PUCHAR)(Port->IoBase + 6));
        if ((msr & 0xB0) == 0xB0) {
            /* line not ready -- matches the CTS-ish check in the disassembly */
            return 2UL;
        }
    }

    while (retries--) {
        if (SerialReadLsr(Port->IoBase) & 0x01) {   /* Data Ready */
            *Byte = READ_PORT_UCHAR((PUCHAR)Port->IoBase);
            return 0UL;                              /* success */
        }
    }
    return 2UL;   /* confirmed: "no data", only reachable when Wait == FALSE */
}

static VOID
SerialPutByte(
    IN PPORT_DESCRIPTOR Port,
    IN UCHAR Byte
    )
{
    if (Port->IoBase == 0) {
        return;
    }
    while (!(SerialReadLsr(Port->IoBase) & 0x20))   /* wait for THR empty */
        ;
    WRITE_PORT_UCHAR((PUCHAR)Port->IoBase, Byte);
}

static VOID
SerialSave(
    IN PPORT_DESCRIPTOR Port
    )
{
    Port->Flags |= PORT_FLAG_SAVE_RESTORE_BIT;   /* confirmed: Port+0x8 bit 2 */
}

static VOID
SerialRestore(
    IN PPORT_DESCRIPTOR Port
    )
{
    Port->Flags &= ~PORT_FLAG_SAVE_RESTORE_BIT;
}

KD_TRANSPORT KdSerialTransport = {
    "COM",
    SerialInitialize,
    SerialGetByte,
    SerialPutByte,
    SerialSave,
    SerialRestore
};
