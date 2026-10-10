/*
 * kdport_wrappers.c
 *
 * ADDITIVE-ONLY patch description. Given CpReadLsr turned out to bundle
 * cable-detection, error counters, and modem retraining (see kdtransport.h),
 * the original compiled Cp*() code is left completely alone. Nothing here
 * replaces it. Each of the five simple KdPort* exports gets a few bytes
 * prepended at its existing address -- a check against KdActiveTransport,
 * and a conditional jump either into new code (USB/NET) or straight into
 * the original, unmodified instructions that were already there. The
 * functions below are what that prepended check calls into; they are not
 * standalone replacements for the whole export.
 *
 * PACKING, worked out from addresses already on hand rather than a new
 * query: the five exports are packed with zero padding (KdPortGetByte's
 * address plus its own disassembled byte count lands exactly on
 * KdPortPollByte's address, and so on through KdPortSave, which the very
 * first live dump showed running straight into hal!HalpMapPhysicalMemory64
 * with nothing in between). Restore is the tight case -- 9 bytes of `and
 * word ptr [Port+8],0FFFBh` plus a 1-byte `ret`, 10 total. A 5-byte JMP
 * redirect at its start lands mid-instruction, so the "prepended check"
 * language above is shorthand for the standard fix: steal that whole 9-byte
 * instruction into the trampoline, execute it there, then jump back to
 * original+9 (the ret). Same idea for the other four, all of which have
 * more slack than Restore does. This doesn't change anything already
 * written here -- it's what makes the prologue-check description above
 * actually buildable rather than a hole in the plan.
 *
 * KdPortInitialize is the one exception in shape, not in spirit: instead of
 * a prologue check, the splice sits at its single existing call site --
 *
 *     push [PortInformation+4]     ; baud
 *     push eax                     ; resolved io_base
 *     push offset Port
 *     call CpInitialize
 *
 * -- which is where KdpTransportInitOverride below gets called instead.
 * Same rule applies: if nothing overrides it, the original three
 * instructions run exactly as compiled.
 */

#include "kdtransport.h"

PKD_TRANSPORT KdActiveTransport = NULL;   /* NULL = original code path, untouched */

/* Address of the HAL's real, existing Port global -- not allocated here. */
extern PORT_DESCRIPTOR Port;

#define LOADER_BLOCK_LOAD_OPTIONS_OFFSET 0x44   /* confirmed: dt nt!_LOADER_PARAMETER_BLOCK */

/*
 * Called from the splice at KdPortInitialize's CpInitialize call site.
 * ResolvedIoBase/BaudRate are exactly what that call site already has on
 * hand (eax, and [PortInformation+4]); LoaderBlock is KdPortInitialize's
 * own second argument, still needed here to reach LoadOptions.
 *
 * Returns TRUE/FALSE as CpInitialize itself would (BOOLEAN success), so the
 * splice can treat this call exactly like the call it's replacing.
 */
static __forceinline CHAR KdpToUpper(CHAR c)
{
    if (c >= 'a' && c <= 'z') {
        return c - ('a' - 'A');
    }
    return c;
}

static __forceinline PSTR KdpStrStr(PCSTR str, PCSTR substr)
{
    while (*str) {
        PCSTR h = str;
        PCSTR n = substr;
        while (*h && *n && (KdpToUpper(*h) == KdpToUpper(*n))) {
            h++;
            n++;
        }
        if (!*n) {
            return (PSTR)str;
        }
        str++;
    }
    return NULL;
}


BOOLEAN
KdpTransportInitOverride(
    IN OUT PPORT_DESCRIPTOR PortArg,
    IN ULONG ResolvedIoBase,
    IN ULONG BaudRate
    )
{
    PVOID LoaderBlock = NULL;
    PSTR loadOptions = NULL;

    __asm {
        mov LoaderBlock, ebx
    }

    if (LoaderBlock != NULL) {
        loadOptions = *(PSTR *)((PUCHAR)LoaderBlock + LOADER_BLOCK_LOAD_OPTIONS_OFFSET);
    }

    if (loadOptions != NULL && KdpStrStr(loadOptions, "DEBUGPORT=USB") != NULL) {
        if (KdUsbTransport.Initialize(PortArg, 0, BaudRate)) {
            KdActiveTransport = &KdUsbTransport;
            return TRUE;
        }
        KdActiveTransport = NULL;
        return CpInitialize(PortArg, ResolvedIoBase, BaudRate);
    }

    if (loadOptions != NULL && KdpStrStr(loadOptions, "DEBUGPORT=NET") != NULL) {
        if (KdNetTransport.Initialize(PortArg, 0, BaudRate)) {
            KdActiveTransport = &KdNetTransport;
            return TRUE;
        }
        KdActiveTransport = NULL;
        return CpInitialize(PortArg, ResolvedIoBase, BaudRate);
    }


    /* No override -- this is the fall-through case. KdActiveTransport stays
       NULL and the splice should really just be "call original CpInitialize
       here" rather than routing through this function at all; included for
       completeness/symmetry, not because it needs to exist at runtime. */
    return CpInitialize(PortArg, ResolvedIoBase, BaudRate);
}

/*
 * Each of these is what the prepended prologue check calls when
 * KdActiveTransport is non-NULL. When it's NULL, the prologue check jumps
 * past this entirely into the original, untouched function body -- these
 * are never reached for the serial case, and don't need a serial branch.
 */

ULONG
KdpTransportGetByteOverride(OUT PUCHAR Byte)
{
    return (ULONG)KdActiveTransport->GetByte(&Port, Byte, TRUE);
}

ULONG
KdpTransportPollByteOverride(OUT PUCHAR Byte)
{
    return (ULONG)KdActiveTransport->GetByte(&Port, Byte, FALSE);
}

VOID
KdpTransportPutByteOverride(IN UCHAR Byte)
{
    KdActiveTransport->PutByte(&Port, Byte);
}

VOID
KdpTransportSaveOverride(VOID)
{
    KdActiveTransport->Save(&Port);
}

VOID
KdpTransportRestoreOverride(VOID)
{
    KdActiveTransport->Restore(&Port);
}

/*
 * RESOLVED without a new query, from the KdPortInitialize disassembly
 * already on hand: ebx is set once from ARG2 at function entry
 * (mov ebx,[ebp+0xc]) and never reassigned anywhere in the function --
 * every later use is `test ebx,ebx` or `push dword ptr [ebx+30h]`, both
 * read-only, all the way to the epilogue's `pop ebx`. Every call in
 * between (HalpSetupAcpiPhase0, KeFindConfigurationEntry, CpDoesPortExist)
 * is a normal call under a convention where ebx is callee-saved, so none of
 * them touch it either. It's still the LoaderBlock pointer, unchanged, at
 * the CpInitialize call site -- the splice can read it there directly.
 *
 * Still open, low priority: nt!KdUpdateDataBlock+0x32's literal bytes
 * ("COM", inferred from behavior, not read directly like "DEBUGPORT" was).
 */
