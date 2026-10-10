/*
 * kdtransport_net.c
 *
 * Network KD transport -- multi-chipset, tries each in order:
 *   1. Realtek RTL8168/RTL8111 (real hardware, confirmed: Sandy Bridge
 *      machine with "Realtek PCIe GBE Family Controller", MAC 3C:D9:2B:53:7D:95)
 *   2. AMD PCnet Am79C970A  (QEMU fallback for development/testing)
 *
 * WIRE FRAMING: raw Ethernet, EtherType 0x88B5 (IEEE 802.1 Experimental).
 * Host bridge: Npcap/WinPcap on host-only or local network interface,
 * filter "ether proto 0x88b5", pipe bytes to WinDbg named pipe.
 * WinDbg: windbg -k com:pipe,port=\\.\pipe\KdNet,reconnect
 *
 * PHYSICAL ADDRESS: MiGetPteAddress-based (confirmed phase-0-safe).
 * See virt->phys note in kdtransport_usb.c -- same mechanism.
 *
 * STACK USAGE NOTE (critical):
 *   KdPortInitialize runs on the osloader's boot stack (~8KB), which is
 *   mostly consumed by ntoskrnl!KdInitSystem and other init functions by
 *   the time our code is called.  Every function call (non-inlined) adds
 *   ~20-40 bytes of stack frame (push ebp/mov ebp,esp + locals + params).
 *   The original CpInitialize uses <50 bytes of stack.  Our NET init was
 *   causing a triple fault because the deep call chain (NetInitialize ->
 *   FindNicByClass -> PciReadConfig32 * N -> PcnetInitialize -> HalPhysAddr
 *   * 4 -> MiGetPteAddress) exhausted the remaining stack.
 *
 *   FIX: All helper functions in the init path are __forceinline.  This
 *   eliminates call frames entirely -- the compiler folds everything into
 *   a single large function body with shared locals.  Only the top-level
 *   NetInitialize (called from KdpTransportInitOverride) and the runtime
 *   send/receive functions (called later on the kernel stack, which is
 *   much larger) remain as real function calls.
 */

#include "kdtransport.h"

/* ------------------------------------------------------------------ */
/*  Shared: Ethernet framing, physical address, PCI scan              */
/* ------------------------------------------------------------------ */

#define ETHER_ADDR_LEN    6
#define KD_ETHERTYPE_WIRE 0xB588   /* 0x88B5 big-endian on wire */
#define ETHER_HDR_SIZE    16       /* 6+6+2+2 */
#define MAX_ETHER_PAYLOAD 1500
#define NIC_BUF_SIZE      1520

static const UCHAR BroadcastMac[ETHER_ADDR_LEN] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

/*
 * Phase-0-safe physical address for HAL memory.
 * Uses inline assembly so the compiler emits relocatable 'mov eax, OFFSET symbol'
 * rather than folding (symbol - 0x80000000) into a non-relocatable compile-time constant.
 * At runtime, subtracting 0x80000000 from the relocated VA produces the exact physical address.
 */
static __forceinline ULONG HalPhysAddr(IN PVOID Va) {
    ULONG phys;
    __asm {
        mov eax, Va
        sub eax, 0x80000000
        mov phys, eax
    }
    return phys;
}

/*
 * Direct PCI Configuration Mechanism #1 (ports 0xCF8 / 0xCFC).
 * Phase-0 safe: does NOT call HalGetBusDataByOffset which crashes before
 * bus handlers are registered in Phase 1.
 * __forceinline: critical for boot stack conservation.
 */
static __forceinline ULONG PciReadConfig32(ULONG Bus, ULONG Slot, ULONG Func, ULONG Offset)
{
    ULONG address = 0x80000000UL | ((Bus & 0xFF) << 16) | ((Slot & 0x1F) << 11) | ((Func & 0x7) << 8) | (Offset & 0xFC);
    WRITE_PORT_ULONG((PULONG)0xCF8, address);
    return READ_PORT_ULONG((PULONG)0xCFC);
}

static __forceinline VOID PciWriteConfig32(ULONG Bus, ULONG Slot, ULONG Func, ULONG Offset, ULONG Value)
{
    ULONG address = 0x80000000UL | ((Bus & 0xFF) << 16) | ((Slot & 0x1F) << 11) | ((Func & 0x7) << 8) | (Offset & 0xFC);
    WRITE_PORT_ULONG((PULONG)0xCF8, address);
    WRITE_PORT_ULONG((PULONG)0xCFC, Value);
}

/*
 * FindNicByClass scans PCI buses for a device with a given Vendor/Device ID.
 * __forceinline: eliminates 6 out-pointer pushes + call frame on boot stack.
 */
static __forceinline BOOLEAN
FindNicByClass(IN ULONG VendorId, IN ULONG DeviceId,
               OUT PULONG Bus, OUT PULONG Slot, OUT PULONG Func,
               OUT PULONG IoBase)
{
    ULONG b, s, f, idReg, barVal, cmd;
    for (b = 0; b < 8; b++) {
        for (s = 0; s < 32; s++) {
            for (f = 0; f < 8; f++) {
                idReg = PciReadConfig32(b, s, f, 0x00);
                if (idReg == 0xFFFFFFFF || idReg == 0) {
                    if (f == 0) break;
                    continue;
                }
                if (idReg != ((DeviceId << 16) | VendorId))
                    continue;
                barVal = PciReadConfig32(b, s, f, 0x10);
                if (!(barVal & 0x1)) continue;   /* must be I/O BAR */

                /* Enable I/O Space (bit 0) and Bus Master DMA (bit 2) */
                cmd = PciReadConfig32(b, s, f, 0x04);
                cmd |= 0x0005;
                PciWriteConfig32(b, s, f, 0x04, cmd);

                *Bus = b; *Slot = s; *Func = f;
                *IoBase = barVal & ~0x3UL;
                return TRUE;
            }
        }
    }
    return FALSE;
}


/* Staging buffers shared by both chipset backends */
static UCHAR TxStage[MAX_ETHER_PAYLOAD];
static ULONG TxStageLen;
static UCHAR RxStage[NIC_BUF_SIZE];
static ULONG RxStageLen;
static ULONG RxStagePos;
static UCHAR NetMacAddr[ETHER_ADDR_LEN];

/* ------------------------------------------------------------------ */
/*  RTL8168 / RTL8111 backend                                         */
/* ------------------------------------------------------------------ */
/*
 * Confirmed target: Realtek PCIe GBE (RTL8111E or close variant) on
 * Sandy Bridge machine. VendorID 0x10EC, DeviceID 0x8168 covers the
 * whole RTL8168/RTL8111 family (B/C/D/E/F/G/H). Cable disconnected
 * in ipconfig -- plug in Ethernet to the host running the bridge tool.
 *
 * Register access: I/O ports (BAR0, bit 0 = 1 confirmed for PCIe Realtek).
 * All offsets relative to I/O base from BAR0.
 */

/* RTL8168 registers */
#define RTL_MAC         0x00   /* 6 bytes, read-only after reset */
#define RTL_CR          0x37   /* Command: RST(4)|RE(3)|TE(2) */
#define RTL_TCR         0x40   /* TX config (32-bit) */
#define RTL_RCR         0x44   /* RX config (32-bit) */
#define RTL_9346CR      0x50   /* EEPROM/config unlock: 0xC0=unlock, 0x00=lock */
#define RTL_IMR         0x3C   /* Interrupt mask (16-bit) -- keep 0 (polled) */
#define RTL_ISR         0x3E   /* Interrupt status (16-bit) -- write 1 to clear */
#define RTL_TNPDS_LO    0x20   /* TX Normal Priority Descriptor ring addr low  */
#define RTL_TNPDS_HI    0x24   /* TX Normal Priority Descriptor ring addr high */
#define RTL_RDSAR_LO    0xE4   /* RX Descriptor Start Address low  */
#define RTL_RDSAR_HI    0xE8   /* RX Descriptor Start Address high */
#define RTL_CR_RST      0x10
#define RTL_CR_RE       0x08
#define RTL_CR_TE       0x04
#define RTL_ISR_TOK     0x0004   /* TX OK */
#define RTL_ISR_ROK     0x0001   /* RX OK */

/* RTL8168 TX/RX descriptor (16 bytes, 256-byte aligned ring) */
typedef struct {
    volatile ULONG  Opts1;   /* OWN(31)|EOR(30)|FS(29)|LS(28)|len(15:0) */
    volatile ULONG  Opts2;   /* 0 */
    volatile ULONG  AddrLo;  /* buffer physical address */
    volatile ULONG  AddrHi;  /* 0 (32-bit physical) */
} RTL_DESC;

#define RTL_OWN   0x80000000UL
#define RTL_EOR   0x40000000UL
#define RTL_FS    0x20000000UL
#define RTL_LS    0x10000000UL

__declspec(align(256)) static RTL_DESC RtlTxRing[1];
__declspec(align(256)) static RTL_DESC RtlRxRing[1];
__declspec(align(8))   static UCHAR    RtlTxBuf[NIC_BUF_SIZE];
__declspec(align(8))   static UCHAR    RtlRxBuf[NIC_BUF_SIZE];

static ULONG RtlIoBase;

static VOID RtlSendFrame(IN const UCHAR *Data, IN ULONG Len)
{
    UCHAR *f = RtlTxBuf;
    ULONG frameLen, loop;

    if (!Len || Len > MAX_ETHER_PAYLOAD) return;

    RtlCopyMemory(f, BroadcastMac, ETHER_ADDR_LEN);     f += ETHER_ADDR_LEN;
    RtlCopyMemory(f, NetMacAddr, ETHER_ADDR_LEN);        f += ETHER_ADDR_LEN;
    *(PUSHORT)f = KD_ETHERTYPE_WIRE;                      f += 2;
    *(PUSHORT)f = (USHORT)Len;                            f += 2;
    RtlCopyMemory(f, Data, Len);

    frameLen = Len + ETHER_HDR_SIZE;
    if (frameLen < 60) frameLen = 60;   /* Ethernet minimum */

    RtlTxRing[0].AddrLo = HalPhysAddr(RtlTxBuf);
    RtlTxRing[0].AddrHi = 0;
    RtlTxRing[0].Opts2  = 0;
    RtlTxRing[0].Opts1  = RTL_OWN | RTL_EOR | RTL_FS | RTL_LS | frameLen;

    /* RTL8168 auto-starts TX when it sees an owned descriptor -- no TDMD needed */
    /* Poll OWN bit until cleared */
    for (loop = 100000; (RtlTxRing[0].Opts1 & RTL_OWN) && loop; loop--) { ; }

    /* Clear TX OK status */
    WRITE_PORT_USHORT((PUSHORT)(RtlIoBase + RTL_ISR), RTL_ISR_TOK);
}

static BOOLEAN RtlReceiveFrame(VOID)
{
    ULONG rxOpts, frameLen, payloadLen;
    UCHAR *f;

    if (RtlRxRing[0].Opts1 & RTL_OWN) return FALSE;   /* chip still owns it */

    rxOpts   = RtlRxRing[0].Opts1;
    frameLen = rxOpts & 0x3FFF;
    if (frameLen < ETHER_HDR_SIZE + 4) goto rearm;   /* too short, +4 for FCS */
    frameLen -= 4;   /* strip FCS */

    f = RtlRxBuf;
    if (*(PUSHORT)(f + 12) != KD_ETHERTYPE_WIRE) goto rearm;

    payloadLen = *(PUSHORT)(f + 14);
    if (!payloadLen || payloadLen > MAX_ETHER_PAYLOAD) goto rearm;
    if (payloadLen > frameLen - ETHER_HDR_SIZE)
        payloadLen = frameLen - ETHER_HDR_SIZE;

    RtlCopyMemory(RxStage, f + ETHER_HDR_SIZE, payloadLen);
    RxStageLen = payloadLen;
    RxStagePos = 0;

rearm:
    /* Re-arm: give descriptor back to chip */
    RtlRxRing[0].AddrLo = HalPhysAddr(RtlRxBuf);
    RtlRxRing[0].AddrHi = 0;
    RtlRxRing[0].Opts2  = 0;
    RtlRxRing[0].Opts1  = RTL_OWN | RTL_EOR | NIC_BUF_SIZE;

    WRITE_PORT_USHORT((PUSHORT)(RtlIoBase + RTL_ISR), RTL_ISR_ROK);
    return (RxStageLen > 0);
}

/*
 * RtlInitialize: __forceinline so it merges into NetInitialize's single
 * stack frame, avoiding another ~40 bytes of call overhead on the boot stack.
 */
static __forceinline BOOLEAN RtlInitialize(IN ULONG IoBase)
{
    ULONG i, loop;

    RtlIoBase = IoBase;

    /* Read MAC from APROM (offsets 0x00-0x05, always readable as bytes) */
    for (i = 0; i < ETHER_ADDR_LEN; i++)
        NetMacAddr[i] = READ_PORT_UCHAR((PUCHAR)(IoBase + RTL_MAC + i));

    /* Software reset */
    WRITE_PORT_UCHAR((PUCHAR)(IoBase + RTL_CR), RTL_CR_RST);
    for (loop = 100000; (READ_PORT_UCHAR((PUCHAR)(IoBase + RTL_CR)) & RTL_CR_RST) && loop; loop--) { ; }
    if (!loop) return FALSE;

    /* Unlock config registers */
    WRITE_PORT_UCHAR((PUCHAR)(IoBase + RTL_9346CR), 0xC0);

    /* Interrupts off (polled) */
    WRITE_PORT_USHORT((PUSHORT)(IoBase + RTL_IMR), 0x0000);
    WRITE_PORT_USHORT((PUSHORT)(IoBase + RTL_ISR), 0xFFFF);   /* clear all */

    /* TX ring: one descriptor, EOR always set */
    RtlZeroMemory(&RtlTxRing[0], sizeof(RtlTxRing[0]));
    RtlTxRing[0].Opts1 = RTL_EOR;   /* host owns, EOR so chip wraps */

    /* RX ring: one descriptor, give to chip */
    RtlRxRing[0].AddrLo = HalPhysAddr(RtlRxBuf);
    RtlRxRing[0].AddrHi = 0;
    RtlRxRing[0].Opts2  = 0;
    RtlRxRing[0].Opts1  = RTL_OWN | RTL_EOR | NIC_BUF_SIZE;

    /* Program descriptor ring addresses */
    WRITE_PORT_ULONG((PULONG)(IoBase + RTL_TNPDS_LO), HalPhysAddr(&RtlTxRing[0]));
    WRITE_PORT_ULONG((PULONG)(IoBase + RTL_TNPDS_HI), 0);
    WRITE_PORT_ULONG((PULONG)(IoBase + RTL_RDSAR_LO), HalPhysAddr(&RtlRxRing[0]));
    WRITE_PORT_ULONG((PULONG)(IoBase + RTL_RDSAR_HI), 0);

    /* TX config: IFG=normal, max DMA burst=unlimited */
    WRITE_PORT_ULONG((PULONG)(IoBase + RTL_TCR), 0x03000700);

    /* RX config: accept broadcast+multicast+physical, no FIFO threshold */
    WRITE_PORT_ULONG((PULONG)(IoBase + RTL_RCR), 0x0000E70F);

    /* Lock config, enable TX+RX */
    WRITE_PORT_UCHAR((PUCHAR)(IoBase + RTL_9346CR), 0x00);
    WRITE_PORT_UCHAR((PUCHAR)(IoBase + RTL_CR), RTL_CR_RE | RTL_CR_TE);

    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  AMD PCnet Am79C970A backend (QEMU development/testing only)       */
/* ------------------------------------------------------------------ */

#define PCNET_DWIO_RDP  0x10
#define PCNET_DWIO_RAP  0x14
#define PCNET_DWIO_BDP  0x1C
#define PCNET_BCR20     20
#define BCR20_SWSTYLE2  0x0002
#define PCNET_CSR0      0
#define PCNET_CSR1      1
#define PCNET_CSR2      2
#define PCNET_CSR3      3
#define CSR0_INIT       0x0001
#define CSR0_STRT       0x0002
#define CSR0_STOP       0x0004
#define CSR0_TDMD       0x0008
#define CSR0_IDON       0x0100
#define CSR0_TINT       0x0200
#define CSR0_RINT       0x0400
#define PCNET_OWN       0x8000
#define PCNET_STP       0x0200
#define PCNET_ENP       0x0100

typedef struct {
    volatile ULONG  Base; volatile SHORT  BufLen; volatile USHORT Status;
    volatile ULONG  MsgLen; volatile ULONG Reserved;
} PCNET_RX_ENTRY;
typedef struct {
    volatile ULONG  Base; volatile SHORT  BufLen; volatile USHORT Status;
    volatile ULONG  Misc; volatile ULONG Reserved;
} PCNET_TX_ENTRY;
typedef struct {
    USHORT Mode; UCHAR Rlen; UCHAR Tlen;
    UCHAR PAdr[6]; USHORT Reserved; UCHAR Ladrf[8];
    ULONG Rdra; ULONG Tdra;
} PCNET_INIT_BLOCK;

__declspec(align(16)) static PCNET_INIT_BLOCK PcnetInit;
__declspec(align(16)) static PCNET_RX_ENTRY   PcnetRxRing[1];
__declspec(align(16)) static PCNET_TX_ENTRY   PcnetTxRing[1];
__declspec(align(16)) static UCHAR            PcnetRxBuf[NIC_BUF_SIZE];
__declspec(align(16)) static UCHAR            PcnetTxBuf[NIC_BUF_SIZE];

static ULONG PcnetIoBase;

/*
 * PCnet CSR/BCR accessors: __forceinline for boot-stack safety.
 * These are called many times during PcnetInitialize and would each
 * add ~20 bytes of stack frame overhead if left as regular calls.
 */
static __forceinline VOID PcnetWrCSR(ULONG c, ULONG v) { WRITE_PORT_ULONG((PULONG)(PcnetIoBase+PCNET_DWIO_RAP),c); WRITE_PORT_ULONG((PULONG)(PcnetIoBase+PCNET_DWIO_RDP),v); }
static __forceinline ULONG PcnetRdCSR(ULONG c) { WRITE_PORT_ULONG((PULONG)(PcnetIoBase+PCNET_DWIO_RAP),c); return READ_PORT_ULONG((PULONG)(PcnetIoBase+PCNET_DWIO_RDP)); }
static __forceinline VOID PcnetWrBCR(ULONG c, ULONG v) { WRITE_PORT_ULONG((PULONG)(PcnetIoBase+PCNET_DWIO_RAP),c); WRITE_PORT_ULONG((PULONG)(PcnetIoBase+PCNET_DWIO_BDP),v); }

/* Set once NDIS is detected; used by NetGetByte to reduce timeout */
static BOOLEAN PcnetNdisDetected = FALSE;

/*
 * PcnetStartChip: initialize rings and start the Am79C973 chip.
 * Shared between PcnetInitialize and PcnetRearm to save binary space.
 */
static VOID PcnetStartChip(VOID)
{
    ULONG initPhys, loop;

    PcnetWrCSR(PCNET_CSR0, CSR0_STOP);

    PcnetInit.Rlen = 0; PcnetInit.Tlen = 0;
    RtlCopyMemory(PcnetInit.PAdr, NetMacAddr, ETHER_ADDR_LEN);
    PcnetInit.Rdra = HalPhysAddr(&PcnetRxRing[0]);
    PcnetInit.Tdra = HalPhysAddr(&PcnetTxRing[0]);

    PcnetRxRing[0].Base   = HalPhysAddr(PcnetRxBuf);
    PcnetRxRing[0].BufLen = (SHORT)(-(SHORT)NIC_BUF_SIZE);
    PcnetRxRing[0].Status = PCNET_OWN;
    RtlZeroMemory(&PcnetTxRing[0], sizeof(PcnetTxRing[0]));

    initPhys = HalPhysAddr(&PcnetInit);
    PcnetWrCSR(PCNET_CSR1, initPhys & 0xFFFF);
    PcnetWrCSR(PCNET_CSR2, (initPhys >> 16) & 0xFFFF);
    PcnetWrCSR(PCNET_CSR3, 0x5F00);   /* mask all interrupts */

    PcnetWrCSR(PCNET_CSR0, CSR0_INIT);
    for (loop = 100000; !(PcnetRdCSR(PCNET_CSR0) & CSR0_IDON) && loop; loop--) { ; }
    PcnetWrCSR(PCNET_CSR0, CSR0_IDON | CSR0_STRT);
}

/*
 * PcnetRearm: detect when the Windows NDIS miniport driver (pcntn5m.sys)
 * has reinitialized the Am79C973 chip with its own init block, overwriting
 * our KD transport's descriptor rings.  When detected, stop the chip,
 * reload our init block, and restart.
 *
 * Detection: CSR1 holds the low 16 bits of the init block physical address.
 * If it no longer matches our PcnetInit block, NDIS has taken over.
 *
 * Called only from PcnetSendFrame to minimize NDIS interference.
 */
static VOID PcnetRearm(VOID)
{
    ULONG initPhys, csr1Val;

    if (!PcnetIoBase) return;

    initPhys = HalPhysAddr(&PcnetInit);
    csr1Val  = PcnetRdCSR(PCNET_CSR1);

    if ((csr1Val & 0xFFFF) == (initPhys & 0xFFFF)) return;

    /* NDIS has taken over -- reclaim the chip for KD */
    PcnetNdisDetected = TRUE;
    PcnetStartChip();
}

static VOID PcnetSendFrame(IN const UCHAR *Data, IN ULONG Len)
{
    UCHAR *f = PcnetTxBuf;
    ULONG frameLen, loop;
    if (!Len || Len > MAX_ETHER_PAYLOAD) return;
    PcnetRearm();   /* Reclaim chip if NDIS driver took it */
    RtlCopyMemory(f, BroadcastMac, ETHER_ADDR_LEN);  f += ETHER_ADDR_LEN;
    RtlCopyMemory(f, NetMacAddr, ETHER_ADDR_LEN);     f += ETHER_ADDR_LEN;
    *(PUSHORT)f = KD_ETHERTYPE_WIRE;                   f += 2;
    *(PUSHORT)f = (USHORT)Len;                         f += 2;
    RtlCopyMemory(f, Data, Len);
    frameLen = Len + ETHER_HDR_SIZE;
    if (frameLen < 64) frameLen = 64;
    PcnetTxRing[0].Base   = HalPhysAddr(PcnetTxBuf);
    PcnetTxRing[0].BufLen = (SHORT)(-(SHORT)frameLen);
    PcnetTxRing[0].Misc   = 0;
    PcnetTxRing[0].Status = PCNET_OWN | PCNET_STP | PCNET_ENP;
    PcnetWrCSR(PCNET_CSR0, CSR0_TDMD);
    for (loop = 50000; (PcnetTxRing[0].Status & PCNET_OWN) && loop; loop--) { ; }
    PcnetWrCSR(PCNET_CSR0, CSR0_TINT);
}

static BOOLEAN PcnetReceiveFrame(VOID)
{
    ULONG frameLen, payloadLen; UCHAR *f;
    BOOLEAN valid = FALSE;

    if (PcnetRxRing[0].Status & PCNET_OWN) return FALSE;
    frameLen = PcnetRxRing[0].MsgLen & 0x0FFF;
    f = PcnetRxBuf;

    if (frameLen >= ETHER_HDR_SIZE && *(PUSHORT)(f+12) == KD_ETHERTYPE_WIRE) {
        payloadLen = *(PUSHORT)(f+14);
        if (payloadLen > 0 && payloadLen <= MAX_ETHER_PAYLOAD) {
            if (payloadLen > frameLen - ETHER_HDR_SIZE)
                payloadLen = frameLen - ETHER_HDR_SIZE;
            RtlCopyMemory(RxStage, f + ETHER_HDR_SIZE, payloadLen);
            RxStageLen = payloadLen;
            RxStagePos = 0;
            valid = TRUE;
        }
    }

    /* Re-arm descriptor after copying data */
    PcnetRxRing[0].BufLen = (SHORT)(-(SHORT)NIC_BUF_SIZE);
    PcnetRxRing[0].Status = PCNET_OWN;
    PcnetWrCSR(PCNET_CSR0, CSR0_RINT);

    return valid;
}

static __forceinline BOOLEAN PcnetInitialize(IN ULONG IoBase)
{
    ULONG i, loop;
    PcnetIoBase = IoBase;
    for (i = 0; i < ETHER_ADDR_LEN; i++)
        NetMacAddr[i] = READ_PORT_UCHAR((PUCHAR)(IoBase + i));
    READ_PORT_USHORT((PUSHORT)(IoBase + 0x14));   /* WIO reset */
    for (loop = 50000; loop; loop--) { ; }
    WRITE_PORT_ULONG((PULONG)(IoBase + PCNET_DWIO_RDP), 0);
    PcnetWrBCR(PCNET_BCR20, BCR20_SWSTYLE2);
    RtlZeroMemory(&PcnetInit, sizeof(PcnetInit));
    PcnetStartChip();
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  KD_TRANSPORT dispatch                                             */
/* ------------------------------------------------------------------ */

/* Which backend is active */
static enum { NIC_NONE, NIC_RTL8168, NIC_PCNET } ActiveNic = NIC_NONE;

static VOID FlushTx(VOID)
{
    if (!TxStageLen) return;
    if (ActiveNic == NIC_RTL8168) RtlSendFrame(TxStage, TxStageLen);
    else if (ActiveNic == NIC_PCNET) PcnetSendFrame(TxStage, TxStageLen);
    TxStageLen = 0;
}

static BOOLEAN PollRx(VOID)
{
    if (ActiveNic == NIC_RTL8168) return RtlReceiveFrame();
    if (ActiveNic == NIC_PCNET)   return PcnetReceiveFrame();
    return FALSE;
}

/*
 * NetInitialize: THE single entry point called during early boot.
 * All sub-functions are __forceinline, so the compiler produces a single
 * stack frame here.  This drastically reduces stack usage compared to
 * the original version that had 5+ nested call frames.
 */
static BOOLEAN
NetInitialize(IN OUT PPORT_DESCRIPTOR Port, IN ULONG U1, IN ULONG U2)
{
    ULONG bus, slot, func, ioBase;
    UNREFERENCED_PARAMETER(Port); UNREFERENCED_PARAMETER(U1); UNREFERENCED_PARAMETER(U2);

    TxStageLen = 0; RxStageLen = 0; RxStagePos = 0;

    /* Try RTL8168 (real hardware) -- DeviceID 0x8168 covers the whole family */
    if (FindNicByClass(0x10EC, 0x8168, &bus, &slot, &func, &ioBase)) {
        if (RtlInitialize(ioBase)) { ActiveNic = NIC_RTL8168; return TRUE; }
    }
    /* Same family, some boards report 0x8136 (100Mbps variants) */
    if (FindNicByClass(0x10EC, 0x8136, &bus, &slot, &func, &ioBase)) {
        if (RtlInitialize(ioBase)) { ActiveNic = NIC_RTL8168; return TRUE; }
    }

    /* Try PCnet (QEMU) */
    if (FindNicByClass(0x1022, 0x2000, &bus, &slot, &func, &ioBase)) {
        if (PcnetInitialize(ioBase)) { ActiveNic = NIC_PCNET; return TRUE; }
    }

    return FALSE;
}

static ULONG
NetGetByte(IN PPORT_DESCRIPTOR Port, OUT PUCHAR Byte, IN BOOLEAN Wait)
{
    ULONG timeout = 0;
    UNREFERENCED_PARAMETER(Port);

    for (;;) {
        if (RxStagePos < RxStageLen) {
            *Byte = RxStage[RxStagePos++];
            if (RxStagePos >= RxStageLen) { RxStageLen = 0; RxStagePos = 0; }
            return 0UL;         /* CP_GET_SUCCESS */
        }
        if (PollRx()) continue;
        if (!Wait) return 1UL;         /* CP_GET_NODATA for poll mode */

        /* Paced delay: read port 0x80 takes ~1us */
        READ_PORT_UCHAR((PUCHAR)0x80);

        /* Bounded timeout: 200ms normally, 5ms after NDIS detected.
         * Short timeout after NDIS prevents DPC-level deadlocks that
         * cause the "Preparing network connections..." hang. */
        if (++timeout >= (ULONG)(PcnetNdisDetected ? 5000 : 200000)) {
            return 1UL;                /* CP_GET_NODATA (timeout) */
        }
    }
}

static VOID
NetPutByte(IN PPORT_DESCRIPTOR Port, IN UCHAR Byte)
{
    ULONG leader;
    USHORT payloadLen;

    UNREFERENCED_PARAMETER(Port);

    if (TxStageLen < MAX_ETHER_PAYLOAD) {
        TxStage[TxStageLen++] = Byte;
    }

    if (TxStageLen >= 4) {
        leader = *(PULONG)&TxStage[0];
        if (leader == 0x69696969) {
            /* Control packet (ACK/NAK/RESEND): exactly 16 bytes, no trailing 0xAA */
            if (TxStageLen >= 16) {
                FlushTx();
                return;
            }
        } else if (leader == 0x30303030 || leader == 0x73737373) {
            /* Data packet: 16 bytes header + ByteCount payload + 1 byte (0xAA) */
            if (TxStageLen >= 8) {
                payloadLen = *(PUSHORT)&TxStage[6];
                if (TxStageLen >= (ULONG)(16 + payloadLen + 1)) {
                    FlushTx();
                    return;
                }
            }
        }
    }

    if (TxStageLen >= MAX_ETHER_PAYLOAD) {
        FlushTx();
    }
}

static VOID NetSave(IN PPORT_DESCRIPTOR Port)    { UNREFERENCED_PARAMETER(Port); }
static VOID NetRestore(IN PPORT_DESCRIPTOR Port) { UNREFERENCED_PARAMETER(Port); }

KD_TRANSPORT KdNetTransport = { "NET", NetInitialize, NetGetByte, NetPutByte, NetSave, NetRestore };

/*
 * RTL8168 OPEN: exact Device ID not yet confirmed via !pci.
 * 0x8168 covers RTL8168B/C/D/E/F/G (all PCIe GBE variants).
 * If FindNicByClass(0x10EC, 0x8168) misses it, run !pci 0 0 in WinDbg
 * to find the actual slot and !pci 110 0 <slot> 0 to read the exact ID,
 * then add it to the scan list above.
 *
 * RTL8168 DESCRIPTOR ALIGNMENT: 256-byte alignment confirmed in
 * RTL8168 datasheet. __declspec(align(256)) on RtlTxRing/RtlRxRing
 * handles this; the DDK compiler respects it for global variables.
 *
 * HOST-SIDE BRIDGE: same as PCnet version.
 *   Npcap on host, filter "ether proto 0x88b5", pipe to windbg named pipe.
 *   Run: windbg -k com:pipe,port=\\.\pipe\KdNet,reconnect
 */
