/*
 * hal_addresses.h
 *
 * Confirmed virtual addresses and RVAs of HAL-internal functions and exports
 * in halmacpi.dll from Windows 2000 SP4 + KB891861 Update Rollup 1.
 *
 * File: halmacpi.dll  (KB891861 rollup)
 * Size: 85,888 bytes
 * Preferred load base (ImageBase): 0x80010000
 *
 * Note on live WinDbg vs PE base:
 * In live debug sessions where HAL was relocated to 0x80062000, addresses were
 * shifted by +0x52000 relative to the PE ImageBase (0x80010000). The values
 * below provide both the RVAs and the ImageBase VAs.
 */

#ifndef _HAL_ADDRESSES_H_
#define _HAL_ADDRESSES_H_

/* Preferred image base of halmacpi.dll */
#define HALMACPI_LOAD_BASE      0x80010000UL

/* ---- Cp* serial routines (internal, NOT exported) ---- */
#define RVA_CpInitialize        0x4EB4UL
#define RVA_CpSetBaud           0x4EEAUL
#define RVA_CpReadLsr           0x501FUL
#define RVA_CpGetByte           0x526CUL
#define RVA_CpPutByte           0x5208UL
#define RVA_CpDoesPortExist     0x532CUL
#define RVA_CpSendModemString   0x4F48UL

#define ADDR_CpInitialize       (HALMACPI_LOAD_BASE + RVA_CpInitialize)       /* 0x80014EB4 */
#define ADDR_CpSetBaud          (HALMACPI_LOAD_BASE + RVA_CpSetBaud)          /* 0x80014EEA */
#define ADDR_CpReadLsr          (HALMACPI_LOAD_BASE + RVA_CpReadLsr)          /* 0x8001501F */
#define ADDR_CpGetByte          (HALMACPI_LOAD_BASE + RVA_CpGetByte)          /* 0x8001526C */
#define ADDR_CpPutByte          (HALMACPI_LOAD_BASE + RVA_CpPutByte)          /* 0x80015208 */
#define ADDR_CpDoesPortExist    (HALMACPI_LOAD_BASE + RVA_CpDoesPortExist)    /* 0x8001532C */
#define ADDR_CpSendModemString  (HALMACPI_LOAD_BASE + RVA_CpSendModemString)  /* 0x80014F48 */

/* ---- HAL exported functions (also accessible by absolute addr) ---- */
#define RVA_HalGetBusDataByOffset    0x6640UL
#define RVA_HalpMapPhysicalMemory64  0x7182UL

#define ADDR_HalGetBusDataByOffset    (HALMACPI_LOAD_BASE + RVA_HalGetBusDataByOffset)   /* 0x80016640 */
#define ADDR_HalpMapPhysicalMemory64  (HALMACPI_LOAD_BASE + RVA_HalpMapPhysicalMemory64) /* 0x80017182 */

/* ---- HAL internal page-table helper ---- */
#define RVA_MiGetPteAddress     0x6978UL
#define ADDR_MiGetPteAddress    (HALMACPI_LOAD_BASE + RVA_MiGetPteAddress)    /* 0x80016978 */

/* ---- KdPort* export entry points (patched by kdpatch.py) ---- */
#define RVA_KdPortInitialize    0x6EDCUL
#define RVA_KdPortGetByte       0x7132UL
#define RVA_KdPortPollByte      0x7148UL
#define RVA_KdPortPutByte       0x715EUL
#define RVA_KdPortRestore       0x7170UL
#define RVA_KdPortSave          0x717AUL

#define ADDR_KdPortInitialize   (HALMACPI_LOAD_BASE + RVA_KdPortInitialize)   /* 0x80016EDC */
#define ADDR_KdPortGetByte      (HALMACPI_LOAD_BASE + RVA_KdPortGetByte)      /* 0x80017132 */
#define ADDR_KdPortPollByte     (HALMACPI_LOAD_BASE + RVA_KdPortPollByte)     /* 0x80017148 */
#define ADDR_KdPortPutByte      (HALMACPI_LOAD_BASE + RVA_KdPortPutByte)      /* 0x8001715E */
#define ADDR_KdPortRestore      (HALMACPI_LOAD_BASE + RVA_KdPortRestore)      /* 0x80017170 */
#define ADDR_KdPortSave         (HALMACPI_LOAD_BASE + RVA_KdPortSave)         /* 0x8001717A */

/* ---- The specific CpInitialize call site inside KdPortInitialize ---- */
/* At RVA 0x70A1 (VA 0x800170A1): E8 0E DE FF FF   call CpInitialize (0x80014EB4) */
#define RVA_CALL_CpInit_SITE    0x70A1UL
#define ADDR_CALL_CpInit_SITE   (HALMACPI_LOAD_BASE + RVA_CALL_CpInit_SITE)
#define BYTES_CALL_CpInit       { 0xE8, 0x0E, 0xDE, 0xFF, 0xFF }

/* ---- hal!Port and PortInformation globals ---- */
#define RVA_Port                0x8C50UL
#define RVA_PortInformation     0x8C70UL
#define ADDR_Port               (HALMACPI_LOAD_BASE + RVA_Port)               /* 0x80018C50 */
#define ADDR_PortInformation    (HALMACPI_LOAD_BASE + RVA_PortInformation)    /* 0x80018C70 */

/* ---- Confirmed loader block offset ---- */
#define LOADER_BLOCK_LOAD_OPTIONS_OFFSET 0x044UL

#endif /* _HAL_ADDRESSES_H_ */
