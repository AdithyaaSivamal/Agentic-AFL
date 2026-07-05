/*
 * cfs_compat.h — Minimal compatibility shim for compiling cFE msg module
 *                outside the full cFS build system.
 *
 * This header provides the types, macros, and inline functions that
 * cfe_msg_sechdr_checksum.c depends on, without requiring OSAL/PSP.
 *
 * The actual checksum algorithm in cfe_msg_sechdr_checksum.c is UNMODIFIED
 * NASA source code from github.com/nasa/cFE (Apache-2.0 License).
 */
#ifndef CFS_COMPAT_H
#define CFS_COMPAT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

/* ── OSAL common_types.h replacements ───────────────────────────────── */
typedef uint8_t   uint8;
typedef uint16_t  uint16;
typedef int32_t   int32;
typedef uint32_t  uint32;
typedef size_t    cpusize;

/* ── cFE Status codes ───────────────────────────────────────────────── */
typedef int32 CFE_Status_t;
#define CFE_SUCCESS          ((int32)0x00000000)
#define CFE_MSG_BAD_ARGUMENT ((int32)0xc400FFFF)
#define CFE_MSG_WRONG_MSG_TYPE ((int32)0xc400FFFE)

/* ── CCSDS Primary Header (Big Endian on wire) ──────────────────────── */
/* Matches NASA ccsds_hdr.h / default_cfe_msg_hdr_pri.h */

typedef struct {
    uint8 StreamId[2];    /* Byte 0-1: Version(3) | Type(1) | SecHdrFlag(1) | APID(11) */
    uint8 Sequence[2];    /* Byte 2-3: SeqFlags(2) | SeqCount(14) */
    uint8 Length[2];      /* Byte 4-5: Packet Data Length (remaining - 1) */
} CCSDS_PrimaryHeader_t;

/* ── Command Secondary Header ──────────────────────────────────────── */
typedef uint8 CFE_MSG_FunctionCode_t;
typedef uint8 CFE_MSG_Checksum_t;

typedef struct {
    CFE_MSG_FunctionCode_t FunctionCode;  /* Byte 6 */
    CFE_MSG_Checksum_t     Checksum;      /* Byte 7 */
} CFE_MSG_CommandSecondaryHeader_t;

/* ── Combined message types ────────────────────────────────────────── */
typedef union {
    CCSDS_PrimaryHeader_t Pri;
    uint8                 Byte[1];   /* Variable-length overlay */
} CFE_MSG_Message_t;

typedef struct {
    CFE_MSG_Message_t                Msg;
    CFE_MSG_CommandSecondaryHeader_t Sec;
} CFE_MSG_CommandHeader_t;

/* ── Size type ─────────────────────────────────────────────────────── */
typedef cpusize CFE_MSG_Size_t;

/* ── Header Version (CCSDS v1 = 0) ────────────────────────────────── */
typedef uint16 CFE_MSG_HeaderVersion_t;
#define CFE_MISSION_CCSDSVER 0

/* ── Message Type enum ─────────────────────────────────────────────── */
typedef enum {
    CFE_MSG_Type_Invalid = 0,
    CFE_MSG_Type_Tlm     = 0,
    CFE_MSG_Type_Cmd     = 1,
} CFE_MSG_Type_t;

/* ── Accessor functions matching the cFE MSG API ──────────────────── */
/* These inline functions extract fields from the CCSDS primary header.
   They match the real cFE implementations in cfe_msg_ccsdspri.c. */

static inline CFE_Status_t CFE_MSG_GetSize(const CFE_MSG_Message_t *MsgPtr, CFE_MSG_Size_t *Size)
{
    /* CCSDS packet data length = (Length[0]<<8 | Length[1]) + 7
       (+7 accounts for the 6-byte primary header + the 1-byte offset) */
    *Size = ((uint16)MsgPtr->Pri.Length[0] << 8 | MsgPtr->Pri.Length[1]) + 7;
    return CFE_SUCCESS;
}

static inline CFE_Status_t CFE_MSG_GetHeaderVersion(const CFE_MSG_Message_t *MsgPtr, CFE_MSG_HeaderVersion_t *Version)
{
    /* Version is bits [15:13] of StreamId word = top 3 bits of byte 0 */
    *Version = (MsgPtr->Pri.StreamId[0] >> 5) & 0x07;
    return CFE_SUCCESS;
}

static inline CFE_Status_t CFE_MSG_GetType(const CFE_MSG_Message_t *MsgPtr, CFE_MSG_Type_t *Type)
{
    /* Type is bit [12] of StreamId word = bit 4 of byte 0 */
    *Type = ((MsgPtr->Pri.StreamId[0] >> 4) & 0x01) ? CFE_MSG_Type_Cmd : CFE_MSG_Type_Tlm;
    return CFE_SUCCESS;
}

static inline CFE_Status_t CFE_MSG_GetHasSecondaryHeader(const CFE_MSG_Message_t *MsgPtr, bool *HasSecondary)
{
    /* SecHdrFlag is bit [11] of StreamId word = bit 3 of byte 0 */
    *HasSecondary = ((MsgPtr->Pri.StreamId[0] >> 3) & 0x01) ? true : false;
    return CFE_SUCCESS;
}

/* ── Suppress includes that cfe_msg_sechdr_checksum.c pulls in ───── */
#define CFE_MSG_H          /* Prevent cfe_msg.h from being included */
#define CFE_MSG_PRIV_H     /* Prevent cfe_msg_priv.h from being included */
#define CFE_MSG_DEFAULTS_H /* Prevent cfe_msg_defaults.h */

#endif /* CFS_COMPAT_H */
