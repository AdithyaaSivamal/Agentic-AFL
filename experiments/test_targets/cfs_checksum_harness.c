/*
 * cfs_checksum_harness.c — AFL++ fuzz harness for NASA cFS command checksum.
 *
 * Links against the REAL CFE_MSG_ValidateChecksum() and CFE_MSG_ComputeCheckSum()
 * from the NASA cFE source tree (github.com/nasa/cFE, Apache-2.0).
 *
 * The harness reads a raw CCSDS command packet from stdin and feeds it through
 * the complete validation pipeline:
 *   1. Primary header guards (version, type, secondary header flag)
 *   2. Packet data length consistency check
 *   3. XOR additive checksum validation (the math wall)
 *
 * If all checks pass, the harness prints "APDU_VALIDATED" to stderr.
 *
 * Build:
 *   afl-cc -O1 -g -no-pie \
 *     -include cfs_compat.h \
 *     cfs_checksum_harness.c cfe/modules/msg/fsw/src/cfe_msg_sechdr_checksum.c \
 *     -o cfs_checksum_harness
 */

#include "cfs_compat.h"
#include <stdio.h>
#include <stdlib.h>

/* Forward declarations — implemented in the real NASA source file */
extern CFE_Status_t CFE_MSG_ValidateChecksum(const CFE_MSG_Message_t *MsgPtr, bool *IsValid);
extern CFE_Status_t CFE_MSG_GenerateChecksum(CFE_MSG_Message_t *MsgPtr);

/*
 * Main: reads a CCSDS command packet from stdin and validates it.
 *
 * Return codes:
 *   0 = packet validated successfully (checksum OK)
 *   1 = packet rejected (too short, bad header, bad checksum)
 */
int main(int argc, char **argv)
{
    uint8_t buf[4096];
    size_t  n;

    /* Dual-mode input: file argument (for GDB probes) or stdin (for AFL++) */
    if (argc > 1)
    {
        FILE *f = fopen(argv[1], "rb");
        if (!f)
            return 1;
        n = fread(buf, 1, sizeof(buf), f);
        fclose(f);
    }
    else
    {
        /* Default: read from stdin (AFL++ feeds input this way) */
        n = fread(buf, 1, sizeof(buf), stdin);
    }

    /* Minimum CCSDS command: 6-byte primary + 2-byte secondary = 8 bytes */
    if (n < 8)
    {
        return 1;
    }

    /* ── Pre-validation: Packet Data Length consistency ─────────── */
    /* The CCSDS "Packet Data Length" field (bytes 4-5, big-endian) specifies
       the number of remaining bytes after the primary header, minus 1.
       Total packet size = PacketDataLength + 7.
       We must verify this matches the actual bytes read. */
    uint16_t pkt_data_len = ((uint16_t)buf[4] << 8) | buf[5];
    size_t   declared_size = (size_t)pkt_data_len + 7;

    if (declared_size > n || declared_size < 8)
    {
        return 1; /* Length field is inconsistent with input */
    }

    /* ── Pad buffer if needed (ensure clean memory beyond packet) ── */
    if (declared_size < sizeof(buf))
    {
        memset(buf + n, 0, sizeof(buf) - n);
    }

    /* ── Call the REAL NASA CFE_MSG_ValidateChecksum() ─────────── */
    /* This function internally checks:
       - HeaderVersion == CFE_MISSION_CCSDSVER (0)
       - Type == CFE_MSG_Type_Cmd
       - HasSecondaryHeader == true
       - XOR checksum over all packet bytes == 0
    */
    CFE_MSG_Message_t *msg = (CFE_MSG_Message_t *)buf;
    bool               is_valid = false;
    CFE_Status_t       status;

    status = CFE_MSG_ValidateChecksum(msg, &is_valid);

    if (status != CFE_SUCCESS)
    {
        /* Header guards failed (wrong version, type, or no secondary header) */
        return 1;
    }

    if (!is_valid)
    {
        /* Checksum mismatch — this is the math wall AFL cannot pass */
        return 1;
    }

    /* ═══════════════════════════════════════════════════════════════
     *  PAST THE MATH WALL — Packet is structurally and cryptographically valid
     * ═══════════════════════════════════════════════════════════════ */

    /* Extract function code from the command secondary header */
    uint8_t func_code = buf[6];

    /* Accept marker — used by test_generalization_matrix.py to detect bypass */
    fprintf(stderr, "APDU_VALIDATED fc=%u len=%zu\n", func_code, declared_size);

    /* Simulate deep command processing based on function code */
    switch (func_code)
    {
        case 0x00:
            fprintf(stderr, "CMD_NOOP_ACCEPTED\n");
            break;
        case 0x01:
            fprintf(stderr, "CMD_RESET_COUNTERS\n");
            break;
        case 0x02:
            if (declared_size >= 12)
            {
                /* Process a command with a 4-byte payload */
                uint32_t param = ((uint32_t)buf[8] << 24) | ((uint32_t)buf[9] << 16) |
                                 ((uint32_t)buf[10] << 8) | buf[11];
                fprintf(stderr, "CMD_SET_PARAM param=0x%08X\n", param);
            }
            break;
        default:
            fprintf(stderr, "CMD_UNKNOWN fc=%u\n", func_code);
            break;
    }

    return 0;
}
