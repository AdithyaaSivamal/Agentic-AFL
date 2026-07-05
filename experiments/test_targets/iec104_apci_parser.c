/*
 * iec104_apci_parser.c — IEC 60870-5-104 APCI Header Parser.
 *
 * This program simulates an IEC-104 responder that validates incoming
 * APDU (Application Protocol Data Unit) frames through 4 constraint walls.
 *
 * IEC-104 APCI Header (6 bytes):
 *   [0]    Start Byte       (must be 0x68)
 *   [1]    APDU Length       (4-253, length of remaining bytes)
 *   [2-3]  Control Field 1  (I/S/U format + sequence numbers)
 *   [4-5]  Control Field 2  (receive sequence / reserved)
 *
 * Frame formats (determined by bits 0-1 of byte 2):
 *   I-format: bit 0 = 0            → Information transfer
 *   S-format: bits 0-1 = 01        → Supervisory
 *   U-format: bits 0-1 = 11        → Unnumbered control
 *
 * Compile:
 *   gcc -O1 -g -o iec104_apci_x86 iec104_apci_parser.c
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* ── Wall 1: Start Byte ───────────────────────────────────────────────
 * Constraint: CONSTANT_EQUALITY + PROTOCOL_FRAMING
 * IEC-104 mandates start byte = 0x68. Any other value is not IEC-104.
 */
int check_start_byte(const uint8_t *input, size_t len) {
    if (len < 1) return 0;
    if (input[0] != 0x68) {
        return 0;  /* Stall: not an IEC-104 frame */
    }
    return 1;
}

/* ── Wall 2: APDU Length ──────────────────────────────────────────────
 * Constraint: LENGTH_FIELD_DEPENDENCY + RANGE_BOUND
 * Length byte gives the number of bytes following it.
 * Valid range: 4 (minimum: control fields only) to 253 (max APDU size).
 * The actual frame size must match: total = length + 2 (start + length byte).
 */
int check_apdu_length(const uint8_t *input, size_t len) {
    if (len < 2) return 0;
    uint8_t apdu_len = input[1];

    /* Range check: 4 <= length <= 253 */
    if (apdu_len < 4 || apdu_len > 253) {
        return 0;  /* Stall: invalid APDU length */
    }

    /* Consistency check: actual frame size must match declared length */
    size_t expected_total = (size_t)apdu_len + 2;
    if (len < expected_total) {
        return 0;  /* Stall: truncated frame */
    }

    return 1;
}

/* ── Wall 3: I/S/U Format Dispatch ────────────────────────────────────
 * Constraint: BIT_FIELD_EXTRACTION + BITMASK_CHECK
 * Frame type is encoded in bits 0-1 of control field byte 1 (input[2]):
 *   bit 0 = 0        → I-format (information transfer)
 *   bits 0-1 = 01    → S-format (supervisory)
 *   bits 0-1 = 11    → U-format (unnumbered)
 *   bits 0-1 = 10    → INVALID (reserved, must be rejected)
 */
typedef enum {
    FRAME_I = 0,    /* I-format: bit 0 = 0 */
    FRAME_S = 1,    /* S-format: bits 0-1 = 01 */
    FRAME_U = 3,    /* U-format: bits 0-1 = 11 */
} FrameType;

int check_frame_format(const uint8_t *input, size_t len, FrameType *out_type) {
    if (len < 3) return 0;
    uint8_t ctrl1 = input[2];

    /* Check bit 0 first */
    if ((ctrl1 & 0x01) == 0) {
        /* I-format: bit 0 is clear */
        *out_type = FRAME_I;
        return 1;
    }

    /* Bit 0 is set — check bit 1 */
    uint8_t format_bits = ctrl1 & 0x03;
    if (format_bits == 0x01) {
        *out_type = FRAME_S;
        return 1;
    } else if (format_bits == 0x03) {
        *out_type = FRAME_U;
        return 1;
    }

    /* format_bits == 0x02 is reserved/invalid */
    return 0;  /* Stall: invalid frame format */
}

/* ── Wall 4: Sequence Number Validation ───────────────────────────────
 * Constraint: SEQUENCE_NUMBER + RANGE_BOUND + BIT_FIELD_EXTRACTION
 * For I-format frames:
 *   Send Sequence Number (SSN) = bits 1-15 of bytes 2-3 (big-endian)
 *   Receive Sequence Number (RSN) = bits 1-15 of bytes 4-5
 *   Both must be in range [0, 32767].
 *
 * SSN must match the expected next sequence number (session state).
 */
static uint16_t expected_ssn = 0x0000;

int check_sequence_number(const uint8_t *input, size_t len, FrameType frame_type) {
    if (len < 6) return 0;

    /* Only I-format frames have sequence numbers */
    if (frame_type != FRAME_I) return 1;

    /* Extract SSN from bytes 2-3: bits 1-15 (little-endian in wire format) */
    uint16_t ctrl_word1 = (uint16_t)input[2] | ((uint16_t)input[3] << 8);
    uint16_t ssn = (ctrl_word1 >> 1) & 0x7FFF;

    /* Range check */
    if (ssn > 32767) {
        return 0;  /* Stall: SSN out of range (shouldn't happen with 15 bits) */
    }

    /* Session state check */
    if (ssn != expected_ssn) {
        return 0;  /* Stall: sequence number mismatch */
    }

    return 1;
}

/* ── Combined: Process IEC-104 Frame ──────────────────────────────────
 * All 4 walls must be bypassed in sequence.
 */
void process_iec104_frame(const uint8_t *input, size_t len) {
    if (!check_start_byte(input, len)) {
        printf("REJECT: Bad start byte (expected 0x68, got 0x%02X)\n",
               len >= 1 ? input[0] : 0);
        return;
    }

    if (!check_apdu_length(input, len)) {
        printf("REJECT: Invalid APDU length\n");
        return;
    }

    FrameType frame_type;
    if (!check_frame_format(input, len, &frame_type)) {
        printf("REJECT: Invalid frame format (ctrl=0x%02X)\n",
               len >= 3 ? input[2] : 0);
        return;
    }

    if (!check_sequence_number(input, len, frame_type)) {
        printf("REJECT: Sequence number mismatch (expected %u)\n", expected_ssn);
        return;
    }

    const char *type_str[] = {"I-format", "S-format", "?", "U-format"};
    printf("ACCEPT: Valid IEC-104 %s frame (len=%u)\n",
           type_str[frame_type], input[1]);

    /* Vulnerable code path (only reachable past all 4 walls) */
    if (frame_type == FRAME_I && len > 6) {
        size_t asdu_len = len - 6;
        if (asdu_len > 100) {
            char asdu_buf[64];
            memcpy(asdu_buf, input + 6, asdu_len);  /* Deliberate overflow */
            printf("  ASDU buffer overflow triggered!\n");
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }

    uint8_t buf[512];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);

    process_iec104_frame(buf, n);
    return 0;
}
