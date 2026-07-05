/*
 * harness.c — AFL++ harness for ICS CRC-32 frame validation
 *
 * Frame: [SYNC:2B][TYPE:1B][SEQ:1B][LEN:2B][PAYLOAD:N][CRC32:4B]
 * CRC-32/IEEE 802.3 computed over TYPE+SEQ+LEN+PAYLOAD.
 *
 * Markers:
 *   "ICS_CRC32_PASS"     — CRC validated
 *   "ICS_FRAME_ACCEPTED" — CRC valid + dispatched to state machine
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crc32.h"
#include "protocol.h"
#include "state_machine.h"

static int validate_frame(const uint8_t *buf, size_t len) {
    /* Check minimum size */
    if (len < MIN_FRAME_SIZE) {
        printf("REJECT: too short (%zu < %d)\n", len, MIN_FRAME_SIZE);
        return 0;
    }
    /* Check sync bytes */
    if (buf[0] != SYNC_HI || buf[1] != SYNC_LO) {
        printf("REJECT: bad sync (0x%02X 0x%02X)\n", buf[0], buf[1]);
        return 0;
    }
    /* Parse header */
    uint8_t frame_type = buf[2];
    uint8_t seq_num = buf[3];
    uint16_t payload_len = buf[4] | (buf[5] << 8);

    /* Validate payload length */
    if (payload_len > MAX_PAYLOAD_LEN) {
        printf("REJECT: payload too large (%u > %u)\n", payload_len, MAX_PAYLOAD_LEN);
        return 0;
    }
    size_t expected = 2 + HEADER_SIZE + payload_len + 4;
    if (len < expected) {
        printf("REJECT: truncated (need %zu have %zu)\n", expected, len);
        return 0;
    }
    /* Validate frame type is known */
    if (frame_type < 0x01 || frame_type > 0x0C) {
        printf("REJECT: unknown frame type 0x%02X\n", frame_type);
        return 0;
    }

    /* ═══ CRC-32 MATH WALL ═══
     * CRC computed over: TYPE + SEQ + LEN + PAYLOAD
     * i.e., buf[2..2+4+payload_len)
     */
    size_t crc_data_len = HEADER_SIZE + payload_len;
    const uint8_t *crc_data = buf + 2;
    uint32_t computed = crc32_calc(crc_data, crc_data_len);

    /* Extract stored CRC (little-endian, after payload) */
    size_t crc_offset = 2 + HEADER_SIZE + payload_len;
    uint32_t stored = buf[crc_offset]
                    | (buf[crc_offset+1] << 8)
                    | (buf[crc_offset+2] << 16)
                    | ((uint32_t)buf[crc_offset+3] << 24);

    if (computed != stored) {
        printf("REJECT: CRC-32 mismatch (computed=0x%08X stored=0x%08X)\n",
               computed, stored);
        return 0;
    }

    /* CRC passed! */
    printf("%s: CRC-32 verified (0x%08X)\n", MARKER_CRC_PASS, computed);

    /* Dispatch to ICS state machine */
    const uint8_t *payload = buf + 2 + HEADER_SIZE;
    int result = ics_dispatch(frame_type, seq_num, payload, payload_len);

    if (result > 0) {
        printf("%s: type=0x%02X seq=%u len=%u result=%d\n",
               MARKER_FRAME_VALID, frame_type, seq_num, payload_len, result);
        printf("  [!] Bypassed CRC-32 math wall — deep state machine reached!\n");
    } else {
        printf("REJECT: dispatch failed (result=%d)\n", result);
    }
    return result > 0 ? 1 : 0;
}

int main(int argc, char *argv[]) {
    uint8_t buf[1024];
    size_t len = 0;

    if (argc > 1) {
        FILE *f = fopen(argv[1], "rb");
        if (!f) { perror("fopen"); return 1; }
        len = fread(buf, 1, sizeof(buf), f);
        fclose(f);
    } else {
        len = fread(buf, 1, sizeof(buf), stdin);
    }

    if (len == 0) { printf("REJECT: empty input\n"); return 0; }
    validate_frame(buf, len);
    return 0;
}
