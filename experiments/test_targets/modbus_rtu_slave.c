/*
 * modbus_rtu_slave.c — Realistic Modbus TCP/RTU Slave Packet Parser.
 *
 * This program simulates a Modbus slave device that validates incoming
 * packets through 5 sequential constraint walls. Each wall represents a
 * real constraint pattern found in production ICS firmware.
 *
 * Frame format (Modbus TCP, 12+ bytes):
 *   [0-1]  Transaction ID   (must match expected TID)
 *   [2-3]  Protocol ID      (must be 0x0000 for Modbus)
 *   [4-5]  Length            (remaining bytes after this field)
 *   [6]    Unit ID           (must be in allowed set: {1, 2, 10, 255})
 *   [7]    Function Code     (must be valid: 1-6, 15, 16)
 *   [8..N-2] Data            (function-specific payload)
 *   [N-2..N-1] CRC-16/Modbus (computed over bytes 6..N-2)
 *
 * Compile:
 *   gcc -O1 -g -o modbus_rtu_x86 modbus_rtu_slave.c
 *
 * Test with valid input:
 *   echo -ne '\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0A' > /tmp/modbus.bin
 *   # (CRC bytes must be appended for Wall 5)
 *   ./modbus_rtu_x86 /tmp/modbus.bin
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* ── Wall 1: Transaction ID ───────────────────────────────────────────
 * Constraint: CONSTANT_EQUALITY
 * The TID must match the expected value (simulates session tracking).
 * In real firmware, TID is incremented per transaction.
 */
static uint16_t expected_tid = 0x0001;

int check_transaction_id(const uint8_t *input, size_t len) {
    if (len < 2) return 0;
    uint16_t tid = ((uint16_t)input[0] << 8) | input[1];
    if (tid != expected_tid) {
        return 0;  /* Stall: TID mismatch */
    }
    return 1;
}

/* ── Wall 2: Protocol ID ──────────────────────────────────────────────
 * Constraint: CONSTANT_EQUALITY + PROTOCOL_FRAMING
 * Modbus TCP mandates Protocol ID = 0x0000.
 * Non-zero values indicate a different protocol or corruption.
 */
int check_protocol_id(const uint8_t *input, size_t len) {
    if (len < 4) return 0;
    uint16_t protocol_id = ((uint16_t)input[2] << 8) | input[3];
    if (protocol_id != 0x0000) {
        return 0;  /* Stall: not Modbus protocol */
    }
    return 1;
}

/* ── Wall 3: Unit ID Whitelist ────────────────────────────────────────
 * Constraint: RANGE_BOUND + NESTED_CONDITIONAL
 * Only specific Unit IDs are allowed on this bus segment.
 * This pattern is common in multi-drop RS-485 networks.
 */
static const uint8_t allowed_uids[] = {1, 2, 10, 255};
#define NUM_ALLOWED_UIDS (sizeof(allowed_uids) / sizeof(allowed_uids[0]))

int check_unit_id(const uint8_t *input, size_t len) {
    if (len < 7) return 0;
    uint8_t uid = input[6];

    for (size_t i = 0; i < NUM_ALLOWED_UIDS; i++) {
        if (uid == allowed_uids[i]) {
            return 1;  /* Valid UID */
        }
    }
    return 0;  /* Stall: unauthorized Unit ID */
}

/* ── Wall 4: Function Code Dispatch ───────────────────────────────────
 * Constraint: FUNCTION_CODE_DISPATCH + STATE_MACHINE
 * Valid Modbus function codes: 1-6 (read/write), 15, 16 (multi-write).
 * Invalid FCs are rejected (exception response in real devices).
 */
int check_function_code(const uint8_t *input, size_t len) {
    if (len < 8) return 0;
    uint8_t fc = input[7];

    switch (fc) {
        case 1:   /* Read Coils */
        case 2:   /* Read Discrete Inputs */
        case 3:   /* Read Holding Registers */
        case 4:   /* Read Input Registers */
        case 5:   /* Write Single Coil */
        case 6:   /* Write Single Register */
        case 15:  /* Write Multiple Coils */
        case 16:  /* Write Multiple Registers */
            return 1;
        default:
            return 0;  /* Stall: unsupported function code */
    }
}

/* ── Wall 5: CRC-16/Modbus ────────────────────────────────────────────
 * Constraint: CRC_CHECKSUM + LOOP_BOUNDED + MODULAR_ARITHMETIC
 * Standard Modbus CRC: polynomial 0xA001, init 0xFFFF.
 * Computed over the PDU (Unit ID + FC + Data), NOT the MBAP header.
 */
uint16_t crc16_modbus(const uint8_t *data, size_t len) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    return crc;
}

int check_crc(const uint8_t *input, size_t len) {
    /* Enforce EXACT packet length: 6 MBAP + 2 PDU (UID+FC) + 2 data + 2 CRC = 12 bytes.
     * This eliminates AFL++'s ability to vary PDU length to fish for CRC-0 collisions. */
    if (len != 12) return 0;

    /* PDU starts at byte 6 (Unit ID), CRC is last 2 bytes */
    size_t pdu_start = 6;
    size_t pdu_len = len - pdu_start - 2;   /* = 4 bytes: UID + FC + 2 data */
    const uint8_t *pdu = input + pdu_start;

    uint16_t computed = crc16_modbus(pdu, pdu_len);
    uint16_t received = (uint16_t)input[len - 2] | ((uint16_t)input[len - 1] << 8);

    if (computed != received) {
        return 0;  /* Stall: CRC mismatch */
    }
    return 1;
}

/* ── Wall 6: Session Token ────────────────────────────────────────────
 * Constraint: MULTI_BYTE_EQUALITY (coupled with CRC)
 * After CRC validation, the data field (bytes 8-9) must equal a specific
 * "session token" value 0xC0DE. This creates a coupled constraint:
 * the CRC depends on the data bytes, so AFL++ cannot independently
 * guess the data AND the CRC — it must solve them simultaneously.
 *
 * With fixed UID=0x01, FC=0x03, Data=0xC0DE:
 *   CRC = crc16_modbus([0x01, 0x03, 0xC0, 0xDE]) = specific 16-bit value
 * AFL++ must guess BOTH data=0xC0DE AND the matching CRC, which is
 * a 48-bit coupled constraint (practically infeasible by mutation).
 */
int check_session_token(const uint8_t *input, size_t len) {
    if (len < 10) return 0;
    uint16_t token = ((uint16_t)input[8] << 8) | input[9];
    if (token != 0xC0DE) {
        return 0;  /* Stall: bad session token */
    }
    return 1;
}

/* ── Combined: Process Modbus Packet ──────────────────────────────────
 * All 6 walls must be bypassed in sequence.
 */
void process_modbus_packet(const uint8_t *input, size_t len) {
    if (!check_transaction_id(input, len)) {
        printf("REJECT: Bad Transaction ID (expected 0x%04X)\n", expected_tid);
        return;
    }
    if (!check_protocol_id(input, len)) {
        printf("REJECT: Bad Protocol ID (expected 0x0000)\n");
        return;
    }
    if (!check_unit_id(input, len)) {
        printf("REJECT: Unauthorized Unit ID (0x%02X)\n", len >= 7 ? input[6] : 0);
        return;
    }
    if (!check_function_code(input, len)) {
        printf("REJECT: Unsupported Function Code (0x%02X)\n", len >= 8 ? input[7] : 0);
        return;
    }
    if (!check_crc(input, len)) {
        printf("REJECT: CRC-16 mismatch\n");
        return;
    }
    if (!check_session_token(input, len)) {
        printf("REJECT: Bad session token (expected 0xC0DE)\n");
        return;
    }

    printf("ACCEPT: Valid Modbus packet — FC=%d, UID=%d, Token=0x%02X%02X\n",
           input[7], input[6], input[8], input[9]);

    /* Vulnerable code path (only reachable past all 6 walls) */
    printf("  [!] Reached protected handler — vulnerability triggered!\n");
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

    process_modbus_packet(buf, n);
    return 0;
}

