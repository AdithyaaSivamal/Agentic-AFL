/*
 * math_wall_test.c — Minimal test binary for Ghidra P-Code extraction.
 *
 * This program contains three progressively harder "math walls" that
 * represent the constraint types Agentic-AFL needs to bypass:
 *
 *   1. Magic number check      (CONSTANT_EQUALITY)
 *   2. CRC-16/Modbus checksum  (CRC_CHECKSUM + LOOP_BOUNDED)
 *   3. Bitmask + range check   (BITMASK_CHECK + RANGE_BOUND)
 *
 * Compile for ARM32 (bare-metal target simulation):
 *   arm-none-eabi-gcc -O1 -static -o math_wall_arm math_wall_test.c
 *
 * Compile for x86_64 (desktop testing):
 *   gcc -O1 -o math_wall_x86 math_wall_test.c
 *
 * Usage with Ghidra Script Manager:
 *   1. Load the compiled binary in Ghidra.
 *   2. Navigate to process_packet() or any check function.
 *   3. Run extract_pcode.py with the CBRANCH address as arg[0].
 *
 * Usage with Ghidra Headless:
 *   analyzeHeadless /tmp/ghidra_project TestProject \
 *       -import ./math_wall_x86 \
 *       -postScript extract_pcode.py <cbranch_addr> 0x0 20 \
 *       -deleteProject
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* ── Wall 1: Magic Number Check ───────────────────────────────────────
 * Constraint type: CONSTANT_EQUALITY
 * Z3 solution: trivial — input[0:2] == 0x5A01
 */
int check_magic(const uint8_t *input, size_t len) {
    if (len < 2) return 0;
    uint16_t header = (input[0] << 8) | input[1];
    if (header != 0x5A01) {
        return 0;  /* AFL++ stalls HERE — this is the math wall */
    }
    return 1;
}

/* ── Wall 2: CRC-16/Modbus Checksum ───────────────────────────────────
 * Constraint type: CRC_CHECKSUM, LOOP_BOUNDED, BITWISE_ROTATION
 * Z3 solution: non-trivial — must compute CRC-16 polynomial division
 *
 * CRC-16/Modbus: polynomial 0xA001, init 0xFFFF
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
    if (len < 4) return 0;

    /* Last 2 bytes are the CRC field */
    size_t payload_len = len - 2;
    uint16_t computed_crc = crc16_modbus(input, payload_len);
    uint16_t received_crc = (input[len - 2]) | (input[len - 1] << 8);

    if (computed_crc != received_crc) {
        return 0;  /* AFL++ stalls HERE — CRC wall */
    }
    return 1;
}

/* ── Wall 3: Bitmask + Range Check ────────────────────────────────────
 * Constraint type: BITMASK_CHECK, RANGE_BOUND
 * Z3 solution: moderate — (fc & 0x80) == 0 AND 1 <= fc <= 6
 */
int check_function_code(const uint8_t *input, size_t len) {
    if (len < 3) return 0;

    uint8_t function_code = input[2];

    /* Bit 7 must be clear (not a response frame) */
    if (function_code & 0x80) {
        return 0;  /* AFL++ stalls HERE — bitmask wall */
    }

    /* Function code must be in valid Modbus range 1-6 */
    if (function_code < 1 || function_code > 6) {
        return 0;  /* AFL++ stalls HERE — range wall */
    }

    return 1;
}

/* ── Combined: Process Packet ─────────────────────────────────────────
 * All three walls must be bypassed in sequence.
 * This simulates a real ICS protocol parser.
 */
void process_packet(const uint8_t *input, size_t len) {
    if (!check_magic(input, len)) {
        printf("FAIL: Bad magic number\n");
        return;
    }

    if (!check_function_code(input, len)) {
        printf("FAIL: Bad function code\n");
        return;
    }

    if (!check_crc(input, len)) {
        printf("FAIL: Bad CRC\n");
        return;
    }

    /* If we get here, AFL++ has bypassed all three math walls */
    printf("SUCCESS: Valid packet! FC=%d\n", input[2]);

    /* Simulated vulnerable code path (only reachable past all walls) */
    if (len > 100) {
        char buf[64];
        memcpy(buf, input + 3, len - 5);  /* Deliberate overflow */
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    uint8_t buf[256];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);

    process_packet(buf, n);
    return 0;
}
