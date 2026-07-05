/*
 * arithmetic_constraint_target.c — Pure Arithmetic Constraint for Testing.
 *
 * This binary uses NO loops, NO bitwise operations — only pure arithmetic
 * constraints. It produces a completely different ConstraintTag profile
 * from the CRC and hash targets, testing a different CARM retrieval path.
 *
 * Constraints:
 *   - Multi-variable linear: a*7 + b*13 == expected
 *   - Range bound: a must be in [0x100, 0x200]
 *   - Modular arithmetic: (a + b) mod 256 == checkbyte
 *
 * Frame format (7 bytes):
 *   [0-1]  Field A   (uint16_t, big-endian, must be in [0x100, 0x200])
 *   [2-3]  Field B   (uint16_t, big-endian, arbitrary)
 *   [4-5]  Expected  (uint16_t, big-endian, must equal (a*7 + b*13) & 0xFFFF)
 *   [6]    Checkbyte (uint8_t, must equal (a + b) & 0xFF)
 *
 * Compile:
 *   gcc -O1 -g -o arithmetic_target arithmetic_constraint_target.c
 *   afl-cc -O1 -g -no-pie -o arithmetic_target arithmetic_constraint_target.c
 *
 * Test:
 *   ./arithmetic_target /tmp/test_input.bin
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

/* ── Wall 1: Range Check ─────────────────────────────────────────────
 * Constraint: RANGE_BOUND
 * Field A (bytes 0-1) must be in [0x100, 0x200].
 */
int check_range(const uint8_t *input, size_t len) {
    if (len < 2) return 0;
    uint16_t a = ((uint16_t)input[0] << 8) | input[1];
    if (a < 0x0100 || a > 0x0200) {
        return 0;
    }
    return 1;
}

/* ── Wall 2: Linear Constraint ───────────────────────────────────────
 * Constraint: LINEAR_CONSTRAINT + CONSTANT_EQUALITY
 * (a * 7 + b * 13) & 0xFFFF must equal the value in bytes 4-5.
 * This is a coupled constraint: changing a or b changes the expected value.
 *
 * No loops, no bitwise ops — pure modular arithmetic.
 * Z3 should solve this trivially if the LLM translates it correctly.
 */
int check_linear(const uint8_t *input, size_t len) {
    if (len < 6) return 0;
    uint16_t a = ((uint16_t)input[0] << 8) | input[1];
    uint16_t b = ((uint16_t)input[2] << 8) | input[3];
    uint16_t expected = ((uint16_t)input[4] << 8) | input[5];

    uint16_t computed = (uint16_t)((a * 7 + b * 13) & 0xFFFF);
    if (computed != expected) {
        return 0;
    }
    return 1;
}

/* ── Wall 3: Modular Checkbyte ───────────────────────────────────────
 * Constraint: MODULAR_ARITHMETIC
 * (a + b) & 0xFF must equal byte 6.
 * This creates a second coupled constraint with fields a and b,
 * so all three fields must be solved simultaneously.
 */
int check_modular(const uint8_t *input, size_t len) {
    if (len < 7) return 0;
    uint16_t a = ((uint16_t)input[0] << 8) | input[1];
    uint16_t b = ((uint16_t)input[2] << 8) | input[3];
    uint8_t checkbyte = input[6];

    uint8_t computed = (uint8_t)((a + b) & 0xFF);
    if (computed != checkbyte) {
        return 0;
    }
    return 1;
}

/* ── Combined: Process Packet ────────────────────────────────────────
 * All 3 walls must be bypassed in sequence.
 */
void process_packet(const uint8_t *input, size_t len) {
    if (len != 7) {
        printf("REJECT: Bad length (expected 7, got %zu)\n", len);
        return;
    }
    if (!check_range(input, len)) {
        printf("REJECT: Field A out of range [0x100, 0x200]\n");
        return;
    }
    if (!check_linear(input, len)) {
        printf("REJECT: Linear constraint failed (a*7 + b*13 != expected)\n");
        return;
    }
    if (!check_modular(input, len)) {
        printf("REJECT: Modular checkbyte failed ((a+b)&0xFF != checkbyte)\n");
        return;
    }

    uint16_t a = ((uint16_t)input[0] << 8) | input[1];
    uint16_t b = ((uint16_t)input[2] << 8) | input[3];
    printf("ACCEPT: Valid packet — a=0x%04X, b=0x%04X\n", a, b);
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

    process_packet(buf, n);
    return 0;
}
