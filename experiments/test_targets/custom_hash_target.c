/*
 * custom_hash_target.c — Novel Hash Constraint for Generalization Testing.
 *
 * This binary uses a COMPLETELY CUSTOM hash function that does NOT exist
 * in any standard library, RFC, or training corpus. The LLM must translate
 * the decompiled C to Z3 purely from structural analysis + strategy hints.
 *
 * Hash algorithm: Rotate-XOR-Accumulate with prime additive mixing.
 *   - Init: 0xBEEF
 *   - Per byte: XOR, rotate-left-5, add 0x9E37, avalanche shift
 *   - NOT CRC, NOT MD5, NOT any known algorithm
 *
 * Frame format (8 bytes):
 *   [0]    Magic byte       (must be 0xAA)
 *   [1]    Command          (must be in {0x10, 0x20, 0x30})
 *   [2-3]  Payload          (2 arbitrary bytes — the "data" field)
 *   [4-5]  Hash             (custom_hash over bytes 0-3, little-endian)
 *   [6-7]  Sequence counter (must equal 0x0001, big-endian)
 *
 * Compile:
 *   gcc -O1 -g -o custom_hash_target custom_hash_target.c
 *   afl-cc -O1 -g -no-pie -o custom_hash_target custom_hash_target.c
 *
 * Test (compute hash externally and provide correct packet):
 *   ./custom_hash_target /tmp/test_input.bin
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

/* ── The Novel Hash Function ─────────────────────────────────────────
 * Rotate-XOR-Accumulate with prime additive mixing.
 * This is intentionally NOT any standard algorithm.
 *
 * Properties:
 *   - 16-bit output
 *   - Init value: 0xBEEF (distinctive, not 0xFFFF or 0x0000)
 *   - Rotate-left-5 per byte (not CRC's shift-right-1)
 *   - Additive prime constant 0x9E37 (not XOR polynomial)
 *   - Avalanche: h ^= (h >> 7)
 *
 * This combination does NOT match any known CRC, Fletcher, Adler,
 * FNV, djb2, or other standard hash. The LLM MUST read the C code
 * and implement it faithfully.
 */
uint16_t custom_hash(const uint8_t *data, size_t len) {
    uint16_t h = 0xBEEF;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint16_t)data[i];
        h = ((h << 5) | (h >> 11));  /* rotate left 5 */
        h += 0x9E37;                  /* prime additive mixing */
        h ^= (h >> 7);               /* avalanche */
    }
    return h;
}

/* ── Wall 1: Magic Byte ──────────────────────────────────────────────
 * Constraint: CONSTANT_EQUALITY
 * Byte 0 must be 0xAA.
 */
int check_magic(const uint8_t *input, size_t len) {
    if (len < 1) return 0;
    if (input[0] != 0xAA) {
        return 0;
    }
    return 1;
}

/* ── Wall 2: Command Whitelist ───────────────────────────────────────
 * Constraint: MULTI_WAY_BRANCH
 * Byte 1 must be one of {0x10, 0x20, 0x30}.
 */
int check_command(const uint8_t *input, size_t len) {
    if (len < 2) return 0;
    uint8_t cmd = input[1];
    if (cmd != 0x10 && cmd != 0x20 && cmd != 0x30) {
        return 0;
    }
    return 1;
}

/* ── Wall 3: Custom Hash Validation ──────────────────────────────────
 * Constraint: CALLEE_DEPENDENCY + BITWISE_LOOP (novel algorithm)
 * Hash is computed over bytes 0-3, stored in bytes 4-5 (little-endian).
 * The hash couples all prior fields — you can't solve it independently.
 */
int check_hash(const uint8_t *input, size_t len) {
    if (len != 8) return 0;

    /* Hash is over the first 4 bytes (magic + command + payload) */
    uint16_t computed = custom_hash(input, 4);
    uint16_t received = (uint16_t)input[4] | ((uint16_t)input[5] << 8);

    if (computed != received) {
        return 0;
    }
    return 1;
}

/* ── Wall 4: Sequence Counter ────────────────────────────────────────
 * Constraint: CONSTANT_EQUALITY (coupled with hash)
 * Bytes 6-7 must be 0x0001 (big-endian).
 * This creates a coupled constraint with the hash — the counter
 * can't be guessed independently if the hash depended on it.
 * (In this design, hash does NOT cover bytes 6-7, so they're
 * independent. This tests the pipeline's ability to handle
 * mixed coupled + independent constraints.)
 */
int check_sequence(const uint8_t *input, size_t len) {
    if (len < 8) return 0;
    uint16_t seq = ((uint16_t)input[6] << 8) | input[7];
    if (seq != 0x0001) {
        return 0;
    }
    return 1;
}

/* ── Combined: Process Packet ────────────────────────────────────────
 * All 4 walls must be bypassed in sequence.
 */
void process_packet(const uint8_t *input, size_t len) {
    if (!check_magic(input, len)) {
        printf("REJECT: Bad magic byte (expected 0xAA)\n");
        return;
    }
    if (!check_command(input, len)) {
        printf("REJECT: Bad command (expected 0x10/0x20/0x30)\n");
        return;
    }
    if (!check_hash(input, len)) {
        printf("REJECT: Hash mismatch\n");
        return;
    }
    if (!check_sequence(input, len)) {
        printf("REJECT: Bad sequence counter (expected 0x0001)\n");
        return;
    }

    printf("ACCEPT: Valid packet — cmd=0x%02X, payload=0x%02X%02X\n",
           input[1], input[2], input[3]);
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
