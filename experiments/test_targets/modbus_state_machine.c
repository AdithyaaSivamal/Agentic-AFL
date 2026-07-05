/*
 * modbus_state_machine.c — Modbus Slave with Multi-State Transaction FSM.
 *
 * This program simulates a Modbus slave with a state machine that requires
 * multi-step authentication before allowing command execution.
 *
 * State Machine:
 *   IDLE → AUTH_CHALLENGE → AUTH_VERIFY → COMMAND_READY → EXECUTE
 *
 * Each transition has a distinct constraint type:
 *   IDLE → AUTH_CHALLENGE:  Magic header (CONSTANT_EQUALITY)
 *   AUTH_CHALLENGE → AUTH_VERIFY: Challenge-response XOR (BITMASK_CHECK)
 *   AUTH_VERIFY → COMMAND_READY: Session token match (CONSTANT_EQUALITY)
 *   COMMAND_READY → EXECUTE: Valid FC + CRC (FUNCTION_CODE_DISPATCH + CRC_CHECKSUM)
 *
 * This is a common pattern in authenticated ICS protocols (e.g., DNP3 SA,
 * OPC-UA Security, custom vendor protocols).
 *
 * Compile:
 *   gcc -O1 -g -o modbus_state_x86 modbus_state_machine.c
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

typedef enum {
    STATE_IDLE = 0,
    STATE_AUTH_CHALLENGE = 1,
    STATE_AUTH_VERIFY = 2,
    STATE_COMMAND_READY = 3,
    STATE_EXECUTE = 4,
    STATE_ERROR = 5,
} DeviceState;

static DeviceState current_state = STATE_IDLE;
static uint32_t challenge_nonce = 0xDEADBEEF;
static uint32_t session_token = 0;

/* ── Transition 1: IDLE → AUTH_CHALLENGE ──────────────────────────────
 * Constraint: CONSTANT_EQUALITY + PROTOCOL_FRAMING
 * Input must start with magic bytes 0x4D42 ("MB") to initiate auth.
 */
int transition_idle_to_auth(const uint8_t *input, size_t len) {
    if (len < 4) return 0;

    uint16_t magic = ((uint16_t)input[0] << 8) | input[1];
    if (magic != 0x4D42) {
        return 0;  /* Stall: wrong magic */
    }

    uint8_t cmd = input[2];
    if (cmd != 0x01) {  /* AUTH_REQUEST command */
        return 0;  /* Stall: wrong command type */
    }

    current_state = STATE_AUTH_CHALLENGE;
    printf("  State: IDLE → AUTH_CHALLENGE (nonce=0x%08X)\n", challenge_nonce);
    return 1;
}

/* ── Transition 2: AUTH_CHALLENGE → AUTH_VERIFY ───────────────────────
 * Constraint: BITMASK_CHECK + MODULAR_ARITHMETIC
 * Client must respond with: input_response = challenge_nonce XOR 0xCAFEBABE
 * This is a simplified challenge-response (real protocols use HMAC/AES).
 */
int transition_auth_challenge(const uint8_t *input, size_t len) {
    if (len < 6) return 0;

    uint32_t response = ((uint32_t)input[2] << 24) |
                        ((uint32_t)input[3] << 16) |
                        ((uint32_t)input[4] << 8)  |
                        ((uint32_t)input[5]);

    uint32_t expected = challenge_nonce ^ 0xCAFEBABE;
    if (response != expected) {
        current_state = STATE_ERROR;
        return 0;  /* Stall: wrong challenge response */
    }

    /* Generate session token from nonce */
    session_token = challenge_nonce + 0x12345678;
    current_state = STATE_AUTH_VERIFY;
    printf("  State: AUTH_CHALLENGE → AUTH_VERIFY (token=0x%08X)\n", session_token);
    return 1;
}

/* ── Transition 3: AUTH_VERIFY → COMMAND_READY ────────────────────────
 * Constraint: CONSTANT_EQUALITY
 * Client must echo back the session token to prove it received it.
 */
int transition_auth_verify(const uint8_t *input, size_t len) {
    if (len < 6) return 0;

    uint32_t client_token = ((uint32_t)input[2] << 24) |
                            ((uint32_t)input[3] << 16) |
                            ((uint32_t)input[4] << 8)  |
                            ((uint32_t)input[5]);

    if (client_token != session_token) {
        current_state = STATE_ERROR;
        return 0;  /* Stall: token mismatch */
    }

    current_state = STATE_COMMAND_READY;
    printf("  State: AUTH_VERIFY → COMMAND_READY\n");
    return 1;
}

/* ── Transition 4: COMMAND_READY → EXECUTE ────────────────────────────
 * Constraint: FUNCTION_CODE_DISPATCH + CRC_CHECKSUM
 * Standard Modbus FC dispatch + CRC verification.
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

int transition_command_ready(const uint8_t *input, size_t len) {
    if (len < 6) return 0;

    uint8_t fc = input[2];

    /* Valid function codes */
    if (fc < 1 || fc > 6) {
        return 0;  /* Stall: invalid FC */
    }

    /* CRC over bytes 2..len-2 (FC + data) */
    if (len < 5) return 0;
    size_t crc_payload_len = len - 2 - 2;  /* Skip header(2) + CRC(2) */
    uint16_t computed = crc16_modbus(input + 2, crc_payload_len);
    uint16_t received = (uint16_t)input[len - 2] | ((uint16_t)input[len - 1] << 8);

    if (computed != received) {
        return 0;  /* Stall: CRC mismatch */
    }

    current_state = STATE_EXECUTE;
    printf("  State: COMMAND_READY → EXECUTE (FC=%d)\n", fc);
    return 1;
}

/* ── State Machine Dispatcher ─────────────────────────────────────────
 * Constraint: STATE_MACHINE
 * The state variable determines which transition function to call.
 */
void process_state_machine(const uint8_t *input, size_t len) {
    printf("Processing packet (state=%d, len=%zu)\n", current_state, len);

    switch (current_state) {
        case STATE_IDLE:
            if (!transition_idle_to_auth(input, len)) {
                printf("REJECT: Failed IDLE → AUTH transition\n");
            }
            break;

        case STATE_AUTH_CHALLENGE:
            if (!transition_auth_challenge(input, len)) {
                printf("REJECT: Failed AUTH_CHALLENGE → AUTH_VERIFY\n");
            }
            break;

        case STATE_AUTH_VERIFY:
            if (!transition_auth_verify(input, len)) {
                printf("REJECT: Failed AUTH_VERIFY → COMMAND_READY\n");
            }
            break;

        case STATE_COMMAND_READY:
            if (!transition_command_ready(input, len)) {
                printf("REJECT: Failed COMMAND_READY → EXECUTE\n");
            } else {
                printf("ACCEPT: Command executed successfully!\n");
                /* Vulnerable code path */
                if (len > 100) {
                    char cmd_buf[32];
                    memcpy(cmd_buf, input + 3, len - 5);  /* Deliberate overflow */
                }
            }
            break;

        case STATE_EXECUTE:
            printf("INFO: Already in EXECUTE state\n");
            break;

        case STATE_ERROR:
            printf("ERROR: Device in error state, reset required\n");
            break;
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

    /* Process input as a sequence of length-prefixed packets.
     * Format: [len_byte][packet_data...][len_byte][packet_data...]...
     *
     * Each packet is dispatched to the state machine in order.
     * This allows all 4 state transitions to be reached from a single
     * input file — essential since AFL's forkserver resets process state
     * between executions.
     */
    current_state = STATE_IDLE;
    challenge_nonce = 0xDEADBEEF;
    session_token = 0;

    size_t offset = 0;
    int packet_num = 0;
    while (offset < n && current_state < STATE_EXECUTE && current_state != STATE_ERROR) {
        uint8_t pkt_len = buf[offset];
        offset++;

        if (pkt_len == 0 || offset + pkt_len > n) break;

        printf("[Packet %d] ", packet_num++);
        process_state_machine(buf + offset, pkt_len);
        offset += pkt_len;
    }

    return 0;
}
