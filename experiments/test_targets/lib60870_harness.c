/*
 * lib60870_harness.c — AFL++ Fuzz Harness for lib60870 IEC 60870-5-104
 *
 * Targets the APCI frame validation path: checkMessage() and its
 * internal checkSequenceNumber() math wall.
 *
 * Strategy:
 *   - Include cs104_connection.c directly to access static functions
 *   - Stub out all HAL dependencies (socket, time, threads)
 *   - Initialize a minimal CS104_Connection in STATE_ACTIVE
 *   - Feed AFL input as a raw APCI frame to checkMessage()
 *
 * Math walls exercised:
 *   1. Start byte validation: buffer[0] == 0x68
 *   2. Frame type dispatch: I-frame (bit 0 clear), S-frame, U-frame
 *   3. I-frame: frameSendSequenceNumber == self->receiveCount
 *   4. I-frame: checkSequenceNumber(self, frameRecvSequenceNumber)
 *      - Modular arithmetic: seqNo % 32768
 *      - K-buffer bounds: oldest/newest ASDU tracking
 *      - Overflow detection: wraparound from 32767 → 0
 *   5. S-frame: checkSequenceNumber with seqNo from bytes 4-5
 *   6. ASDU header length validation in CS101_ASDU_createFromBufferEx
 *
 * Compile:
 *   afl-cc -O1 -g -no-pie \
 *     -DCONFIG_USE_THREADS=0 -DCONFIG_USE_SEMAPHORES=0 \
 *     -DCONFIG_CS104_SUPPORT_TLS=0 -DCONFIG_DEBUG_OUTPUT=0 \
 *     -I<lib60870>/config \
 *     -I<lib60870>/src/inc/api \
 *     -I<lib60870>/src/inc/internal \
 *     -I<lib60870>/src/hal/inc \
 *     -I<lib60870>/src/common/inc \
 *     lib60870_harness.c \
 *     <lib60870>/src/iec60870/cs104/cs104_frame.c \
 *     <lib60870>/src/iec60870/cs101/cs101_asdu.c \
 *     <lib60870>/src/iec60870/cs101/cs101_information_objects.c \
 *     <lib60870>/src/iec60870/lib60870_common.c \
 *     <lib60870>/src/iec60870/apl/cpXXtime2a.c \
 *     <lib60870>/src/hal/memory/lib_memory.c \
 *     -o lib60870_harness -lm
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* ═══════════════════════════════════════════════════════════════════════
 * HAL STUBS — Replace all platform-dependent functions with no-ops.
 *
 * These stubs eliminate the need for socket, thread, and TLS libraries
 * while allowing the core protocol parsing logic to compile and run.
 * ═══════════════════════════════════════════════════════════════════════
 */

/* ── Time ───────────────────────────────────────────────────────────── */
uint64_t Hal_getMonotonicTimeInMs(void) {
    /* Return a fixed timestamp. checkConfirmTimeout() uses this for T2,
     * but we don't care about timeouts in fuzzing — we just need a
     * stable value so the math doesn't UB. */
    return 1000000ULL;
}

uint64_t Hal_getTimeInMs(void) {
    return 1000000ULL;
}

uint64_t Hal_getTimeInNs(void) {
    return 1000000000ULL;
}

uint64_t Hal_getMonotonicTimeInNs(void) {
    return 1000000000ULL;
}

bool Hal_setTimeInNs(uint64_t nsTime) {
    (void)nsTime;
    return true;
}

/* ── Socket ─────────────────────────────────────────────────────────── */
/* checkMessage() calls writeToSocket() for U-frame responses (TESTFR_CON,
 * STARTDT_CON). writeToSocket() calls Socket_write(). We stub it to
 * silently succeed — the fuzzer doesn't care about outgoing frames. */
typedef struct sSocket* Socket;

int Socket_write(Socket self, uint8_t* buf, int size) {
    (void)self; (void)buf;
    return size;  /* pretend all bytes were sent */
}

int Socket_read(Socket self, uint8_t* buf, int size) {
    (void)self; (void)buf; (void)size;
    return 0;  /* no data available */
}

/* ── Thread ──────────────────────────────────────────────────────────── */
/* Thread_sleep is called in CS104_Connection_connect even when
 * CONFIG_USE_THREADS=0. Stub it out. */
void Thread_sleep(int millies) { (void)millies; }

/* ── Debug ──────────────────────────────────────────────────────────── */
/* lib60870_debug_print is provided by lib60870_common.c (no-op when
 * CONFIG_DEBUG_OUTPUT=0). Do NOT define it here. */

/* ═══════════════════════════════════════════════════════════════════════
 * Now include the actual lib60870 source file to access static functions.
 *
 * This is the standard pattern for unit-testing C static functions:
 * by #including the .c file, all static symbols become visible in
 * this translation unit. We compile ONLY this file + dependencies,
 * not cs104_connection.c separately (that would cause duplicate symbols).
 * ═══════════════════════════════════════════════════════════════════════
 */
#include "cs104_connection.c"


/* ═══════════════════════════════════════════════════════════════════════
 * HARNESS
 *
 * Sets up a minimal CS104_Connection in STATE_ACTIVE with a valid
 * k-buffer, then feeds AFL input directly to checkMessage().
 * ═══════════════════════════════════════════════════════════════════════
 */

/*
 * Initialize a CS104_Connection struct that is ready to process frames.
 *
 * Key state:
 *   - conState = STATE_ACTIVE (required for writeToSocket to work)
 *   - receiveCount = 0x1A2B (non-trivial 15-bit value)
 *   - k-buffer seqNos at {500, 501, 502} (non-trivial values)
 *   - sendCount = 503
 *
 * The math wall for I-frames is:
 *   Wall 1: ((buf[3] * 0x100) + (buf[2] & 0xFE)) / 2 == 0x1A2B
 *           This requires buf[2] = 0x56, buf[3] = 0x34
 *           (coupled multi-byte constraint, NOT brute-forceable)
 *
 *   Wall 2: checkSequenceNumber(conn, N(R)) where N(R) must be in [500, 502]
 *           Encoding: seqNo = ((buf[5] * 0x100) + (buf[4] & 0xFE)) / 2
 *           For seqNo=500: buf[4]=0xE8, buf[5]=0x03
 *           (also coupled, also not brute-forceable)
 *
 * For S-frames, only Wall 2 applies (seqNo from bytes 4-5).
 */
static CS104_Connection
setup_connection(void)
{
    CS104_Connection conn = CS104_Connection_create("127.0.0.1", 2404);
    if (!conn) {
        fprintf(stderr, "FATAL: Failed to allocate CS104_Connection\n");
        exit(1);
    }

    /* Force into active state so checkMessage processes all frame types */
    conn->conState = STATE_ACTIVE;

    /* Reset counters */
    resetConnection(conn);
    conn->conState = STATE_ACTIVE;  /* resetConnection sets IDLE */

    /* ── Set non-trivial counter values to create a REAL math wall ─── */

    /* receiveCount = 0x1A2B (6699 decimal, 15-bit value in [0, 32767])
     *
     * For an I-frame to pass Wall 1:
     *   frameSendSequenceNumber == receiveCount
     *   ((buf[3] * 256) + (buf[2] & 0xFE)) / 2 == 0x1A2B
     *   (buf[3] * 256) + (buf[2] & 0xFE) == 0x3456
     *   buf[3] = 0x34, buf[2] = 0x56
     *
     * The probability of AFL++ randomly finding buf[2]=0x56, buf[3]=0x34
     * simultaneously is ~1/65536. Combined with buf[0]=0x68 and the
     * I-frame bit constraint on buf[2], this is effectively unsolvable
     * by mutation alone.
     */
    conn->receiveCount = 0x1A2B;

    /* k-buffer: 3 in-flight ASDUs with seqNo = {500, 501, 502}
     * sendCount = 503 (next outgoing sequence number)
     *
     * For Wall 2 (checkSequenceNumber):
     *   seqNo must be in [500, 502] to pass
     *   Encoding for seqNo=501: buf[4]=0xEA, buf[5]=0x03
     *   Combined probability with Wall 1: ~1/4 billion
     */
    conn->sendCount = 503;
    conn->oldestSentASDU = 0;
    conn->newestSentASDU = 2;
    conn->sentASDUs[0].seqNo = 500;
    conn->sentASDUs[0].sentTime = 999000ULL;
    conn->sentASDUs[1].seqNo = 501;
    conn->sentASDUs[1].sentTime = 999000ULL;
    conn->sentASDUs[2].seqNo = 502;
    conn->sentASDUs[2].sentTime = 999000ULL;

    return conn;
}


int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    /* Read AFL input */
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }

    uint8_t buf[260];  /* Max APCI frame = 255 + start byte */
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);

    if (n < 6) {
        /* Minimum APCI frame is 6 bytes (U-format) */
        printf("REJECT: Too short (%zu bytes, need >= 6)\n", n);
        return 0;
    }

    /* Set up connection state */
    CS104_Connection conn = setup_connection();

    /* ── Feed the frame to the actual lib60870 parser ─────────────── */
    bool result = checkMessage(conn, buf, (int)n);

    if (result) {
        printf("ACCEPT: Frame validated successfully\n");

        /* Check what type of frame was accepted */
        if ((buf[2] & 1) == 0) {
            int sendSeq = ((buf[3] * 0x100) + (buf[2] & 0xfe)) / 2;
            int recvSeq = ((buf[5] * 0x100) + (buf[4] & 0xfe)) / 2;
            printf("  I-frame: N(S)=%d N(R)=%d\n", sendSeq, recvSeq);
            printf("  [!] Bypassed sequence number validation!\n");
        } else if (buf[2] == 0x01) {
            int seqNo = (buf[4] + buf[5] * 0x100) / 2;
            printf("  S-frame: N(R)=%d\n", seqNo);
            printf("  [!] Bypassed S-frame sequence check!\n");
        } else if ((buf[2] & 0x03) == 0x03) {
            printf("  U-frame: control=0x%02X\n", buf[2]);
        }
    } else {
        printf("REJECT: Frame validation failed\n");
    }

    /* Cleanup */
    CS104_Connection_destroy(conn);

    return 0;
}
