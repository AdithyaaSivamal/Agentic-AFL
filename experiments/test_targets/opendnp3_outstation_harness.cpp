/*
 * opendnp3_outstation_harness.cpp — AFL++ harness for OpenDNP3 outstation
 *
 * Feeds raw AFL input as a DNP3 data link layer frame into the real
 * OpenDNP3 LinkLayerParser. CRC validation is ENABLED (no
 * FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION). This creates a genuine
 * CRC-16/DNP3 math wall:
 *
 *   - Header CRC:  CRC-16 over bytes 0-7, stored in bytes 8-9
 *   - Body CRC(s): CRC-16 per 16-byte data block
 *
 * Without Agentic-AFL's neuro-symbolic solver, AFL++ cannot brute-force
 * past the CRC wall (probability ~1/65536 per block).
 *
 * Bypass markers (for test_generalization_matrix.py):
 *   "CRC_HEADER_PASS" — header CRC-16 validated
 *   "CRC_BODY_PASS"   — all body CRC blocks validated
 *   "FRAME_ACCEPTED"  — full frame passed to transport layer
 *
 * Build: see build_opendnp3_harness.sh
 */

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>

/* ─── OpenDNP3 includes ──────────────────────────────────────────────── */
#include "opendnp3/logging/Logger.h"
#include "opendnp3/logging/LogLevels.h"
#include "opendnp3/link/LinkHeaderFields.h"

/* Internal source headers */
#include "link/CRC.h"
#include "link/LinkLayerParser.h"
#include "link/IFrameSink.h"

using namespace opendnp3;

/* ─── Instrumented Frame Sink ────────────────────────────────────────── */
/* Receives parsed frames after CRC validation passes. */
class FuzzFrameSink : public IFrameSink
{
public:
    bool frame_received = false;

    bool OnFrame(const LinkHeaderFields& header, const ser4cpp::rseq_t& userdata) override
    {
        frame_received = true;

        printf("FRAME_ACCEPTED: func=%d dir=%s src=%u dest=%u datalen=%zu\n",
               static_cast<int>(header.func),
               header.isFromMaster ? "M->O" : "O->M",
               header.addresses.source,
               header.addresses.destination,
               static_cast<size_t>(userdata.length()));

        if (userdata.length() > 0)
        {
            /* User data present = both header CRC and ALL body CRCs passed */
            printf("  [!] Bypassed CRC-16 math wall with user data payload!\n");

            /* Print first bytes for debugging */
            printf("  DATA: ");
            size_t print_len = userdata.length() < 32 ? userdata.length() : 32;
            for (size_t i = 0; i < print_len; ++i)
            {
                printf("%02X ", userdata[i]);
            }
            printf("\n");
        }

        return true;
    }
};


/* ─── CRC check markers (independent of parser) ──────────────────────── */
static void check_crc_markers(const uint8_t* buf, size_t len)
{
    if (len < 10) return;

    /* Check header CRC (bytes 0-7, CRC in bytes 8-9) */
    if (CRC::IsCorrectCRC(buf, 8))
    {
        printf("CRC_HEADER_PASS: header CRC-16 validated\n");

        /* Check body CRCs if present */
        uint8_t frame_length = buf[2]; /* LEN field */
        if (frame_length > 5)
        {
            uint8_t data_length = frame_length - 5;
            size_t body_offset = 10;
            bool all_body_ok = true;
            size_t remaining = data_length;
            const uint8_t* body_ptr = buf + body_offset;

            while (remaining > 0 && all_body_ok)
            {
                size_t block_size = (remaining > 16) ? 16 : remaining;
                if (body_ptr + block_size + 2 > buf + len)
                {
                    all_body_ok = false;
                    break;
                }
                if (!CRC::IsCorrectCRC(body_ptr, block_size))
                {
                    all_body_ok = false;
                }
                body_ptr += block_size + 2;
                remaining -= block_size;
            }

            if (all_body_ok)
            {
                printf("CRC_BODY_PASS: all body block CRC(s) validated\n");
            }
        }
        else
        {
            printf("CRC_BODY_PASS: no body (control frame)\n");
        }
    }
}


/* ─── Main ───────────────────────────────────────────────────────────── */
int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    /* Read AFL input */
    FILE* f = fopen(argv[1], "rb");
    if (!f)
    {
        perror("fopen");
        return 1;
    }

    uint8_t buf[512]; /* Larger than LPDU_MAX_FRAME_SIZE (292) */
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);

    if (n < 10)
    {
        printf("REJECT: Too short (%zu bytes, need >= 10 for header)\n", n);
        return 0;
    }

    /* Print CRC bypass markers (independent verification) */
    check_crc_markers(buf, n);

    /* Create a null logger (no output — avoid log noise in AFL) */
    Logger logger = Logger::empty();

    /* Create the parser and frame sink */
    LinkLayerParser parser(logger);
    FuzzFrameSink sink;

    /* Copy input into parser's write buffer and process */
    auto write_buff = parser.WriteBuff();
    size_t copy_len = (n < static_cast<size_t>(write_buff.length()))
                          ? n
                          : static_cast<size_t>(write_buff.length());
    memcpy(write_buff, buf, copy_len);

    /* Feed the data to the parser */
    parser.OnRead(copy_len, sink);

    if (!sink.frame_received)
    {
        printf("REJECT: Frame validation failed\n");
    }

    return 0;
}
