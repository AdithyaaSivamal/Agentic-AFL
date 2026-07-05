/*
 * protocol.h — ICS Frame Protocol Definitions
 *
 * Frame format (PROFINET/EtherCAT safety-inspired):
 *
 *   [SYNC_HI: 1B = 0xA5][SYNC_LO: 1B = 0x5A]
 *   [FRAME_TYPE: 1B][SEQ_NUM: 1B]
 *   [PAYLOAD_LEN: 2B little-endian]
 *   [PAYLOAD: PAYLOAD_LEN bytes]
 *   [CRC-32: 4B little-endian]
 *
 * CRC-32 is computed over bytes [2..2+4+PAYLOAD_LEN) i.e. from
 * FRAME_TYPE through end of PAYLOAD (excludes sync and CRC itself).
 *
 * Minimum frame: 2 (sync) + 4 (header) + 0 (payload) + 4 (CRC) = 10 bytes
 */

#ifndef ICS_PROTOCOL_H
#define ICS_PROTOCOL_H

#include <stdint.h>

#define SYNC_HI         0xA5
#define SYNC_LO         0x5A
#define MIN_FRAME_SIZE  10
#define MAX_PAYLOAD_LEN 512
#define HEADER_SIZE     4   /* type + seq + len(2) */

/* Frame types */
#define FRAME_PROCESS_DATA    0x01
#define FRAME_PARAM_READ      0x02
#define FRAME_PARAM_WRITE     0x03
#define FRAME_ALARM           0x04
#define FRAME_DIAG            0x05
#define FRAME_SAFETY          0x06
#define FRAME_FW_UPDATE       0x07
#define FRAME_TIME_SYNC       0x08
#define FRAME_AUTH_REQUEST    0x09
#define FRAME_AUTH_RESPONSE   0x0A
#define FRAME_NETWORK_MGMT   0x0B
#define FRAME_DEVICE_PROFILE  0x0C

/* Process data sub-functions */
#define PD_READ_COILS         0x01
#define PD_READ_DISCRETE      0x02
#define PD_READ_HOLDING       0x03
#define PD_READ_INPUT         0x04
#define PD_WRITE_COIL         0x05
#define PD_WRITE_REGISTER     0x06
#define PD_WRITE_MULTI_COIL   0x07
#define PD_WRITE_MULTI_REG    0x08
#define PD_MASK_WRITE         0x09
#define PD_READ_WRITE_MULTI   0x0A

/* Alarm severities */
#define ALARM_INFO            0x01
#define ALARM_WARNING         0x02
#define ALARM_CRITICAL        0x03
#define ALARM_EMERGENCY       0x04

/* Safety sub-types */
#define SAFETY_HEARTBEAT      0x01
#define SAFETY_WATCHDOG       0x02
#define SAFETY_SIL_CHECK      0x03
#define SAFETY_TRIP           0x04

/* Diagnostic sub-types */
#define DIAG_STATUS           0x01
#define DIAG_COUNTERS         0x02
#define DIAG_IDENT            0x03
#define DIAG_TRACE            0x04
#define DIAG_SELF_TEST        0x05

/* Device profile sub-types */
#define PROFILE_READ_VENDOR   0x01
#define PROFILE_READ_MODEL    0x02
#define PROFILE_READ_SERIAL   0x03
#define PROFILE_READ_FW_VER   0x04
#define PROFILE_READ_CAPS     0x05
#define PROFILE_WRITE_NAME    0x06

/* Address ranges for register validation */
#define REG_COIL_START        0x0000
#define REG_COIL_END          0x07FF
#define REG_DISCRETE_START    0x1000
#define REG_DISCRETE_END      0x17FF
#define REG_INPUT_START       0x3000
#define REG_INPUT_END         0x37FF
#define REG_HOLDING_START     0x4000
#define REG_HOLDING_END       0x4FFF

/* Simulated memory */
#define SIM_MEM_SIZE          4096

/* Accept markers for test framework */
#define MARKER_CRC_PASS       "ICS_CRC32_PASS"
#define MARKER_FRAME_VALID    "ICS_FRAME_ACCEPTED"

#endif /* ICS_PROTOCOL_H */
