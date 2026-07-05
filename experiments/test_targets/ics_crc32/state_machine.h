/* state_machine.h — Deep ICS state machine behind CRC-32 wall */
#ifndef ICS_STATE_MACHINE_H
#define ICS_STATE_MACHINE_H
#include "protocol.h"
#include <string.h>
#include <stdio.h>

static uint8_t sim_mem[SIM_MEM_SIZE];
static uint8_t auth_state = 0;
static uint16_t watchdog_counter = 0;

static int validate_reg_range(uint16_t addr, uint16_t count, uint16_t start, uint16_t end) {
    if (addr < start || addr > end) return 0;
    if (count == 0 || count > 125) return 0;
    if ((uint32_t)addr + count > (uint32_t)end + 1) return 0;
    return 1;
}

static int handle_process_data(const uint8_t *p, uint16_t len) {
    if (len < 5) return -1;
    uint8_t subfn = p[0];
    uint16_t addr = p[1] | (p[2] << 8);
    uint16_t count = p[3] | (p[4] << 8);
    switch (subfn) {
    case PD_READ_COILS:
        if (!validate_reg_range(addr, count, REG_COIL_START, REG_COIL_END)) return -2;
        printf("  PD: read %u coils @ 0x%04X\n", count, addr);
        for (uint16_t i = 0; i < count && (addr+i) < SIM_MEM_SIZE; i++)
            sim_mem[addr+i] ^= 0x01;
        return 1;
    case PD_READ_DISCRETE:
        if (!validate_reg_range(addr, count, REG_DISCRETE_START, REG_DISCRETE_END)) return -2;
        printf("  PD: read %u discrete @ 0x%04X\n", count, addr);
        return 2;
    case PD_READ_HOLDING:
        if (!validate_reg_range(addr, count, REG_HOLDING_START, REG_HOLDING_END)) return -2;
        printf("  PD: read %u holding @ 0x%04X\n", count, addr);
        if (count > 50) printf("  PD: large batch read\n");
        return 3;
    case PD_READ_INPUT:
        if (!validate_reg_range(addr, count, REG_INPUT_START, REG_INPUT_END)) return -2;
        printf("  PD: read %u input @ 0x%04X\n", count, addr);
        return 4;
    case PD_WRITE_COIL:
        if (!auth_state) { printf("  PD: write denied - not auth\n"); return -3; }
        if (addr < REG_COIL_START || addr > REG_COIL_END) return -2;
        if (len < 7) return -1;
        { uint16_t val = p[5] | (p[6] << 8);
          if (val != 0x0000 && val != 0xFF00) return -4;
          if (addr < SIM_MEM_SIZE) sim_mem[addr] = (val == 0xFF00) ? 1 : 0;
          printf("  PD: write coil @ 0x%04X = %s\n", addr, val ? "ON" : "OFF");
        }
        return 5;
    case PD_WRITE_REGISTER:
        if (!auth_state) { printf("  PD: write denied\n"); return -3; }
        if (addr < REG_HOLDING_START || addr > REG_HOLDING_END) return -2;
        if (len < 7) return -1;
        { uint16_t val = p[5] | (p[6] << 8);
          uint16_t off = addr - REG_HOLDING_START;
          if (off + 1 < SIM_MEM_SIZE) { sim_mem[off] = val & 0xFF; sim_mem[off+1] = val >> 8; }
          printf("  PD: write reg @ 0x%04X = 0x%04X\n", addr, val);
        }
        return 6;
    case PD_WRITE_MULTI_COIL:
        if (!auth_state) return -3;
        if (len < 6) return -1;
        { uint8_t byte_count = p[5];
          if (len < 6u + byte_count) return -1;
          if (!validate_reg_range(addr, count, REG_COIL_START, REG_COIL_END)) return -2;
          for (uint8_t i = 0; i < byte_count && i < 32; i++)
              if (addr + i*8 < SIM_MEM_SIZE) sim_mem[addr + i*8] = p[6+i];
          printf("  PD: write %u coils @ 0x%04X (%u bytes)\n", count, addr, byte_count);
        }
        return 7;
    case PD_WRITE_MULTI_REG:
        if (!auth_state) return -3;
        if (len < 6) return -1;
        { uint8_t byte_count = p[5];
          if (byte_count != count * 2) return -4;
          if (len < 6u + byte_count) return -1;
          if (!validate_reg_range(addr, count, REG_HOLDING_START, REG_HOLDING_END)) return -2;
          uint16_t off = addr - REG_HOLDING_START;
          for (uint16_t i = 0; i < count && (off + i*2 + 1) < SIM_MEM_SIZE; i++) {
              sim_mem[off + i*2] = p[6 + i*2];
              sim_mem[off + i*2 + 1] = p[7 + i*2];
          }
          printf("  PD: write %u regs @ 0x%04X\n", count, addr);
        }
        return 8;
    case PD_MASK_WRITE:
        if (!auth_state) return -3;
        if (len < 9) return -1;
        if (addr < REG_HOLDING_START || addr > REG_HOLDING_END) return -2;
        { uint16_t and_mask = p[5] | (p[6] << 8);
          uint16_t or_mask = p[7] | (p[8] << 8);
          uint16_t off = addr - REG_HOLDING_START;
          if (off + 1 < SIM_MEM_SIZE) {
              uint16_t cur = sim_mem[off] | (sim_mem[off+1] << 8);
              cur = (cur & and_mask) | (or_mask & ~and_mask);
              sim_mem[off] = cur & 0xFF; sim_mem[off+1] = cur >> 8;
          }
          printf("  PD: mask write @ 0x%04X AND=0x%04X OR=0x%04X\n", addr, and_mask, or_mask);
        }
        return 9;
    case PD_READ_WRITE_MULTI:
        if (!auth_state) return -3;
        if (len < 11) return -1;
        { uint16_t rd_addr = addr, rd_cnt = count;
          uint16_t wr_addr = p[5] | (p[6] << 8);
          uint16_t wr_cnt = p[7] | (p[8] << 8);
          uint8_t wr_bytes = p[9];
          if (wr_bytes != wr_cnt * 2) return -4;
          if (len < 10u + wr_bytes) return -1;
          if (!validate_reg_range(rd_addr, rd_cnt, REG_HOLDING_START, REG_HOLDING_END)) return -2;
          if (!validate_reg_range(wr_addr, wr_cnt, REG_HOLDING_START, REG_HOLDING_END)) return -2;
          printf("  PD: R/W multi read=%u@0x%04X write=%u@0x%04X\n", rd_cnt, rd_addr, wr_cnt, wr_addr);
        }
        return 10;
    default:
        printf("  PD: unknown subfn 0x%02X\n", subfn);
        return -5;
    }
}

static int handle_alarm(const uint8_t *p, uint16_t len) {
    if (len < 4) return -1;
    uint8_t severity = p[0];
    uint16_t alarm_id = p[1] | (p[2] << 8);
    uint8_t ack = p[3];
    switch (severity) {
    case ALARM_INFO:
        printf("  ALARM: INFO id=%u\n", alarm_id);
        if (ack) printf("  ALARM: ack'd\n");
        return 20;
    case ALARM_WARNING:
        printf("  ALARM: WARNING id=%u\n", alarm_id);
        if (len >= 6) { uint16_t src = p[4] | (p[5] << 8); printf("  ALARM: src=0x%04X\n", src); }
        return 21;
    case ALARM_CRITICAL:
        printf("  ALARM: CRITICAL id=%u\n", alarm_id);
        if (len >= 8) {
            uint32_t ts = p[4] | (p[5]<<8) | (p[6]<<16) | (p[7]<<24);
            printf("  ALARM: timestamp=%u\n", ts);
        }
        return 22;
    case ALARM_EMERGENCY:
        printf("  ALARM: EMERGENCY id=%u - SYSTEM TRIP\n", alarm_id);
        if (len >= 5) { uint8_t zone = p[4]; printf("  ALARM: zone=%u\n", zone); }
        auth_state = 0;
        return 23;
    default: return -5;
    }
}

static int handle_diag(const uint8_t *p, uint16_t len) {
    if (len < 1) return -1;
    uint8_t sub = p[0];
    switch (sub) {
    case DIAG_STATUS:
        printf("  DIAG: status request\n");
        printf("  DIAG: auth=%d wdog=%u mem_used=%zu\n", auth_state, watchdog_counter, sizeof(sim_mem));
        return 30;
    case DIAG_COUNTERS:
        if (len < 2) return -1;
        { uint8_t ctr_id = p[1];
          if (ctr_id < 8) printf("  DIAG: counter[%u]=%u\n", ctr_id, watchdog_counter + ctr_id);
          else printf("  DIAG: invalid counter %u\n", ctr_id);
        }
        return 31;
    case DIAG_IDENT:
        printf("  DIAG: device ident request\n");
        printf("  DIAG: vendor=AgenticAFL model=ICS-CRC32 ver=1.0\n");
        return 32;
    case DIAG_TRACE:
        if (len < 3) return -1;
        { uint16_t trace_len = p[1] | (p[2] << 8);
          if (trace_len > 256) trace_len = 256;
          printf("  DIAG: trace capture %u bytes\n", trace_len);
          if (len >= 5) { uint16_t interval = p[3] | (p[4] << 8); printf("  DIAG: interval=%ums\n", interval); }
        }
        return 33;
    case DIAG_SELF_TEST:
        printf("  DIAG: running self-test...\n");
        { int pass = 1;
          for (int i = 0; i < 16; i++) { if (sim_mem[i] == 0xDE) { pass = 0; break; } }
          printf("  DIAG: self-test %s\n", pass ? "PASS" : "FAIL");
        }
        return 34;
    default: return -5;
    }
}

static int handle_safety(const uint8_t *p, uint16_t len) {
    if (len < 2) return -1;
    uint8_t sub = p[0];
    uint8_t sil_level = p[1];
    if (sil_level < 1 || sil_level > 4) { printf("  SAFETY: invalid SIL %u\n", sil_level); return -4; }
    switch (sub) {
    case SAFETY_HEARTBEAT:
        watchdog_counter++;
        printf("  SAFETY: heartbeat SIL%u wdog=%u\n", sil_level, watchdog_counter);
        if (watchdog_counter > 1000) { printf("  SAFETY: watchdog overflow\n"); watchdog_counter = 0; }
        return 40;
    case SAFETY_WATCHDOG:
        if (len < 4) return -1;
        { uint16_t timeout = p[2] | (p[3] << 8);
          printf("  SAFETY: watchdog config timeout=%ums SIL%u\n", timeout, sil_level);
          if (timeout < 10) printf("  SAFETY: WARNING timeout too short\n");
          if (timeout > 5000) printf("  SAFETY: WARNING timeout too long\n");
        }
        return 41;
    case SAFETY_SIL_CHECK:
        printf("  SAFETY: SIL%u integrity check\n", sil_level);
        if (len >= 6) {
            uint32_t expected = p[2] | (p[3]<<8) | (p[4]<<16) | (p[5]<<24);
            uint32_t computed = 0;
            for (int i = 0; i < 64 && i < SIM_MEM_SIZE; i++) computed += sim_mem[i];
            printf("  SAFETY: checksum expected=0x%08X computed=0x%08X %s\n",
                   expected, computed, (expected == computed) ? "OK" : "MISMATCH");
        }
        return 42;
    case SAFETY_TRIP:
        printf("  SAFETY: TRIP SIL%u - emergency shutdown\n", sil_level);
        auth_state = 0;
        memset(sim_mem, 0, 256);
        return 43;
    default: return -5;
    }
}

static int handle_auth(const uint8_t *p, uint16_t len, uint8_t frame_type) {
    if (len < 4) return -1;
    uint32_t token = p[0] | (p[1]<<8) | (p[2]<<16) | (p[3]<<24);
    if (frame_type == FRAME_AUTH_REQUEST) {
        if (token == 0x00000000) { printf("  AUTH: null token rejected\n"); return -3; }
        uint32_t challenge = token ^ 0xDEADBEEF;
        printf("  AUTH: challenge issued 0x%08X\n", challenge);
        return 50;
    } else {
        uint32_t expected = token ^ 0xDEADBEEF ^ 0xCAFEBABE;
        if (len >= 8) {
            uint32_t response = p[4] | (p[5]<<8) | (p[6]<<16) | (p[7]<<24);
            if (response == expected) {
                auth_state = 1;
                printf("  AUTH: authenticated successfully\n");
                if (len >= 9) {
                    uint8_t role = p[8];
                    printf("  AUTH: role=%s\n", role == 1 ? "operator" : role == 2 ? "engineer" : "admin");
                }
                return 51;
            }
            printf("  AUTH: failed (expected 0x%08X got 0x%08X)\n", expected, response);
        }
        return -3;
    }
}

static int handle_fw_update(const uint8_t *p, uint16_t len) {
    if (!auth_state) { printf("  FW: not authenticated\n"); return -3; }
    if (len < 6) return -1;
    uint8_t cmd = p[0];
    uint8_t block_num = p[1];
    uint32_t offset = p[2] | (p[3]<<8) | (p[4]<<16) | (p[5]<<24);
    switch (cmd) {
    case 0x01: /* Start */
        printf("  FW: update start, total blocks=%u\n", block_num);
        if (offset != 0) { printf("  FW: invalid start offset\n"); return -4; }
        return 60;
    case 0x02: /* Data block */
        if (len < 8) return -1;
        { uint16_t data_len = p[6] | (p[7] << 8);
          if (data_len > 256) { printf("  FW: block too large\n"); return -4; }
          if (len < 8u + data_len) return -1;
          printf("  FW: block %u offset=0x%08X len=%u\n", block_num, offset, data_len);
          if (offset + data_len > SIM_MEM_SIZE) { printf("  FW: offset overflow\n"); return -2; }
          memcpy(sim_mem + offset, p + 8, data_len);
        }
        return 61;
    case 0x03: /* Verify */
        printf("  FW: verify block %u\n", block_num);
        if (len >= 10) {
            uint32_t expected_crc = p[6] | (p[7]<<8) | (p[8]<<16) | (p[9]<<24);
            printf("  FW: expected CRC=0x%08X\n", expected_crc);
        }
        return 62;
    case 0x04: /* Commit */
        printf("  FW: commit and reboot\n");
        return 63;
    default: printf("  FW: unknown cmd 0x%02X\n", cmd); return -5;
    }
}

static int handle_time_sync(const uint8_t *p, uint16_t len) {
    if (len < 8) return -1;
    uint32_t sec = p[0] | (p[1]<<8) | (p[2]<<16) | (p[3]<<24);
    uint32_t nsec = p[4] | (p[5]<<8) | (p[6]<<16) | (p[7]<<24);
    printf("  TIME: sync %u.%09u\n", sec, nsec);
    if (nsec >= 1000000000) { printf("  TIME: invalid nsec\n"); return -4; }
    if (len >= 9) {
        uint8_t src = p[8];
        printf("  TIME: source=%s\n", src == 1 ? "GPS" : src == 2 ? "NTP" : src == 3 ? "PTP" : "LOCAL");
        if (src == 3 && len >= 11) {
            uint16_t domain = p[9] | (p[10] << 8);
            printf("  TIME: PTP domain=%u\n", domain);
        }
    }
    return 70;
}

static int handle_network_mgmt(const uint8_t *p, uint16_t len) {
    if (len < 2) return -1;
    uint8_t cmd = p[0];
    uint8_t node_id = p[1];
    switch (cmd) {
    case 0x01: printf("  NET: discover node %u\n", node_id); return 80;
    case 0x02: printf("  NET: ping node %u\n", node_id);
        if (len >= 4) { uint16_t timeout = p[2]|(p[3]<<8); printf("  NET: timeout=%ums\n", timeout); }
        return 81;
    case 0x03:
        if (!auth_state) return -3;
        printf("  NET: reset node %u\n", node_id);
        if (len >= 3 && p[2] == 0x01) printf("  NET: factory reset\n");
        return 82;
    case 0x04:
        if (len < 6) return -1;
        { uint32_t ip = p[2] | (p[3]<<8) | (p[4]<<16) | (p[5]<<24);
          printf("  NET: set node %u IP=%u.%u.%u.%u\n", node_id, ip&0xFF, (ip>>8)&0xFF, (ip>>16)&0xFF, ip>>24);
        }
        return 83;
    case 0x05:
        printf("  NET: topology scan\n");
        if (len >= 3) printf("  NET: max_hops=%u\n", p[2]);
        return 84;
    default: return -5;
    }
}

static int handle_device_profile(const uint8_t *p, uint16_t len) {
    if (len < 1) return -1;
    uint8_t sub = p[0];
    switch (sub) {
    case PROFILE_READ_VENDOR: printf("  PROF: vendor=AgenticAFL-Labs\n"); return 90;
    case PROFILE_READ_MODEL: printf("  PROF: model=ICS-Safety-CRC32\n"); return 91;
    case PROFILE_READ_SERIAL: printf("  PROF: serial=AFC32-2026-001\n"); return 92;
    case PROFILE_READ_FW_VER: printf("  PROF: fw_ver=1.0.0-rc1\n"); return 93;
    case PROFILE_READ_CAPS:
        printf("  PROF: caps: PD=yes SAFETY=yes AUTH=yes FW=yes\n");
        printf("  PROF: max_payload=%u regs=%u\n", MAX_PAYLOAD_LEN, REG_HOLDING_END - REG_HOLDING_START);
        return 94;
    case PROFILE_WRITE_NAME:
        if (!auth_state) return -3;
        if (len < 2) return -1;
        { uint8_t name_len = p[1];
          if (name_len > 32) name_len = 32;
          if (len < 2u + name_len) return -1;
          printf("  PROF: set name len=%u\n", name_len);
        }
        return 95;
    default: return -5;
    }
}

static int handle_param_read(const uint8_t *p, uint16_t len) {
    if (len < 3) return -1;
    uint8_t param_group = p[0];
    uint16_t param_id = p[1] | (p[2] << 8);
    switch (param_group) {
    case 0x01: printf("  PARAM_R: comm group id=%u\n", param_id);
        if (param_id < 10) printf("  PARAM_R: baud=%u\n", 9600 * (param_id + 1));
        return 100;
    case 0x02: printf("  PARAM_R: control group id=%u\n", param_id);
        if (param_id == 0) printf("  PARAM_R: mode=AUTO\n");
        else if (param_id == 1) printf("  PARAM_R: mode=MANUAL\n");
        else printf("  PARAM_R: mode=CUSTOM(%u)\n", param_id);
        return 101;
    case 0x03: printf("  PARAM_R: safety group id=%u\n", param_id);
        if (param_id < 4) printf("  PARAM_R: SIL_level=%u\n", param_id + 1);
        return 102;
    case 0x04: printf("  PARAM_R: tuning group id=%u\n", param_id);
        return 103;
    default: printf("  PARAM_R: unknown group 0x%02X\n", param_group); return -5;
    }
}

static int handle_param_write(const uint8_t *p, uint16_t len) {
    if (!auth_state) { printf("  PARAM_W: not authenticated\n"); return -3; }
    if (len < 5) return -1;
    uint8_t param_group = p[0];
    uint16_t param_id = p[1] | (p[2] << 8);
    uint8_t dtype = p[3];
    uint8_t vlen = p[4];
    if (len < 5u + vlen) return -1;
    printf("  PARAM_W: group=%u id=%u dtype=%u vlen=%u\n", param_group, param_id, dtype, vlen);
    switch (dtype) {
    case 0x01: if (vlen != 1) return -4; printf("  PARAM_W: BOOL=%u\n", p[5]); return 110;
    case 0x02: if (vlen != 2) return -4; printf("  PARAM_W: INT16=%d\n", (int16_t)(p[5]|(p[6]<<8))); return 111;
    case 0x03: if (vlen != 4) return -4; printf("  PARAM_W: INT32=%d\n", (int32_t)(p[5]|(p[6]<<8)|(p[7]<<16)|(p[8]<<24))); return 112;
    case 0x04: if (vlen != 4) return -4; { float f; memcpy(&f, p+5, 4); printf("  PARAM_W: FLOAT=%f\n", f); } return 113;
    case 0x05: if (vlen > 32) return -4; printf("  PARAM_W: STRING len=%u\n", vlen); return 114;
    default: printf("  PARAM_W: unknown dtype 0x%02X\n", dtype); return -5;
    }
}

/* Main dispatch — called ONLY after CRC-32 validation passes */
static int ics_dispatch(uint8_t frame_type, uint8_t seq, const uint8_t *payload, uint16_t len) {
    printf("  dispatch: type=0x%02X seq=%u len=%u\n", frame_type, seq, len);
    switch (frame_type) {
    case FRAME_PROCESS_DATA:  return handle_process_data(payload, len);
    case FRAME_PARAM_READ:    return handle_param_read(payload, len);
    case FRAME_PARAM_WRITE:   return handle_param_write(payload, len);
    case FRAME_ALARM:         return handle_alarm(payload, len);
    case FRAME_DIAG:          return handle_diag(payload, len);
    case FRAME_SAFETY:        return handle_safety(payload, len);
    case FRAME_FW_UPDATE:     return handle_fw_update(payload, len);
    case FRAME_TIME_SYNC:     return handle_time_sync(payload, len);
    case FRAME_AUTH_REQUEST:   /* fall through */
    case FRAME_AUTH_RESPONSE:  return handle_auth(payload, len, frame_type);
    case FRAME_NETWORK_MGMT:  return handle_network_mgmt(payload, len);
    case FRAME_DEVICE_PROFILE: return handle_device_profile(payload, len);
    default:
        printf("  dispatch: unknown type 0x%02X\n", frame_type);
        return -5;
    }
}
#endif
