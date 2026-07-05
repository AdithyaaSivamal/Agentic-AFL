# Bug Fix Tasks

- `[x]` Bug 1: Edge-gain verification in agent_loop.py
  - `[x]` Added `_read_current_edges()` helper
  - `[x]` Added `_verify_edge_gain()` with 30s polling
  - `[x]` Only mark SOLVED on actual edge increase
  - `[x]` Only commit template to CARM on edge gain
- `[x]` Bug 2: Protocol-aware diversity generator
  - `[x]` Added `crc16_modbus()` function
  - `[x]` Added `_make_modbus_rtu_frame()` builder
  - `[x]` 18 Modbus RTU variants (FC 0x01-0x11, multiple slaves)
  - `[x]` Auto-detection from constraint tags (BITWISE_LOOP → Modbus)
  - `[x]` Legacy CRC-32 API preserved
  - `[x]` Verified CRC matches nanoMODBUS test vector (0x0A84)
- `[x]` Bug 3: CARM template contamination guard
  - `[x]` `update_template()` only called inside `edge_gained` block
  - `[x]` Failed payloads logged but NOT stored
- `[x]` Run test suite — 84/84 passed
