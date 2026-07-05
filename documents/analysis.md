# Generalization Audit — Hardcoding Check

## ✅ Fully General Changes (No Issues)

| Change | File | Why It Generalizes |
|--------|------|--------------------|
| AFL instrumentation stripping | `llm_client.py` | Strips `__afl_area_ptr`/`DAT_0011c*` — ALL AFL-instrumented binaries have this |
| Edge-gain verification | `agent_loop.py` | Reads generic `edges_found` from AFL++ stats — target-independent |
| CARM contamination guard | `agent_loop.py` | Only commits templates on edge gain — target-independent |
| Token limit increase (16K→65K) | `config.py` | Benefits all targets with complex constraints |
| Conciseness directive (no comments) | `z3_translation.py` | Reduces truncation risk for all targets |
| Byte freedom prompt | `z3_translation.py` | "Leave data bytes free" — applies to any integrity-checked protocol |

## ⚠️ Hardcoded Items (2 Found)

### 1. CRC-16 Reference Template — `z3_translation.py` + `llm_client.py`

**Problem:** `CRC16_REFERENCE_TEMPLATE` hardcodes polynomial `0xA001` and init `0xFFFF` (CRC-16/Modbus). This template is injected whenever `BITWISE_LOOP` is detected. But `BITWISE_LOOP` fires for ANY bitwise loop — including CRC-32, CRC-16/CCITT (poly `0x1021`), CRC-16/DNP3 (poly `0xA6BC`), SHA-256, etc.

**Impact:** If a target uses CRC-32 or CRC-16/CCITT, the LLM would be told "USE THIS EXACT CRC-16/Modbus pattern" — producing wrong checksums.

**Fix:** Detect the polynomial from the decompiled C, then inject the correct template (or none if unknown).

---

### 2. Diversity Generator Protocol Detection — `diversity_generator.py`

**Problem:** `_detect_protocol()` maps `BITWISE_LOOP → modbus_rtu`. This means ANY target with a bitwise loop (including CRC-32 targets) would get Modbus RTU frames injected.

**Impact:** Non-Modbus targets would get 18 Modbus RTU frames injected — all with wrong framing and wrong checksum algorithm. These frames would be rejected by the target, wasting injection slots.

**Fix:** Detect protocol from the decompiled C polynomial constants, not just the constraint tag.

## Proposed Generalized Fix

Both issues are solved by the same approach: **extract the CRC polynomial from the decompiled C**.

```python
def _detect_crc_variant(decompiled_c: str) -> str | None:
    """Detect CRC variant from polynomial constants in decompiled C."""
    # Ghidra sign-extends 16-bit values to 32-bit, so we see
    # 0xffffa001 instead of 0xa001, 0xffff1021 instead of 0x1021, etc.
    POLYNOMIALS = {
        "0xa001": "crc16_modbus",   # CRC-16/Modbus (reversed 0x8005)
        "0xffffa001": "crc16_modbus",
        "0x1021": "crc16_ccitt",    # CRC-16/CCITT
        "0xffff1021": "crc16_ccitt",
        "0xa6bc": "crc16_dnp3",     # CRC-16/DNP3
        "0xffffa6bc": "crc16_dnp3",
        "0xedb88320": "crc32",      # CRC-32 (reversed IEEE)
    }
    c_lower = decompiled_c.lower()
    for poly, variant in POLYNOMIALS.items():
        if poly in c_lower:
            return variant
    return None  # Unknown — don't inject any reference template
```

This fixes both issues:
- **CRC reference template**: Only inject CRC-16/Modbus template when `0xa001`/`0xffffa001` is found
- **Diversity generator**: Use detected variant to choose Modbus RTU vs CRC-32 vs skip
