# P0 Deployment Readiness — Walkthrough

## Overview

Implemented all P0 priority items from the [deployment readiness assessment](file:///home/adi/Documents/IoT_Lab/Agentic-AFL/whiteboard/documents/08_deployment_readiness.md): pre-flight validation, PostgreSQL fallback, unit tests, and diagnostic CLI subcommands.

## Changes Made

### 1. InMemorySpecStore ([memory_store.py](file:///home/adi/Documents/IoT_Lab/Agentic-AFL/whiteboard/Agentic-AFL-dev/agentic_afl/database/memory_store.py))

**New file** — Drop-in replacement for `SpecStore` when PostgreSQL is unavailable.

- Same async interface: `initialize()`, `save_spec()`, `query_by_jaccard()`, `load_spec()`, `update_template()`, `append_correction()`, `get_store_stats()`, `close()`
- Implements Jaccard similarity in Python (O(N), acceptable for N<100 per campaign)
- Same `tags_to_int_array()` / `int_array_to_tags()` static helpers
- Data is ephemeral — discarded on process exit

---

### 2. Pre-flight Validation ([agent_loop.py](file:///home/adi/Documents/IoT_Lab/Agentic-AFL/whiteboard/Agentic-AFL-dev/agentic_afl/orchestrator/agent_loop.py))

Three new methods in `AgentLoop`, called during `setup()` before any pipeline work:

| Method | Checks | On Failure |
|--------|--------|------------|
| `_validate_ghidra()` | `pyghidraRun`/`analyzeHeadless` in `GHIDRA_INSTALL_DIR` + PATH | `RuntimeError` with install URL |
| `_validate_llm_api_key()` | Non-empty key + lightweight `models.list()` ping | `RuntimeError` with env var name |
| `_initialize_store()` | PostgreSQL connection | Falls back to `InMemorySpecStore` with warning |

---

### 3. Unit Test Suite (74 tests, all passing)

| Test File | Tests | What's Covered |
|-----------|-------|----------------|
| [test_constraint_profiler.py](file:///home/adi/Documents/IoT_Lab/Agentic-AFL/whiteboard/Agentic-AFL-dev/tests/test_constraint_profiler.py) | 19 | All 11 tag detectors, decompiled C analysis, metrics, CRC-16 composite |
| [test_z3_sandbox.py](file:///home/adi/Documents/IoT_Lab/Agentic-AFL/whiteboard/Agentic-AFL-dev/tests/test_z3_sandbox.py) | 12 | Script sanitization, SAT/UNSAT execution, blocked imports, timing |
| [test_stall_detector.py](file:///home/adi/Documents/IoT_Lab/Agentic-AFL/whiteboard/Agentic-AFL-dev/tests/test_stall_detector.py) | 7 | fuzzer_stats parsing, edge cases, numbered instances, stall override |
| [test_payload_injector.py](file:///home/adi/Documents/IoT_Lab/Agentic-AFL/whiteboard/Agentic-AFL-dev/tests/test_payload_injector.py) | 5 | Atomic write, filename gen, injection tracking, cleanup |
| [test_memory_store.py](file:///home/adi/Documents/IoT_Lab/Agentic-AFL/whiteboard/Agentic-AFL-dev/tests/test_memory_store.py) | 14 | Save/load, Jaccard (exact/partial/threshold/arch filter), templates, stats |
| [test_preflight.py](file:///home/adi/Documents/IoT_Lab/Agentic-AFL/whiteboard/Agentic-AFL-dev/tests/test_preflight.py) | 9 | Ghidra (missing/PATH/valid), LLM key (empty/invalid/local), PG fallback |

```
$ python3 -m pytest tests/ -v
========================== 74 passed in 0.86s ==========================
```

---

### 4. Diagnostic CLI Subcommands ([cli.py](file:///home/adi/Documents/IoT_Lab/Agentic-AFL/whiteboard/Agentic-AFL-dev/agentic_afl/cli.py))

#### `agentic-afl check`
Runs all pre-flight checks and reports status:
```
$ agentic-afl check --fix

  ════════════════════════════════════════════════════════════
    AGENTIC-AFL PRE-FLIGHT CHECK
  ════════════════════════════════════════════════════════════

    ✅ Ghidra          — found
    ❌ LLM API key     — INVALID (gemini)
    ⚠️  PostgreSQL     — unavailable (in-memory fallback)
    ✅ Z3 solver       — v4.13.0
    ⚠️  AFL++           — not on PATH
```

#### `agentic-afl analyze ./binary --address 0xADDR`
Runs Ghidra extraction + constraint profiling without launching AFL++:
```
$ agentic-afl analyze ./harness --address 0x0000d7e4

  [1/3] Running Ghidra P-Code extraction...
        ✓ 12 P-Code instructions extracted
        ✓ Function: crc16_modbus @ 0x0000d500

  [2/3] Running constraint profiler...
        ✓ Tags detected: 4
          • BITWISE_LOOP
          • CONSTANT_EQUALITY
          • COUNTED_LOOP
          • INDEXED_LOOKUP

  [3/3] Structural metrics:
        Bitwise density:     0.4167
        Estimated complexity: 72/100

  STRATEGY HINT:
    → CRC/hash-like: Unroll loop, model as GF(2) polynomial
    → Table lookup: Inline table values as Array() in Z3
```

## Verification

All 74 unit tests pass. The diagnostic subcommands exercise the same validation logic that runs during `setup()`, so they serve as both a user tool and an integration test surface.
