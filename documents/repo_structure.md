# Agentic-AFL — GitHub Repository Structure

## Proposed Repo Tree

```
agentic-afl/
├── README.md
├── LICENSE
├── pyproject.toml
├── .env.example
├── .gitignore
├── docker-compose.yml
│
├── agentic_afl/                    # ── Core Python package ──
│   ├── __init__.py
│   ├── cli.py                      # Entry point: `agentic-afl fuzz|plot`
│   ├── campaign.py                 # CampaignRunner lifecycle manager
│   ├── config.py                   # Settings (env-based)
│   ├── constants.py                # ConstraintTag ontology, enums
│   ├── models.py                   # Dataclasses (VulnerabilitySpec, etc.)
│   ├── tui.py                      # Rich TUI dashboard
│   │
│   ├── extractor/                  # Phase 1: Binary analysis
│   │   ├── __init__.py
│   │   ├── pcode_slicer.py         # Ghidra headless P-Code extraction
│   │   ├── constraint_profiler.py  # Structural tag detection
│   │   ├── spec_exporter.py        # PostgreSQL spec persistence
│   │   ├── offset_probe.py         # Heuristic byte-to-register mapping
│   │   └── ghidra_scripts/
│   │       └── extract_pcode.py    # Ghidra postScript
│   │
│   ├── orchestrator/               # Phase 2: LLM + Z3 reasoning
│   │   ├── __init__.py
│   │   ├── agent_loop.py           # Main async orchestration daemon
│   │   ├── llm_client.py           # LLM API (Gemini/OpenAI)
│   │   ├── z3_sandbox.py           # Sandboxed Z3 execution
│   │   ├── retrieval_carm.py       # Constraint-Aware Retrieval Model
│   │   ├── harvest_mode.py         # Post-solve corpus harvesting
│   │   └── prompts/
│   │       ├── __init__.py
│   │       ├── z3_translation.py   # Z3 generation prompt templates
│   │       └── react_templates.py  # ReAct self-correction templates
│   │
│   ├── fuzzer_bridge/              # Phase 3: AFL++ integration
│   │   ├── __init__.py
│   │   ├── stall_detector.py       # Edge-plateau + GDB frontier tracing
│   │   ├── payload_injector.py     # Atomic file-based injection
│   │   └── diversity_generator.py  # Post-solve frame variant generator
│   │
│   └── database/                   # PostgreSQL CARM store
│       ├── __init__.py
│       └── spec_store.py
│
├── database/                       # ── Database schema ──
│   └── init.sql                    # PostgreSQL DDL for spec_store
│
├── data/                           # ── Static data ──
│   └── knowledge_base.json         # CARM seed templates
│
├── scripts/                        # ── Utility scripts ──
│   ├── import_induscp.py           # Import ICS constraint patterns
│   └── run_micro_harvest.py        # Micro-harvest utility
│
├── experiments/                    # ── Evaluation harnesses & campaigns ──
│   ├── targets/                    # Renamed from test_targets
│   │   ├── Makefile
│   │   │
│   │   ├── ics_crc32/              # ICS CRC-32 target
│   │   │   ├── crc32.h
│   │   │   ├── ics_crc32_harness.c
│   │   │   └── crc32_fixup_mutator.py
│   │   ├── ics_crc32_seeds/
│   │   ├── build_ics_crc32.sh
│   │   │
│   │   ├── modbus_rtu_slave.c      # Synthetic Modbus CRC-16
│   │   ├── custom_hash_target.c    # Novel rotate-XOR hash
│   │   ├── arithmetic_constraint_target.c
│   │   ├── iec104_apci_parser.c    # IEC 60870-5-104
│   │   ├── modbus_state_machine.c  # Multi-state FSM
│   │   ├── math_wall_test.c        # Original test target
│   │   │
│   │   ├── lib60870_harness.c      # Real-world: lib60870
│   │   ├── build_lib60870_harness.sh
│   │   ├── lib60870_seeds/
│   │   │
│   │   ├── libmodbus_harness.c     # Real-world: libmodbus
│   │   ├── build_libmodbus_harness.sh
│   │   ├── libmodbus_seeds/
│   │   │
│   │   ├── opendnp3_outstation_harness.cpp  # Real-world: OpenDNP3
│   │   ├── opendnp3_force_crc.h
│   │   ├── build_opendnp3_harness.sh
│   │   ├── opendnp3_seeds/
│   │   │
│   │   ├── cfs_checksum_harness.c  # Real-world: NASA cFS
│   │   ├── cfs_compat.h
│   │   ├── build_cfs_harness.sh
│   │   ├── cfs_seeds/
│   │   ├── cfs_stubs/
│   │   │
│   │   ├── gen_cfs_seeds.py        # Seed generators
│   │   ├── gen_libmodbus_seeds.py
│   │   └── gen_opendnp3_seeds.py
│   │
│   ├── campaigns/                  # Renamed from tests
│   │   ├── run_e2e_campaign.py     # E2E campaign runner (TargetSpec-based)
│   │   ├── test_generalization_matrix.py
│   │   └── plot_coverage.py
│   │
│   └── results/                    # Campaign JSON + plots (gitignored, except examples)
│       └── .gitkeep
│
├── tests/                          # ── Unit & integration tests ──
│   ├── __init__.py
│   ├── test_agent_loop_unit.py     # Move from experiments/tests/
│   ├── test_phase2_integration.py
│   ├── test_phase3_carm.py
│   └── test_phase4_bridge.py
│
└── docs/                           # ── Documentation ──
    ├── architecture.md             # System design overview
    └── figures/                    # Paper figures, diagrams
        └── coverage_final.png
```

---

## What to EXCLUDE (`.gitignore` additions)

These exist on disk but must NOT enter the repo:

| Path | Why |
|---|---|
| `venv/` | Python virtualenv |
| `AFLplusplus/` | AFL++ source clone — external dependency |
| `afl_output/` | Runtime fuzzer output |
| `agentic_afl.egg-info/` | Build artifact |
| `.pytest_cache/` | Test cache |
| `experiments/tests/e2e_results*/` | Campaign output data |
| `experiments/test_targets/*_harness` (no ext) | Compiled binaries (ELF) |
| `experiments/test_targets/*_x86*` | Compiled binaries |
| `experiments/test_targets/*_afl` | Compiled binaries |
| `experiments/test_targets/*_test` | Compiled binaries |
| `experiments/test_targets/*_probe` | Compiled binaries |
| `experiments/test_targets/*.core` | Core dumps |
| `experiments/test_targets/libmodbus/` | Cloned library source |
| `experiments/test_targets/libmodbus.zip` | Downloaded archive |
| `experiments/test_targets/opendnp3/` | Cloned library source |
| `experiments/test_targets/opendnp3_deps/` | Build deps |
| `experiments/test_targets/cfe/` | Cloned NASA cFS source |
| `experiments/test_targets/pcode_fixtures/` | Generated test fixtures |
| `setup_ghidra_python.fish` | Local shell config |
| `update_afl_qemu.sh` | Local build script |
| `.env` | Secrets (API keys) |
| `/tmp/ghidra_projects/` | Ghidra headless workspace |

---

## Proposed `.gitignore`

```gitignore
# ── Python ──
__pycache__/
*.pyc
*.pyo
*.egg-info/
dist/
build/
.venv/
venv/

# ── Runtime ──
afl_output/
logs/
/tmp/agentic_afl_sandbox/
pgdata/

# ── Compiled binaries (ELF) ──
experiments/targets/*_harness
experiments/targets/*_x86*
experiments/targets/*_afl
experiments/targets/*_test
experiments/targets/*_probe
experiments/test_targets/*_harness
experiments/test_targets/*_x86*
experiments/test_targets/*_afl
experiments/test_targets/*_test
experiments/test_targets/*_probe

# ── Core dumps ──
*.core

# ── Cloned dependencies (built locally) ──
AFLplusplus/
experiments/targets/libmodbus/
experiments/targets/opendnp3/
experiments/targets/opendnp3_deps/
experiments/targets/cfe/
experiments/test_targets/libmodbus/
experiments/test_targets/opendnp3/
experiments/test_targets/opendnp3_deps/
experiments/test_targets/cfe/
*.zip

# ── Campaign output (reproducible) ──
experiments/**/e2e_results*/
experiments/**/e2e_campaign/
experiments/results/*.json
experiments/results/*.png
!experiments/results/.gitkeep

# ── Generated fixtures ──
experiments/targets/pcode_fixtures/
experiments/test_targets/pcode_fixtures/

# ── IDE / OS ──
.idea/
.vscode/
*.swp
*.swo
.DS_Store
Thumbs.db
.pytest_cache/

# ── Secrets ──
.env

# ── Local scripts ──
setup_ghidra_python.fish
update_afl_qemu.sh
```

---

## Renames for Clarity

| Current | Proposed | Reason |
|---|---|---|
| `experiments/test_targets/` | `experiments/targets/` | Shorter, clearer |
| `experiments/tests/` | `experiments/campaigns/` | Distinguishes from `tests/` (unit tests) |
| `experiments/tests/tui.py` | **DELETE** | Duplicate of `agentic_afl/tui.py` |
| `experiments/test_targets/test_slice.py` | **DELETE** | One-off debug script |

---

## Pre-Push Checklist

1. `git init` in a clean directory (or reset the existing repo)
2. Copy the `.gitignore` above
3. Verify no compiled binaries: `find . -executable -type f | grep -v '.git' | grep -v 'venv'`
4. Verify no secrets: `grep -r "GEMINI_API_KEY\|sk-" --include='*.py' --include='*.sh'`
5. Verify no core dumps: `find . -name '*.core'`
6. Add `LICENSE` (MIT, per `pyproject.toml`)
7. Update `README.md` with install/usage instructions
8. `git add -A && git status` — review before committing
