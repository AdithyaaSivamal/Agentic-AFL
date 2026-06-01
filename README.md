# Agentic-AFL

**Neuro-Symbolic Fuzzing Orchestration for ICS/OT Math Walls**

Agentic-AFL autonomously bypasses cryptographic integrity checks (CRC, HMAC, sequence counters) that block coverage-guided fuzzers. It detects AFL++ coverage stalls, extracts constraint semantics via Ghidra P-Code analysis, translates them to Z3 specifications using an LLM, solves for valid inputs, and injects them back into the running fuzzer — all without human intervention.

```bash
agentic-afl fuzz ./my_harness -i ./seeds --duration 6h --tui
```

## How It Works

```
AFL++ detects stall ──► Ghidra P-Code slice ──► Constraint profiling
                                                        │
                                                        ▼
Payload injection ◄── Z3 SAT solve ◄── LLM Z3 translation ◄── CARM retrieval
        │
        ▼
AFL++ resumes with ──► Diversity injection ──► Custom mutator deployment
new coverage               (35 variants)        (CRC-aware mutation)
```

**Three-level coverage escalation:**

1. **Solve** — Z3-generated payload bypasses the math wall (e.g., 15 → 84 edges)
2. **Diversify** — 35 protocol-compliant frame variants maximize state coverage
3. **Sustain** — Custom mutator ensures every AFL++ mutation produces valid checksums (e.g., 84 → 157 edges)

## Quick Start

### Prerequisites

- Python 3.11+
- [AFL++](https://github.com/AFLplusplus/AFLplusplus) 4.x (with `afl-fuzz` and `afl-cc` in `$PATH`)
- [Ghidra](https://ghidra-sre.org/) 11.x
- Docker (for PostgreSQL)
- An LLM API key (Gemini, OpenAI, or DeepSeek)

### Install

```bash
git clone https://github.com/<your-username>/agentic-afl.git
cd agentic-afl

# Start PostgreSQL (CARM spec store).
docker compose up -d

# Install the package.
pip install -e .

# Configure.
cp .env.example .env
# Edit .env with your API key and Ghidra path.
```

### Run a Campaign

```bash
# Compile your harness with AFL++ instrumentation.
afl-cc -o my_harness my_harness.c

# Fuzz with Agentic-AFL.
agentic-afl fuzz ./my_harness -i ./seeds --duration 1h --tui
```

### CLI Reference

```bash
# Fuzz a target (primary command).
agentic-afl fuzz ./harness -i ./seeds \
    --duration 6h \
    --stall-minutes 5 \
    --accept-marker "FRAME_VALID" \
    --custom-mutator ./crc_fixup.py \
    --log-dir ./results \
    --tui

# Plot coverage from campaign results.
agentic-afl plot ./results/campaign.json -o coverage.png
```

## Architecture

```
agentic_afl/
├── cli.py                     # CLI entry point (subcommands: fuzz, plot)
├── campaign.py                # CampaignRunner — AFL++ + AgentLoop lifecycle
├── tui.py                     # Rich TUI dashboard (braille coverage chart)
├── config.py                  # Environment-based configuration
├── constants.py               # Constraint tag ontology (15 structural tags)
├── models.py                  # Core dataclasses
│
├── extractor/                 # Phase 1: Binary Analysis
│   ├── pcode_slicer.py        # Ghidra headless P-Code extraction
│   ├── constraint_profiler.py # Algorithm-agnostic structural tagging
│   ├── offset_probe.py        # Heuristic byte-to-register mapping
│   ├── spec_exporter.py       # PostgreSQL persistence
│   └── ghidra_scripts/
│       └── extract_pcode.py   # Ghidra postScript
│
├── orchestrator/              # Phase 2: LLM + Z3 Reasoning
│   ├── agent_loop.py          # Async orchestration daemon (ReAct loop)
│   ├── llm_client.py          # Multi-provider LLM API (Gemini/OpenAI/local)
│   ├── z3_sandbox.py          # Sandboxed Z3 execution with timeout
│   ├── retrieval_carm.py      # Constraint-Aware Retrieval (Jaccard similarity)
│   └── prompts/               # Z3 translation + ReAct prompt templates
│
├── fuzzer_bridge/             # Phase 3: AFL++ Integration
│   ├── stall_detector.py      # Edge-plateau detection + GDB frontier tracing
│   ├── payload_injector.py    # Atomic sync-dir file injection
│   └── diversity_generator.py # Post-solve frame variant generation
│
└── database/
    └── spec_store.py          # PostgreSQL spec store (asyncpg)
```

## Evaluation Targets

10 targets across 6 constraint types, including 4 real-world ICS libraries:

| Target | Constraint | Math Wall | Real-World |
|---|---|---|---|
| ICS CRC-32 | CRC-32/IEEE 802.3 | `crc32_calc` | Synthetic |
| Libmodbus | CRC-16/Modbus (0xA001) | `crc16` | ✅ |
| OpenDNP3 | CRC-16/DNP3 | `LinkLayerParser::ReadHeader` | ✅ |
| lib60870 | Sequence number | `checkSequenceNumber` | ✅ |
| NASA cFS | XOR additive checksum | `CFE_MSG_ValidateChecksum` | ✅ |
| Modbus RTU | CRC-16/Modbus | `check_crc` | Synthetic |
| Custom Hash | Rotate-XOR-accumulate | `check_hash` | Synthetic |
| Arithmetic | Linear (a*7 + b*13) | `check_linear` | Synthetic |
| IEC 104 | Bit-field + sequence | `check_sequence_number` | Synthetic |
| State Machine | XOR challenge-response | `transition_auth_challenge` | Synthetic |

Build and run the evaluation targets:

```bash
# Build a target (example: ICS CRC-32).
cd experiments/test_targets
./build_ics_crc32.sh

# Run an E2E campaign via the target registry.
cd experiments/tests
python3 run_e2e_campaign.py ics_crc32 --duration 15m --tui
```

## Configuration

All configuration is via environment variables (`.env`):

```bash
# LLM Provider — "gemini", "openai", or "local"
LLM_API_PROVIDER=gemini
LLM_MODEL_NAME=gemini-2.5-flash       # Recommended for cost/quality balance
GEMINI_API_KEY=your-key-here

# PostgreSQL (matches docker-compose.yml defaults)
POSTGRES_DSN=postgresql://agentic_afl:agentic_afl@localhost:5432/agentic_afl

# Ghidra
GHIDRA_INSTALL_DIR=/opt/ghidra

# Tuning
K_VOTE_COUNT=3                         # Parallel Z3 script candidates
Z3_TIMEOUT_SECONDS=30                  # Per-script Z3 solve timeout
```

## Key Design Decisions

1. **Algorithm-agnostic constraint profiling** — The system tags structural patterns (`BITWISE_LOOP`, `INDEXED_LOOKUP`, `LINEAR_CONSTRAINT`), not algorithm names. This lets it generalize to proprietary checksums it has never seen before, via Jaccard similarity matching in CARM.

2. **Filesystem-based IPC** — The agent communicates with AFL++ through the sync directory (atomic file writes). No shared memory, no fuzzer modifications, no blocking IPC.

3. **ReAct self-correction** — When Z3 generation fails, the error is fed back to the LLM for iterative repair (up to 5 turns). This mitigates the ~30% syntax error rate of single-shot LLM code generation.

4. **K-way voting** — 3 parallel Z3 scripts are generated per stall. The first to return SAT wins. This exploits the variance in LLM outputs to maximize solve probability.

## Literature Foundation

| Component | References |
|---|---|
| Backward slicing | AutoBug, HyLLfuzz |
| Constraint profiling | ConstraintLLM §2.1 |
| CARM retrieval | ConstraintLLM §2.2-2.3 |
| LLM → Z3 translation | LLM-Sym §3.2, Logic-LM §3 |
| K-way voting | LINC §2 |
| ReAct self-correction | SAILOR §4, Logic-LM §3.3 |
| Sync-dir injection | HyLLfuzz §3.2, TDD_v2 §4.4 |

## License

MIT
