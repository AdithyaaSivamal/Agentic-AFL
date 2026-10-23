# Agentic-AFL

**Neuro-Symbolic Fuzzing Orchestration for ICS/OT Math Walls**

Agentic-AFL is an autonomous co-process that runs alongside an unmodified AFL++ campaign, detects coverage plateaus caused by checksum and sequence-counter integrity checks, and closes the loop end to end: it extracts the blocking constraint via Ghidra P-Code slicing, has an LLM translate it to a Z3 model, verifies the solution in an isolated sandbox, and injects the result straight into AFL++'s own sync directory — no human in the loop, and the fuzzer never blocks waiting for any of it.

```bash
agentic-afl fuzz ./my_harness -i ./seeds --duration 6h --tui
```

**Scope, stated plainly:** this targets constraints Z3 can model directly from the decompiled logic — CRCs, checksums, and sequence/state counters. It explicitly does **not** break cryptographic MACs or signatures (HMAC, RSA, etc.) — those require either the secret key or symbolically modeling a hash/cipher primitive, neither of which this system attempts. When the extracted slice resolves into a call to an opaque crypto library rather than inlineable arithmetic, the system detects that it can't make progress and defers the stall rather than claiming a false bypass.

## How It Works

```
AFL++ detects stall ──► Ghidra P-Code slice ──► Constraint profiling
                                                        │
                                                        ▼
Payload injection ◄── Z3 SAT solve ◄── LLM Z3 translation ◄── CARM retrieval
        │
        ▼
AFL++ resumes with ──► Diversity injection ──► Custom mutator deployment
new coverage            (protocol-valid variants)   (CRC-aware mutation)
```

**Three-level coverage escalation**, after a stall is solved:

1. **Solve** — inject the Z3-derived payload that satisfies the constraint.
2. **Diversify** — generate a protocol-valid family of additional frame variants (currently up to 18 Modbus RTU frames or 10 CRC-32 ICS frames, depending on target) so the mutator has real material to work from, not just one input.
3. **Sustain** — if configured, restart AFL++ with a constraint-preserving custom mutator so every subsequent mutation keeps producing valid checksums.

**A real, cited result** (full run log and independent cross-machine re-run in `documents/`, kept local — see Evaluation below): against the `magma_libpng` target (libpng's IHDR CRC-32 check), AFL++ alone plateaus at 123 edges; Agentic-AFL detects the stall, solves it, and the campaign reaches 188 edges — reproduced independently on a second machine at 165 → 186 edges.

## Quick Start

### Prerequisites

- Python 3.11+
- [AFL++](https://github.com/AFLplusplus/AFLplusplus) 4.x (with `afl-fuzz` and `afl-cc` in `$PATH`)
- [Ghidra](https://ghidra-sre.org/) 11.x
- Docker (for PostgreSQL — optional; falls back to an in-memory store without it)
- An LLM API key (Gemini, OpenAI, or a local provider)

### Install

```bash
git clone https://github.com/AdithyaaSivamal/Agentic-AFL.git
cd Agentic-AFL

# Start PostgreSQL (CARM spec store) — optional.
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
├── cli.py                     # CLI entry point (subcommands: fuzz, check, analyze, plot)
├── campaign.py                # CampaignRunner — AFL++ + AgentLoop lifecycle
├── tui.py                     # Rich TUI dashboard (braille coverage chart)
├── config.py                  # Environment-based configuration
├── constants.py               # Constraint tag ontology (16 structural tags)
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
│   ├── z3_sandbox.py          # Sandboxed Z3 execution (timeout + seed-preserving pins)
│   ├── retrieval_carm.py      # Constraint-Aware Retrieval (weighted Jaccard + complexity + solve-history)
│   └── prompts/               # Z3 translation + ReAct prompt templates
│
├── fuzzer_bridge/              # Phase 3: AFL++ Integration
│   ├── stall_detector.py      # Edge-plateau detection + GDB frontier tracing
│   ├── payload_injector.py    # Atomic sync-dir file injection
│   └── diversity_generator.py # Post-solve frame variant generation
│
└── database/
    └── spec_store.py          # PostgreSQL spec store (asyncpg)
```

## Evaluation

Results below are reported per-target with the actual evidence behind them, not a combined claim — a deliberate choice after finding that an earlier version of this table overstated several targets.

**Verified bypass, with a real cited run:**

| Target | Constraint | Result |
|---|---|---|
| `magma_libpng` (real-world: libpng) | CRC-32/IEEE, table-driven | 123 → 188 edges; independently reproduced on a second machine at 165 → 186 edges |
| `ics_crc32` (synthetic) | CRC-32/IEEE 802.3 | 9 → 157 edges (best of 3 runs; one LLM call each run, final edge count varies 84–157 across runs) |
| `arithmetic` (synthetic) | Linear constraint (a·7 + b·13) | 7 → 12 edges, full accept |

**Implemented in the target registry, not yet independently re-verified in this pass:** `libmodbus`, `OpenDNP3`, `lib60870`, `NASA cFS`, Modbus RTU, custom rotate-XOR hash, IEC 104, challenge-response state machine. Several of these were attempted in earlier development; the saved run data for them is mixed (some show AFL++ making progress without any LLM involvement, one recorded run did not bypass its wall) rather than a clean confirmation, so they're listed here as available targets, not proven results.

```bash
# Run an E2E campaign via the target registry (pass a target key from TARGETS in the script).
cd experiments/integration
python3 test_generalization_matrix.py magma_libpng
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
GHIDRA_TIMEOUT_SECONDS=180             # Raise on CPU-constrained hosts running Ghidra alongside a live campaign

# Tuning
K_VOTE_COUNT=3                         # Parallel Z3 script candidates
Z3_TIMEOUT_SECONDS=30                  # Per-script Z3 solve timeout
```

## Key Design Decisions

1. **Algorithm-agnostic constraint profiling** — The system tags structural patterns (`BITWISE_LOOP`, `INDEXED_LOOKUP`, `LINEAR_CONSTRAINT`, ...) rather than algorithm names. This lets it match a proprietary checksum against a previously-solved standard one when both present the same computational shape, via a weighted Jaccard/complexity/solve-history score in CARM.

2. **Filesystem-based IPC** — The agent communicates with AFL++ through the sync directory (atomic file writes). No shared memory, no fuzzer modifications, no blocking IPC.

3. **ReAct self-correction** — When Z3 generation fails, the solver's own error output is fed back to the LLM for a bounded number of repair turns, rather than retrying blind.

4. **K-way voting** — Several parallel Z3 scripts are generated per stall; the first to return SAT wins. This exploits variance in LLM outputs to raise the odds that at least one candidate is both syntactically valid and correct.

5. **Seed-preserving sandbox** — A script that only needs to constrain a checksum field, but declares byte variables across the whole buffer, would otherwise let the solver pick arbitrary (typically zero) values for every other field — silently corrupting already-valid data outside the constraint. The sandbox pins every declared-but-unconstrained byte to its seed value by default, relaxing a pin only when an unsat-core proves it genuinely conflicts with the real constraint.

## Related Work

| This project's component | Related prior work |
|---|---|
| Backward slicing from a stall address | AutoBug (Li, Meng & Duck, OOPSLA 2025); HyLLfuzz (2024) |
| LLM → Z3 translation + self-correction | Logic-LM (Pan et al., EMNLP Findings 2023) |
| K-way voting | LINC (Olausson et al., EMNLP 2023) |
| Structural constraint ontology + CARM retrieval | Original contribution of this project |
| Sync-directory payload injection | Reuses AFL++'s own multi-instance foreign-sync convention; not drawn from external literature |

## License

MIT
