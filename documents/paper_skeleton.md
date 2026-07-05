# Agentic-AFL Paper Skeleton

> **Working Title Options:**
> - *Agentic-AFL: Neuro-Symbolic Fuzzing Orchestration for Cryptographic Math Walls in ICS Binaries*
> - *Breaking Math Walls Autonomously: An LLM-Guided Constraint Solving Architecture for Grey-Box Fuzzing*
> - *From Stall to Solve: Agentic Fuzzing with LLM-Driven P-Code Analysis and SAT Injection*

---

## §1 — Introduction (~1.5 pages)

**Goal:** Establish the problem, state the thesis, and summarize contributions.

### Flow:
1. **Hook** — ICS/OT binaries protect critical infrastructure. Fuzzing is the dominant vulnerability discovery technique, but coverage-guided fuzzers like AFL++ plateau at cryptographic integrity checks (CRC, HMAC, sequence counters). These "math walls" are provably unreachable by random mutation.

2. **The Gap** — Existing approaches attack this from one side:
   - *Symbolic execution* (Angr, SymCC, QSYM) — path explosion on real binaries, doesn't scale
   - *Taint-guided fuzzing* (Redqueen, CmpLog) — handles magic bytes but not polynomial constraints
   - *LLM-based repair* (LLM-Sym, ConstraintLLM) — generates Z3 but can't close the loop back to the fuzzer autonomously

3. **Thesis** — We present Agentic-AFL, a neuro-symbolic fuzzing orchestrator that autonomously detects coverage stalls, extracts constraint semantics via binary analysis, translates them to formal specifications using an LLM, solves them with Z3, and injects valid payloads back into a running AFL++ campaign — all without human intervention.

4. **Contributions** (bulleted):
   - An end-to-end autonomous pipeline: stall detection → Ghidra P-Code slicing → LLM-driven Z3 translation → payload injection
   - A Constraint-Aware Retrieval Model (CARM) using structural fingerprinting and Jaccard similarity
   - A three-level coverage escalation strategy (SAT solve → diversity injection → custom mutator deployment)
   - Empirical evaluation across 10 targets spanning 6 constraint types, including 4 real-world ICS libraries
   - Open-source release of the framework and all evaluation harnesses

---

## §2 — Background & Motivation (~1.5 pages)

**Goal:** Give reviewers the minimum context needed to understand the design.

### §2.1 — Coverage-Guided Grey-Box Fuzzing
- AFL++ feedback loop (bitmap, edge coverage)
- Why random mutation fails at integrity checks (avalanche effect)

### §2.2 — Math Walls in ICS Protocols
- What they are: CRC-16/32, HMAC, sequence counters, challenge-response
- Why they matter: they guard deep protocol state machines
- Concrete example: a Modbus RTU frame with CRC-16 — 1 in 2^16 chance of random bypass

### §2.3 — Limitations of Existing Approaches
- **SymCC/QSYM**: concolic execution, path explosion problem, doesn't integrate autonomously
- **Redqueen/CmpLog**: input-to-state correspondence — works for magic bytes, fails for polynomial constraints
- **LLM-Sym/ConstraintLLM**: generate Z3 from decompiled C, but require human orchestration and don't close the loop

### §2.4 — Key Insight
> A single LLM call cannot reliably solve a CRC-32. But an *agentic loop* — where the LLM's output is executed, verified, and fed back for self-correction — converges reliably in 1-3 turns.

---

## §3 — System Design (~3-4 pages)

**Goal:** The core technical contribution. Describe the architecture with enough detail to reproduce.

> [!NOTE]
> This is the section reviewers will scrutinize most. Every design decision needs justification.

### §3.1 — Architecture Overview
- **Figure 1:** Full system diagram (AFL++ ↔ StallDetector ↔ AgentLoop ↔ Ghidra ↔ LLM ↔ Z3 ↔ PayloadInjector)
- Filesystem-based IPC — zero fuzzer interference
- Fully asynchronous — agent never blocks AFL++

### §3.2 — Stall Detection
- Edge-plateau heuristic with time-based threshold
- GDB frontier tracing to identify the blocking function
- Severity classification (CRITICAL/HIGH/MEDIUM/LOW)

### §3.3 — Constraint Extraction (Ghidra P-Code Slicing)
- Headless Ghidra with taint-bounded backward slicing
- Depth-limited traversal (avoids state explosion)
- Output: P-Code instruction sequence + decompiled C

### §3.4 — Structural Constraint Profiling
- Algorithm-agnostic tag ontology (Table 1: 15 tags across 5 categories)
- Why tags, not algorithm labels — generalizes to unknown/proprietary checksums
- Complexity scoring for prioritization

### §3.5 — Constraint-Aware Retrieval (CARM)
- PostgreSQL-backed template store with server-side Jaccard similarity
- How structural fingerprints match across algorithm families
- **Figure 2:** CARM retrieval example — CRC-16 query matches CRC-32 template via shared `{BITWISE_LOOP, INDEXED_LOOKUP}` tags

### §3.6 — LLM-Driven Z3 Translation
- Prompt architecture: P-Code slice + decompiled C + CARM templates + structural hints
- K-way voting (K=3): generate K scripts, execute all, pick first SAT
- ReAct self-correction loop: error → LLM repair → re-execute (up to 5 turns)

### §3.7 — Offset Probing & Payload Construction
- Heuristic input-byte-to-register mapping via differential execution
- Building full-length payloads from sparse Z3 byte models
- Padding strategy for protocol-length requirements

### §3.8 — Post-Solve Coverage Escalation
- **Level 1:** Single SAT payload (bypasses the wall)
- **Level 2:** Diversity injection (35 frame variants across all protocol types)
- **Level 3:** Custom mutator deployment (AFL++ restarts with CRC-aware mutation)
- **Figure 3:** Coverage-over-time showing three escalation phases

---

## §4 — Implementation (~0.5 pages)

- Python 3.11+, asyncio-based
- Ghidra 11.x headless (PyGhidra)
- AFL++ 4.x with foreign sync
- Gemini API (configurable: OpenAI, local models)
- PostgreSQL for CARM spec store
- ~4,500 LoC core (excluding tests/harnesses)
- Open-source: [URL]

---

## §5 — Evaluation (~4-5 pages)

**Goal:** Empirical evidence that the approach works, generalizes, and outperforms baselines.

### §5.1 — Experimental Setup
- **Table 2:** Target matrix (10 targets × constraint type × source × math wall function)
- Hardware: [your lab machine specs]
- Duration: 1h per campaign, 5 runs per configuration
- Random seeds: 5 distinct AFL++ random seeds per run

### §5.2 — RQ1: Does Agentic-AFL autonomously bypass math walls?
- **Table 3:** Per-target results (baseline edges, final edges, gain %, bypass time, LLM calls)
- Success rate across constraint types
- **Figure 4:** Coverage-over-time for all 4 real-world targets (2×2 subplot grid)
- Key result: *"Agentic-AFL bypasses X/10 targets autonomously, achieving mean edge gain of Y% in Z minutes"*

### §5.3 — RQ2: How does Agentic-AFL compare to baselines?
- **Table 4:** Agentic-AFL vs. AFL++ alone vs. SymCC vs. QSYM
- Same targets, same duration, same seeds
- Mann-Whitney U test for statistical significance (p-values in table)
- **Figure 5:** Coverage-over-time comparison (Agentic-AFL vs baselines for 2-3 representative targets)

### §5.4 — RQ3: What is the contribution of each component?
- **Ablation study (Table 5):**
  - Full pipeline vs. no CARM (random template) vs. no diversity injection vs. no custom mutator vs. no ReAct loop
- Shows each component's marginal contribution

### §5.5 — RQ4: How efficient is the agent?
- LLM call counts, Z3 solve times, end-to-end latency
- Token costs per campaign
- **Figure 6:** Latency breakdown (pie chart: Ghidra extraction vs. LLM generation vs. Z3 solving)

### §5.6 — Case Study: ICS CRC-32
- Detailed walkthrough of one campaign (the 157-edge result)
- Timeline narrative: flat at 15 → agent fires → 84 edges → mutator → 157 edges
- **Figure 7:** Annotated coverage plot (the publication-quality one you already have)

---

## §6 — Discussion (~1 page)

### §6.1 — Limitations
- **Constraint types not yet covered:** HMAC/SHA (would require symbolic memory modeling)
- **LLM reliability:** Z3 generation is non-deterministic; ReAct loop mitigates but doesn't eliminate
- **Offset probing:** Heuristic, not sound — may fail on complex calling conventions
- **Single-threaded agent:** Currently processes one stall at a time

### §6.2 — Generalizability
- Structural tag ontology means unknown algorithms are handled via nearest-neighbor matching
- Framework is target-agnostic — works on any AFL++ harness
- LLM provider is swappable (Gemini, GPT-4, local models)

### §6.3 — Ethical Considerations
- All targets are open-source libraries or synthetic
- No zero-days disclosed as part of this work
- Framework designed for defensive security research

---

## §7 — Related Work (~1 page)

### Hybrid Fuzzing
- Driller, QSYM, SymCC, Fuzzolic — concolic execution integration
- Key difference: we use LLM + Z3 instead of symbolic execution (no path explosion)

### LLM-Assisted Program Analysis
- LLM-Sym, ConstraintLLM, LINC, HyLLfuzz, SAILOR
- Key difference: we close the loop (detect → solve → inject → verify) autonomously

### Protocol-Aware Fuzzing
- AFLNet, SGFuzz, StateAFL — stateful protocol fuzzing
- Key difference: we target the math walls that block protocol state exploration

### Checksum-Aware Approaches
- TaintScope, Redqueen, CmpLog — input-to-state inference
- Key difference: polynomial constraints (CRC) defeat I2S heuristics

---

## §8 — Conclusion (~0.5 pages)

- Restate the thesis
- Summarize key results (X targets, Y% mean edge gain, Z autonomy)
- Future work: HMAC support, multi-stall parallel solving, integration with coverage-guided symbolic execution

---

## Appendices (if needed)

- **A:** Full Z3 script example (generated by LLM for CRC-32)
- **B:** Complete target matrix with build instructions
- **C:** CARM template store schema

---

## Key Figures & Tables Checklist

| # | Type | Content | Status |
|---|---|---|---|
| Fig 1 | Diagram | System architecture | ❌ Need to create |
| Fig 2 | Diagram | CARM retrieval example | ❌ Need to create |
| Fig 3 | Plot | Three-level escalation coverage | ✅ Have data |
| Fig 4 | Plot | Coverage-over-time (4 real targets) | ❌ Need runs |
| Fig 5 | Plot | Baseline comparison | ❌ Need baseline runs |
| Fig 6 | Chart | Latency breakdown | ❌ Need profiling |
| Fig 7 | Plot | Annotated ICS CRC-32 case study | ✅ Have (`coverage_final3.png`) |
| Tab 1 | Table | Constraint tag ontology | ✅ In `constants.py` |
| Tab 2 | Table | Target matrix | ✅ In `test_generalization_matrix.py` |
| Tab 3 | Table | Per-target results | ❌ Need runs |
| Tab 4 | Table | Baseline comparison + p-values | ❌ Need baseline runs |
| Tab 5 | Table | Ablation study | ❌ Need ablation runs |
