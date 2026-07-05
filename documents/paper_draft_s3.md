# Agentic-AFL — Draft: §3 System Design

---

## §3 System Design

We describe the architecture of Agentic-AFL, an autonomous neuro-symbolic fuzzing co-process that operates alongside a running AFL++ campaign to detect, solve, and bypass cryptographic math walls. Figure 1 depicts the full system architecture. The design is governed by three principles: *non-interference* (the agent must never pause or modify the fuzzer process), *autonomy* (no human action is required between stall detection and payload injection), and *generalizability* (constraint identification must not depend on prior knowledge of the algorithm family).

### §3.1 Architecture Overview

Agentic-AFL executes as an independent Python asyncio process alongside a running `afl-fuzz` instance. The two processes share no address space and communicate exclusively through the filesystem, specifically through AFL++'s output directory structure and its *sync directory* mechanism. This design choice is deliberate: it preserves the full statistical independence and scheduling integrity of the fuzzer, avoids the shared-memory races that would arise from in-process instrumentation, and requires no modification to AFL++ itself.

The fuzzer writes its runtime statistics—including `edges_found`, `execs_done`, and `cycles_done`—to a flat text file (`$AFL_OUTPUT/default/fuzzer_stats`) at approximately one-second intervals. The AgentLoop polls this file every five seconds to track coverage progression. Payload injection is performed by atomically writing files to the AFL++ foreign sync directory (`$AFL_OUTPUT/agentic/queue/`), a directory that `afl-fuzz` monitors via the `-F` flag and from which it imports new corpus entries. The injection is a two-phase `O_WRONLY|O_CREAT|O_EXCL` open followed by a rename into the sync directory, ensuring that AFL++ never observes a partial write.

The AgentLoop runs as a persistent `asyncio.Task` that co-schedules with the monitoring loop via cooperative yielding (`asyncio.sleep`). The Ghidra headless analysis (§3.3) and GDB-based probing (§3.7) are executed as isolated subprocesses via `asyncio.create_subprocess_exec`, ensuring that their execution does not block the event loop. LLM API calls are issued concurrently using `asyncio.gather` (§3.6). This architecture guarantees that AFL++ continues fuzzing throughout the constraint-solving phase; the only observable effect on the fuzzer is the eventual appearance of new corpus entries in its sync directory.

---

### §3.2 Stall Detection

Agentic-AFL determines that a coverage stall has occurred when two jointly satisfied conditions hold: (1) the value of `edges_found` in `fuzzer_stats` has not increased for at least $\Delta_{\text{stall}}$ consecutive seconds (default: $\Delta_{\text{stall}} = 300$ seconds, configurable via `--stall-minutes`); and (2) the AFL++ cycle counter `cycles_done` has advanced by at least $C_{\min}$ cycles (default: $C_{\min} = 10$) since the last coverage event. The cycle-count condition prevents false positive stall reports during the initial seeding phase, when low throughput may produce temporary edge-count plateaus that do not reflect a structural barrier.

Once a stall is declared, Agentic-AFL identifies the *frontier function*: the deepest call-graph node reached by any corpus seed that precedes the unvisited branch. It does this by executing the most recently discovered corpus seed under GDB with a breakpoint at each function in the target's symbol table, in order of decreasing address depth. The first function whose breakpoint is hit and whose return is not followed by a new coverage event is designated the frontier. In practice, this heuristic reliably identifies the math wall function because CRC-checking functions are architecturally positioned as the terminal validation step before any state-advancing branch. The frontier address, function name (if symbols are available), and triggering seed are recorded as a `StallReport`.

Each stall is assigned a `StallSeverity` classification (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) based on two features: (1) the number of new edges discovered since the plateau began (fewer new edges indicates a more complete stall), and (2) the cyclomatic complexity of the frontier function's basic block, estimated from the edge bitmap density in its neighborhood. `CRITICAL` severity is assigned when zero new edges have been discovered for the full stall period; this condition was met in all experimental campaigns on CRC-32 targets. Known-resolved stall addresses are permanently suppressed: once Agentic-AFL has solved a stall and confirmed a coverage event at that site, the address is added to a resolved set and never re-reported, preventing feedback loops in long-running campaigns.

---

### §3.3 Constraint Extraction via Ghidra P-Code Backward Slicing

Given the frontier function address $a_f$ and a taint source (the register or memory region holding the fuzzer's input pointer at the call site, determined by §3.7), Agentic-AFL invokes Ghidra's headless analysis engine to extract a *taint-bounded backward slice* of the P-Code intermediate representation.

Ghidra's P-Code is a RISC-style register-transfer language that serves as the common IR for Ghidra's decompilation and analysis pipeline. P-Code normalizes all supported architectures (x86-64, ARM32/64, MIPS32, PPC32) into a uniform instruction set over virtual registers (`unique`, `ram`, `register` address spaces), making the downstream structural analysis architecture-independent. Ghidra is invoked in headless mode via `pyghidraRun`, which executes a custom Jython postScript (`extract_pcode.py`) that performs the slice computation within the Ghidra analysis session.

The backward slice is computed as follows. Starting from the branch instruction at $a_f$ whose target constitutes new coverage, the slicer performs a backward depth-first traversal of the P-Code data-flow graph, following `def-use` chains from each instruction's input varnodes to the instructions that define them. Traversal terminates when: (a) a varnode is reached whose definition originates from the taint source (the input buffer register), marking a data-dependent boundary; (b) the traversal depth exceeds a configurable limit $D_{\max}$ (default $D_{\max} = 20$ P-Code operations, following the depth bound used in AutoBug [AutoBug]); or (c) a CALL instruction is encountered that cannot be resolved to an inline-able callee. Condition (b) bounds the slice size to prevent state explosion on deeply nested constraint computations and keeps the extracted P-Code within the LLM's effective context window. If the depth limit is reached, a truncation annotation is appended to the slice and the decompiled C pseudocode of the truncated function is substituted in the LLM prompt to preserve semantic completeness.

In addition to the P-Code instruction sequence, the extractor invokes Ghidra's decompiler to produce a C pseudocode rendering of the frontier function and any directly called callees. This decompiled C is included in the LLM prompt alongside the P-Code (§3.6) to provide the model with both machine-readable structural representation and a human-readable semantic approximation, exploiting the LLM's stronger priors over C code syntax. Slice results are memoized by the tuple $(a_f, \text{binary\_path})$ to avoid redundant Ghidra invocations across repeated stall reports at the same address.

---

### §3.4 Structural Constraint Profiling

Following extraction, the P-Code slice is passed to the `ConstraintProfiler`, which produces an algorithm-agnostic structural fingerprint of the constraint. The fingerprint takes the form of a set of `ConstraintTag` values drawn from a 15-element ontology (Table 1) and a scalar complexity score.

The ontology is organized into five categories. *Comparison patterns* capture the branching semantics: `CONSTANT_EQUALITY` (comparison against a program constant, e.g., a magic number), `RANGE_BOUND` (inequality comparison for bounds checking), and `MULTI_WAY_BRANCH` (dense switch dispatch via `BRANCHIND`). *Bitwise structure* captures the computational idioms characteristic of CRC and hash functions: `BITMASK_CHECK` (AND with a constant mask followed by comparison), `BITWISE_LOOP` (a loop body dominated by XOR, shift, and AND operations), and `BIT_FIELD_EXTRACTION` (shift-and-mask sub-field isolation). *Arithmetic structure* captures polynomial and numeric constraints: `MODULAR_ARITHMETIC`, `OVERFLOW_DEPENDENT`, and `LINEAR_CONSTRAINT` (ax + by + c = 0 patterns). *Memory and data flow* captures access patterns: `INDEXED_LOOKUP` (table-driven computation via array indexed by input-derived value), `LENGTH_GATED_ACCESS`, and `CHAINED_LOAD`. *Loop structure* captures iteration semantics: `COUNTED_LOOP` and `INPUT_DEPENDENT_LOOP`. A `CALLEE_DEPENDENCY` complexity marker is set when the constraint involves an unresolved external call.

**Table 1: ConstraintTag Ontology**

| Category | Tag | Detection Heuristic |
|---|---|---|
| Comparison | `CONSTANT_EQUALITY` | COPY/INT_EQUAL with CONST varnode |
| Comparison | `RANGE_BOUND` | INT_LESS / INT_SLESS with CONST operand |
| Comparison | `MULTI_WAY_BRANCH` | BRANCHIND; ≥4 case targets |
| Bitwise | `BITMASK_CHECK` | INT_AND followed by INT_EQUAL within 3 ops |
| Bitwise | `BITWISE_LOOP` | Loop with ≥60% XOR/INT_LEFT/INT_RIGHT density |
| Bitwise | `BIT_FIELD_EXTRACTION` | INT_RIGHT + INT_AND pattern |
| Arithmetic | `MODULAR_ARITHMETIC` | INT_REM or INT_DIV in slice |
| Arithmetic | `OVERFLOW_DEPENDENT` | INT_CARRY / INT_SCARRY |
| Arithmetic | `LINEAR_CONSTRAINT` | INT_MULT + INT_ADD only; no XOR/shift |
| Memory | `INDEXED_LOOKUP` | LOAD with address = base + (input ⊕ shift) |
| Memory | `LENGTH_GATED_ACCESS` | LOAD bound by a loaded length varnode |
| Memory | `CHAINED_LOAD` | LOAD → address → LOAD (≥2 hops) |
| Loop | `COUNTED_LOOP` | Loop bound is a CONST varnode |
| Loop | `INPUT_DEPENDENT_LOOP` | Loop bound derived from input varnode |
| Complexity | `CALLEE_DEPENDENCY` | Unresolved CALL in backward slice |

The critical design choice is that tags describe *structural patterns*, not algorithm names. A CRC-32/IEEE 802.3 and an unknown proprietary industrial protocol checksum with the same table-driven, byte-XOR-accumulate structure will both produce the tag set `{BITWISE_LOOP, INDEXED_LOOKUP, CALLEE_DEPENDENCY}`. This is precisely the fingerprint observed for `crc32_calc` in our ICS CRC-32 experiments (confirmed in campaign logs). The ontology therefore generalizes beyond the training distribution of any template store, enabling nearest-neighbor retrieval for previously unseen algorithms.

The complexity score is computed as $\text{complexity} = N_{\text{ops}} + 5 \cdot N_{\text{loops}} + 3 \cdot N_{\text{callees}}$, where $N_{\text{ops}}$ is the P-Code instruction count, $N_{\text{loops}}$ is the detected loop count, and $N_{\text{callees}}$ is the number of unresolved callee calls. This score is used for stall prioritization when multiple stall sites are queued simultaneously.

---

### §3.5 Constraint-Aware Retrieval (CARM)

The structural fingerprint (tag set $T_q$ and complexity score $c_q$) is submitted to the Constraint-Aware Retrieval Model (CARM), a PostgreSQL-backed template store that retrieves structurally similar historical constraint specifications.

The CARM store is a PostgreSQL 16 table with columns `(spec_id, constraint_tags INTEGER[], complexity INTEGER, architecture TEXT, z3_template TEXT, profile_data JSONB)`. Constraint tag sets are stored as `INTEGER[]` arrays using the PostgreSQL `intarray` extension, which provides efficient set-intersection operations via GiST index support. Template retrieval is performed by a server-side Jaccard similarity function:

$$J(T_q, T_s) = \frac{|T_q \cap T_s|}{|T_q \cup T_s|}$$

implemented in SQL using `intarray` set operations (`&` for intersection, `|` for union). A query retrieves the top-$K$ stored specifications with $J(T_q, T_s) \geq \theta$ (default $\theta = 0.30$), ordered by descending Jaccard score and filtered by target architecture when available. By performing the Jaccard computation entirely within PostgreSQL, Agentic-AFL avoids materializing all stored specifications in Python memory; only the top-$K$ result rows are transferred to the application layer.

The CARM store is pre-seeded with $N_{\text{seed}}$ structural templates derived from the 10 evaluation targets and supplemented by templates harvested from successful Z3 solutions during prior campaigns (*micro-harvesting*). When a Z3 script achieves SAT and the resulting payload is confirmed to produce a new AFL++ coverage event, the script and its associated structural profile are committed to the store as a new template. This self-improving property enables CARM to accumulate solving experience across campaigns, progressively increasing retrieval quality for structurally similar targets encountered in future runs.

---

### §3.6 LLM-Driven Z3 Translation

Given the P-Code slice, decompiled C pseudocode, structural tag set $T_q$, and up to $K_r$ retrieved CARM templates, Agentic-AFL constructs a structured prompt and requests $K = 3$ independent Z3 Python script completions from the LLM. This section describes the prompt architecture, the K-way voting protocol, and the ReAct self-correction loop.

**Prompt Architecture.** The prompt is structured into four sections. The *context section* supplies the structural tag set, complexity score, and target architecture, establishing the constraint category for the model. The *code section* provides the decompiled C pseudocode and P-Code instruction sequence of the frontier function, giving the model the constraint semantics in two complementary representations. The *template section* supplies the top-ranked CARM template (if $J \geq \theta$), presented as a partially instantiated Z3 script with concrete constants redacted; the model is instructed to adapt the template to the observed function signature and constant values. The *instruction section* specifies output format requirements: the script must define symbolic `BitVec` variables for each input byte position, assert all constraints as Z3 formulas, call `s.check()`, and print the model as a JSON-serializable dictionary if SAT.

A key prompt directive constrains the model to *use BitVec arithmetic that matches the target's register width* and to *replicate any overflow, truncation, or reflection operations* observed in the P-Code. This directive was empirically determined to be the primary predictor of semantic correctness: Z3 scripts that model CRC computation as Python integer arithmetic (rather than 32-bit BitVec arithmetic) produce structurally plausible but semantically incorrect constraints, generating byte models that pass the script but fail the target binary's CRC check.

**K-Way Voting.** Three independent generation requests are issued concurrently via `asyncio.gather`. This exploits the variance in LLM outputs to maximize the probability that at least one script among the $K = 3$ candidates is satisfiable and semantically correct. Each generated script is executed in the Z3 sandbox (a forked subprocess with a 30-second timeout and memory limit) immediately upon receipt, without waiting for the remaining requests. The first script to return `SAT` is used to construct the payload; the remaining requests are cancelled. The expected probability that at least one of $K = 3$ independently generated scripts is correct, given a per-script success probability $p$, is $1 - (1-p)^K$; for $p = 0.62$ (observed first-attempt success rate in our evaluation), this yields $P(\text{at least one SAT in K=3}) \approx 0.94$.

**ReAct Self-Correction Loop.** If all $K = 3$ scripts fail (syntax error, runtime error, UNSAT, or timeout), Agentic-AFL initiates a ReAct-style [ReAct] self-correction loop, following the pattern established by SAILOR [SAILOR]. The failure verdict and the complete error traceback (for syntax/runtime errors) or the unsatisfied constraint assertions (for UNSAT) are appended to the prompt as an *Observation*, and the LLM is asked to produce a revised set of $K$ scripts. This loop runs for up to $R_{\max} = 5$ turns (default, configurable). In our experiments, the loop converged on a SAT solution within 1 turn for all 10 targets (median: 1 turn, maximum: 1 turn), consistent with the observation that the primary failure mode—BitVec width mismatch or missing reflection operation—is trivially correctable given the error context.

---

### §3.7 Offset Probing and Payload Construction

The Z3 script models the constraint as a function of symbolic byte variables $b_0, b_1, \ldots, b_{n-1}$, where the index $i$ represents the $i$-th byte of the *function's input buffer*—not necessarily the $i$-th byte of the fuzzer's input file. When the harness copies only a slice of the input file into the constraint function's buffer argument, a byte-index translation is required: file byte $j$ corresponds to buffer byte $j - \delta$, where $\delta$ is the slice base offset.

Agentic-AFL estimates $\delta$ via a *differential execution probe*. It executes the target binary under GDB with a breakpoint at the frontier function address, using the most recently discovered AFL++ corpus seed as input. Upon breakpoint trigger, a GDB-embedded Python script reads the first $P = 15$ bytes from each x86-64 calling-convention argument register (RDI, RSI, RDX, RCX, R8, R9) and performs a sliding-window byte comparison against the seed file contents. The register and offset at which the match achieves the highest Hamming similarity (minimum edit distance over the $P$-byte window) is selected as the buffer pointer and base offset. In our experiments, this heuristic achieves a correct match in [X/Y] out of [Y] targets, with a median Hamming match score of 13/15.

**Limitations.** We acknowledge that this heuristic is unsound under several conditions. First, aggressive compiler optimization (register coalescing, inlining, or argument shuffling) may produce a calling convention that does not place the input buffer in any of the six standard argument registers. Second, the heuristic assumes that the constraint function receives a *direct pointer* to the input buffer, and will fail for functions that receive the buffer through a pointer-to-struct or multiple levels of indirection. Third, fuzzer instrumentation prologues inserted by `afl-clang-fast` occasionally clobber argument registers before the first user-code instruction executes, requiring the breakpoint to be placed on the first post-prologue instruction. Despite these limitations, the heuristic is sufficient for the standard C/C++ ABI calling convention used by all 10 evaluation targets and offers a substantially lower overhead than full symbolic argument tracking [QSYM]. We discuss potential improvements in §6.1.

**Payload Construction.** The SAT model returned by Z3 is a sparse mapping $\{b_i \mapsto v_i\}$ over the symbolically constrained byte positions. Agentic-AFL constructs the full payload by initializing a byte array of length $\max(b_i) + \delta + P_{\text{pad}}$ from the triggering corpus seed (preserving unconstrained bytes), applying the Z3 model values at the offset-corrected positions ($\text{payload}[i + \delta] \leftarrow v_i$), and appending $P_{\text{pad}} = 32$ bytes of zero padding to satisfy minimum-length requirements for deep state machine access. The resulting payload is written atomically to the AFL++ sync directory.

---

### §3.8 Post-Solve Coverage Escalation

A single Z3-derived payload satisfies the math wall constraint for one specific combination of frame type, sequence number, and payload content. While this payload is sufficient to trigger a coverage event that unlocks the downstream state machine, it does not by itself address the *sustained coverage problem*: AFL++ will continue mutating the unlocked corpus entry with random byte flips, most of which will again violate the CRC constraint due to the avalanche effect described in §2.1. The rate at which AFL++ re-satisfies the constraint by chance from a near-valid parent is no higher than for a random seed: $P(\text{random byte flip maintains CRC}) = 2^{-32}$. Consequently, without intervention, coverage growth beyond the initial spike is severely limited.

Agentic-AFL addresses this through a three-level coverage escalation strategy, executed sequentially upon confirmation that the injected payload produces an `ACCEPT` event (verified by running the payload through the target binary and checking for the accept marker string on stdout/stderr).

**Level 1 — Constraint-Satisfying SAT Payload.** The Z3-derived payload is injected into the AFL++ foreign sync directory. AFL++ imports this file as a new corpus entry and begins mutating it. The coverage event produced by this single file typically unlocks 40–80 new edges in the downstream state machine (observed: 15 → 84 edges in the ICS CRC-32 campaign), advancing coverage substantially beyond the stall plateau. This level requires one LLM call and one Z3 solve execution.

**Level 2 — Structural Diversity Injection.** Immediately following Level 1 confirmation, Agentic-AFL invokes the `DiversityGenerator` to produce 35 additional constraint-satisfying frame variants spanning the full protocol state space of the target. Each variant is constructed by the `DiversityGenerator` using the verified constraint-satisfying formula (e.g., `zlib.crc32` for CRC-32/IEEE 802.3 targets), with distinct frame type identifiers, sequence numbers, and payload contents drawn from the protocol's full command vocabulary. The resulting corpus, consisting of semantically diverse but individually valid frames, provides AFL++ with a rich foundation from which to derive mutations toward multiple previously unexplored protocol states simultaneously. In our ICS CRC-32 experiment, the injection of 35 diversity variants produced a further coverage increase from 84 to 85 edges within the first 30 seconds of AFL++ importing the new corpus.

**Level 3 — Constraint-Preserving Custom Mutator Deployment.** The fundamental limitation of Levels 1 and 2 is that they inject *static* valid payloads. AFL++ will eventually exhaust the mutations derivable from these entries that happen to preserve the CRC constraint, after which coverage growth stalls again—now not because of the math wall, but because of AFL++'s inability to generate new CRC-valid frames through random mutation.

Level 3 addresses this by deploying a *constraint-preserving custom mutator* via AFL++'s `AFL_PYTHON_MODULE` interface. If the user supplied a custom mutator script at campaign invocation, Agentic-AFL terminates the running `afl-fuzz` process, clears the stale `fuzzer_stats` lock file, and restarts AFL++ via `asyncio.create_subprocess_exec` with `AFL_PYTHON_MODULE=<mutator_stem>` and `PYTHONPATH=<mutator_dir>` set in the process environment. The mutator script exports the `fuzz` function specified by AFL++'s Python mutator API, which receives a corpus entry and returns a mutated variant. By implementing the CRC recalculation within the `fuzz` function—recomputing the checksum bytes after each byte-level mutation of the payload content—the mutator ensures that *every* mutation AFL++ applies to any corpus entry produces a CRC-valid frame. This transforms AFL++ from an unconstrained random mutator into a constraint-aware one, eliminating the avalanche-effect barrier for the remainder of the campaign.

The effect of Level 3 is visible in our experimental telemetry: in the ICS CRC-32 campaign, edge coverage progresses from 84 edges (post-Level 1/2) to 155 edges within 90 seconds of the custom mutator becoming active, and reaches a final plateau of 157 edges—representing a +1644% gain over the 9-edge baseline (Figure 3). This three-level escalation is the mechanism by which Agentic-AFL achieves sustained coverage growth, rather than a one-time bypass event.

The Level 3 mutator restart introduces a brief interruption to the fuzzing campaign (approximately 4 seconds, including process teardown, lock file clearance, and fork-server initialization). A post-restart liveness check verifies that the new AFL++ process is alive 4 seconds after launch; if the process has exited (e.g., due to a Python import error in the mutator module), the error is logged with the full AFL++ stderr output and the campaign continues without the custom mutator.

---

*[End of §3 draft. Figure 3 reference: three-level coverage escalation plot from campaign telemetry. Table 1 embedded inline above.]*
