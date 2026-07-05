# Agentic-AFL — Draft: Title, Abstract, §1 Introduction

---

## Title Options

**Primary (Recommended):**
> Agentic-AFL: Autonomous Neuro-Symbolic Constraint Solving for Coverage-Guided Fuzzing of ICS Binaries

**Alternative A (Technique-forward):**
> Closing the Loop: LLM-Driven Z3 Synthesis and Autonomous Payload Injection for Cryptographic Math Wall Bypass

**Alternative B (Shorter, venue-friendly):**
> Agentic-AFL: Autonomous Math Wall Bypass via Structural Constraint Profiling and LLM-Guided SAT Solving

---

## Abstract

Coverage-guided grey-box fuzzers such as AFL++ are highly effective at discovering shallow program paths but systematically stall at non-linear cryptographic integrity checks—commonly termed *math walls*—that guard the deep protocol state machines of Industrial Control System (ICS) and Operational Technology (OT) binaries. Random mutation cannot satisfy a 32-bit polynomial CRC constraint with non-negligible probability, and existing hybrid approaches are insufficient: concolic execution engines suffer from path explosion on real-world C++ protocol stacks, while input-to-state inference techniques are effective only for constant-equality comparisons, not polynomial constraints. Recent LLM-assisted constraint solving approaches demonstrate promise but require human orchestration and do not integrate closed-loop feedback with a running fuzzer.

We present **Agentic-AFL**, an autonomous neuro-symbolic fuzzing orchestrator that continuously monitors a running AFL++ campaign, detects coverage plateaus attributable to cryptographic math walls, extracts constraint semantics via Ghidra P-Code backward slicing, and leverages a large language model to synthesize Z3 satisfiability scripts that produce constraint-satisfying byte sequences. These sequences are injected into the AFL++ sync directory without interrupting the fuzzer process. Upon bypass confirmation, Agentic-AFL executes a three-level coverage escalation strategy—SAT-solve injection, structural diversity generation, and persistent custom mutator deployment—that drives continued exploration of previously unreachable program states.

We evaluate Agentic-AFL against ten targets spanning six constraint classes, including four real-world ICS libraries (libmodbus, OpenDNP3, lib60870, NASA cFS). On our primary benchmark, a PROFINET/EtherCAT-style CRC-32/IEEE 802.3 harness with a 245-edge deep state machine, Agentic-AFL achieves a **+1644% edge gain** (9→157 edges) within 15 minutes, compared to zero gain by AFL++ alone over the same period. Agentic-AFL requires a single LLM call and one Z3 solve turn per stall site, with a median end-to-end constraint resolution time of [X] seconds. We release all tooling, harnesses, and evaluation artifacts as open-source software.

---

## §1 Introduction

Industrial Control System (ICS) and Operational Technology (OT) protocols are foundational to the safety and reliability of power grids, water treatment facilities, and manufacturing infrastructure. Despite their criticality, firmware and protocol implementations in this domain remain substantially underexplored by automated vulnerability discovery tools. Coverage-guided grey-box fuzzing, as exemplified by AFL++ [AFL++], has become the dominant approach for automated bug finding due to its efficiency and scalability. However, a structural class of barriers—which we term *math walls*—systematically prevents fuzzers from reaching the deeply nested program states where protocol logic vulnerabilities tend to reside.

Math walls arise when a protocol parser gates access to its internal state machine behind a cryptographic integrity check, such as a CRC-16 or CRC-32 checksum, an HMAC verification, or a sequence number comparison derived from prior protocol state. From the perspective of a coverage-guided fuzzer, these checks are opaque: the feedback signal (edge coverage) provides no gradient information toward satisfying a non-linear polynomial constraint. Under the avalanche effect of polynomial CRC computation, a single-bit mutation to the payload propagates to all bits of the checksum, producing a uniformly distributed output that bears no resemblance to the expected value. Consequently, the probability of a random mutation satisfying a 32-bit CRC constraint is 2^{-32}—approximately 2.3 × 10^{-10}—rendering brute-force approaches computationally infeasible at typical fuzzer throughput rates of 10^3–10^5 executions per second.

Several categories of prior work have addressed complementary aspects of this problem, but none provides a complete, autonomous solution. *Concolic execution* engines such as QSYM [QSYM], SymCC [SymCC], and Angr [Angr] can, in principle, derive satisfying inputs by tracking symbolic path constraints and invoking an SMT solver. However, these tools suffer from state explosion when applied to realistic protocol implementations, where C++ virtual dispatch, heap-allocated state, and library calls rapidly exhaust solver capacity [HyLLfuzz]. *Input-to-state inference* techniques, including Redqueen [Redqueen] and AFL++'s CmpLog mode [AFL++], achieve substantial coverage improvements by identifying magic-byte comparisons and substituting matching values. These approaches are effective for constant-equality constraints but do not generalize to polynomial constraints, whose output depends on all input bits through a non-invertible transformation. Recent work on *LLM-assisted constraint solving*, including LLM-Sym [LLM-Sym], ConstraintLLM [ConstraintLLM], and LINC [LINC], demonstrates that large language models can generate syntactically and semantically correct Z3 specifications from decompiled program fragments. However, these systems are designed as offline analysis pipelines: they require manual identification of the target constraint, human-in-the-loop validation of the generated specification, and ad-hoc integration of the resulting payload with the fuzzing campaign.

The central observation motivating this work is that none of the above approaches *closes the loop* between constraint solving and continuous fuzzing. A practical system must autonomously identify the blocking constraint during a live campaign, solve it without human intervention, verify the solution against the running binary, and inject the result into the fuzzer's corpus in a manner that drives subsequent exploration—all while preserving the statistical properties of the fuzzer's mutation engine. Furthermore, following a successful bypass, the system must sustain coverage growth in the newly unlocked program region, a challenge that a single injected payload is insufficient to address.

We present **Agentic-AFL**, a neuro-symbolic fuzzing orchestrator that achieves autonomous, end-to-end math wall bypass. Agentic-AFL operates as a co-process alongside a running AFL++ instance, monitoring edge coverage via the fuzzer's statistics interface. Upon detecting a coverage plateau consistent with a math wall, it identifies the frontier function via GDB-assisted execution tracing, performs a taint-bounded backward P-Code slice using Ghidra's headless analysis engine to extract the constraint's structural semantics, and queries a Constraint-Aware Retrieval Model (CARM)—a PostgreSQL-backed store of structural constraint templates indexed by Jaccard similarity over an algorithm-agnostic tag ontology. The retrieved template and extracted P-Code slice are provided to an LLM in a structured prompt, which generates a Z3 satisfiability script. The script is executed in a sandboxed subprocess; if satisfiable, the resulting byte model is assembled into a complete protocol payload and injected into AFL++'s sync directory via an atomic file write, requiring no modification to the fuzzer process.

A key design principle of Agentic-AFL is the separation of constraint *identification* (structural, algorithm-agnostic) from constraint *solving* (LLM-driven, instance-specific). Rather than recognizing algorithms by name—an approach that fails on proprietary or obfuscated implementations—Agentic-AFL profiles constraints by their *structural signatures*: the P-Code mnemonic density, loop topology, memory access patterns, and branching structure observable in the backward slice. A CRC-16/Modbus and a novel rotate-XOR-accumulate hash produce the same structural fingerprint under this ontology, enabling retrieval of semantically appropriate solving templates for previously unseen algorithms via nearest-neighbor matching.

Following successful bypass, Agentic-AFL applies a three-level coverage escalation strategy. At Level 1, the Z3-derived payload is injected into the AFL++ sync directory, triggering a coverage event that unlocks downstream program states. At Level 2, Agentic-AFL generates 35 structurally diverse, constraint-satisfying frame variants spanning the full space of protocol frame types, providing the fuzzer with a rich corpus from which to derive mutations. At Level 3, if the target was pre-supplied with a custom mutator, Agentic-AFL terminates and restarts the AFL++ process with the mutator enabled, ensuring that all subsequent mutations maintain constraint validity—transforming AFL++ from a random mutator into a constraint-aware one for the remainder of the campaign.

This paper makes the following contributions:

1. **Agentic-AFL**, an autonomous neuro-symbolic fuzzing co-process that detects, solves, and bypasses cryptographic math walls during a live AFL++ campaign without human intervention (§3).

2. A **Constraint-Aware Retrieval Model (CARM)** that indexes structural constraint fingerprints via Jaccard similarity over an algorithm-agnostic 15-tag P-Code ontology, enabling template retrieval for previously unseen constraint algorithms (§3.4–3.5).

3. A **three-level post-solve coverage escalation strategy** that sustains edge growth beyond the initial bypass through diversity injection and constraint-preserving custom mutator deployment (§3.8).

4. An **empirical evaluation** across ten targets representing six distinct constraint classes, including four real-world ICS libraries—libmodbus [libmodbus], OpenDNP3 [OpenDNP3], lib60870 [lib60870], and NASA cFS [cFS]—demonstrating autonomous bypass across constraint types including CRC-16, CRC-32, XOR-additive checksums, and multi-state sequence number constraints (§5).

5. An **open-source release** of the complete framework, all evaluation harnesses, seed corpora, and campaign result artifacts, to facilitate reproducibility and extension by the research community.

The remainder of this paper is organized as follows. §2 provides background on coverage-guided fuzzing and formalizes the math wall problem. §3 details the Agentic-AFL architecture. §4 describes the implementation. §5 presents our evaluation. §6 discusses limitations and directions for future work. §7 surveys related work, and §8 concludes.

---

*[Draft ends here. References to be populated from BibTeX; citation keys are placeholders.]*
