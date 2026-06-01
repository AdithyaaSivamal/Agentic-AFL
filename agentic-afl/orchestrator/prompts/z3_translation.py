"""
z3_translation.py — Prompt Templates for P-Code → Z3Py Translation.

This module contains the system and user prompt templates used by llm_client.py
to instruct the LLM to translate P-Code slices into Z3Py solver scripts.

CRITICAL CONSTRAINTS (enforced in every prompt):
    1. All register values MUST use BitVec(name, WIDTH) — NEVER Int().
       Reference: TDD_v2 §4.3, LLM-Sym §3.2.
    2. SSA naming: reg_0, reg_1, mem_0, mem_1.
       Reference: LLM-Sym §3.2.
    3. Output must be a complete, standalone Z3Py script.
    4. Script must end with s.check() + model extraction.
    5. No imports beyond z3 are allowed.

Template Variables:
    {register_width}    — BitVec width from Architecture (e.g., 32).
    {pcode_text}        — The P-Code slice text.
    {constraint_tags}   — The detected constraint types (for context).
    {seed_input_hex}    — The closest seed input as hex string.
    {retrieved_templates} — Previously successful Z3 scripts for similar problems.
    {correction_history}  — Past errors and corrections for this stall.
"""

# ---------------------------------------------------------------------------
# System Prompt — Sets the LLM's role and hard constraints.
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are a precise firmware reverse engineering assistant. Your SOLE task is to
translate Ghidra P-Code intermediate representation into Z3Py solver scripts
that find concrete input values bypassing a specific branch constraint.

## HARD CONSTRAINTS — Violating ANY of these makes the output INVALID:

1. ALL register/memory values MUST use `BitVec(name, {register_width})`.
   NEVER use `Int()` or `IntVal()` for register values.
   Rationale: Firmware operates on fixed-width registers. Int() ignores overflow
   behavior and produces mathematically correct but physically impossible values.

2. Variable naming MUST follow SSA convention:
   - Registers: `reg_0 = BitVec('reg_0', {register_width})`
   - Memory:    `mem_0 = BitVec('mem_0', {register_width})`
   - Constants: Use Python integer literals directly.

3. Output MUST be a complete, standalone Python script:
   ```python
   from z3 import *
   s = Solver()
   # ... your constraints ...
   if s.check() == sat:
       m = s.model()
       print({{str(d): m[d].as_long() for d in m.decls()}})
   else:
       print("UNSAT")
   ```

4. ONLY import from `z3`. No os, sys, subprocess, or network calls.

5. You MUST wrap your complete Z3Py script in ```python ... ``` code blocks.
   Output ONLY the code block — do NOT include explanatory text before or after.
   Your entire response should be a single ```python ... ``` block.

6. NEVER hardcode large arrays or lookup tables (e.g., 256-element CRC tables)
   as Python lists. Your generation WILL truncate mid-array and produce a
   SyntaxError. If the decompiled C uses a lookup table for CRC/checksum/hash:
   - Reconstruct the algorithm using BITWISE LOOPS (XOR, shift, If()).
   - A CRC table[256] is just a precomputed shortcut for 8 rounds of
     polynomial division. Replace the table lookup with the 8-bit loop.
   - Example: Instead of `table[idx]`, use:
     ```
     for _ in range(8):
         lsb = Extract(0, 0, crc)
         crc = If(lsb == 1, LShR(crc, 1) ^ poly, LShR(crc, 1))
     ```

7. NEVER reproduce the seed input as a Python list (e.g., `seed = [0x68, ...]`).
   This WILL truncate and cause SyntaxError. The seed hex is shown for
   REFERENCE ONLY — use it to read fixed protocol field values.
   Your script must ONLY declare Z3 BitVec variables and add constraints.
   The orchestrator overlays your solved byte values onto the seed automatically.

## Architecture: {architecture}
## Register Width: {register_width} bits
"""

# ---------------------------------------------------------------------------
# User Prompt — Contains the P-Code slice and all context.
# ---------------------------------------------------------------------------

USER_PROMPT = """\
## Task
Translate the following P-Code slice into a Z3Py script that finds concrete
input byte values satisfying the path condition to reach address {stall_address}.

## P-Code Slice (from function {function_name}):
```
{pcode_text}
```

{decompiled_c_section}

## Detected Constraint Types:
{constraint_tags}

## Closest Seed Input (hex, {input_length} bytes total — REFERENCE ONLY, do NOT reproduce as a list):
{seed_input_hex}

{function_context}

{templates_section}

{corrections_section}

{offset_mapping_section}

## CRITICAL Instructions:
1. Model the INPUT BUFFER using an array comprehension to declare ALL bytes,
   then create a dict for named access:
   ```python
   input_bytes = [BitVec(f'byte_{{i}}', 8) for i in range({input_length})]
   # Create named variables for convenient access
   b = {{i: input_bytes[i] for i in range({input_length})}}
   # Use b[0], b[1], ... b[{last_byte_index}] throughout your script
   # Or unpack specific ranges: byte_0 = b[0]; byte_8 = b[8]; etc.
   ```
   WARNING: Do NOT reference `byte_N` as a standalone variable unless you
   explicitly assigned it (e.g., `byte_16 = b[16]`). Use `b[N]` or
   `input_bytes[N]` for safe access. NameError on `byte_N` is the #1 failure.

2. The seed input above shows the current input. Your Z3 script MUST find
   values for byte_0 through byte_{last_byte_index} that satisfy ALL
   constraints needed to reach address {stall_address}.

3. Translate the P-Code constraints into Z3. For operations on multi-byte
   values (e.g., uint16_t from bytes 8-9), use:
   `word = Concat(byte_8, byte_9)` for big-endian, or
   `word = Concat(byte_9, byte_8)` for little-endian.

4. The goal is to find byte values that make the BRANCH at {stall_address}
   take the currently-untaken path (i.e., pass the check).

5. Use `s.add(...)` for each constraint.

6. End with the s.check() + model print block shown in the system prompt.

7. Read the DECOMPILED C carefully. If the function computes a value over
   the input bytes (checksum, CRC, hash, MAC, etc.) and compares the result,
   you MUST model the FULL computation in Z3 using BitVec operations.
   The computed field bytes MUST appear as constrained variables.
   Do NOT leave any bytes unconstrained or set them to zero.

8. EVERY input byte (b[0] through b[{last_byte_index}]) must appear
   in at least one `s.add(...)` constraint. If a byte is part of a computed
   field (e.g., checksum), constrain it via the computation. If a byte is a
   fixed protocol field, constrain it to the required value.

Provide your complete Z3Py script below:
"""

# ---------------------------------------------------------------------------
# Offset Mapping Section — Injected when base_offset > 0.
# ---------------------------------------------------------------------------

OFFSET_MAPPING_SECTION = """\
## IMPORTANT: Byte Offset Mapping
This function receives input starting at **byte {base_offset}** of the file,
NOT at byte 0. The decompiled C references `input[0]`, `input[1]`, etc.,
but these correspond to file bytes as follows:

{offset_table}

When the C code references `input[N]`, you MUST use `byte_{mapped_N}` in Z3.
Bytes before byte_{base_offset} (byte_0 through byte_{prev_offset}) are
protocol framing that must be preserved from the seed. Constrain them to
their seed values.
"""

# ---------------------------------------------------------------------------
# Template Sections — Conditionally included in the user prompt.
# ---------------------------------------------------------------------------

TEMPLATES_SECTION = """\
## Previously Successful Z3 Scripts for Similar Constraints:
These scripts solved similar constraint profiles. Use them as reference patterns,
but adapt variable names and constants to match the current P-Code slice.

{templates}
"""

CORRECTIONS_SECTION = """\
## Previous Errors for This Stall (DO NOT repeat these mistakes):

{corrections}
"""

# ---------------------------------------------------------------------------
# Repair Prompt — Used when a Z3 script fails and needs correction.
# ---------------------------------------------------------------------------

REPAIR_PROMPT = """\
## Z3 Script Repair

The following Z3Py script was generated for the P-Code at address {stall_address},
but it FAILED with verdict: **{verdict}**.

### Failed Script:
```python
{failed_script}
```

### Error Details:
```
{error_message}
```

### Original P-Code Slice:
```
{pcode_text}
```

## Repair Instructions:
{repair_guidance}

Provide the COMPLETE corrected Z3Py script below (not just the changed lines):
"""

# ---------------------------------------------------------------------------
# Repair Guidance — Verdict-specific instructions for the LLM.
# Reference: Logic-LM §3.3 — Structured error feedback.
# ---------------------------------------------------------------------------

REPAIR_GUIDANCE = {
    "syntax_error": (
        "The Z3Py script has a SYNTAX ERROR. Common causes:\n"
        "- Missing parentheses or incorrect Z3 function names.\n"
        "- Using Int() instead of BitVec().\n"
        "- Incorrect BitVec operation (e.g., using + instead of bvadd for explicit ops).\n"
        "Fix the syntax error shown above."
    ),
    "runtime_error": (
        "The Z3Py script CRASHED during execution. Common causes:\n"
        "- Type mismatch (comparing BitVec of different widths).\n"
        "- Undefined variable (SSA naming error).\n"
        "- Incorrect Z3 API usage.\n"
        "Fix the runtime error shown above."
    ),
    "timeout": (
        "Z3 TIMED OUT trying to solve the constraints. The problem is TOO COMPLEX.\n"
        "You MUST simplify:\n"
        "- CONCRETIZE peripheral variables that are not directly from the input buffer.\n"
        "- REDUCE loop unrolling depth.\n"
        "- SPLIT complex constraints into independent sub-problems.\n"
        "Reference: TDD_v2 §4.3 — Concretize peripheral values on timeout."
    ),
    "unsat": (
        "Z3 returned UNSAT — the constraints are UNSATISFIABLE.\n"
        "This usually means the path condition was incorrectly translated.\n"
        "Common causes:\n"
        "- A branch condition was negated incorrectly.\n"
        "- A constraint was too restrictive (wrong constant value).\n"
        "- Missing constraints that establish preconditions.\n"
        "Re-examine the P-Code branch conditions carefully."
    ),
    "unknown": (
        "Z3 returned UNKNOWN. This typically happens with non-linear arithmetic.\n"
        "Try linearizing the constraints or using alternative Z3 tactics."
    ),
}



# ---------------------------------------------------------------------------
# Strategy Hints Section -- Dynamically generated from ConstraintProfile
# metrics by react_templates.build_strategy_hints().
#
# This replaces the old THOUGHT_CARD_SECTION + Z3_HELPERS approach.
# The content is algorithm-agnostic and generated at runtime.
#
# Reference: ConstraintLLM §2.1 -- structural constraint profiles.
# ---------------------------------------------------------------------------

STRATEGY_HINTS_SECTION = """\
{strategy_hints_content}
"""

