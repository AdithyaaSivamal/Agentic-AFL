"""
pcode_slicer.py — Taint-Bounded Backward Slicing on Ghidra P-Code.

This module is the FIRST component in the data pipeline. It takes a binary
and a stall address, runs Ghidra headless analysis, and extracts a backward
slice of P-Code instructions that are data-dependent on the fuzzer's input.

Inputs:
    - binary_path: Path     — The firmware binary to analyze.
    - stall_address: str    — Hex address where AFL++ coverage stalled.
    - taint_source: str     — Memory region of the fuzzer's input buffer.

Outputs:
    - PCodeSlice            — The extracted slice (see models.py).

Key Design Decisions:
    1. TAINT BOUNDING (TDD_v2 §4.1): The backward slice is strictly bounded
       to instructions that resolve to the tainted input buffer. Any P-Code
       branch depending on global state NOT connected to the input is pruned.
       This prevents "memory-state explosion" where tracing globals would
       pull in the entire firmware binary.

    2. TRUNCATION (AutoBug Algorithm 2): If the slice exceeds
       config.max_pcode_instructions, we apply assuming(0) to prune the
       deepest unreached branches. This keeps the P-Code within the LLM's
       token budget (~4K tokens).

    3. GHIDRA HEADLESS: This module shells out to Ghidra's analyzeHeadless
       script, passing a Jython/Python script that performs the actual slicing
       within Ghidra's analysis framework. The Jython script writes JSON to
       stdout, which this module parses into PCodeSlice.

Implementation Notes:
    - The Ghidra Jython script (ghidra_scripts/extract_pcode.py) must be
      developed separately and placed in the Ghidra scripts directory.
    - This Python module handles orchestration: invoking Ghidra, parsing
      output, constructing the PCodeSlice dataclass.
    - Consider caching: if the same (binary, stall_address) pair is requested
      again, return the cached slice instead of re-running Ghidra.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from pathlib import Path

from agentic_afl.config import settings
from agentic_afl.constants import Architecture
from agentic_afl.models import PCodeInstruction, PCodeSlice

logger = logging.getLogger(__name__)

# Delimiters emitted by the Ghidra Jython script (extract_pcode.py).
# These must match exactly what the script prints.
_JSON_START_DELIMITER = "===PCODE_JSON_START==="
_JSON_END_DELIMITER = "===PCODE_JSON_END==="

# Path to the Ghidra Jython script, relative to this file.
_GHIDRA_SCRIPT_DIR = Path(__file__).parent / "ghidra_scripts"


class PCodeSlicerError(Exception):
    """Raised when P-Code extraction fails."""
    pass


class PCodeSlicer:
    """
    Extracts taint-bounded P-Code slices from binaries via Ghidra headless.

    Usage:
        slicer = PCodeSlicer(
            binary_path=Path("./firmware.bin"),
            architecture=Architecture.ARM32,
        )
        pcode_slice = slicer.extract_slice(
            stall_address="0x08001234",
            taint_source="input_buffer @ 0x20001000",
        )

    The extract_slice method is the primary interface. It:
      1. Invokes Ghidra's analyzeHeadless with the extraction Jython script.
      2. Parses the JSON output into PCodeInstruction objects.
      3. Applies taint bounding to prune non-input-dependent instructions.
      4. Applies truncation if the slice exceeds the instruction limit.
      5. Returns a PCodeSlice dataclass.
    """

    def __init__(
        self,
        architecture: Architecture = settings.target_architecture,
        max_slice_depth: int = settings.max_slice_depth,
        max_instructions: int = settings.max_pcode_instructions,
    ) -> None:
        self.architecture = architecture
        self.max_slice_depth = max_slice_depth
        self.max_instructions = max_instructions

    def extract_slice(
        self,
        binary_path: Path,
        stall_address: str,
        taint_source: str,
    ) -> PCodeSlice:
        """
        Extract a taint-bounded backward slice from the binary at the given stall address.

        Args:
            stall_address: Hex address where AFL++ stalled (e.g., "0x08001234").
            taint_source:  Description of the taint origin (e.g., "RDI" or "0x20001000").

        Returns:
            PCodeSlice with the extracted instructions, bounded and truncated as needed.

        Raises:
            PCodeSlicerError: If Ghidra analysis fails or produces invalid output.
        """
        if not binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        # Step 1: Invoke Ghidra headless analysis.
        raw_json = self._run_ghidra_headless(binary_path, stall_address, taint_source)

        # Step 2: Parse the raw JSON into PCodeInstruction objects.
        instructions = self._parse_pcode_json(raw_json)

        # Step 3: Extract metadata from the Ghidra JSON output.
        function_name = raw_json.get("function_name", "unknown")
        function_entry = raw_json.get("function_entry", "0x0")
        slice_depth = raw_json.get("slice_depth", 0)
        was_truncated = raw_json.get("was_truncated", False)

        # Step 3b: Extract decompiled C pseudocode (best-effort).
        decompiled_c = raw_json.get("decompiled_c", "")
        callee_c = raw_json.get("callee_c", [])
        if callee_c:
            # Append callee C code sections for full algorithmic context.
            for entry in callee_c:
                decompiled_c += "\n\n// --- Callee: %s ---\n%s" % (
                    entry.get("name", "unknown"), entry.get("c_code", "")
                )
            logger.info(
                "Included decompiled C for %d callee(s): %s",
                len(callee_c),
                [e.get("name") for e in callee_c],
            )

        # Step 3c: Include CALLER context when stall is at function entry.
        # The caller's C shows how input buffer bytes are parsed into the
        # function arguments we're trying to solve. Without this, the LLM
        # sees the constraint algorithm but not the byte-to-parameter mapping.
        caller_c = raw_json.get("caller_c", [])
        if caller_c:
            for entry in caller_c:
                decompiled_c += (
                    "\n\n// --- CALLER: %s ---\n"
                    "// This function CALLS the target function above.\n"
                    "// It shows how input buffer bytes are parsed into\n"
                    "// the function's parameters.\n%s"
                ) % (entry.get("name", "unknown"), entry.get("c_code", ""))
            logger.info(
                "Included decompiled C for %d caller(s): %s",
                len(caller_c),
                [e.get("name") for e in caller_c],
            )

        # Step 4: Apply taint bounding — prune instructions not data-dependent on taint_source.
        # NOTE: The Ghidra script already performs taint-bounded slicing internally.
        # This Python-side pass is a defense-in-depth filter: if the Ghidra script
        # returns any instructions with addresses outside the taint set (e.g., due
        # to overly aggressive inclusion), they are pruned here.
        bounded = self._apply_taint_bound(instructions, taint_source)

        # Step 5: Apply truncation if needed — assuming(0) on deepest branches.
        if len(bounded) > self.max_instructions:
            bounded = self._truncate_slice(bounded)
            was_truncated = True

        # Step 6: Handle pruned LOADs from Ghidra script (untainted memory accesses).
        pruned_loads = raw_json.get("pruned_loads", [])
        if pruned_loads:
            logger.info(
                "Ghidra pruned %d untainted LOAD operations from slice",
                len(pruned_loads),
            )

        logger.info(
            "Extracted slice: %s @ %s → %d instructions (depth=%d, truncated=%s, decompiled_c=%d chars)",
            function_name,
            stall_address,
            len(bounded),
            slice_depth,
            was_truncated,
            len(decompiled_c),
        )

        return PCodeSlice(
            binary_path=binary_path,
            stall_address=stall_address,
            function_name=function_name,
            function_entry=function_entry,
            instructions=bounded,
            taint_source=taint_source,
            slice_depth=slice_depth,
            truncated=was_truncated,
            architecture=self.architecture,
            decompiled_c=decompiled_c,
        )

    def _run_ghidra_headless(
        self,
        binary_path: Path,
        stall_address: str,
        taint_source: str,
    ) -> dict:
        """
        Invoke Ghidra's analyzeHeadless with the extraction script.

        The Ghidra Jython script (ghidra_scripts/extract_pcode.py) performs
        the actual backward slicing within Ghidra's analysis framework. It
        outputs JSON between delimiters that this method parses.

        Returns:
            Parsed JSON dictionary from Ghidra's output.

        Raises:
            PCodeSlicerError: If Ghidra exits with non-zero or produces invalid JSON.
        """
        ghidra_headless = settings.ghidra_install_dir / "support" / "pyghidraRun"

        if not ghidra_headless.exists():
            raise PCodeSlicerError(
                f"Ghidra pyghidraRun not found at {ghidra_headless}. "
                f"Set GHIDRA_INSTALL_DIR env var to your Ghidra installation."
            )

        # Ensure the project directory exists.
        project_dir = settings.ghidra_project_dir
        project_dir.mkdir(parents=True, exist_ok=True)

        # Build the analyzeHeadless command.
        # Script args are passed positionally after the script name.
        cmd = [
            str(ghidra_headless),
            "-H",
            str(project_dir),
            "agentic_afl_project",
            "-import", str(binary_path),
            "-postScript", "extract_pcode.py",
            stall_address,
            taint_source,
            str(self.max_slice_depth),
            "-scriptPath", str(_GHIDRA_SCRIPT_DIR),
            "-deleteProject",          # Clean up temp project after extraction
        ]

        logger.info("Running Ghidra headless: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180,  # 3 minute timeout for Ghidra analysis + decompiled C extraction
            )
        except subprocess.TimeoutExpired as e:
            raise PCodeSlicerError(
                f"Ghidra headless timed out after 180s for {binary_path} @ {stall_address}"
            ) from e
        except FileNotFoundError as e:
            raise PCodeSlicerError(
                f"Failed to execute Ghidra headless: {e}"
            ) from e

        # Ghidra writes progress info to stderr; actual JSON to stdout.
        stdout = result.stdout
        stderr = result.stderr

        if result.returncode != 0:
            logger.error("Ghidra stderr:\n%s", stderr[-2000:] if stderr else "(empty)")
            raise PCodeSlicerError(
                f"Ghidra headless exited with code {result.returncode} "
                f"for {binary_path} @ {stall_address}"
            )

        # Extract JSON between delimiters.
        json_str = self._extract_json_from_output(stdout, stderr)

        try:
            parsed = json.loads(json_str)
        except json.JSONDecodeError as e:
            raise PCodeSlicerError(
                f"Invalid JSON from Ghidra script: {e}\n"
                f"Raw output (first 500 chars): {json_str[:500]}"
            ) from e

        # Check for errors reported by the Ghidra script itself.
        if parsed.get("error"):
            raise PCodeSlicerError(
                f"Ghidra script reported error: {parsed['error']}"
            )

        return parsed

    def _extract_json_from_output(self, stdout: str, stderr: str = "") -> str:
        """
        Extract the JSON string between the start and end delimiters.
        """
        combined = stdout + "\n" + stderr
        start_idx = combined.find(_JSON_START_DELIMITER)
        end_idx = combined.find(_JSON_END_DELIMITER)

        if start_idx == -1 or end_idx == -1:
            raise PCodeSlicerError(
                f"Could not find P-Code JSON delimiters in Ghidra output. "
                f"Expected '{_JSON_START_DELIMITER}' and '{_JSON_END_DELIMITER}'. "
                f"Output length: {len(combined)} chars.\n\nOutput:\n{combined}"
            )

        json_start = start_idx + len(_JSON_START_DELIMITER)
        return combined[json_start:end_idx].strip()

    def _parse_pcode_json(self, raw_json: dict) -> list[PCodeInstruction]:
        """
        Parse Ghidra's JSON output into a list of PCodeInstruction objects.

        Expected JSON format from the Ghidra script:
        {
            "function_name": "check_function_code",
            "function_entry": "0x101245",
            "stall_address": "0x101257",
            "taint_source": "RDI",
            "taint_mode": "register",
            "slice_depth": 20,
            "instruction_count": 6,
            "was_truncated": false,
            "pruned_loads": [],
            "instructions": [
                {
                    "address": "0x101250",
                    "mnemonic": "LOAD",
                    "inputs": ["(const, 0x1b1, 4)", "(unique, 0x8f00@101250, 8)"],
                    "output": "(unique, 0x23b00@101250, 1)",
                    "raw_pcode": "(unique, 0x23b00@101250, 1) = LOAD ...",
                    "call_target": null
                },
                ...
            ]
        }
        """
        raw_instructions = raw_json.get("instructions", [])

        if not raw_instructions:
            logger.warning("Ghidra script returned 0 instructions.")
            return []

        instructions = []
        for idx, inst_dict in enumerate(raw_instructions):
            try:
                instruction = PCodeInstruction(
                    address=inst_dict["address"],
                    mnemonic=inst_dict["mnemonic"],
                    inputs=inst_dict.get("inputs", []),
                    output=inst_dict.get("output"),
                    raw_pcode=inst_dict.get("raw_pcode", ""),
                    call_target=inst_dict.get("call_target"),
                )
                instructions.append(instruction)
            except (KeyError, TypeError) as e:
                logger.warning(
                    "Skipping malformed instruction at index %d: %s (error: %s)",
                    idx, inst_dict, e,
                )

        return instructions

    def _apply_taint_bound(
        self,
        instructions: list[PCodeInstruction],
        taint_source: str,
    ) -> list[PCodeInstruction]:
        """
        Prune instructions not data-dependent on the taint source.

        Algorithm (backward data-dependency analysis):
          1. Start with the LAST instruction in the slice (closest to stall) —
             its inputs define the initial "taint set" of varnodes.
          2. Walk backward through the instruction list.
          3. If an instruction's OUTPUT is in the taint set:
             - Include it in the slice.
             - Add its INPUTS to the taint set.
          4. If an instruction's output is NOT in the taint set, prune it.
          5. Continue until reaching the function entry or max_slice_depth.

        Reference: AutoBug Algorithm 2 (GenSlice) — backward slicing on CFG.
        Reference: TDD_v2 §4.1 — Taint bounding to prevent memory-state explosion.

        NOTE: The Ghidra script already does taint-bounded slicing. This
        Python-side pass is defense-in-depth. If the Ghidra script produces
        a clean, taint-bounded slice, this function returns it unchanged.
        """
        if not instructions:
            return instructions

        # Initialize the taint set from the last instruction's inputs.
        # Also include the taint source itself.
        taint_set: set[str] = set()
        taint_set.add(taint_source)

        # Seed the taint set from the stall instruction (last in the list).
        stall_inst = instructions[-1]
        for inp in stall_inst.inputs:
            taint_set.add(inp)

        # Walk backward, collecting tainted instructions.
        tainted: list[PCodeInstruction] = [stall_inst]

        for inst in reversed(instructions[:-1]):
            if inst.output and inst.output in taint_set:
                tainted.append(inst)
                # Propagate taint to this instruction's inputs.
                for inp in inst.inputs:
                    taint_set.add(inp)

        # Reverse to restore chronological order (entry → stall).
        tainted.reverse()

        logger.debug(
            "Taint bounding: %d → %d instructions (pruned %d)",
            len(instructions),
            len(tainted),
            len(instructions) - len(tainted),
        )

        return tainted

    def _truncate_slice(
        self,
        instructions: list[PCodeInstruction],
    ) -> list[PCodeInstruction]:
        """
        Truncate a slice that exceeds max_instructions via assuming(0).

        Strategy (AutoBug §3.2):
          1. Identify the deepest branch points in the slice.
          2. Replace the deepest branches with assuming(0) — assume the branch
             is not taken, effectively pruning that subtree.
          3. Repeat until len(instructions) <= max_instructions.

        Simplified implementation: Since P-Code slices are linear (no CFG
        structure in the list), we truncate from the top (oldest instructions)
        to keep the instructions closest to the stall address. This preserves
        the most relevant constraints.

        This is a lossy operation — the truncated flag in PCodeSlice will be True.
        """
        if len(instructions) <= self.max_instructions:
            return instructions

        excess = len(instructions) - self.max_instructions

        logger.info(
            "Truncating slice: %d → %d instructions (dropping %d oldest)",
            len(instructions),
            self.max_instructions,
            excess,
        )

        # Keep the N instructions closest to the stall address.
        return instructions[excess:]

    @staticmethod
    def from_json_file(json_path: Path, architecture: Architecture = Architecture.X86_64) -> PCodeSlice:
        """
        Construct a PCodeSlice directly from a JSON file (bypass Ghidra).

        This is used for testing and for processing pre-extracted JSON from
        Ghidra script runs outside of this wrapper (e.g., via the GUI).

        Args:
            json_path:    Path to a JSON file matching the Ghidra script output format.
            architecture: Target architecture for BitVec widths.

        Returns:
            A PCodeSlice constructed from the JSON.

        Raises:
            PCodeSlicerError: If the JSON is malformed.
        """
        try:
            raw = json.loads(json_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            raise PCodeSlicerError(f"Failed to load JSON from {json_path}: {e}") from e

        # Use a temporary slicer to parse the instructions.
        # binary_path can be a placeholder since we're not running Ghidra.
        binary_path = Path(raw.get("binary_path", str(json_path)))

        slicer = PCodeSlicer.__new__(PCodeSlicer)
        slicer.architecture = architecture
        slicer.max_slice_depth = raw.get("slice_depth", 20)
        slicer.max_instructions = 200

        instructions = slicer._parse_pcode_json(raw)

        return PCodeSlice(
            binary_path=binary_path,
            stall_address=raw.get("stall_address", "0x0"),
            function_name=raw.get("function_name", "unknown"),
            function_entry=raw.get("function_entry", "0x0"),
            instructions=instructions,
            taint_source=raw.get("taint_source", "unknown"),
            slice_depth=raw.get("slice_depth", 0),
            truncated=raw.get("was_truncated", False),
            architecture=architecture,
        )
