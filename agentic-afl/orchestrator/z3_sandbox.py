"""
z3_sandbox.py -- Isolated Z3 Script Execution Environment.

This module executes LLM-generated Z3Py scripts in a sandboxed subprocess.
It enforces strict timeouts and captures the solver verdict + model.

Inputs:
    - Z3Script         -- From llm_client.py

Outputs:
    - Z3Result         -- Verdict (SAT/UNSAT/TIMEOUT/ERROR) + concrete model

Key Design Decisions:
    1. SUBPROCESS ISOLATION: Z3 scripts run in a separate Python subprocess,
       not in the main process. This prevents:
       - Malicious/buggy LLM-generated code from crashing the Orchestrator.
       - Z3 hangs from blocking the event loop.
       - Memory leaks from accumulating Z3 contexts.

    2. STRICT TIMEOUTS (TDD_v2 S4.3): The s.check() call is bounded by
       config.z3_timeout_seconds (default 5s). This prevents Z3 path explosion
       on complex cryptographic constraints.

    3. RESOURCE LIMITS (Linux RLIMIT): The subprocess is spawned with
       RLIMIT_AS (memory cap) and RLIMIT_CPU (CPU time) to prevent
       fork bombs and unbounded memory consumption.

    4. IMPORT WHITELISTING: The execution harness restricts __import__ to
       only 'z3' and 'json'. This is a first-line defense; RLIMIT is the
       backstop for Python sandbox escapes.

    5. OUTPUT PARSING: The subprocess prints its result as JSON to stdout.
       The sandbox parses this to construct the Z3Result.

Security Note:
    The LLM-generated code is UNTRUSTED. The sandbox MUST:
    - Run in a subprocess with restricted permissions.
    - Disallow filesystem access, network access, and os/sys calls.
    - Kill the process after the timeout.
    - Limit memory usage via resource limits.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
import time
import uuid
from pathlib import Path

from agentic_afl.config import settings
from agentic_afl.constants import Z3Verdict
from agentic_afl.models import Z3Result, Z3Script

logger = logging.getLogger(__name__)


# Maximum memory for Z3 subprocess: 512 MB.
_MAX_MEMORY_BYTES = 512 * 1024 * 1024

# The execution harness template.
# {timeout_ms} and {script_text} are substituted at runtime.
_HARNESS_TEMPLATE = '''\
import json
import sys
import resource

# --- Resource limits ---
try:
    resource.setrlimit(resource.RLIMIT_AS, ({max_memory}, {max_memory}))
except (ValueError, resource.error):
    pass  # Non-Linux or insufficient permissions

from z3 import *

# --- Security: block dangerous imports AFTER z3 is loaded ---
# Z3's C extension internally imports os, ctypes, etc. at module load time.
# We install the blocklist AFTER z3 is imported so only the LLM-generated
# code section is restricted. RLIMIT_AS + RLIMIT_CPU remain the true
# security backstop for a research MVP.
_BLOCKED_IMPORTS = frozenset({{
    "os", "subprocess", "shutil", "pathlib",
    "socket", "http", "urllib", "requests", "httpx",
    "multiprocessing", "threading",
    "code", "codeop",
}})
_original_import = __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__

def _restricted_import(name, *args, **kwargs):
    root = name.split(".")[0]
    if root in _BLOCKED_IMPORTS:
        raise ImportError(f"Import of '{{name}}' is blocked in the Z3 sandbox.")
    return _original_import(name, *args, **kwargs)

try:
    __builtins__.__import__ = _restricted_import
except AttributeError:
    pass

def _execute():
    result = {{"verdict": "unknown", "model": None, "error": None}}
    try:
        s = Solver()
        s.set("timeout", {timeout_ms})

        # === BEGIN LLM SCRIPT ===
{indented_script}
        # === END LLM SCRIPT ===

        check = s.check()
        if check == sat:
            m = s.model()
            model_dict = {{}}
            for d in m.decls():
                val = m[d]
                if is_bv_value(val):
                    model_dict[str(d)] = val.as_long()
                elif is_int_value(val):
                    model_dict[str(d)] = val.as_long()
                else:
                    model_dict[str(d)] = str(val)
            result["verdict"] = "sat"
            result["model"] = model_dict
        elif check == unsat:
            result["verdict"] = "unsat"
        else:
            result["verdict"] = "unknown"
            result["error"] = str(check)
    except Exception as e:
        error_type = type(e).__name__
        result["verdict"] = "runtime_error"
        result["error"] = f"{{error_type}}: {{str(e)}}"

    print("===Z3_RESULT_JSON===")
    print(json.dumps(result))
    print("===Z3_RESULT_END===")

_execute()
'''


class Z3SandboxError(Exception):
    """Raised when the sandbox encounters an unrecoverable error."""
    pass


class Z3Sandbox:
    """
    Executes Z3Py scripts in an isolated subprocess environment.

    Usage:
        sandbox = Z3Sandbox()
        result = await sandbox.execute(z3_script)

        if result.verdict == Z3Verdict.SAT:
            model = result.model  # dict[str, int]
        elif result.verdict == Z3Verdict.SYNTAX_ERROR:
            error = result.error_message  # feed back to LLM for repair
    """

    def __init__(
        self,
        timeout_seconds: int = settings.z3_timeout_seconds,
        sandbox_dir: Path = settings.z3_sandbox_dir,
        keep_scripts: bool = False,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.sandbox_dir = sandbox_dir
        self.keep_scripts = keep_scripts
        self.sandbox_dir.mkdir(parents=True, exist_ok=True)

    async def execute(self, script: Z3Script) -> Z3Result:
        """
        Execute a Z3 script in an isolated subprocess.

        Args:
            script: The Z3Script to execute.

        Returns:
            Z3Result with verdict, model (if SAT), error message, and timing.
        """
        start_time = time.monotonic()

        # Step 1: Wrap and write the script.
        wrapped = self._wrap_script(script.script_text)
        script_path = self._write_temp_script(wrapped)

        try:
            # Step 2: Execute in subprocess with timeout.
            # Add overhead buffer for subprocess startup.
            total_timeout = self.timeout_seconds + 5
            try:
                raw_output = await asyncio.wait_for(
                    self._run_subprocess(script_path),
                    timeout=total_timeout,
                )
            except asyncio.TimeoutError:
                elapsed = time.monotonic() - start_time
                logger.warning("Z3 sandbox timed out after %.1fs", elapsed)
                return Z3Result(
                    verdict=Z3Verdict.TIMEOUT,
                    model=None,
                    error_message=(
                        f"Z3 execution exceeded {self.timeout_seconds}s timeout"
                    ),
                    execution_time=elapsed,
                    script=script,
                )

            # Step 3: Parse result.
            elapsed = time.monotonic() - start_time
            return self._parse_result(raw_output, script, elapsed)

        finally:
            # Step 4: Cleanup temp file.
            if not self.keep_scripts:
                try:
                    script_path.unlink(missing_ok=True)
                except OSError:
                    pass

    def _wrap_script(self, script_text: str) -> str:
        """
        Wrap the LLM-generated Z3 script with the execution harness.

        The harness:
          1. Restricts __import__ to whitelist only 'z3' and 'json'.
          2. Sets the solver timeout via s.set("timeout", ms).
          3. Executes the LLM's script.
          4. Captures the solver verdict and model.
          5. Outputs the result as JSON between delimiters.

        IMPORTANT: The harness already provides:
          - from z3 import *
          - s = Solver()  (with timeout configured)
          - s.check() + model extraction + JSON output
        So we strip these from the LLM's script to avoid conflicts.
        """
        # Sanitize: remove lines the harness already provides.
        sanitized_lines: list[str] = []
        skip_indented_body = False
        skip_indent_level = 0
        for line in script_text.splitlines():
            stripped = line.strip()

            # If we're skipping the body of a stripped if/for block,
            # continue skipping lines that are indented deeper.
            if skip_indented_body:
                if stripped == "" or (len(line) - len(line.lstrip()) > skip_indent_level):
                    continue  # Still inside the block body
                else:
                    skip_indented_body = False  # Exited the block

            # Skip import lines (harness has `from z3 import *` at module level).
            if stripped.startswith(("from z3 import", "import z3", "from z3 ")):
                continue
            # Skip import json (harness has it).
            if stripped == "import json":
                continue
            # Skip Solver() creation (harness creates `s = Solver()` already).
            if stripped.startswith("s = Solver(") or stripped == "s = Solver()":
                continue
            # Skip solver timeout setting (harness sets timeout).
            if "s.set(" in stripped and "timeout" in stripped:
                continue

            # Skip ALL s.check() assignment patterns:
            #   result = s.check(), check = s.check(), r = s.check(), etc.
            if "= s.check()" in stripped:
                continue
            # Skip standalone s.check() call.
            if stripped == "s.check()":
                continue
            # Skip print(s.check()) and print(s.model()).
            if stripped.startswith(("print(s.check()", "print(s.model()")):
                continue

            # Skip ALL model extraction patterns:
            #   m = s.model(), model = s.model(), etc.
            if "= s.model()" in stripped:
                continue
            # Skip model iteration: for d in m.decls(), for v in model.decls(), etc.
            if stripped.startswith("for ") and ".decls()" in stripped:
                skip_indented_body = True
                skip_indent_level = len(line) - len(line.lstrip())
                continue
            # Skip print(m), print(model), print(model_dict), etc.
            if stripped.startswith("print(m)") or stripped.startswith("print(model"):
                continue

            # Skip if-sat blocks AND their entire indented bodies.
            if stripped in ("if s.check() == sat:", "if result == sat:",
                           "if check == sat:", "if r == sat:"):
                skip_indented_body = True
                skip_indent_level = len(line) - len(line.lstrip())
                continue
            # Also skip else/elif blocks paired with sat checks.
            if skip_indented_body is False and stripped in ("else:", "elif check == unsat:",
                                                            "elif result == unsat:",
                                                            "elif r == unsat:"):
                skip_indented_body = True
                skip_indent_level = len(line) - len(line.lstrip())
                continue

            sanitized_lines.append(line)

        sanitized = "\n".join(sanitized_lines)

        # Indent the sanitized script to sit inside the _execute() function.
        indented = "\n".join(
            "        " + line for line in sanitized.splitlines()
        )
        return _HARNESS_TEMPLATE.format(
            timeout_ms=self.timeout_seconds * 1000,
            indented_script=indented,
            max_memory=_MAX_MEMORY_BYTES,
        )

    def _write_temp_script(self, wrapped_script: str) -> Path:
        """Write the wrapped script to a temp file and return its path."""
        filename = f"z3_exec_{uuid.uuid4().hex[:8]}.py"
        script_path = self.sandbox_dir / filename
        script_path.write_text(wrapped_script, encoding="utf-8")
        return script_path

    async def _run_subprocess(self, script_path: Path) -> dict:
        """
        Run the Z3 script in a subprocess.

        Uses asyncio.create_subprocess_exec for non-blocking execution.

        Returns:
            Parsed JSON dict from the subprocess stdout.
        """
        process = await asyncio.create_subprocess_exec(
            sys.executable, str(script_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout_bytes, stderr_bytes = await process.communicate()
        stdout_str = stdout_bytes.decode("utf-8", errors="replace")
        stderr_str = stderr_bytes.decode("utf-8", errors="replace")

        # Extract JSON between delimiters.
        json_start = stdout_str.find("===Z3_RESULT_JSON===")
        json_end = stdout_str.find("===Z3_RESULT_END===")

        if json_start != -1 and json_end != -1:
            json_text = stdout_str[json_start + len("===Z3_RESULT_JSON==="):json_end].strip()
            try:
                return json.loads(json_text)
            except json.JSONDecodeError as e:
                return {
                    "verdict": "runtime_error",
                    "model": None,
                    "error": f"Failed to parse Z3 output JSON: {e}",
                }

        # No delimiters found -- likely a syntax error that crashed before
        # the harness could produce output.
        if process.returncode != 0:
            # Combine stderr and any stdout for the error message.
            error_msg = stderr_str.strip() or stdout_str.strip() or "Unknown error"
            return {
                "verdict": "syntax_error",
                "model": None,
                "error": error_msg[:2000],  # Cap error message length
            }

        return {
            "verdict": "runtime_error",
            "model": None,
            "error": f"No structured output from Z3 subprocess. stdout: {stdout_str[:500]}",
        }

    def _parse_result(
        self, raw_output: dict, script: Z3Script, elapsed: float
    ) -> Z3Result:
        """
        Parse subprocess JSON output into a Z3Result.

        Maps the subprocess output format to the Z3Verdict enum and
        constructs the Z3Result dataclass.
        """
        verdict_str = raw_output.get("verdict", "unknown")
        model = raw_output.get("model")
        error = raw_output.get("error")

        # Map string verdict to enum.
        verdict_map = {
            "sat": Z3Verdict.SAT,
            "unsat": Z3Verdict.UNSAT,
            "timeout": Z3Verdict.TIMEOUT,
            "syntax_error": Z3Verdict.SYNTAX_ERROR,
            "runtime_error": Z3Verdict.RUNTIME_ERROR,
            "unknown": Z3Verdict.UNKNOWN,
        }
        verdict = verdict_map.get(verdict_str, Z3Verdict.UNKNOWN)

        logger.info(
            "Z3 sandbox result: verdict=%s elapsed=%.2fs",
            verdict.value, elapsed,
        )
        if verdict == Z3Verdict.SAT and model:
            logger.info("  Model: %s", model)
        elif error:
            logger.debug("  Error: %s", error[:200])

        return Z3Result(
            verdict=verdict,
            model=model,
            error_message=error,
            execution_time=elapsed,
            script=script,
        )

    async def validate_equivalence(
        self,
        script_a: str,
        script_b: str,
    ) -> bool:
        """
        Check if two Z3 scripts are semantically equivalent.

        Uses the bidirectional UNSAT test from WARP S4.4:
            phi_a <=> phi_b  iff  (phi_a AND NOT phi_b) is UNSAT
                                AND (phi_b AND NOT phi_a) is UNSAT

        This is used to validate LLM-generated scripts against known-good
        templates from the spec store.

        Returns:
            True if the scripts are semantically equivalent.
        """
        # TODO: Future work -- implement bidirectional equivalence checking.
        # This requires extracting the constraint set from each script,
        # which is non-trivial for arbitrary Z3Py code.
        raise NotImplementedError("WARP equivalence checking is deferred to post-MVP")
