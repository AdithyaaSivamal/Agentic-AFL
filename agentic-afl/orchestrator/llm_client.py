"""
llm_client.py -- LLM Translation Engine with K-Way Voting and Self-Repair.

This module handles ALL communication with the LLM API. The LLM's role is
strictly as a TRANSLATOR: it converts P-Code slices into Z3Py scripts.
It NEVER acts as a solver or reasoner about satisfiability.

Inputs:
    - Z3GenerationRequest  -- From agent_loop.py (contains VulnerabilitySpec + context)

Outputs:
    - list[Z3Script]       -- K candidate Z3 scripts for voting (see models.py)

Key Design Decisions:
    1. K-WAY VOTING (LINC S2): Generate K=3 Z3 scripts in parallel. The
       z3_sandbox executes all K, and the agent_loop picks the one that
       returns SAT. This mitigates the 13-38% syntax error rate observed
       in LLM-generated formal logic.

    2. SSA NAMING (LLM-Sym S3.2): Prompts enforce Static Single Assignment
       naming for Z3 variables: BitVec('reg_0', 32), BitVec('reg_1', 32).
       This prevents variable name collisions in the generated script.

    3. STRICT BITVEC ENFORCEMENT (TDD_v2 S4.3): The system prompt explicitly
       forbids using Z3's Int() type for register values. All register-width
       values MUST be BitVec with the correct bit-width from the architecture.
       This prevents "correct but useless" Z3 models that ignore overflow behavior.

    4. SELF-REPAIR (LLM-Sym + Logic-LM): When z3_sandbox returns an error,
       the error message is fed back to the LLM with a structured correction
       prompt. Up to max_repair_attempts (default 3) retries are allowed.

    5. THOUGHT CARD INJECTION (HiAR-ICL): When the ConstraintProfiler detects
       known patterns (CRC, bitmask, etc.), pre-written Z3 helper functions
       and reasoning patterns are forcefully injected into the prompt.

    6. MULTI-PROVIDER (Option C): Abstract BaseLLMProvider with OpenAI +
       Gemini backends. Provider swap via config.py string.
"""

from __future__ import annotations
from agentic_afl.models import ConstraintProfile

import asyncio
import logging
import re
from abc import ABC, abstractmethod
from pathlib import Path

from agentic_afl.config import settings
from agentic_afl.constants import ARCH_REGISTER_WIDTH, Architecture, ConstraintTag
from agentic_afl.models import (
    CorrectionEntry,
    VulnerabilitySpec,
    Z3GenerationRequest,
    Z3Result,
    Z3Script,
)
from agentic_afl.orchestrator.prompts.z3_translation import (
    CORRECTIONS_SECTION,
    OFFSET_MAPPING_SECTION,
    REPAIR_GUIDANCE,
    REPAIR_PROMPT,
    STRATEGY_HINTS_SECTION,
    SYSTEM_PROMPT,
    TEMPLATES_SECTION,
    USER_PROMPT,
)
from agentic_afl.orchestrator.prompts.react_templates import build_strategy_hints

logger = logging.getLogger(__name__)

# Regex to extract code from ```python ... ``` blocks.
_CODE_BLOCK_RE = re.compile(
    r"```(?:python)?\s*\n(.*?)```",
    re.DOTALL,
)


class LLMClientError(Exception):
    """Raised when LLM API communication fails."""
    pass


class BaseLLMProvider(ABC):
    """
    Abstract base class for LLM API providers.

    Implement this for each provider (OpenAI, Anthropic, local vLLM, etc.).
    The Orchestrator only interacts through this interface.
    """

    @abstractmethod
    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float,
        max_tokens: int,
        n: int,
    ) -> list[str]:
        """
        Generate n completions from the LLM.

        Args:
            system_prompt: The system/role prompt.
            user_prompt:   The user message containing the P-Code and instructions.
            temperature:   Sampling temperature.
            max_tokens:    Maximum output tokens per completion.
            n:             Number of completions to generate (for K-way voting).

        Returns:
            List of n completion strings.
        """
        ...


class OpenAIProvider(BaseLLMProvider):
    """OpenAI API provider (GPT-4.1, etc.)."""

    def __init__(self, api_key: str, model_name: str) -> None:
        self.api_key = api_key
        self.model_name = model_name
        self._client = None

    def _get_client(self):
        """Lazy-init the OpenAI async client."""
        if self._client is None:
            from openai import AsyncOpenAI
            self._client = AsyncOpenAI(api_key=self.api_key)
        return self._client

    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float,
        max_tokens: int,
        n: int,
    ) -> list[str]:
        """Generate n completions via OpenAI's chat.completions API."""
        client = self._get_client()
        response = await client.chat.completions.create(
            model=self.model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=temperature,
            max_tokens=max_tokens,
            n=n,
        )
        return [choice.message.content or "" for choice in response.choices]


class GeminiProvider(BaseLLMProvider):
    """Google Gemini API provider."""

    def __init__(self, api_key: str, model_name: str) -> None:
        self.api_key = api_key
        self.model_name = model_name
        self._client = None

    def _get_client(self):
        """Lazy-init the Gemini async client."""
        if self._client is None:
            from google import genai
            self._client = genai.Client(api_key=self.api_key)
        return self._client

    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float,
        max_tokens: int,
        n: int,
    ) -> list[str]:
        """
        Generate n completions via Gemini API.

        Uses asyncio.gather for K concurrent, independent calls.
        This maximizes variance between candidates (LINC requirement)
        and avoids any API candidate_count restrictions.
        """
        from google.genai import types

        client = self._get_client()

        async def _single_call() -> str:
            response = await client.aio.models.generate_content(
                model=self.model_name,
                contents=user_prompt,
                config=types.GenerateContentConfig(
                    system_instruction=system_prompt,
                    temperature=temperature,
                    max_output_tokens=max_tokens,
                ),
            )
            # Log truncation: if finish_reason is MAX_TOKENS, the script
            # was cut off and will almost certainly have a SyntaxError.
            if response.candidates:
                fr = response.candidates[0].finish_reason
                fr_str = str(fr) if fr else ""
                # FinishReason.STOP = normal completion (str is "FinishReason.STOP" or "1")
                if fr and "STOP" not in fr_str and fr_str != "1":
                    logger.warning(
                        "Gemini finish_reason=%s — output likely truncated",
                        fr,
                    )
            return response.text or ""

        results = await asyncio.gather(*[_single_call() for _ in range(n)])
        return list(results)


class LocalProvider(BaseLLMProvider):
    """
    Stub for local LLM backends (vLLM, Ollama, etc.).

    Interface-compatible with the other providers. Not implemented in MVP.
    Intended for offline testing and 72-hour fuzzing campaigns without
    API costs.
    """

    def __init__(self, endpoint: str = "http://localhost:8000", model_name: str = "") -> None:
        self.endpoint = endpoint
        self.model_name = model_name

    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float,
        max_tokens: int,
        n: int,
    ) -> list[str]:
        raise NotImplementedError(
            "LocalProvider is a stub for future vLLM/Ollama integration. "
            "Use OpenAI or Gemini for MVP testing."
        )


class LLMClient:
    """
    High-level LLM translation engine.

    This class orchestrates:
      1. Prompt construction from VulnerabilitySpec + context.
      2. K-way parallel generation.
      3. Z3 script extraction from LLM output.
      4. Self-repair loop (error -> correction prompt -> retry).

    Usage:
        client = LLMClient()
        scripts = await client.generate_z3_scripts(request)
        # scripts is a list of K Z3Script objects ready for z3_sandbox.
    """

    def __init__(
        self,
        provider: BaseLLMProvider | None = None,
        temperature: float = settings.llm_temperature,
        max_tokens: int = settings.llm_max_output_tokens,
    ) -> None:
        self.provider = provider or self._create_default_provider()
        self.temperature = temperature
        self.max_tokens = max_tokens

    def _create_default_provider(self) -> BaseLLMProvider:
        """Create the default provider from config settings."""
        provider_name = settings.llm_api_provider.lower()
        if provider_name == "openai":
            return OpenAIProvider(
                api_key=settings.llm_api_key,
                model_name=settings.llm_model_name,
            )
        elif provider_name == "gemini":
            return GeminiProvider(
                api_key=settings.gemini_api_key,
                model_name=settings.llm_model_name,
            )
        elif provider_name == "local":
            return LocalProvider()
        raise LLMClientError(f"Unknown LLM provider: {settings.llm_api_provider}")

    async def generate_z3_scripts(
        self,
        request: Z3GenerationRequest,
    ) -> list[Z3Script]:
        """
        Generate K candidate Z3 scripts for a stall site.

        This is the primary interface called by agent_loop.py.

        Args:
            request: Z3GenerationRequest containing the VulnerabilitySpec,
                     seed input, retrieved templates, and correction history.

        Returns:
            List of K Z3Script objects. Each script is a complete, standalone
            Z3Py program that can be executed by z3_sandbox.py.
        """
        spec = request.vuln_spec
        system_prompt = self._build_system_prompt(spec.architecture)
        user_prompt = self._build_user_prompt(request)

        logger.info(
            "Generating %d Z3 scripts for %s @ %s",
            request.k_vote_count,
            spec.function_name,
            spec.stall_address,
        )

        completions = await self.provider.generate(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            n=request.k_vote_count,
        )

        scripts = []
        for idx, completion in enumerate(completions):
            # Debug: save raw completion before extraction.
            if settings.debug_mode:
                debug_dir = Path("/tmp/agentic_afl_debug")
                debug_dir.mkdir(exist_ok=True)
                (debug_dir / f"raw_completion_{idx}.txt").write_text(completion)

            script_text = self._extract_z3_code(completion)
            scripts.append(Z3Script(
                script_text=script_text,
                generation_idx=idx,
                attempt_number=1,
                model_name=settings.llm_model_name,
            ))
            logger.debug("Script %d: %d chars extracted (raw=%d chars)", idx, len(script_text), len(completion))

        return scripts

    async def repair_z3_script(
        self,
        original_request: Z3GenerationRequest,
        failed_script: Z3Script,
        error_result: Z3Result,
        attempt_number: int,
    ) -> Z3Script:
        """
        Generate a corrected Z3 script using solver error feedback.

        Reference: Logic-LM S3.3 -- Self-refinement via solver error messages.
        Reference: LLM-Sym S3.2 -- 3-attempt self-repair cycle.
        """
        spec = original_request.vuln_spec
        system_prompt = self._build_system_prompt(spec.architecture)
        repair_prompt = self._build_repair_prompt(
            original_request, failed_script, error_result
        )

        logger.info(
            "Repairing Z3 script for %s (attempt %d, verdict=%s)",
            spec.stall_address,
            attempt_number,
            error_result.verdict.value,
        )

        completions = await self.provider.generate(
            system_prompt=system_prompt,
            user_prompt=repair_prompt,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            n=1,  # Single repair attempt
        )

        script_text = self._extract_z3_code(completions[0])
        return Z3Script(
            script_text=script_text,
            generation_idx=0,
            attempt_number=attempt_number,
            model_name=settings.llm_model_name,
        )

    # -- Prompt Construction -------------------------------------------------

    def _build_system_prompt(self, architecture: Architecture) -> str:
        """
        Build the system prompt with architecture-specific constraints.

        Reference: TDD_v2 S4.3 -- Strict Verification Conditions.
        Reference: LLM-Sym S3.2 -- SSA naming convention.
        """
        register_width = ARCH_REGISTER_WIDTH.get(architecture, 32)
        return SYSTEM_PROMPT.format(
            register_width=register_width,
            architecture=architecture.value,
        )

    def _build_user_prompt(self, request: Z3GenerationRequest) -> str:
        """
        Build the user prompt containing all context for Z3 generation.

        Includes:
          1. P-Code slice text
          2. Constraint profile tags
          3. Seed input hex
          4. Retrieved templates (if any)
          5. Correction history (if any)
          6. Thought Cards + Z3 helpers for detected patterns (HiAR-ICL)
        """
        spec = request.vuln_spec
        profile = spec.constraint_profile

        # Format constraint tags.
        tag_names = ", ".join(sorted(t.name for t in profile.tags)) if profile.tags else "NONE"

        # Format seed input as hex with spaced bytes for readability.
        # Truncate to first 64 bytes to prevent the LLM from trying to
        # hardcode the entire seed as a Python list (token truncation trap).
        MAX_SEED_HEX_BYTES = 64
        if request.seed_input:
            seed_data = request.seed_input[:MAX_SEED_HEX_BYTES]
            seed_hex = " ".join(f"{b:02x}" for b in seed_data)
            if len(request.seed_input) > MAX_SEED_HEX_BYTES:
                seed_hex += f"  ... ({len(request.seed_input)} bytes total, showing first {MAX_SEED_HEX_BYTES})"
        else:
            seed_hex = "N/A"
        input_length = len(request.seed_input) if request.seed_input else 0

        # Build decompiled C section from Ghidra's output (scalable — no
        # hardcoded function name matching). The LLM reads C directly and
        # understands the algorithm regardless of what it is.
        decompiled_c_section = ""
        decompiled_c = spec.pcode_slice.decompiled_c
        if decompiled_c:
            # Truncate to avoid exceeding token budget.
            if len(decompiled_c) > 5000:
                decompiled_c = decompiled_c[:5000] + "\n// ... (truncated)"
            decompiled_c_section = (
                "## Decompiled C Pseudocode (from Ghidra):\n"
                "**READ THIS CAREFULLY.** This is the decompiled C for the function "
                "and its callees. It contains the FULL algorithm that your Z3 script "
                "must model. If you see a function call (e.g., `crc16(...)`, "
                "`compute_hash(...)`, `validate(...)`), you MUST inline that "
                "function's logic into Z3 constraints. The P-Code slice above may "
                "be truncated, but this C code shows the complete computation.\n"
                f"```c\n{decompiled_c}\n```"
            )

        # Templates section (CARM-retrieved).
        templates_section = ""
        if request.retrieved_templates:
            templates_text = "\n\n---\n\n".join(
                f"### Template {i+1}:\n```python\n{t}\n```"
                for i, t in enumerate(request.retrieved_templates)
            )
            templates_section = TEMPLATES_SECTION.format(templates=templates_text)

        # Corrections section (past errors).
        corrections_section = ""
        if request.correction_history:
            corrections_text = "\n\n".join(
                f"**Error:** {c.error_message}\n**Corrected Script:**\n```python\n{c.corrected_script}\n```"
                for c in request.correction_history
            )
            corrections_section = CORRECTIONS_SECTION.format(corrections=corrections_text)

        # Structural strategy hints (replaces old thought cards + Z3 helpers).
        strategy_section = self._build_strategy_section(profile)

        # Offset mapping section (REDQUEEN-style I2S correction).
        offset_mapping_section = ""
        base_offset = request.base_offset
        if base_offset > 0:
            # Build a table showing input[N] → byte_{base_offset + N}
            func_input_len = input_length - base_offset
            rows = []
            for i in range(min(func_input_len, 8)):  # Show first 8 mappings
                rows.append(f"  input[{i}] → byte_{base_offset + i}")
            if func_input_len > 8:
                rows.append(f"  ... (up to input[{func_input_len - 1}] → byte_{input_length - 1})")
            offset_table = "\n".join(rows)
            offset_mapping_section = OFFSET_MAPPING_SECTION.format(
                base_offset=base_offset,
                offset_table=offset_table,
                mapped_N=f"{base_offset}+N",
                prev_offset=base_offset - 1,
            )

        user_prompt = USER_PROMPT.format(
            stall_address=spec.stall_address,
            function_name=spec.function_name,
            pcode_text=spec.pcode_slice.pcode_text,
            decompiled_c_section=decompiled_c_section,
            constraint_tags=tag_names,
            seed_input_hex=seed_hex,
            input_length=input_length,
            last_byte_index=max(0, input_length - 1),
            function_context="",  # Deprecated -- now using decompiled_c_section
            templates_section=templates_section,
            corrections_section=corrections_section,
            offset_mapping_section=offset_mapping_section,
        )

        # Append strategy hints section at the end (highest priority context).
        if strategy_section:
            user_prompt += "\n\n" + strategy_section

        # Append runtime state section (GDB arg memory dumps).
        # This gives the LLM concrete struct field values that are invisible
        # to static analysis. The LLM overlays the raw hex with the
        # decompiled C struct definition to find offsets.
        runtime_state = request.runtime_state
        if runtime_state:
            runtime_lines = [
                "## Runtime State at Function Entry (from GDB)",
                "The following memory/register values were observed at runtime when",
                f"the function `{spec.function_name}` was called with the seed input.",
                "Use these to determine CONCRETE field values in the struct passed",
                "to this function. Cross-reference with the decompiled C struct",
                "definition above to find the field offsets you need.",
                "",
            ]
            if "rdi_ptr" in runtime_state:
                runtime_lines.append(
                    f"**Arg 1 (RDI)**: pointer at `{runtime_state['rdi_ptr']}`"
                )
            if "rdi_hex" in runtime_state:
                # Format as 16 bytes per row with offset labels
                hex_str = runtime_state["rdi_hex"]
                runtime_lines.append("First 128 bytes at *RDI (flat hex dump):")
                runtime_lines.append("```")
                for i in range(0, len(hex_str), 32):  # 16 bytes = 32 hex chars per row
                    row_hex = hex_str[i:i+32]
                    offset = i // 2
                    # Add spaces between bytes for readability
                    spaced = " ".join(row_hex[j:j+2] for j in range(0, len(row_hex), 2))
                    runtime_lines.append(f"  +0x{offset:04x}: {spaced}")
                runtime_lines.append("```")
            if "rsi_value" in runtime_state:
                runtime_lines.append(
                    f"**Arg 2 (RSI)**: `{runtime_state['rsi_value']}`"
                    f" ({int(runtime_state['rsi_value'], 16)} decimal)"
                )
            if "rsi_hex" in runtime_state:
                hex_str = runtime_state["rsi_hex"]
                runtime_lines.append("First 128 bytes at *RSI:")
                runtime_lines.append("```")
                for i in range(0, len(hex_str), 32):
                    row_hex = hex_str[i:i+32]
                    offset = i // 2
                    spaced = " ".join(row_hex[j:j+2] for j in range(0, len(row_hex), 2))
                    runtime_lines.append(f"  +0x{offset:04x}: {spaced}")
                runtime_lines.append("```")
            if "rdx_value" in runtime_state:
                runtime_lines.append(
                    f"**Arg 3 (RDX)**: `{runtime_state['rdx_value']}`"
                )
            if "rcx_value" in runtime_state:
                runtime_lines.append(
                    f"**Arg 4 (RCX)**: `{runtime_state['rcx_value']}`"
                )
            user_prompt += "\n\n" + "\n".join(runtime_lines)
        else:
            # No runtime state available — guide the LLM to find constants
            # from the decompiled C instead of hallucinating them.
            user_prompt += (
                "\n\n## Struct Constant Resolution\n"
                "**No runtime memory dump is available for this function's arguments.**\n"
                "If the decompiled C shows comparisons against struct fields "
                "(e.g., `self->receiveCount`, `state->expected_crc`), you MUST "
                "determine their concrete values by:\n"
                "1. **Search the CALLER section** of the decompiled C above for "
                "initialization statements (e.g., `*(conn + 0x1234) = 0x1A2B`).\n"
                "2. If the caller calls a setup/init function, look for the "
                "concrete values being written to the struct fields.\n"
                "3. **Do NOT guess or hallucinate struct field values.** If you "
                "cannot determine a concrete value, state this explicitly in a "
                "comment and constrain the Z3 variable to the widest valid range.\n"
            )

        return user_prompt

    def _build_strategy_section(self, profile: ConstraintProfile) -> str:
        """
        Build the structural strategy hints section from ConstraintProfile metrics.

        Replaces the old _build_thought_card_section(). Hints are generated
        dynamically from structural metrics, not from hardcoded tag-to-card maps.
        """
        hints_content = build_strategy_hints(profile)
        if not hints_content:
            return ""

        return STRATEGY_HINTS_SECTION.format(
            strategy_hints_content=hints_content
        )

    def _build_repair_prompt(
        self,
        original_request: Z3GenerationRequest,
        failed_script: Z3Script,
        error_result: Z3Result,
    ) -> str:
        """
        Build a repair prompt that feeds back the solver error.

        Reference: Logic-LM S3.3 -- Structured error feedback.
        """
        verdict_str = error_result.verdict.value
        repair_guidance = REPAIR_GUIDANCE.get(
            verdict_str,
            "Re-examine the Z3 script for logical and syntactic errors.",
        )

        return REPAIR_PROMPT.format(
            stall_address=original_request.vuln_spec.stall_address,
            verdict=verdict_str.upper(),
            failed_script=failed_script.script_text,
            error_message=error_result.error_message or "No error details available.",
            pcode_text=original_request.vuln_spec.pcode_slice.pcode_text,
            repair_guidance=repair_guidance,
        )

    def _extract_z3_code(self, llm_completion: str) -> str:
        """
        Extract the Z3Py code block from an LLM completion.

        The LLM is prompted to wrap its code in ```python ... ``` blocks.
        This method tries multiple extraction strategies:
          1. Standard ```python ... ``` regex.
          2. Relaxed regex (no newline requirement after language tag).
          3. Fallback: strip markdown fences and return cleaned text.
        """
        if not llm_completion:
            return ""

        # Strategy 1: Standard regex (```python\n...\n```).
        matches = _CODE_BLOCK_RE.findall(llm_completion)
        if matches:
            return matches[-1].strip()

        # Strategy 2: Relaxed regex — no \n required after language tag.
        relaxed = re.findall(r"```(?:python|py)?\s*(.*?)```", llm_completion, re.DOTALL)
        if relaxed:
            code = relaxed[-1].strip()
            if code:
                return code

        # Strategy 3: Fallback — strip markdown fences and leading/trailing prose.
        logger.warning("No code block markers found in LLM completion, stripping fences.")
        cleaned = llm_completion.strip()

        # Remove leading ```python or ``` and trailing ```.
        cleaned = re.sub(r"^```(?:python|py)?\s*\n?", "", cleaned)
        cleaned = re.sub(r"\n?```\s*$", "", cleaned)

        # If the cleaned text still starts with non-code prose, try to
        # find the first line that looks like actual Python/Z3 code.
        # We check for common Z3 patterns beyond just import lines.
        _CODE_STARTS = (
            "from z3", "import z3", "from Z3",
            "# ", "byte_", "s.add(", "s.add (",
            "BitVec(", "BitVecVal(", "Bool(",
            "crc", "data", "pdu", "buf",
        )
        lines = cleaned.split("\n")
        for i, line in enumerate(lines):
            stripped = line.strip()
            if any(stripped.startswith(p) for p in _CODE_STARTS):
                cleaned = "\n".join(lines[i:])
                break
            # Also detect assignment patterns: `x = BitVec(...)`, `x = 0`, etc.
            if re.match(r"^[a-zA-Z_]\w*\s*=\s*", stripped):
                cleaned = "\n".join(lines[i:])
                break

        return cleaned.strip()
