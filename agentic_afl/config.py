"""
config.py — Centralized Configuration for Agentic-AFL.

All tunable parameters live here. Components import from this module
rather than hardcoding values. Environment variables override defaults
for deployment flexibility.

Usage:
    from agentic_afl.config import settings
    timeout = settings.z3_timeout_seconds
"""

from __future__ import annotations

import getpass
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path


def _user_scoped_tmp(name: str) -> Path:
    """Return a per-user working directory under the system temp dir.

    Health-review fix (H3): the previous defaults hardcoded shared paths
    like ``/tmp/agentic_afl_sandbox`` and ``/tmp/agentic_afl_debug``. On a
    shared multi-user research host these are world-writable and collide
    (or invite symlink attacks) between users. Suffixing with the current
    username gives each user their own directory while still honoring
    ``$TMPDIR``. All of these remain overridable via their env vars.
    """
    try:
        user = getpass.getuser()
    except Exception:
        # getpass can raise if there's no controlling user (e.g. some
        # containers); fall back to the numeric uid where available.
        user = str(getattr(os, "getuid", lambda: "shared")())
    return Path(tempfile.gettempdir()) / f"{name}_{user}"

# Load .env file if present (before any os.environ access).
# python-dotenv does NOT override existing environment variables,
# so explicit exports always take priority.
try:
    from dotenv import load_dotenv
    # Walk up from this file to find .env at the project root.
    _project_root = Path(__file__).resolve().parent.parent
    load_dotenv(_project_root / ".env")
except ImportError:
    pass  # python-dotenv is optional; fall back to plain os.environ


from .constants import (
    Architecture,
    DEFAULT_K_WAY_VOTE_COUNT,
    DEFAULT_MAX_REACT_TURNS,
    DEFAULT_MAX_REPAIR_ATTEMPTS,
    DEFAULT_Z3_TIMEOUT_SECONDS,
)


@dataclass
class AgenticAFLConfig:
    """
    Top-level configuration container.

    Values are loaded from environment variables where available,
    falling back to literature-informed defaults defined in constants.py.
    """

    # ── Ghidra / Extractor ──────────────────────────────────────────────
    ghidra_install_dir: Path = field(
        default_factory=lambda: Path(
            os.environ.get("GHIDRA_INSTALL_DIR", "/opt/ghidra")
        )
    )
    ghidra_project_dir: Path = field(
        default_factory=lambda: Path(
            os.environ.get("GHIDRA_PROJECT_DIR", str(_user_scoped_tmp("ghidra_projects")))
        )
    )
    # Maximum number of basic blocks to traverse during backward slicing.
    # Deeper slices = more context for the LLM but higher token cost.
    max_slice_depth: int = 20
    # Maximum P-Code instruction count before truncation (AutoBug assuming(0)).
    # Tuned to stay within ~4K tokens after prompt framing.
    max_pcode_instructions: int = 200

    # ── Target Architecture ─────────────────────────────────────────────
    target_architecture: Architecture = Architecture.ARM32

    # ── LLM / Orchestrator ──────────────────────────────────────────────
    llm_api_provider: str = field(
        default_factory=lambda: os.environ.get("LLM_API_PROVIDER", "openai")
    )
    llm_api_key: str = field(
        default_factory=lambda: os.environ.get("LLM_API_KEY", "")
    )
    # Gemini-specific API key (separate from OpenAI since users may have both).
    gemini_api_key: str = field(
        default_factory=lambda: os.environ.get("GEMINI_API_KEY", "")
    )
    llm_model_name: str = field(
        default_factory=lambda: os.environ.get("LLM_MODEL_NAME", "gpt-4.1-2025-04-14")
    )
    llm_temperature: float = 0.7       # Moderate creativity for Z3 generation
    llm_max_output_tokens: int = 65536  # Gemini 2.5 Flash needs headroom for thinking + CRC loops

    # Health-review fix (C1): bounds every provider.generate() call. Without
    # this, a stuck LLM HTTP call hangs the AgentLoop's single event loop
    # forever — an infinite *wait*, not an infinite *retry*. Observed live
    # Gemini K=3 calls take 44-74s (see documents/health_report.md), so the
    # default leaves generous headroom above normal latency.
    llm_timeout_seconds: float = field(
        default_factory=lambda: float(os.environ.get("LLM_TIMEOUT_SECONDS", "120"))
    )

    # Rate limiting: prevents 429 errors during intensive stall-solving loops.
    # Default 15 RPM matches Gemini's free tier. Set higher for paid tiers.
    llm_max_rpm: int = field(
        default_factory=lambda: int(os.environ.get("LLM_MAX_RPM", "15"))
    )
    llm_burst_size: int = field(
        default_factory=lambda: int(os.environ.get("LLM_BURST_SIZE", "5"))
    )

    # LINC §2: K-way voting — generate K scripts, pick the SAT result.
    # K=3 is cheap (3x parallel API calls) and mitigates 13-38% syntax error rate.
    k_vote_count: int = field(
        default_factory=lambda: int(
            os.environ.get("K_VOTE_COUNT", str(DEFAULT_K_WAY_VOTE_COUNT))
        )
    )

    # LLM-Sym §3.2: Maximum self-repair attempts per Z3 generation.
    max_repair_attempts: int = DEFAULT_MAX_REPAIR_ATTEMPTS

    # SAILOR §4: Maximum ReAct turns before deferring back to AFL++.
    max_react_turns: int = DEFAULT_MAX_REACT_TURNS

    # ── Z3 Sandbox ──────────────────────────────────────────────────────
    # TDD_v2 §4.3: Strict timeout prevents Z3 path explosion on crypto.
    z3_timeout_seconds: int = field(
        default_factory=lambda: int(
            os.environ.get("Z3_TIMEOUT_SECONDS", str(DEFAULT_Z3_TIMEOUT_SECONDS))
        )
    )
    # Directory for Z3 sandbox temp files (isolated execution environment).
    z3_sandbox_dir: Path = field(
        default_factory=lambda: Path(
            os.environ.get("Z3_SANDBOX_DIR", str(_user_scoped_tmp("agentic_afl_sandbox")))
        )
    )

    # ── AFL++ / Fuzzer Bridge ───────────────────────────────────────────
    afl_output_dir: Path = field(
        default_factory=lambda: Path(
            os.environ.get("AFL_OUTPUT_DIR", "./afl_output")
        )
    )
    # The sync directory where solved payloads are dropped.
    # AFL++ natively ingests files from this directory on each cycle.
    afl_sync_dir: Path = field(
        default_factory=lambda: Path(
            os.environ.get("AFL_SYNC_DIR", "./afl_output/sync_dir")
        )
    )
    # Minimum AFL++ cycles at a stall before the Orchestrator intervenes.
    min_stall_cycles: int = 50
    # Polling interval for stall detection (seconds).
    stall_poll_interval: float = 5.0
    # Time-based stall threshold for E2E campaigns (seconds).
    # Triggers frontier discovery when no new edges for this long.
    # Overrides cycle-based detection when > 0.
    min_stall_time_seconds: int = field(
        default_factory=lambda: int(
            os.environ.get("MIN_STALL_TIME_SECONDS", "0")
        )
    )

    # ── PostgreSQL (Spec Store) ────────────────────────────────────────
    # PostgreSQL replaces the original mem0 filesystem store.
    # mem0 is a vector-DB abstraction optimized for cosine similarity —
    # fundamentally incompatible with CARM's Jaccard similarity on tag sets.
    # PostgreSQL with JSONB + a custom jaccard_similarity() SQL function
    # computes the math server-side and returns only the top-N matches.
    postgres_dsn: str = field(
        default_factory=lambda: os.environ.get(
            "POSTGRES_DSN",
            "postgresql://agentic_afl:agentic_afl@localhost:5432/agentic_afl",
        )
    )
    # Minimum Jaccard similarity score for CARM retrieval to consider a match.
    # ConstraintLLM §2.2: Lower threshold = more candidates but noisier.
    # This value is passed directly to the SQL WHERE clause.
    carm_similarity_threshold: float = 0.3
    # Maximum number of templates to retrieve per query (SQL LIMIT).
    carm_max_results: int = 5

    # ── Logging ─────────────────────────────────────────────────────────
    log_level: str = field(
        default_factory=lambda: os.environ.get("LOG_LEVEL", "INFO")
    )
    log_dir: Path = field(
        default_factory=lambda: Path(
            os.environ.get("LOG_DIR", "./logs")
        )
    )
    # Debug mode: when True, saves raw LLM completions and Z3 scripts
    # to debug_dir for post-mortem analysis.
    debug_mode: bool = field(
        default_factory=lambda: os.environ.get("DEBUG_MODE", "").lower() in ("1", "true", "yes")
    )
    # Directory for debug artifacts (raw LLM completions, Z3 scripts).
    # Health-review fix (H3): was a hardcoded, shared /tmp/agentic_afl_debug
    # in llm_client.py and agent_loop.py. Now a user-scoped, overridable path.
    debug_dir: Path = field(
        default_factory=lambda: Path(
            os.environ.get("DEBUG_DIR", str(_user_scoped_tmp("agentic_afl_debug")))
        )
    )


# ---------------------------------------------------------------------------
# Module-level singleton — import this directly:
#   from agentic_afl.config import settings
# ---------------------------------------------------------------------------
settings = AgenticAFLConfig()
