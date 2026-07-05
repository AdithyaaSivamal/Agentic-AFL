"""
test_preflight.py — Unit tests for P0 pre-flight validation.

Tests Ghidra validation, LLM API key validation, and PostgreSQL fallback.
"""

import pytest
from pathlib import Path
from unittest.mock import patch

from agentic_afl.orchestrator.agent_loop import AgentLoop
from agentic_afl.config import AgenticAFLConfig


@pytest.fixture
def agent():
    return AgentLoop(
        afl_output_dir="/tmp/afl_test",
        afl_sync_dir="/tmp/afl_sync",
        register_signals=False,
    )


# ═══════════════════════════════════════════════════════════════════════
#  Ghidra Validation
# ═══════════════════════════════════════════════════════════════════════

class TestGhidraValidation:
    def test_fails_with_missing_ghidra(self, agent):
        """Should raise RuntimeError with clear install instructions."""
        with patch.object(
            type(agent), '_validate_ghidra',
            wraps=agent._validate_ghidra,
        ):
            from agentic_afl.config import settings
            original = settings.ghidra_install_dir
            settings.ghidra_install_dir = Path("/nonexistent/ghidra_fake")
            try:
                with pytest.raises(RuntimeError, match="Ghidra not found"):
                    agent._validate_ghidra()
            finally:
                settings.ghidra_install_dir = original

    def test_error_contains_instructions(self, agent):
        """Error message should contain GHIDRA_INSTALL_DIR and URL."""
        from agentic_afl.config import settings
        original = settings.ghidra_install_dir
        settings.ghidra_install_dir = Path("/nonexistent/ghidra_fake")
        try:
            with pytest.raises(RuntimeError) as exc_info:
                agent._validate_ghidra()
            msg = str(exc_info.value)
            assert "GHIDRA_INSTALL_DIR" in msg
            assert "ghidra-sre.org" in msg
            assert "export" in msg
        finally:
            settings.ghidra_install_dir = original

    def test_succeeds_when_on_path(self, agent, tmp_path):
        """Should succeed if analyzeHeadless is found on PATH."""
        from agentic_afl.config import settings
        original = settings.ghidra_install_dir
        settings.ghidra_install_dir = Path("/nonexistent/ghidra_fake")
        try:
            with patch("shutil.which", side_effect=lambda x: "/usr/bin/analyzeHeadless" if x == "analyzeHeadless" else None):
                agent._validate_ghidra()  # Should NOT raise
        finally:
            settings.ghidra_install_dir = original

    def test_succeeds_with_valid_install_dir(self, agent, tmp_path):
        """Should succeed if pyghidraRun exists in install dir."""
        from agentic_afl.config import settings
        original = settings.ghidra_install_dir

        ghidra_support = tmp_path / "ghidra" / "support"
        ghidra_support.mkdir(parents=True)
        (ghidra_support / "pyghidraRun").touch()

        settings.ghidra_install_dir = tmp_path / "ghidra"
        try:
            agent._validate_ghidra()  # Should NOT raise
        finally:
            settings.ghidra_install_dir = original


# ═══════════════════════════════════════════════════════════════════════
#  LLM API Key Validation
# ═══════════════════════════════════════════════════════════════════════

class TestLLMKeyValidation:
    @pytest.mark.asyncio
    async def test_fails_with_empty_gemini_key(self, agent):
        """Should raise RuntimeError when GEMINI_API_KEY is empty."""
        from agentic_afl.config import settings
        orig_provider = settings.llm_api_provider
        orig_key = settings.gemini_api_key
        settings.llm_api_provider = "gemini"
        settings.gemini_api_key = ""
        try:
            with pytest.raises(RuntimeError, match="LLM API key not configured"):
                await agent._validate_llm_api_key()
        finally:
            settings.llm_api_provider = orig_provider
            settings.gemini_api_key = orig_key

    @pytest.mark.asyncio
    async def test_fails_with_empty_openai_key(self, agent):
        """Should raise RuntimeError when LLM_API_KEY is empty."""
        from agentic_afl.config import settings
        orig_provider = settings.llm_api_provider
        orig_key = settings.llm_api_key
        settings.llm_api_provider = "openai"
        settings.llm_api_key = ""
        try:
            with pytest.raises(RuntimeError, match="LLM API key not configured"):
                await agent._validate_llm_api_key()
        finally:
            settings.llm_api_provider = orig_provider
            settings.llm_api_key = orig_key

    @pytest.mark.asyncio
    async def test_error_contains_env_var_name(self, agent):
        """Error should mention the specific env var to set."""
        from agentic_afl.config import settings
        orig_provider = settings.llm_api_provider
        orig_key = settings.gemini_api_key
        settings.llm_api_provider = "gemini"
        settings.gemini_api_key = ""
        try:
            with pytest.raises(RuntimeError) as exc_info:
                await agent._validate_llm_api_key()
            msg = str(exc_info.value)
            assert "GEMINI_API_KEY" in msg
            assert "export" in msg
        finally:
            settings.llm_api_provider = orig_provider
            settings.gemini_api_key = orig_key

    @pytest.mark.asyncio
    async def test_skips_local_provider(self, agent):
        """Local provider should skip validation entirely."""
        from agentic_afl.config import settings
        orig_provider = settings.llm_api_provider
        settings.llm_api_provider = "local"
        try:
            await agent._validate_llm_api_key()  # Should NOT raise
        finally:
            settings.llm_api_provider = orig_provider


# ═══════════════════════════════════════════════════════════════════════
#  PostgreSQL Fallback
# ═══════════════════════════════════════════════════════════════════════

class TestPostgresFallback:
    @pytest.mark.asyncio
    async def test_falls_back_to_memory_store(self, agent):
        """When PostgreSQL is unreachable, should fall back to InMemorySpecStore."""
        from agentic_afl.config import settings
        from agentic_afl.database.memory_store import InMemorySpecStore
        orig_dsn = settings.postgres_dsn
        settings.postgres_dsn = "postgresql://bad:bad@localhost:59999/nonexistent"
        try:
            store = await agent._initialize_store()
            assert isinstance(store, InMemorySpecStore)
            await store.close()
        finally:
            settings.postgres_dsn = orig_dsn
