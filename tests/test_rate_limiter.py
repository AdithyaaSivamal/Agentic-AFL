"""
test_rate_limiter.py — Unit tests for the RateLimiter.

Tests token bucket semantics, burst behavior, and throttling.
"""

import asyncio
import time
import pytest

from agentic_afl.orchestrator.rate_limiter import RateLimiter


# ═══════════════════════════════════════════════════════════════════════
#  Token Bucket Semantics
# ═══════════════════════════════════════════════════════════════════════

class TestTokenBucket:
    @pytest.mark.asyncio
    async def test_burst_within_limit(self):
        """Burst of requests within burst_size should not block."""
        limiter = RateLimiter(max_rpm=60, burst_size=5)
        start = time.monotonic()

        for _ in range(5):
            await limiter.acquire()

        elapsed = time.monotonic() - start
        assert elapsed < 0.5, f"Burst of 5 took {elapsed:.2f}s (should be instant)"

    @pytest.mark.asyncio
    async def test_throttles_beyond_burst(self):
        """Requests beyond burst_size should be throttled."""
        # 60 RPM = 1 token/sec, burst=2
        limiter = RateLimiter(max_rpm=60, burst_size=2)

        # First 2 should be instant (burst).
        for _ in range(2):
            await limiter.acquire()

        # Third call should wait ~1 second for a refill.
        start = time.monotonic()
        await limiter.acquire()
        elapsed = time.monotonic() - start

        assert elapsed > 0.5, f"Third call should have waited, only took {elapsed:.2f}s"
        assert elapsed < 3.0, f"Third call waited too long: {elapsed:.2f}s"

    @pytest.mark.asyncio
    async def test_steady_rate(self):
        """Sustained calls should proceed at the configured rate."""
        # 600 RPM = 10 tokens/sec, burst=1
        limiter = RateLimiter(max_rpm=600, burst_size=1)

        start = time.monotonic()
        for _ in range(5):
            await limiter.acquire()
        elapsed = time.monotonic() - start

        # 5 calls at 10/sec with burst=1:
        # Call 1: instant (burst token). Calls 2-5: ~0.1s each = ~0.4s
        assert elapsed > 0.3, f"5 calls too fast: {elapsed:.2f}s"
        assert elapsed < 2.0, f"5 calls too slow: {elapsed:.2f}s"


# ═══════════════════════════════════════════════════════════════════════
#  Context Manager
# ═══════════════════════════════════════════════════════════════════════

class TestContextManager:
    @pytest.mark.asyncio
    async def test_async_with(self):
        """Should work as an async context manager."""
        limiter = RateLimiter(max_rpm=60, burst_size=3)

        async with limiter:
            pass  # Should not raise

        stats = limiter.get_stats()
        assert stats["total_acquired"] == 1


# ═══════════════════════════════════════════════════════════════════════
#  Statistics
# ═══════════════════════════════════════════════════════════════════════

class TestStats:
    @pytest.mark.asyncio
    async def test_stats_tracking(self):
        """Stats should accurately track acquisitions."""
        limiter = RateLimiter(max_rpm=120, burst_size=10)

        for _ in range(7):
            await limiter.acquire()

        stats = limiter.get_stats()
        assert stats["max_rpm"] == 120
        assert stats["burst_size"] == 10
        assert stats["total_acquired"] == 7
        assert stats["current_tokens"] >= 0

    @pytest.mark.asyncio
    async def test_empty_stats(self):
        """Stats should work on a fresh limiter."""
        limiter = RateLimiter(max_rpm=15)
        stats = limiter.get_stats()
        assert stats["total_acquired"] == 0
        assert stats["avg_wait_seconds"] == 0.0


# ═══════════════════════════════════════════════════════════════════════
#  Configuration
# ═══════════════════════════════════════════════════════════════════════

class TestConfiguration:
    def test_default_burst_capped_at_5(self):
        """Default burst should be min(max_rpm, 5)."""
        limiter = RateLimiter(max_rpm=100)
        assert limiter.burst_size == 5

    def test_default_burst_for_low_rpm(self):
        """For very low RPM, burst should equal max_rpm."""
        limiter = RateLimiter(max_rpm=3)
        assert limiter.burst_size == 3

    def test_min_rpm_floor(self):
        """max_rpm should be at least 1."""
        limiter = RateLimiter(max_rpm=0)
        assert limiter.max_rpm == 1

    def test_custom_burst_override(self):
        """Explicit burst_size should override default."""
        limiter = RateLimiter(max_rpm=15, burst_size=10)
        assert limiter.burst_size == 10
