"""
rate_limiter.py — Async Token-Bucket Rate Limiter for LLM API Calls.

Prevents Agentic-AFL from hitting API rate limits during intensive
stall-solving loops. Uses a token-bucket algorithm that naturally
handles burst allowance while enforcing a sustained request ceiling.

Design rationale:
    When the agent detects multiple stalls in quick succession (or the
    same stall keeps failing through the self-repair loop), it can fire
    K=3 parallel LLM calls per attempt × 3 repair attempts × N stalls
    = potentially 9N calls in rapid succession. For Gemini's free tier
    (15 RPM), this causes 429 errors within minutes.

    The rate limiter wraps each provider's generate() call with an async
    semaphore + token bucket that transparently throttles calls to stay
    within configured limits.

Usage:
    limiter = RateLimiter(max_rpm=15, burst_size=5)
    await limiter.acquire()   # Blocks until a token is available
    # ... make API call ...

    # Or as a decorator-style wrapper:
    limiter = RateLimiter(max_rpm=15)
    async with limiter:
        response = await provider.generate(...)

Reference: Deployment Readiness Doc §9 (P2).
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

logger = logging.getLogger(__name__)


class RateLimiter:
    """
    Async token-bucket rate limiter for LLM API calls.

    The bucket starts full (burst_size tokens). Tokens are refilled at
    a steady rate (max_rpm / 60 tokens per second). Each acquire() call
    consumes one token. If the bucket is empty, the caller blocks until
    a token is available.

    Attributes:
        max_rpm:     Maximum requests per minute (sustained rate).
        burst_size:  Maximum burst size (initial tokens). Defaults to
                     min(max_rpm, 5) to allow short bursts for K-way voting.
        _tokens:     Current number of available tokens.
        _last_refill: Timestamp of the last refill calculation.
        _lock:       asyncio.Lock to ensure thread-safe token access.
    """

    def __init__(
        self,
        max_rpm: int = 15,
        burst_size: int | None = None,
    ) -> None:
        self.max_rpm = max(1, max_rpm)
        self.burst_size = burst_size if burst_size is not None else min(max_rpm, 5)
        self._tokens: float = float(self.burst_size)
        self._last_refill: float = time.monotonic()
        self._lock = asyncio.Lock()
        self._total_acquired: int = 0
        self._total_waited: float = 0.0

        logger.debug(
            "RateLimiter initialized: max_rpm=%d, burst_size=%d",
            self.max_rpm, self.burst_size,
        )

    async def acquire(self) -> float:
        """
        Acquire one rate limit token. Blocks if the bucket is empty.

        Returns:
            The number of seconds spent waiting (0.0 if no wait needed).
        """
        wait_start = time.monotonic()

        while True:
            async with self._lock:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    self._total_acquired += 1
                    waited = time.monotonic() - wait_start
                    self._total_waited += waited
                    if waited > 0.1:
                        logger.info(
                            "Rate limiter: waited %.1fs before acquiring token "
                            "(%.1f tokens remaining, %d total calls)",
                            waited, self._tokens, self._total_acquired,
                        )
                    return waited

            # Bucket empty — calculate how long until next token.
            async with self._lock:
                self._refill()
                if self._tokens >= 1.0:
                    continue  # Token appeared while we re-acquired lock
                tokens_needed = 1.0 - self._tokens
                refill_rate = self.max_rpm / 60.0  # tokens per second
                sleep_seconds = tokens_needed / refill_rate

            logger.debug(
                "Rate limiter: bucket empty, sleeping %.2fs (need %.2f tokens)",
                sleep_seconds, tokens_needed,
            )
            await asyncio.sleep(sleep_seconds)

    def _refill(self) -> None:
        """Refill tokens based on elapsed time since last refill."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._last_refill = now

        # Add tokens at the sustained rate.
        refill_rate = self.max_rpm / 60.0  # tokens per second
        self._tokens = min(
            float(self.burst_size),
            self._tokens + elapsed * refill_rate,
        )

    async def __aenter__(self) -> RateLimiter:
        await self.acquire()
        return self

    async def __aexit__(self, *args: Any) -> None:
        pass  # No cleanup needed

    def get_stats(self) -> dict[str, Any]:
        """Return rate limiter statistics."""
        return {
            "max_rpm": self.max_rpm,
            "burst_size": self.burst_size,
            "current_tokens": round(self._tokens, 2),
            "total_acquired": self._total_acquired,
            "total_wait_seconds": round(self._total_waited, 2),
            "avg_wait_seconds": (
                round(self._total_waited / self._total_acquired, 3)
                if self._total_acquired > 0 else 0.0
            ),
        }
