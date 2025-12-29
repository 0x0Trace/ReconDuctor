"""Adaptive rate limiting with WAF detection and exponential backoff."""

from __future__ import annotations

import asyncio
import random
import re
import time
from collections import defaultdict
from typing import Optional

from reconductor.core.logger import get_logger

logger = get_logger(__name__)


class AdaptiveRateLimiter:
    """
    Adaptive rate limiting with exponential backoff on WAF detection.

    Monitors response status codes and body content to detect WAF blocking,
    then automatically reduces request rate to avoid further detection.
    """

    # HTTP status codes indicating WAF/rate limiting
    WAF_STATUS_CODES = {
        429,  # Too Many Requests
        403,  # Forbidden
        503,  # Service Unavailable (often WAF)
        406,  # Not Acceptable
        418,  # I'm a Teapot (sometimes used by WAFs)
        520,  # Cloudflare - Unknown Error
        521,  # Cloudflare - Web Server Down
        522,  # Cloudflare - Connection Timed Out
        523,  # Cloudflare - Origin Unreachable
        524,  # Cloudflare - Timeout Occurred
    }

    # Body patterns indicating WAF/blocking
    WAF_BODY_PATTERNS = [
        r"Access Denied",
        r"Cloudflare",
        r"Please complete the security check",
        r"Rate limit exceeded",
        r"Too many requests",
        r"Your IP has been blocked",
        r"Please enable JavaScript",
        r"Checking your browser",
        r"DDoS protection by",
        r"Attention Required",
        r"cf-ray",
        r"__cf_bm",
        r"Incapsula",
        r"PerimeterX",
        r"DataDome",
        r"Imperva",
        r"AWS WAF",
        r"Request blocked",
        r"Security check",
    ]

    def __init__(
        self,
        initial_rate: float = 30.0,
        min_rate: float = 1.0,
        backoff_factor: float = 0.5,
        recovery_factor: float = 1.1,
    ):
        """
        Initialize rate limiter.

        Args:
            initial_rate: Starting requests per second
            min_rate: Minimum requests per second (floor)
            backoff_factor: Rate multiplier on WAF detection (0.5 = halve rate)
            recovery_factor: Rate multiplier on success (1.1 = 10% increase)
        """
        self.initial_rate = initial_rate
        self.min_rate = min_rate
        self.backoff_factor = backoff_factor
        self.recovery_factor = recovery_factor

        # Per-IP tracking
        self.ip_rates: dict[str, float] = defaultdict(lambda: initial_rate)
        self.ip_backoffs: dict[str, int] = defaultdict(int)
        self.last_request: dict[str, float] = {}
        self.consecutive_success: dict[str, int] = defaultdict(int)

        # Compile WAF patterns
        self._waf_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.WAF_BODY_PATTERNS
        ]

        # Lock for thread-safe operations
        self._locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    async def acquire(self, ip: str) -> None:
        """
        Acquire permission to make a request to an IP with rate limiting.

        Args:
            ip: Target IP address
        """
        async with self._locks[ip]:
            current_rate = self.ip_rates[ip]
            min_interval = 1.0 / current_rate

            if ip in self.last_request:
                elapsed = time.time() - self.last_request[ip]
                if elapsed < min_interval:
                    # Add jitter: random 0.5-2.0 multiplier
                    jitter = random.uniform(0.5, 2.0)
                    wait_time = (min_interval - elapsed) * jitter
                    await asyncio.sleep(wait_time)

            self.last_request[ip] = time.time()

    def record_response(
        self,
        ip: str,
        status_code: int,
        body: Optional[str] = None,
    ) -> bool:
        """
        Record a response and adjust rate if needed.

        Args:
            ip: Target IP address
            status_code: HTTP response status code
            body: Optional response body for WAF detection

        Returns:
            True if WAF detected, False otherwise
        """
        waf_detected = False

        # Check status code
        if status_code in self.WAF_STATUS_CODES:
            waf_detected = True
            self._backoff(ip, f"status_code_{status_code}")

        # Check body patterns if provided
        elif body and self._detect_waf_in_body(body):
            waf_detected = True
            self._backoff(ip, "body_pattern")

        # Success - gradually recover
        elif 200 <= status_code < 400:
            self._recover(ip)

        return waf_detected

    def _detect_waf_in_body(self, body: str) -> bool:
        """
        Detect WAF/block pages by response body content.

        Args:
            body: Response body text

        Returns:
            True if WAF detected in body
        """
        if not body:
            return False

        for pattern in self._waf_patterns:
            if pattern.search(body):
                return True

        return False

    def _backoff(self, ip: str, reason: str) -> None:
        """
        Apply exponential backoff for an IP.

        Args:
            ip: Target IP address
            reason: Reason for backoff
        """
        self.ip_backoffs[ip] += 1
        self.consecutive_success[ip] = 0

        # Apply backoff factor (default: halve rate)
        new_rate = max(self.min_rate, self.ip_rates[ip] * self.backoff_factor)
        old_rate = self.ip_rates[ip]
        self.ip_rates[ip] = new_rate

        logger.warning(
            "WAF detected, backing off",
            ip=ip,
            reason=reason,
            backoff_count=self.ip_backoffs[ip],
            old_rate=round(old_rate, 2),
            new_rate=round(new_rate, 2),
        )

    def _recover(self, ip: str) -> None:
        """
        Slowly recover rate after successful requests.

        Args:
            ip: Target IP address
        """
        self.consecutive_success[ip] += 1

        # Only recover after multiple consecutive successes
        if self.consecutive_success[ip] >= 5:
            current = self.ip_rates[ip]
            if current < self.initial_rate:
                new_rate = min(self.initial_rate, current * self.recovery_factor)
                self.ip_rates[ip] = new_rate

                if new_rate > current:
                    logger.debug(
                        "Rate recovering",
                        ip=ip,
                        new_rate=round(new_rate, 2),
                    )

            self.consecutive_success[ip] = 0

    def get_rate(self, ip: str) -> float:
        """
        Get current rate limit for an IP.

        Args:
            ip: Target IP address

        Returns:
            Current requests per second for this IP
        """
        return self.ip_rates[ip]

    def get_stats(self) -> dict[str, any]:
        """
        Get rate limiter statistics.

        Returns:
            Dictionary with rate limiter stats
        """
        rates = dict(self.ip_rates)
        return {
            "total_ips": len(rates),
            "backed_off_ips": sum(1 for r in rates.values() if r < self.initial_rate),
            "min_rate": min(rates.values()) if rates else self.initial_rate,
            "max_rate": max(rates.values()) if rates else self.initial_rate,
            "avg_rate": sum(rates.values()) / len(rates) if rates else self.initial_rate,
            "total_backoffs": sum(self.ip_backoffs.values()),
        }

    def reset(self, ip: Optional[str] = None) -> None:
        """
        Reset rate limiting state.

        Args:
            ip: Optional specific IP to reset, or all if None
        """
        if ip:
            self.ip_rates[ip] = self.initial_rate
            self.ip_backoffs[ip] = 0
            self.consecutive_success[ip] = 0
            if ip in self.last_request:
                del self.last_request[ip]
        else:
            self.ip_rates.clear()
            self.ip_backoffs.clear()
            self.consecutive_success.clear()
            self.last_request.clear()


class TokenBucket:
    """
    Token bucket rate limiter for global rate limiting.

    Provides smooth rate limiting with burst capability.
    """

    def __init__(
        self,
        rate: float,
        burst: int = 10,
    ):
        """
        Initialize token bucket.

        Args:
            rate: Tokens per second
            burst: Maximum burst size
        """
        self.rate = rate
        self.burst = burst
        self.tokens = burst
        self.last_update = time.time()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: int = 1) -> None:
        """
        Acquire tokens, waiting if necessary.

        Args:
            tokens: Number of tokens to acquire
        """
        async with self._lock:
            await self._wait_for_tokens(tokens)
            self.tokens -= tokens

    async def _wait_for_tokens(self, tokens: int) -> None:
        """Wait until enough tokens are available."""
        while True:
            self._add_tokens()
            if self.tokens >= tokens:
                return
            # Calculate wait time
            needed = tokens - self.tokens
            wait_time = needed / self.rate
            await asyncio.sleep(wait_time)

    def _add_tokens(self) -> None:
        """Add tokens based on elapsed time."""
        now = time.time()
        elapsed = now - self.last_update
        self.last_update = now
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
