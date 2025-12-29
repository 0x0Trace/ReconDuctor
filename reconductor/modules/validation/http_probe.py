"""HTTP probing for live host validation using httpx."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Callable, Optional

from reconductor.core.config import HttpConfig
from reconductor.core.logger import get_logger
from reconductor.core.rate_limiter import AdaptiveRateLimiter
from reconductor.models.host import Host
from reconductor.utils.executor import ToolExecutor, get_executor
from reconductor.utils.parser import OutputParser
from reconductor.utils.tempfiles import secure_temp_file

logger = get_logger(__name__)


class HttpProber:
    """
    HTTP probing for live host validation using httpx.

    Probes hosts for HTTP/HTTPS availability, extracts titles,
    technologies, and CDN information.
    """

    def __init__(
        self,
        config: Optional[HttpConfig] = None,
        executor: Optional[ToolExecutor] = None,
        rate_limiter: Optional[AdaptiveRateLimiter] = None,
    ):
        """
        Initialize HTTP prober.

        Args:
            config: HTTP configuration
            executor: Tool executor instance
            rate_limiter: Adaptive rate limiter
        """
        self.config = config or HttpConfig()
        self.executor = executor or get_executor()
        self.rate_limiter = rate_limiter

    async def probe(
        self,
        targets: list[str],
        output_file: Optional[Path] = None,
        threads: int = 50,
        rate_limit: int = 150,
        timeout: int = 10,
        tech_detect: bool = True,
        cdn_detect: bool = True,
    ) -> list[Host]:
        """
        Probe targets for HTTP availability.

        Args:
            targets: List of targets (hosts/URLs)
            output_file: Output file path (optional)
            threads: Number of concurrent threads
            rate_limit: Requests per second
            timeout: Request timeout in seconds
            tech_detect: Enable technology detection
            cdn_detect: Enable CDN detection

        Returns:
            List of Host objects with probe results
        """
        logger.info(f"Starting HTTP probe for {len(targets)} targets")

        # Write targets to temp file (secure creation)
        input_file = secure_temp_file(suffix="_targets.txt")
        input_file.write_text("\n".join(targets))

        # Prepare output
        if output_file is None:
            output_file = secure_temp_file(suffix="_httpx.json")

        # Build command - use full path to avoid conflicts with Python httpx
        httpx_path = ToolExecutor.get_tool_path("httpx")
        if not httpx_path:
            logger.error("httpx tool not found")
            return []

        cmd = [
            httpx_path,
            "-l", str(input_file),
            "-o", str(output_file),
            "-json",
            "-silent",
            "-threads", str(threads),
            "-rate-limit", str(rate_limit),
            "-timeout", str(timeout),
            # Output options
            "-title",
            "-status-code",
            "-content-length",
            "-web-server",
            "-ip",
            "-cname",
            "-response-time",
            "-hash", "sha256",
            # Follow redirects
            "-follow-redirects",
            "-max-redirects", "10",
        ]

        # Technology detection
        if tech_detect:
            cmd.append("-tech-detect")

        # CDN detection
        if cdn_detect:
            cmd.append("-cdn")

        # Add default headers for OPSEC
        cmd.extend([
            "-H", f"User-Agent: {self.config.user_agent}",
            "-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "-H", "Accept-Language: en-US,en;q=0.9",
        ])

        # Execute httpx
        result = await self.executor.run(cmd, timeout=600)

        if not result.success:
            logger.error(f"httpx failed: {result.error or result.stderr}")
            return []

        # Parse results
        hosts = []
        if output_file.exists():
            content = output_file.read_text()
            hosts = OutputParser.parse_httpx(content)

        alive_count = sum(1 for h in hosts if h.is_alive)
        logger.info(
            f"HTTP probe complete",
            total=len(targets),
            probed=len(hosts),
            alive=alive_count,
        )

        return hosts

    async def probe_parallel(
        self,
        targets: list[str],
        max_workers: Optional[int] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        **kwargs,
    ) -> list[Host]:
        """
        Probe targets using multiple parallel httpx workers.

        Similar to Nuclei parallel scanning - splits targets into batches
        and runs multiple httpx processes concurrently for faster probing.

        Args:
            targets: List of targets (hosts/URLs)
            max_workers: Maximum parallel workers (default: auto based on CPU)
            progress_callback: Callback(current, total) for progress updates
            **kwargs: Additional arguments for probe()

        Returns:
            List of Host objects with probe results
        """
        if not targets:
            return []

        # Calculate optimal workers
        cpu_cores = os.cpu_count() or 4
        total_targets = len(targets)

        # Auto-calculate workers: ~100-200 targets per worker, max based on CPUs
        if max_workers is None or max_workers == 0:
            targets_per_worker = 150
            max_workers = min(
                cpu_cores * 2,  # 2 workers per CPU
                max(1, (total_targets + targets_per_worker - 1) // targets_per_worker),
                12,  # Cap at 12 workers
            )

        # Don't use more workers than targets
        max_workers = min(max_workers, total_targets)

        if max_workers <= 1 or total_targets < 50:
            # Small target list, use single worker
            return await self.probe(targets, **kwargs)

        logger.info(
            f"Starting parallel HTTP probe",
            targets=total_targets,
            workers=max_workers,
        )

        # Split targets into batches
        batch_size = (total_targets + max_workers - 1) // max_workers
        batches = [
            targets[i:i + batch_size]
            for i in range(0, total_targets, batch_size)
        ]

        # Track progress - update when batches START and COMPLETE
        started = 0
        completed = 0
        all_hosts: list[Host] = []
        lock = asyncio.Lock()

        async def probe_batch(batch: list[str], batch_idx: int) -> list[Host]:
            nonlocal started, completed
            try:
                # Update progress when batch STARTS
                async with lock:
                    started += len(batch)
                    if progress_callback:
                        # Show started count so users see incremental progress
                        progress_callback(started, total_targets)

                hosts = await self.probe(batch, **kwargs)

                # Update completed count (for logging)
                async with lock:
                    completed += len(batch)

                return hosts
            except Exception as e:
                logger.warning(f"Batch {batch_idx} failed: {e}")
                async with lock:
                    completed += len(batch)
                return []

        # Run batches with slight stagger to show progress
        results = []
        semaphore = asyncio.Semaphore(max_workers)

        async def run_with_semaphore(batch: list[str], idx: int) -> list[Host]:
            async with semaphore:
                return await probe_batch(batch, idx)

        tasks = [
            run_with_semaphore(batch, idx)
            for idx, batch in enumerate(batches)
        ]

        results = await asyncio.gather(*tasks)

        # Merge results
        for batch_hosts in results:
            all_hosts.extend(batch_hosts)

        alive_count = sum(1 for h in all_hosts if h.is_alive)
        logger.info(
            f"Parallel HTTP probe complete",
            workers=max_workers,
            total=total_targets,
            probed=len(all_hosts),
            alive=alive_count,
        )

        return all_hosts

    async def probe_with_retries(
        self,
        targets: list[str],
        max_retries: int = 2,
        **kwargs,
    ) -> list[Host]:
        """
        Probe targets with retry logic for failed ones.

        Args:
            targets: List of targets
            max_retries: Maximum retry attempts
            **kwargs: Additional arguments for probe()

        Returns:
            List of Host objects
        """
        all_hosts = []
        failed = list(targets)

        for attempt in range(max_retries + 1):
            if not failed:
                break

            logger.info(f"Probe attempt {attempt + 1}/{max_retries + 1} for {len(failed)} targets")

            hosts = await self.probe(failed, **kwargs)
            all_hosts.extend(hosts)

            # Find targets that didn't respond
            probed_hosts = {h.hostname for h in hosts}
            failed = [t for t in failed if t not in probed_hosts and not any(
                h.hostname in t or t in h.hostname for h in hosts
            )]

            if failed and attempt < max_retries:
                # Reduce rate for retries
                kwargs["rate_limit"] = kwargs.get("rate_limit", 150) // 2
                kwargs["timeout"] = kwargs.get("timeout", 10) + 5

        return all_hosts

    async def probe_single(
        self,
        target: str,
        timeout: int = 10,
    ) -> Optional[Host]:
        """
        Probe a single target.

        Args:
            target: Target host/URL
            timeout: Request timeout

        Returns:
            Host object if alive, None otherwise
        """
        hosts = await self.probe([target], timeout=timeout, threads=1, rate_limit=10)
        return hosts[0] if hosts else None

    async def probe_ports(
        self,
        targets: list[str],
        ports: list[int],
        **kwargs,
    ) -> list[Host]:
        """
        Probe targets on specific ports.

        Args:
            targets: List of hosts
            ports: List of ports to probe
            **kwargs: Additional probe arguments

        Returns:
            List of Host objects with port-specific results
        """
        # Build port-specific URLs
        port_targets = []
        for target in targets:
            for port in ports:
                if port == 443:
                    port_targets.append(f"https://{target}")
                elif port == 80:
                    port_targets.append(f"http://{target}")
                else:
                    port_targets.append(f"https://{target}:{port}")
                    port_targets.append(f"http://{target}:{port}")

        return await self.probe(port_targets, **kwargs)

    @staticmethod
    def is_available() -> bool:
        """Check if httpx is installed."""
        return get_executor().check_tool_available("httpx")


class CurlImpersonateProber:
    """
    HTTP probing using curl-impersonate for TLS fingerprint evasion.

    curl-impersonate mimics real browser TLS fingerprints to bypass
    WAFs that detect non-browser clients.
    """

    BROWSER_PROFILES = [
        "chrome120",
        "chrome119",
        "chrome116",
        "firefox121",
        "firefox115",
        "safari17.0",
    ]

    def __init__(
        self,
        executor: Optional[ToolExecutor] = None,
        timeout: int = 10,
    ):
        """
        Initialize curl-impersonate prober.

        Args:
            executor: Tool executor instance
            timeout: Request timeout
        """
        self.executor = executor or get_executor()
        self.timeout = timeout

    async def probe(
        self,
        url: str,
        profile: Optional[str] = None,
    ) -> dict:
        """
        Probe a URL with browser-like TLS fingerprint.

        Args:
            url: Target URL
            profile: Browser profile to use

        Returns:
            Dictionary with response data
        """
        import random

        profile = profile or random.choice(self.BROWSER_PROFILES)

        # Select the right curl binary based on profile
        if "chrome" in profile:
            curl_bin = f"curl_chrome116"  # Most common
        elif "firefox" in profile:
            curl_bin = f"curl_ff117"
        elif "safari" in profile:
            curl_bin = f"curl_safari15_3"
        else:
            curl_bin = "curl"

        cmd = [
            curl_bin,
            "-s",
            "-L",
            "-o", "-",
            "-w", "\n%{http_code}\n%{time_total}\n%{content_type}",
            "--max-time", str(self.timeout),
            "-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "-H", "Accept-Language: en-US,en;q=0.9",
            url,
        ]

        result = await self.executor.run(cmd, timeout=self.timeout + 5)

        if not result.success:
            return {
                "url": url,
                "success": False,
                "error": result.error,
            }

        # Parse output
        lines = result.stdout.strip().split("\n")
        if len(lines) >= 3:
            body = "\n".join(lines[:-3])
            status_code = int(lines[-3]) if lines[-3].isdigit() else 0
            time_total = float(lines[-2]) if lines[-2].replace(".", "").isdigit() else 0
            content_type = lines[-1]
        else:
            body = result.stdout
            status_code = 0
            time_total = 0
            content_type = ""

        return {
            "url": url,
            "success": status_code > 0,
            "status_code": status_code,
            "body": body[:10000],  # Limit body size
            "time_total": time_total,
            "content_type": content_type,
            "profile": profile,
        }

    @staticmethod
    def is_available() -> bool:
        """Check if curl-impersonate is installed."""
        executor = get_executor()
        return (
            executor.check_tool_available("curl_chrome116") or
            executor.check_tool_available("curl_ff117") or
            executor.check_tool_available("curl-impersonate")
        )
