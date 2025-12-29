"""Nuclei vulnerability scanner manager with checkpoint/resume support."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from reconductor.core.config import NucleiConfig
from reconductor.core.logger import get_logger, log_finding
from reconductor.core.rate_limiter import AdaptiveRateLimiter
from reconductor.models.finding import Finding
from reconductor.models.host import Host
from reconductor.utils.executor import ToolExecutor, get_executor
from reconductor.utils.parser import OutputParser
from reconductor.utils.tempfiles import secure_temp_file

logger = get_logger(__name__)

# Default batch size for checkpoint/resume (hosts per nuclei invocation)
DEFAULT_BATCH_SIZE = 50


@dataclass
class ScanProgress:
    """Track scan progress."""
    total_hosts: int = 0
    scanned_hosts: int = 0
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    errors: list[str] = field(default_factory=list)


def split_into_batches(hosts: list[Host], batch_size: int = DEFAULT_BATCH_SIZE) -> list[list[Host]]:
    """
    Split hosts into batches for checkpoint/resume support.

    Batches run sequentially (one nuclei process at a time) but progress
    is saved after each batch, allowing resume if interrupted.

    Args:
        hosts: List of hosts to scan
        batch_size: Hosts per batch (default: 50)

    Returns:
        List of host batches
    """
    if not hosts:
        return []

    # Split into fixed-size batches
    batches = []
    for i in range(0, len(hosts), batch_size):
        batches.append(hosts[i:i + batch_size])

    logger.debug(
        f"Split {len(hosts)} hosts into {len(batches)} batches",
        batch_sizes=[len(b) for b in batches],
    )

    return batches


class NucleiManager:
    """
    Nuclei vulnerability scanner manager.

    Provides dynamic parallelization, rate limiting, and
    comprehensive finding collection with resumable scanning.
    """

    def __init__(
        self,
        config: Optional[NucleiConfig] = None,
        executor: Optional[ToolExecutor] = None,
        rate_limiter: Optional[AdaptiveRateLimiter] = None,
        output_dir: Optional[Path] = None,
    ):
        """
        Initialize Nuclei manager.

        Args:
            config: Nuclei configuration
            executor: Tool executor instance
            rate_limiter: Adaptive rate limiter
            output_dir: Output directory for progress tracking
        """
        self.config = config or NucleiConfig()
        self.executor = executor or get_executor()
        self.rate_limiter = rate_limiter or AdaptiveRateLimiter()
        self.output_dir = output_dir

    def _get_progress_file(self) -> Optional[Path]:
        """Get the path to the nuclei progress file."""
        if self.output_dir:
            return self.output_dir / ".nuclei_progress.txt"
        return None

    def _get_findings_progress_file(self) -> Optional[Path]:
        """Get the path to the incremental findings file."""
        if self.output_dir:
            return self.output_dir / ".nuclei_findings_partial.json"
        return None

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Normalize URL for consistent comparison (remove default ports)."""
        url = url.rstrip("/")
        # Remove default ports
        if url.startswith("https://") and ":443" in url:
            url = url.replace(":443", "")
        elif url.startswith("http://") and ":80" in url:
            url = url.replace(":80", "")
        return url

    def load_scanned_hosts(self) -> set[str]:
        """Load the set of already-scanned hosts from progress file."""
        progress_file = self._get_progress_file()
        if progress_file and progress_file.exists():
            try:
                content = progress_file.read_text().strip()
                if content:
                    # Normalize URLs for consistent matching
                    return set(self._normalize_url(url) for url in content.split("\n") if url)
            except Exception as e:
                logger.warning(f"Failed to load nuclei progress: {e}")
        return set()

    def save_scanned_hosts(self, hosts: set[str]) -> None:
        """Save the set of scanned hosts to progress file."""
        progress_file = self._get_progress_file()
        if progress_file:
            try:
                progress_file.write_text("\n".join(sorted(hosts)))
            except Exception as e:
                logger.warning(f"Failed to save nuclei progress: {e}")

    def append_scanned_hosts(self, new_hosts: list[str]) -> None:
        """Append newly scanned hosts to progress file."""
        progress_file = self._get_progress_file()
        if progress_file:
            try:
                with open(progress_file, "a") as f:
                    for host in new_hosts:
                        f.write(f"{host}\n")
            except Exception as e:
                logger.warning(f"Failed to append nuclei progress: {e}")

    def load_partial_findings(self) -> list[Finding]:
        """Load partial findings from interrupted scan."""
        import json
        findings_file = self._get_findings_progress_file()
        if findings_file and findings_file.exists():
            try:
                content = findings_file.read_text()
                data = json.loads(content) if content else []
                # Convert dicts back to Finding objects
                findings = []
                for item in data:
                    finding = Finding.from_dict(item) if hasattr(Finding, 'from_dict') else None
                    if finding:
                        findings.append(finding)
                return findings
            except Exception as e:
                logger.warning(f"Failed to load partial findings: {e}")
        return []

    def append_findings(self, findings: list[Finding]) -> None:
        """Append findings to incremental file."""
        import json
        findings_file = self._get_findings_progress_file()
        if findings_file and findings:
            try:
                # Load existing
                existing = []
                if findings_file.exists():
                    content = findings_file.read_text()
                    existing = json.loads(content) if content else []

                # Append new
                for f in findings:
                    existing.append(f.to_dict())

                # Save
                findings_file.write_text(json.dumps(existing, indent=2, default=str))
            except Exception as e:
                logger.warning(f"Failed to save partial findings: {e}")

    def clear_progress(self) -> None:
        """Clear progress files after successful completion."""
        for file_path in [self._get_progress_file(), self._get_findings_progress_file()]:
            if file_path and file_path.exists():
                try:
                    file_path.unlink()
                except Exception:
                    pass

    def get_resume_info(self) -> dict[str, Any]:
        """Get info about resumable scan progress."""
        scanned = self.load_scanned_hosts()
        partial_findings = self.load_partial_findings()
        return {
            "scanned_hosts": len(scanned),
            "partial_findings": len(partial_findings),
            "can_resume": len(scanned) > 0,
        }

    async def scan(
        self,
        targets: list[str],
        output_file: Optional[Path] = None,
        templates: Optional[list[str]] = None,
        severity: Optional[list[str]] = None,
        exclude_tags: Optional[list[str]] = None,
        rate_limit: Optional[int] = None,
        bulk_size: Optional[int] = None,
        concurrency: Optional[int] = None,
        progress_callback: Optional[callable] = None,
        batch_info: Optional[tuple[int, int]] = None,
        standalone: bool = True,
        cumulative_findings: int = 0,
    ) -> list[Finding]:
        """
        Scan targets with Nuclei with real-time progress tracking.

        Args:
            targets: List of URLs/hosts to scan
            output_file: Output file path (optional)
            templates: Specific templates to use
            severity: Severity levels to scan
            exclude_tags: Tags to exclude
            rate_limit: Requests per second
            bulk_size: Parallel hosts per template
            concurrency: Parallel templates
            progress_callback: Callback(percent, requests, total, rps) for progress
            batch_info: Tuple of (current_batch, total_batches)
            standalone: If True, print progress directly (for CLI continue command)
                       If False, don't print (Live display handles it)
            cumulative_findings: Findings count from previous batches (for accurate totals)

        Returns:
            List of Finding objects
        """
        import json as json_module

        logger.info(f"Starting Nuclei scan for {len(targets)} targets")

        # Write targets to temp file (secure creation)
        input_file = secure_temp_file(suffix="_targets.txt")
        input_file.write_text("\n".join(targets))

        # Prepare output
        if output_file is None:
            output_file = secure_temp_file(suffix="_nuclei.json")

        # Build command - use full path to avoid conflicts
        nuclei_path = ToolExecutor.get_tool_path("nuclei")
        if not nuclei_path:
            logger.error("nuclei tool not found")
            return []

        cmd = [
            nuclei_path,
            "-l", str(input_file),
            "-o", str(output_file),
            "-jsonl",
            "-stats",              # Enable stats output
            "-stats-json",         # JSON format for parsing
            "-stats-interval", "3",  # Update every 3 seconds
            # Performance settings
            "-rl", str(rate_limit or self.config.rate_limit),
            "-bs", str(bulk_size or self.config.bulk_size),
            "-c", str(concurrency or self.config.concurrency),
            "-pc", str(self.config.payload_concurrency),
            "-timeout", str(self.config.timeout),
            "-retries", str(self.config.retries),
            "-mhe", str(self.config.max_host_error),
            "-rsr", str(self.config.response_size_read),
            "-ss", self.config.scan_strategy,
        ]

        # Templates
        if templates:
            for t in templates:
                cmd.extend(["-t", t])

        # Severity filter
        sev_list = severity or self.config.severity
        if sev_list:
            cmd.extend(["-severity", ",".join(sev_list)])

        # Exclude tags
        tags_list = exclude_tags or self.config.exclude_tags
        if tags_list:
            cmd.extend(["-etags", ",".join(tags_list)])

        # Disable interactsh if configured
        if self.config.disable_interactsh:
            cmd.append("-ni")

        # Run with streaming stderr to capture stats
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Use Rich console for standalone progress (only when no Live display)
        from rich.console import Console
        rich_console = Console(stderr=True)
        last_percent = -1

        # Read stderr for stats updates
        async def read_stats():
            nonlocal last_percent
            while True:
                line = await process.stderr.readline()
                if not line:
                    break
                try:
                    line_str = line.decode('utf-8').strip()
                    if line_str.startswith('{') and 'percent' in line_str:
                        stats = json_module.loads(line_str)

                        # Parse string values from nuclei stats JSON
                        try:
                            percent = float(stats.get('percent', '0'))
                            # Handle overflow values (nuclei bug)
                            if percent > 100:
                                percent = 0
                        except (ValueError, TypeError):
                            percent = 0

                        requests = stats.get('requests', '0')
                        total = stats.get('total', '0')
                        matched = stats.get('matched', '0')

                        try:
                            rps = float(stats.get('rps', '0'))
                            if rps > 1000000:  # Handle overflow
                                rps = 0
                        except (ValueError, TypeError):
                            rps = 0

                        # Calculate total findings: cumulative from previous batches + current batch
                        try:
                            current_batch_matched = int(matched) if matched else 0
                        except (ValueError, TypeError):
                            current_batch_matched = 0
                        total_findings_display = cumulative_findings + current_batch_matched

                        if progress_callback:
                            progress_callback(percent, requests, total, rps, total_findings_display)

                        # Calculate overall progress if we have batch info
                        if batch_info:
                            current_batch, total_batches = batch_info
                            # Overall = completed batches + current batch progress
                            completed_batches = current_batch - 1
                            overall_percent = (completed_batches / total_batches * 100) + (percent / total_batches)
                        else:
                            overall_percent = percent

                        # Only print directly in standalone mode (not when Live display is active)
                        # This prevents interference with Rich Live display
                        if standalone:
                            bucket = int(overall_percent // 5) * 5
                            if bucket != last_percent and overall_percent <= 100:
                                last_percent = bucket
                                if batch_info:
                                    rich_console.print(f"  [cyan]Nuclei: {overall_percent:.0f}%[/] (batch {batch_info[0]}/{batch_info[1]}) | [green]{total_findings_display} findings[/]")
                                else:
                                    rich_console.print(f"  [cyan]Nuclei: {overall_percent:.0f}%[/] | [green]{total_findings_display} findings[/]")
                except (json_module.JSONDecodeError, UnicodeDecodeError):
                    pass  # Ignore non-JSON lines

        # Run stats reader and wait for completion
        stats_task = asyncio.create_task(read_stats())

        try:
            # Scale timeout based on target count: ~30 seconds per target minimum
            # Min 1 hour, max 8 hours
            target_count = len(targets)
            timeout = min(28800, max(3600, 1800 + target_count * 30))  # 1-8 hours
            timeout_hours = timeout / 3600

            await asyncio.wait_for(process.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            process.kill()
            logger.error(f"Nuclei scan timed out after {timeout_hours:.1f} hours ({target_count} targets)")
            return []
        finally:
            stats_task.cancel()
            try:
                await stats_task
            except asyncio.CancelledError:
                pass

        # Print newline after progress updates
        rich_console.print()

        if process.returncode != 0:
            logger.error(f"Nuclei failed with exit code {process.returncode}")
            return []

        # Parse results
        findings = []
        if output_file.exists():
            content = output_file.read_text()
            findings = OutputParser.parse_nuclei(content)

            # Deduplicate findings by (template_id, target, severity)
            seen = set()
            unique_findings = []
            for finding in findings:
                key = (finding.template_id, finding.target, finding.severity.value)
                if key not in seen:
                    seen.add(key)
                    unique_findings.append(finding)

            if len(findings) != len(unique_findings):
                logger.debug(f"Deduplicated findings: {len(findings)} -> {len(unique_findings)}")
            findings = unique_findings

            # Log findings
            for finding in findings:
                log_finding(
                    finding.finding_type.value,
                    finding.severity.value,
                    finding.target,
                    template_id=finding.template_id,
                )

        critical_high = sum(1 for f in findings if f.is_critical_or_high)
        logger.info(
            f"Nuclei scan complete",
            targets=len(targets),
            findings=len(findings),
            critical_high=critical_high,
        )

        return findings

    async def scan_batched(
        self,
        hosts: list[Host],
        progress_callback: Optional[callable] = None,
        resume: bool = True,
        standalone: bool = True,
    ) -> list[Finding]:
        """
        Scan hosts in batches with checkpoint/resume support.

        Runs one nuclei process at a time, saving progress after each batch.
        This allows resuming interrupted scans from where they left off.

        Args:
            hosts: List of Host objects to scan
            progress_callback: Callback(current, total) for progress updates
            resume: Whether to resume from previous progress
            standalone: If True, print progress directly (for CLI continue command)
                       If False, let caller handle display (for Live display)

        Returns:
            List of Finding objects
        """
        # Check for previous progress and filter hosts
        already_scanned: set[str] = set()
        partial_findings: list[Finding] = []
        original_total = len(hosts)

        if resume and self.output_dir:
            already_scanned = self.load_scanned_hosts()
            if already_scanned:
                # Filter out already-scanned hosts
                hosts = [h for h in hosts if self._normalize_url(h.full_url) not in already_scanned]
                partial_findings = self.load_partial_findings()

                if not hosts:
                    logger.info("All hosts already scanned, returning cached findings")
                    self.clear_progress()
                    return partial_findings

                logger.warning(
                    f"Resuming scan: {len(already_scanned)} already done, {len(hosts)} remaining",
                    already_scanned=len(already_scanned),
                    remaining=len(hosts),
                    partial_findings=len(partial_findings),
                )

        # Split into batches for checkpoint/resume
        batches = split_into_batches(hosts)
        num_batches = len(batches)

        if num_batches == 0:
            return partial_findings

        # Log scan info
        hosts_per_batch = len(hosts) // num_batches if num_batches > 0 else len(hosts)
        logger.warning(f"Nuclei: {len(hosts)} hosts, {num_batches} batches (~{hosts_per_batch} each)")

        # Track progress
        total_hosts = original_total
        completed_hosts = len(already_scanned)
        cumulative_findings = len(partial_findings)
        all_findings = list(partial_findings)

        # Process batches sequentially (one nuclei process at a time)
        for batch_num, batch_hosts in enumerate(batches, 1):
            urls = [h.full_url for h in batch_hosts]

            logger.info(f"Batch {batch_num}/{num_batches}: {len(urls)} hosts")

            # Create progress callback for this batch
            def batch_progress(percent: float, requests: int, total: int, rps: float, matched: int):
                if progress_callback:
                    # Calculate overall progress including completed batches
                    batch_contribution = (batch_num - 1) / num_batches
                    current_contribution = (percent / 100) / num_batches
                    overall_hosts = int(completed_hosts + len(batch_hosts) * (percent / 100))
                    progress_callback(overall_hosts, total_hosts)

            # Run nuclei for this batch
            findings = await self.scan(
                urls,
                progress_callback=batch_progress,
                batch_info=(batch_num, num_batches),
                standalone=standalone,
                cumulative_findings=cumulative_findings,
            )

            # Update tracking
            completed_hosts += len(urls)
            cumulative_findings += len(findings)
            all_findings.extend(findings)

            if progress_callback:
                progress_callback(completed_hosts, total_hosts)

            # Save progress incrementally (allows resume if interrupted)
            self.append_scanned_hosts(urls)
            if findings:
                self.append_findings(findings)

        # Deduplicate findings across all batches
        seen = set()
        unique_findings = []
        for finding in all_findings:
            key = (finding.template_id, finding.target, finding.severity.value)
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)

        if len(all_findings) != len(unique_findings):
            logger.info(f"Deduplicated findings: {len(all_findings)} -> {len(unique_findings)}")

        # Clear progress files on successful completion
        self.clear_progress()

        return unique_findings

    # Keep scan_parallel as an alias for backwards compatibility
    async def scan_parallel(
        self,
        hosts: list[Host],
        max_workers: Optional[int] = None,  # Ignored, kept for compatibility
        progress_callback: Optional[callable] = None,
        resume: bool = True,
        standalone: bool = True,
    ) -> list[Finding]:
        """Alias for scan_batched (kept for backwards compatibility)."""
        return await self.scan_batched(
            hosts=hosts,
            progress_callback=progress_callback,
            resume=resume,
            standalone=standalone,
        )

    async def scan_by_severity(
        self,
        targets: list[str],
    ) -> dict[str, list[Finding]]:
        """
        Scan targets and group findings by severity.

        Args:
            targets: List of URLs/hosts

        Returns:
            Dictionary mapping severity to findings
        """
        findings = await self.scan(targets)

        grouped: dict[str, list[Finding]] = defaultdict(list)
        for finding in findings:
            grouped[finding.severity.value].append(finding)

        return dict(grouped)

    async def scan_with_technology(
        self,
        targets: list[str],
        technology: str,
    ) -> list[Finding]:
        """
        Scan targets with technology-specific templates.

        Args:
            targets: List of URLs/hosts
            technology: Technology to target (e.g., "wordpress", "jira")

        Returns:
            List of Finding objects
        """
        # Use technology-specific templates
        templates = [f"technologies/{technology}"]

        return await self.scan(
            targets,
            templates=templates,
        )

    @staticmethod
    def is_available() -> bool:
        """Check if nuclei is installed."""
        return get_executor().check_tool_available("nuclei")

    @staticmethod
    async def update_templates() -> bool:
        """
        Update Nuclei templates.

        Returns:
            True if update successful
        """
        nuclei_path = ToolExecutor.get_tool_path("nuclei")
        if not nuclei_path:
            logger.error("nuclei tool not found")
            return False

        executor = get_executor()
        result = await executor.run([nuclei_path, "-ut"], timeout=300)
        return result.success
