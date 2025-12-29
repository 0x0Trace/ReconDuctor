"""Screenshot capture using gowitness for visual reconnaissance."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from reconductor.core.logger import get_logger
from reconductor.utils.executor import ToolExecutor, get_executor
from reconductor.utils.tempfiles import secure_temp_file

logger = get_logger(__name__)


@dataclass
class ScreenshotResult:
    """Result from a screenshot capture."""
    url: str
    screenshot_path: Optional[Path] = None
    status_code: Optional[int] = None
    title: Optional[str] = None
    final_url: Optional[str] = None  # After redirects
    content_length: Optional[int] = None
    technologies: list[str] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def success(self) -> bool:
        return self.screenshot_path is not None and self.screenshot_path.exists()


@dataclass
class ScreenshotBatchResult:
    """Result from batch screenshot capture."""
    domain: str
    total_targets: int = 0
    successful: int = 0
    failed: int = 0
    screenshots: list[ScreenshotResult] = field(default_factory=list)
    screenshot_dir: Optional[Path] = None
    jsonl_file: Optional[Path] = None
    errors: list[str] = field(default_factory=list)


class ScreenshotCapture:
    """
    Screenshot capture using gowitness v3.

    Takes screenshots of web targets for visual reconnaissance.
    """

    def __init__(
        self,
        executor: Optional[ToolExecutor] = None,
        screenshot_format: str = "jpeg",
        window_width: int = 1920,
        window_height: int = 1080,
    ):
        """
        Initialize screenshot capture.

        Args:
            executor: Tool executor instance
            screenshot_format: Image format (jpeg or png)
            window_width: Browser window width
            window_height: Browser window height
        """
        self.executor = executor or get_executor()
        self.screenshot_format = screenshot_format
        self.window_width = window_width
        self.window_height = window_height

    async def capture_batch(
        self,
        targets: list[str],
        output_dir: Path,
        threads: int = 8,
        timeout: int = 30,
        delay: int = 2,
        fullpage: bool = False,
        save_metadata: bool = True,
    ) -> ScreenshotBatchResult:
        """
        Capture screenshots for multiple targets.

        Args:
            targets: List of URLs to screenshot
            output_dir: Directory to save screenshots
            threads: Number of concurrent threads
            timeout: Page timeout in seconds
            delay: Delay before screenshot (for JS rendering)
            fullpage: Capture full page instead of viewport
            save_metadata: Save metadata as JSONL

        Returns:
            ScreenshotBatchResult with capture results
        """
        result = ScreenshotBatchResult(
            domain=targets[0].split("/")[2] if targets else "unknown",
            total_targets=len(targets),
            screenshot_dir=output_dir,
        )

        if not self.is_available():
            result.errors.append("gowitness not found in PATH")
            logger.error("gowitness not available")
            return result

        if not targets:
            logger.warning("No targets provided for screenshot capture")
            return result

        # Ensure output directory exists
        output_dir.mkdir(parents=True, exist_ok=True)

        # Write targets to temp file
        targets_file = secure_temp_file(suffix="_screenshot_targets.txt")
        targets_file.write_text("\n".join(targets))

        # Build gowitness command
        gowitness_path = ToolExecutor.get_tool_path("gowitness")
        cmd = [
            gowitness_path,
            "scan", "file",
            "-f", str(targets_file),
            "-s", str(output_dir),
            "-t", str(threads),
            "-T", str(timeout),
            "--delay", str(delay),
            "--screenshot-format", self.screenshot_format,
            "--chrome-window-x", str(self.window_width),
            "--chrome-window-y", str(self.window_height),
        ]

        if fullpage:
            cmd.append("--screenshot-fullpage")

        # Write metadata as JSONL for later analysis
        if save_metadata:
            jsonl_file = output_dir / "screenshots.jsonl"
            cmd.extend(["--write-jsonl", "--write-jsonl-file", str(jsonl_file)])
            result.jsonl_file = jsonl_file

        logger.info(f"Starting screenshot capture for {len(targets)} targets")

        # Execute gowitness
        # Timeout: base 60s + 10s per target, max 30 minutes
        exec_timeout = min(1800, 60 + len(targets) * 10)
        exec_result = await self.executor.run(cmd, timeout=exec_timeout)

        if not exec_result.success:
            result.errors.append(f"gowitness failed: {exec_result.error or exec_result.stderr}")
            logger.error(f"gowitness failed: {exec_result.error}")
            # Don't return early - partial results may exist

        # Parse JSONL results if available
        if save_metadata and result.jsonl_file and result.jsonl_file.exists():
            result.screenshots = self._parse_jsonl_results(result.jsonl_file, output_dir)
            result.successful = sum(1 for s in result.screenshots if s.success)
            result.failed = result.total_targets - result.successful
        else:
            # Count screenshots directly from directory
            screenshot_files = list(output_dir.glob(f"*.{self.screenshot_format}"))
            result.successful = len(screenshot_files)
            result.failed = result.total_targets - result.successful

        logger.info(
            f"Screenshot capture complete",
            successful=result.successful,
            failed=result.failed,
            output_dir=str(output_dir),
        )

        return result

    def _parse_jsonl_results(
        self,
        jsonl_file: Path,
        screenshot_dir: Path,
    ) -> list[ScreenshotResult]:
        """Parse gowitness v3 JSONL output."""
        results = []

        try:
            for line in jsonl_file.read_text().strip().split("\n"):
                if not line.strip():
                    continue

                try:
                    data = json.loads(line)

                    # gowitness v3 JSONL format
                    url = data.get("url", "")
                    filename = data.get("file_name", "")  # v3 uses file_name not filename

                    screenshot_path = None
                    if filename:
                        potential_path = screenshot_dir / filename
                        if potential_path.exists():
                            screenshot_path = potential_path

                    result = ScreenshotResult(
                        url=url,
                        screenshot_path=screenshot_path,
                        status_code=data.get("response_code"),
                        title=data.get("title"),
                        final_url=data.get("final_url"),
                        content_length=data.get("content_length"),
                    )

                    # Extract technologies from v3 format (array of {value: str})
                    tech_list = data.get("technologies", [])
                    if tech_list:
                        result.technologies = [t.get("value", "") for t in tech_list if t.get("value")]

                    # Mark as failed if gowitness reported failure
                    if data.get("failed", False):
                        result.error = data.get("failed_reason", "Unknown failure")

                    results.append(result)

                except json.JSONDecodeError:
                    continue

        except Exception as e:
            logger.warning(f"Failed to parse JSONL results: {e}")

        return results

    async def capture_single(
        self,
        url: str,
        output_path: Path,
        timeout: int = 30,
        delay: int = 2,
    ) -> ScreenshotResult:
        """
        Capture a single screenshot.

        Args:
            url: URL to screenshot
            output_path: Path to save screenshot
            timeout: Page timeout
            delay: Delay before screenshot

        Returns:
            ScreenshotResult
        """
        result = ScreenshotResult(url=url)

        if not self.is_available():
            result.error = "gowitness not available"
            return result

        # Ensure parent directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)

        gowitness_path = ToolExecutor.get_tool_path("gowitness")
        cmd = [
            gowitness_path,
            "scan", "single",
            "-u", url,  # v3 requires -u flag for URL
            "-s", str(output_path.parent),
            "-T", str(timeout),
            "--delay", str(delay),
            "--screenshot-format", self.screenshot_format,
            "--write-none",  # Don't write metadata for single
        ]

        exec_result = await self.executor.run(cmd, timeout=timeout + 30)

        if exec_result.success:
            # Find the screenshot file (gowitness generates filename from URL hash)
            screenshots = list(output_path.parent.glob(f"*.{self.screenshot_format}"))
            if screenshots:
                # Get most recent if multiple
                latest = max(screenshots, key=lambda p: p.stat().st_mtime)
                # Rename to desired output path
                latest.rename(output_path)
                result.screenshot_path = output_path
        else:
            result.error = exec_result.error or exec_result.stderr

        return result

    @staticmethod
    def is_available() -> bool:
        """Check if gowitness is installed."""
        return get_executor().check_tool_available("gowitness")


def generate_screenshot_gallery_html(
    results: list[ScreenshotResult],
    output_path: Path,
    title: str = "Screenshot Gallery",
) -> Path:
    """
    Generate an HTML gallery from screenshot results.

    Args:
        results: List of ScreenshotResult
        output_path: Path to save HTML file
        title: Gallery title

    Returns:
        Path to generated HTML file
    """
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        :root {{
            --bg-primary: #1a1a2e;
            --bg-secondary: #16213e;
            --text-primary: #eee;
            --text-secondary: #aaa;
            --accent: #0f3460;
            --success: #2ecc71;
            --error: #e74c3c;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            padding: 20px;
        }}
        h1 {{
            text-align: center;
            margin-bottom: 30px;
            color: var(--text-primary);
        }}
        .stats {{
            display: flex;
            justify-content: center;
            gap: 40px;
            margin-bottom: 30px;
            padding: 15px;
            background: var(--bg-secondary);
            border-radius: 8px;
        }}
        .stat {{
            text-align: center;
        }}
        .stat-value {{
            font-size: 2em;
            font-weight: bold;
        }}
        .stat-label {{
            color: var(--text-secondary);
            font-size: 0.9em;
        }}
        .gallery {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
            gap: 20px;
        }}
        .screenshot-card {{
            background: var(--bg-secondary);
            border-radius: 8px;
            overflow: hidden;
            transition: transform 0.2s;
        }}
        .screenshot-card:hover {{
            transform: scale(1.02);
        }}
        .screenshot-img {{
            width: 100%;
            height: 250px;
            object-fit: cover;
            cursor: pointer;
        }}
        .screenshot-info {{
            padding: 15px;
        }}
        .screenshot-url {{
            font-size: 0.85em;
            word-break: break-all;
            color: #4fc3f7;
            text-decoration: none;
        }}
        .screenshot-url:hover {{
            text-decoration: underline;
        }}
        .screenshot-meta {{
            display: flex;
            justify-content: space-between;
            margin-top: 10px;
            font-size: 0.8em;
            color: var(--text-secondary);
        }}
        .status-code {{
            padding: 2px 8px;
            border-radius: 4px;
            font-weight: bold;
        }}
        .status-2xx {{ background: var(--success); color: #fff; }}
        .status-3xx {{ background: #f39c12; color: #fff; }}
        .status-4xx {{ background: var(--error); color: #fff; }}
        .status-5xx {{ background: #9b59b6; color: #fff; }}
        .title {{
            margin-top: 5px;
            font-size: 0.9em;
            color: var(--text-primary);
        }}
        .error-card {{
            background: #2c1a1a;
            border: 1px solid var(--error);
        }}
        .lightbox {{
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.9);
            z-index: 1000;
            cursor: pointer;
        }}
        .lightbox img {{
            max-width: 95%;
            max-height: 95%;
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
        }}
        .filter-bar {{
            display: flex;
            justify-content: center;
            gap: 10px;
            margin-bottom: 20px;
        }}
        .filter-btn {{
            padding: 8px 16px;
            border: none;
            border-radius: 4px;
            background: var(--accent);
            color: var(--text-primary);
            cursor: pointer;
            transition: background 0.2s;
        }}
        .filter-btn:hover, .filter-btn.active {{
            background: #1a5f9e;
        }}
    </style>
</head>
<body>
    <h1>{title}</h1>

    <div class="stats">
        <div class="stat">
            <div class="stat-value">{len(results)}</div>
            <div class="stat-label">Total</div>
        </div>
        <div class="stat">
            <div class="stat-value">{sum(1 for r in results if r.success)}</div>
            <div class="stat-label">Captured</div>
        </div>
        <div class="stat">
            <div class="stat-value">{sum(1 for r in results if not r.success)}</div>
            <div class="stat-label">Failed</div>
        </div>
    </div>

    <div class="filter-bar">
        <button class="filter-btn active" onclick="filterScreenshots('all')">All</button>
        <button class="filter-btn" onclick="filterScreenshots('success')">Captured</button>
        <button class="filter-btn" onclick="filterScreenshots('error')">Failed</button>
    </div>

    <div class="gallery">
"""

    for r in results:
        status_class = ""
        if r.status_code:
            if 200 <= r.status_code < 300:
                status_class = "status-2xx"
            elif 300 <= r.status_code < 400:
                status_class = "status-3xx"
            elif 400 <= r.status_code < 500:
                status_class = "status-4xx"
            else:
                status_class = "status-5xx"

        card_class = "error-card" if not r.success else ""
        data_status = "success" if r.success else "error"

        # Use relative path for screenshot
        img_src = ""
        if r.screenshot_path and r.screenshot_path.exists():
            img_src = r.screenshot_path.name

        html_content += f"""
        <div class="screenshot-card {card_class}" data-status="{data_status}">
            {"<img class='screenshot-img' src='" + img_src + "' onclick='openLightbox(this)' alt='Screenshot'>" if img_src else "<div style='height:250px;display:flex;align-items:center;justify-content:center;color:var(--error)'>Screenshot Failed</div>"}
            <div class="screenshot-info">
                <a href="{r.url}" target="_blank" class="screenshot-url">{r.url}</a>
                <div class="screenshot-meta">
                    <span class="status-code {status_class}">{r.status_code or 'N/A'}</span>
                </div>
                {"<div class='title'>" + (r.title or '') + "</div>" if r.title else ""}
            </div>
        </div>
"""

    html_content += """
    </div>

    <div class="lightbox" id="lightbox" onclick="closeLightbox()">
        <img id="lightbox-img" src="" alt="Full screenshot">
    </div>

    <script>
        function openLightbox(img) {
            document.getElementById('lightbox-img').src = img.src;
            document.getElementById('lightbox').style.display = 'block';
        }
        function closeLightbox() {
            document.getElementById('lightbox').style.display = 'none';
        }
        function filterScreenshots(filter) {
            document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');

            document.querySelectorAll('.screenshot-card').forEach(card => {
                if (filter === 'all') {
                    card.style.display = 'block';
                } else {
                    card.style.display = card.dataset.status === filter ? 'block' : 'none';
                }
            });
        }
        document.addEventListener('keydown', e => {
            if (e.key === 'Escape') closeLightbox();
        });
    </script>
</body>
</html>
"""

    output_path.write_text(html_content)
    return output_path


async def capture_screenshots(
    urls: list[str],
    output_dir: Path,
    threads: int = 8,
) -> ScreenshotBatchResult:
    """
    Convenience function to capture screenshots.

    Args:
        urls: URLs to screenshot
        output_dir: Directory for screenshots
        threads: Concurrent threads

    Returns:
        ScreenshotBatchResult
    """
    capture = ScreenshotCapture()
    return await capture.capture_batch(
        targets=urls,
        output_dir=output_dir,
        threads=threads,
    )
