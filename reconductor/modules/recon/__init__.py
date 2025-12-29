"""Reconnaissance modules including Shodan, GAU, screenshot capture, and origin IP discovery."""

from reconductor.modules.recon.shodan_recon import (
    ShodanClient,
    ShodanEnumerator,
    ShodanOriginFinder,
    FaviconHasher,
    SecurityTrailsClient,
    OriginIPResult,
    ShodanSearchResult,
)
from reconductor.modules.recon.gau_wrapper import (
    GauWrapper,
    GauUrl,
    GauResult,
    fetch_historical_urls,
)
from reconductor.modules.recon.screenshot_capture import (
    ScreenshotCapture,
    ScreenshotResult,
    ScreenshotBatchResult,
    capture_screenshots,
    generate_screenshot_gallery_html,
)
from reconductor.modules.recon.origin_discovery import (
    OriginDiscovery,
    OriginCandidate,
    OriginDiscoveryResult,
    discover_origin_ips,
    CheckHostValidator,
    SecurityTrailsClient as OriginSecurityTrailsClient,  # Renamed to avoid conflict
)

__all__ = [
    # Shodan
    "ShodanClient",
    "ShodanEnumerator",
    "ShodanOriginFinder",
    "FaviconHasher",
    "SecurityTrailsClient",
    "OriginIPResult",
    "ShodanSearchResult",
    # GAU
    "GauWrapper",
    "GauUrl",
    "GauResult",
    "fetch_historical_urls",
    # Screenshots
    "ScreenshotCapture",
    "ScreenshotResult",
    "ScreenshotBatchResult",
    "capture_screenshots",
    "generate_screenshot_gallery_html",
    # Origin Discovery
    "OriginDiscovery",
    "OriginCandidate",
    "OriginDiscoveryResult",
    "discover_origin_ips",
    "CheckHostValidator",
    "OriginSecurityTrailsClient",
]
