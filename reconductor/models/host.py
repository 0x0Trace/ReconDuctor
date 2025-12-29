"""Host data model with full IPv4/IPv6 support."""

from __future__ import annotations

import ipaddress
from datetime import datetime
from enum import Enum
from typing import Any, ClassVar, Optional

from pydantic import BaseModel, Field, computed_field


class HostStatus(str, Enum):
    """Host status values."""
    UNKNOWN = "unknown"
    ALIVE = "alive"
    DEAD = "dead"
    FILTERED = "filtered"
    TIMEOUT = "timeout"
    ERROR = "error"


class CDNProvider(str, Enum):
    """Known CDN providers."""
    CLOUDFLARE = "cloudflare"
    AKAMAI = "akamai"
    FASTLY = "fastly"
    AWS_CLOUDFRONT = "aws-cloudfront"
    AZURE_CDN = "azure-cdn"
    GOOGLE_CLOUD_CDN = "google-cloud-cdn"
    CLOUDINARY = "cloudinary"
    IMPERVA = "imperva"
    STACKPATH = "stackpath"
    UNKNOWN = "unknown"
    NONE = "none"


class Host(BaseModel):
    """
    Host data model with full IPv4/IPv6 support.

    Represents a live host with HTTP information, technologies,
    and CDN detection.
    """

    # Configurable IPv6 prefix for rate limiting groups
    _ipv6_prefix: ClassVar[int] = 64

    # Core fields
    hostname: str = Field(..., description="Hostname or subdomain")
    url: Optional[str] = None
    scheme: str = "https"
    port: int = 443

    # IP addresses
    ipv4_addresses: list[str] = Field(default_factory=list)
    ipv6_addresses: list[str] = Field(default_factory=list)

    # HTTP information
    status_code: Optional[int] = None
    title: Optional[str] = None
    content_length: Optional[int] = None
    content_type: Optional[str] = None
    server: Optional[str] = None
    response_time: Optional[float] = None  # in seconds

    # Security headers
    headers: dict[str, str] = Field(default_factory=dict)
    csp: Optional[str] = None
    hsts: bool = False
    x_frame_options: Optional[str] = None

    # Technology detection
    technologies: list[str] = Field(default_factory=list)
    favicon_hash: Optional[str] = None
    body_hash: Optional[str] = None

    # CDN information
    cdn_provider: CDNProvider = CDNProvider.NONE
    cdn_detected: bool = False

    # Status
    status: HostStatus = HostStatus.UNKNOWN
    is_alive: bool = False

    # Ports (from naabu)
    open_ports: list[int] = Field(default_factory=list)

    # Screenshot
    screenshot_path: Optional[str] = None
    screenshot_classification: Optional[str] = None

    # Origin IP (CDN bypass)
    origin_ip: Optional[str] = None
    origin_discovery_method: Optional[str] = None

    # Timestamps
    discovered_at: Optional[datetime] = None
    last_checked: Optional[datetime] = None

    # Additional data
    extra: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def set_ipv6_prefix(cls, prefix: int) -> None:
        """
        Configure IPv6 prefix for rate limiting groups.

        Args:
            prefix: Prefix length (48, 56, or 64)
        """
        if prefix not in [48, 56, 64]:
            raise ValueError(f"IPv6 prefix must be 48, 56, or 64, got {prefix}")
        cls._ipv6_prefix = prefix

    @computed_field
    @property
    def primary_ip(self) -> Optional[str]:
        """Get primary IP (prefer IPv4 for compatibility)."""
        if self.ipv4_addresses:
            return self.ipv4_addresses[0]
        if self.ipv6_addresses:
            return self.ipv6_addresses[0]
        return None

    @computed_field
    @property
    def ip_cluster_key(self) -> str:
        """
        Get IP cluster key for worker distribution.

        Groups hosts by IP for rate limiting purposes.
        IPv6 addresses are grouped by configurable prefix.
        """
        if self.ipv4_addresses:
            return self.ipv4_addresses[0]
        if self.ipv6_addresses:
            return self._ipv6_to_prefix(self.ipv6_addresses[0])
        return "unknown"

    def _ipv6_to_prefix(self, ipv6: str) -> str:
        """Convert IPv6 to configurable prefix."""
        try:
            addr = ipaddress.IPv6Address(ipv6)
            network = ipaddress.IPv6Network(
                f"{addr}/{self._ipv6_prefix}",
                strict=False,
            )
            return str(network.network_address)
        except ValueError:
            return ipv6

    @property
    def full_url(self) -> str:
        """Get full URL with scheme, host, and port."""
        if self.url:
            return self.url

        # Build URL from components
        url = f"{self.scheme}://{self.hostname}"

        # Only add port if non-standard
        if (self.scheme == "https" and self.port != 443) or \
           (self.scheme == "http" and self.port != 80):
            url += f":{self.port}"

        return url

    @property
    def has_waf(self) -> bool:
        """Check if host appears to be behind a WAF."""
        return self.cdn_detected or self.cdn_provider != CDNProvider.NONE

    def add_technology(self, tech: str) -> None:
        """Add a detected technology."""
        if tech and tech not in self.technologies:
            self.technologies.append(tech)

    def add_open_port(self, port: int) -> None:
        """Add an open port."""
        if port not in self.open_ports:
            self.open_ports.append(port)
            self.open_ports.sort()

    def set_cdn(self, provider: str) -> None:
        """Set CDN provider."""
        self.cdn_detected = True
        try:
            self.cdn_provider = CDNProvider(provider.lower())
        except ValueError:
            self.cdn_provider = CDNProvider.UNKNOWN

    def mark_alive(
        self,
        status_code: int,
        title: Optional[str] = None,
    ) -> None:
        """Mark host as alive with HTTP response info."""
        self.is_alive = True
        self.status = HostStatus.ALIVE
        self.status_code = status_code
        self.title = title
        self.last_checked = datetime.now()

    def mark_dead(self, reason: str = "timeout") -> None:
        """Mark host as dead."""
        self.is_alive = False
        if reason == "timeout":
            self.status = HostStatus.TIMEOUT
        elif reason == "filtered":
            self.status = HostStatus.FILTERED
        else:
            self.status = HostStatus.DEAD
        self.last_checked = datetime.now()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return self.model_dump(mode="json")

    @classmethod
    def from_httpx_result(cls, data: dict[str, Any]) -> "Host":
        """
        Create Host from httpx JSON output.

        Args:
            data: httpx JSON result

        Returns:
            Host instance
        """
        # Parse URL components
        url = data.get("url", "")
        scheme = data.get("scheme", "https")

        # Port can be string or int in httpx output
        port_val = data.get("port", 443 if scheme == "https" else 80)
        port = int(port_val) if port_val else (443 if scheme == "https" else 80)

        # Parse hostname - 'input' is the original hostname, 'host' is the resolved IP
        hostname = data.get("input", "")
        if not hostname:
            # Fall back to extracting from URL if no input
            if url:
                import re
                match = re.match(r"https?://([^/:]+)", url)
                if match:
                    hostname = match.group(1)
            if not hostname:
                hostname = data.get("host", "")

        # Parse response time - can be string like "387.203299ms" or float
        response_time = None
        time_val = data.get("time")
        if time_val:
            if isinstance(time_val, str):
                # Parse time string like "387.203299ms" or "1.088063419s"
                import re
                match = re.match(r"([\d.]+)(ms|s|ns|µs)?", time_val)
                if match:
                    val = float(match.group(1))
                    unit = match.group(2) or "s"
                    if unit == "ms":
                        response_time = val / 1000
                    elif unit == "ns":
                        response_time = val / 1_000_000_000
                    elif unit == "µs":
                        response_time = val / 1_000_000
                    else:
                        response_time = val
            else:
                response_time = float(time_val)

        host = cls(
            hostname=hostname,
            url=url,
            scheme=scheme,
            port=port,
            status_code=data.get("status_code") or data.get("status-code"),
            title=data.get("title"),
            content_length=data.get("content_length") or data.get("content-length"),
            content_type=data.get("content_type") or data.get("content-type"),
            server=data.get("webserver"),
            response_time=response_time,
        )

        # Set IPs - 'host' field contains the resolved IP
        resolved_ip = data.get("host", "")
        if resolved_ip and resolved_ip != hostname:
            # Check if it's IPv4 or IPv6
            try:
                addr = ipaddress.ip_address(resolved_ip)
                if isinstance(addr, ipaddress.IPv4Address):
                    host.ipv4_addresses = [resolved_ip]
                else:
                    host.ipv6_addresses = [resolved_ip]
            except ValueError:
                pass

        # Additional IPs from 'a' and 'aaaa' fields
        if "a" in data:
            ips = data["a"] if isinstance(data["a"], list) else [data["a"]]
            for ip in ips:
                if ip and ip not in host.ipv4_addresses:
                    host.ipv4_addresses.append(ip)
        if "aaaa" in data:
            ips = data["aaaa"] if isinstance(data["aaaa"], list) else [data["aaaa"]]
            for ip in ips:
                if ip and ip not in host.ipv6_addresses:
                    host.ipv6_addresses.append(ip)

        # Technologies
        if "tech" in data:
            host.technologies = data["tech"] if isinstance(data["tech"], list) else [data["tech"]]

        # CDN
        if "cdn" in data and data["cdn"]:
            host.cdn_detected = True
            if "cdn_name" in data:
                host.set_cdn(data["cdn_name"])

        # Mark as alive if we got a response
        if host.status_code:
            host.mark_alive(host.status_code, host.title)

        return host
