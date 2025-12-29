"""Subdomain data model."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class SubdomainSource(str, Enum):
    """Sources for subdomain discovery."""
    SUBFINDER = "subfinder"
    SHODAN = "shodan"
    CENSYS = "censys"
    CRTSH = "crtsh"
    SECURITYTRAILS = "securitytrails"
    VIRUSTOTAL = "virustotal"
    HACKERTARGET = "hackertarget"
    THREATCROWD = "threatcrowd"
    DNSDUMPSTER = "dnsdumpster"
    WAYBACK = "wayback"
    PUREDNS = "puredns"
    ALTERX = "alterx"
    SUBWIZ = "subwiz"
    LLM = "llm"
    MANUAL = "manual"
    UNKNOWN = "unknown"


class SubdomainStatus(str, Enum):
    """Subdomain processing status."""
    PENDING = "pending"
    DISCOVERED = "discovered"
    VALIDATED = "validated"
    ALIVE = "alive"
    DEAD = "dead"
    SCANNED = "scanned"
    FAILED = "failed"


class Subdomain(BaseModel):
    """Subdomain data model."""

    # Core fields
    name: str = Field(..., description="Full subdomain name (e.g., api.example.com)")
    domain: str = Field(..., description="Base domain (e.g., example.com)")
    source: SubdomainSource = Field(default=SubdomainSource.UNKNOWN)
    status: SubdomainStatus = Field(default=SubdomainStatus.PENDING)

    # DNS information
    cname_chain: list[str] = Field(default_factory=list, description="CNAME resolution chain")
    a_records: list[str] = Field(default_factory=list, description="A record IP addresses")
    aaaa_records: list[str] = Field(default_factory=list, description="AAAA record IPv6 addresses")
    mx_records: list[str] = Field(default_factory=list)
    txt_records: list[str] = Field(default_factory=list)
    ns_records: list[str] = Field(default_factory=list)

    # Metadata
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    is_wildcard: bool = False
    is_new: bool = False  # First seen within threshold days
    age_days: Optional[int] = None

    # Takeover potential
    takeover_candidate: bool = False
    takeover_service: Optional[str] = None
    takeover_confidence: float = 0.0

    # Additional data
    tags: list[str] = Field(default_factory=list)
    notes: Optional[str] = None
    extra: dict[str, Any] = Field(default_factory=dict)

    @property
    def prefix(self) -> str:
        """Get the subdomain prefix (without base domain)."""
        if self.name == self.domain:
            return ""
        suffix = f".{self.domain}"
        if self.name.endswith(suffix):
            return self.name[: -len(suffix)]
        return self.name

    @property
    def depth(self) -> int:
        """Get the subdomain depth (number of levels)."""
        if not self.prefix:
            return 0
        return self.prefix.count(".") + 1

    @property
    def primary_ip(self) -> Optional[str]:
        """Get the primary IP address (prefer IPv4)."""
        if self.a_records:
            return self.a_records[0]
        if self.aaaa_records:
            return self.aaaa_records[0]
        return None

    @property
    def has_cname(self) -> bool:
        """Check if subdomain has CNAME records."""
        return len(self.cname_chain) > 0

    @property
    def final_cname(self) -> Optional[str]:
        """Get the final target in CNAME chain."""
        if self.cname_chain:
            return self.cname_chain[-1]
        return None

    def mark_as_takeover_candidate(
        self,
        service: str,
        confidence: float = 0.5,
    ) -> None:
        """Mark this subdomain as a potential takeover candidate."""
        self.takeover_candidate = True
        self.takeover_service = service
        self.takeover_confidence = confidence

    def add_tag(self, tag: str) -> None:
        """Add a tag to this subdomain."""
        if tag not in self.tags:
            self.tags.append(tag)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return self.model_dump(mode="json")

    @classmethod
    def from_name(
        cls,
        name: str,
        source: SubdomainSource = SubdomainSource.UNKNOWN,
    ) -> "Subdomain":
        """
        Create a Subdomain from just a name.

        Automatically extracts the base domain.

        Args:
            name: Full subdomain name
            source: Discovery source

        Returns:
            Subdomain instance
        """
        # Simple domain extraction (assumes last 2 parts are base domain)
        parts = name.lower().strip().split(".")
        if len(parts) >= 2:
            domain = ".".join(parts[-2:])
        else:
            domain = name

        return cls(
            name=name.lower().strip(),
            domain=domain,
            source=source,
        )
