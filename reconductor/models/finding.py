"""Vulnerability finding data model."""

from __future__ import annotations

import hashlib
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, computed_field


class Severity(str, Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class FindingType(str, Enum):
    """Types of findings."""
    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"
    EXPOSURE = "exposure"
    TAKEOVER = "takeover"
    INFORMATION = "information"
    DEFAULT_CREDENTIALS = "default_credentials"
    CVE = "cve"
    TECHNOLOGY = "technology"


class Finding(BaseModel):
    """
    Vulnerability or security finding model.

    Represents a discovered security issue with full context
    for reporting and remediation.
    """

    # Core fields
    finding_type: FindingType = Field(default=FindingType.VULNERABILITY)
    severity: Severity = Field(default=Severity.UNKNOWN)
    target: str = Field(..., description="Target URL or host")

    # Nuclei-specific fields
    template_id: Optional[str] = None
    template_name: Optional[str] = None
    template_path: Optional[str] = None

    # Description
    title: str = Field(..., description="Finding title")
    description: Optional[str] = None
    remediation: Optional[str] = None

    # Evidence
    evidence: Optional[str] = None
    matched_at: Optional[str] = None
    extracted_results: list[str] = Field(default_factory=list)

    # Request/Response
    request: Optional[str] = None
    response: Optional[str] = None
    curl_command: Optional[str] = None

    # CVE information
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_metrics: Optional[str] = None

    # References
    references: list[str] = Field(default_factory=list)

    # Classification
    tags: list[str] = Field(default_factory=list)
    classification: dict[str, Any] = Field(default_factory=dict)

    # Metadata
    scanner: str = "nuclei"
    discovered_at: datetime = Field(default_factory=datetime.now)
    verified: bool = False

    # Additional data
    extra: dict[str, Any] = Field(default_factory=dict)

    @computed_field
    @property
    def fingerprint(self) -> str:
        """
        Generate unique fingerprint for deduplication.

        Combines template, target, and matched location.
        """
        components = [
            self.template_id or "",
            self.target,
            self.matched_at or "",
        ]
        content = "|".join(components)
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    @property
    def severity_score(self) -> int:
        """Get numeric severity score for sorting."""
        scores = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
            Severity.UNKNOWN: 0,
        }
        return scores.get(self.severity, 0)

    @property
    def is_critical_or_high(self) -> bool:
        """Check if finding is critical or high severity."""
        return self.severity in [Severity.CRITICAL, Severity.HIGH]

    def add_reference(self, url: str) -> None:
        """Add a reference URL."""
        if url and url not in self.references:
            self.references.append(url)

    def add_tag(self, tag: str) -> None:
        """Add a tag."""
        if tag and tag not in self.tags:
            self.tags.append(tag)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        """
        Create Finding from dictionary.

        Args:
            data: Dictionary with finding data

        Returns:
            Finding instance
        """
        # Handle severity enum
        if "severity" in data and isinstance(data["severity"], str):
            data["severity"] = Severity(data["severity"].lower())

        # Handle finding_type enum
        if "finding_type" in data and isinstance(data["finding_type"], str):
            data["finding_type"] = FindingType(data["finding_type"])

        # Handle datetime
        if "discovered_at" in data and isinstance(data["discovered_at"], str):
            from datetime import datetime
            try:
                data["discovered_at"] = datetime.fromisoformat(data["discovered_at"].replace("Z", "+00:00"))
            except Exception:
                data["discovered_at"] = datetime.now()

        return cls.model_validate(data)

    def to_markdown(self) -> str:
        """Format finding as Markdown for reports."""
        md = []
        md.append(f"## [{self.severity.value.upper()}] {self.title}")
        md.append("")
        md.append(f"**Target:** `{self.target}`")

        if self.template_id:
            md.append(f"**Template:** `{self.template_id}`")

        if self.cve_id:
            md.append(f"**CVE:** {self.cve_id}")

        if self.cvss_score:
            md.append(f"**CVSS:** {self.cvss_score}")

        md.append("")

        if self.description:
            md.append("### Description")
            md.append(self.description)
            md.append("")

        if self.evidence:
            md.append("### Evidence")
            md.append(f"```\n{self.evidence}\n```")
            md.append("")

        if self.remediation:
            md.append("### Remediation")
            md.append(self.remediation)
            md.append("")

        if self.references:
            md.append("### References")
            for ref in self.references:
                md.append(f"- {ref}")
            md.append("")

        if self.curl_command:
            md.append("### Reproduction")
            md.append(f"```bash\n{self.curl_command}\n```")
            md.append("")

        return "\n".join(md)

    @classmethod
    def from_nuclei_result(cls, data: dict[str, Any]) -> "Finding":
        """
        Create Finding from Nuclei JSON output.

        Args:
            data: Nuclei JSON result

        Returns:
            Finding instance
        """
        # Map severity
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        severity = severity_map.get(
            data.get("info", {}).get("severity", "").lower(),
            Severity.UNKNOWN,
        )

        # Extract template info
        info = data.get("info", {})
        template_id = data.get("template-id", data.get("templateID"))
        template_name = info.get("name", template_id)

        # Build finding
        finding = cls(
            finding_type=FindingType.VULNERABILITY,
            severity=severity,
            target=data.get("host", data.get("matched-at", "")),
            template_id=template_id,
            template_name=template_name,
            template_path=data.get("template-path"),
            title=template_name or "Unknown Finding",
            description=info.get("description"),
            remediation=info.get("remediation"),
            matched_at=data.get("matched-at"),
            curl_command=data.get("curl-command"),
            scanner="nuclei",
        )

        # Add extracted results
        if "extracted-results" in data:
            finding.extracted_results = data["extracted-results"]

        # Add references
        if "reference" in info:
            refs = info["reference"]
            if isinstance(refs, list):
                finding.references = refs
            elif isinstance(refs, str):
                finding.references = [refs]

        # Add tags
        if "tags" in info:
            tags = info["tags"]
            if isinstance(tags, list):
                finding.tags = tags
            elif isinstance(tags, str):
                finding.tags = tags.split(",")

        # Add classification
        if "classification" in info:
            finding.classification = info["classification"]
            # Extract CVE if present
            if "cve-id" in info["classification"]:
                cve_ids = info["classification"]["cve-id"]
                if isinstance(cve_ids, list) and cve_ids:
                    finding.cve_id = cve_ids[0]
                elif isinstance(cve_ids, str):
                    finding.cve_id = cve_ids

            # Extract CVSS
            if "cvss-score" in info["classification"]:
                finding.cvss_score = float(info["classification"]["cvss-score"])
            if "cvss-metrics" in info["classification"]:
                finding.cvss_metrics = info["classification"]["cvss-metrics"]

        # Store full data in extra
        finding.extra = data

        return finding


class TakeoverFinding(Finding):
    """Specialized finding for subdomain takeovers."""

    subdomain: str = ""
    cname_chain: list[str] = Field(default_factory=list)
    vulnerable_service: str = ""
    takeover_documentation: Optional[str] = None
    confidence: float = 0.0

    def __init__(self, **data: Any):
        """Initialize takeover finding with defaults."""
        data.setdefault("finding_type", FindingType.TAKEOVER)
        data.setdefault("severity", Severity.HIGH)
        data.setdefault("scanner", "reconductor")
        super().__init__(**data)
