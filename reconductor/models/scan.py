"""Scan state and result models."""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class ScanPhase(int, Enum):
    """Scan phases."""
    INIT = 0
    ENUMERATION = 1
    VALIDATION = 2
    SCANNING = 3
    ANALYSIS = 4
    COMPLETE = 5


class ScanStatus(str, Enum):
    """Scan status values."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanStats(BaseModel):
    """Scan statistics."""

    # Counts
    subdomains_discovered: int = 0
    subdomains_alive: int = 0
    hosts_validated: int = 0
    hosts_alive: int = 0
    findings_total: int = 0
    findings_critical: int = 0
    findings_high: int = 0
    findings_medium: int = 0
    findings_low: int = 0
    findings_info: int = 0

    # Takeovers
    takeover_candidates: int = 0

    # Timing
    phase_durations: dict[str, float] = Field(default_factory=dict)

    def add_finding(self, severity: str) -> None:
        """Increment finding count by severity."""
        self.findings_total += 1
        severity = severity.lower()
        if severity == "critical":
            self.findings_critical += 1
        elif severity == "high":
            self.findings_high += 1
        elif severity == "medium":
            self.findings_medium += 1
        elif severity == "low":
            self.findings_low += 1
        else:
            self.findings_info += 1

    def record_phase_duration(self, phase: str, duration: float) -> None:
        """Record phase duration in seconds."""
        self.phase_durations[phase] = duration


class Scan(BaseModel):
    """
    Main scan model representing a complete reconnaissance scan.
    """

    # Identification
    scan_id: str = Field(default_factory=lambda: str(uuid4())[:8])
    domain: str = Field(..., description="Target domain")

    # Status
    phase: ScanPhase = ScanPhase.INIT
    status: ScanStatus = ScanStatus.PENDING

    # Timing
    started_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    # Configuration
    config: dict[str, Any] = Field(default_factory=dict)

    # Results
    subdomains: list[str] = Field(default_factory=list)
    hosts: list[dict[str, Any]] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)

    # GAU historical URL mining results
    gau_result: Optional[Any] = Field(default=None, description="GauResult from historical URL mining")

    # Non-HTTP subdomains (resolved via DNS but no HTTP response - may have other services)
    non_http_subdomains: list[str] = Field(default_factory=list)
    non_http_subdomains_ports: dict[str, list[int]] = Field(default_factory=dict)  # hostname -> open ports

    # Statistics
    stats: ScanStats = Field(default_factory=ScanStats)

    # Error handling
    error_message: Optional[str] = None
    errors: list[str] = Field(default_factory=list)

    # Checkpoint data
    checkpoint_data: dict[str, Any] = Field(default_factory=dict)

    # Extra data (origin scan results, etc.)
    extra: dict[str, Any] = Field(default_factory=dict)

    @property
    def duration(self) -> Optional[timedelta]:
        """Get scan duration."""
        if not self.started_at:
            return None
        end = self.completed_at or datetime.now()
        return end - self.started_at

    @property
    def duration_seconds(self) -> float:
        """Get scan duration in seconds."""
        if duration := self.duration:
            return duration.total_seconds()
        return 0.0

    @property
    def is_complete(self) -> bool:
        """Check if scan is complete."""
        return self.status == ScanStatus.COMPLETED

    @property
    def is_failed(self) -> bool:
        """Check if scan failed."""
        return self.status == ScanStatus.FAILED

    @property
    def is_running(self) -> bool:
        """Check if scan is currently running."""
        return self.status == ScanStatus.IN_PROGRESS

    @property
    def can_resume(self) -> bool:
        """Check if scan can be resumed."""
        return self.status in [ScanStatus.PAUSED, ScanStatus.FAILED]

    def start(self) -> None:
        """Mark scan as started."""
        self.status = ScanStatus.IN_PROGRESS
        self.started_at = datetime.now()
        self.updated_at = datetime.now()

    def update_phase(self, phase: ScanPhase) -> None:
        """Update current phase."""
        self.phase = phase
        self.updated_at = datetime.now()

    def complete(self) -> None:
        """Mark scan as completed."""
        self.status = ScanStatus.COMPLETED
        self.phase = ScanPhase.COMPLETE
        self.completed_at = datetime.now()
        self.updated_at = datetime.now()

    def fail(self, error: str) -> None:
        """Mark scan as failed."""
        self.status = ScanStatus.FAILED
        self.error_message = error
        self.errors.append(error)
        self.updated_at = datetime.now()

    def pause(self) -> None:
        """Pause the scan."""
        self.status = ScanStatus.PAUSED
        self.updated_at = datetime.now()

    def add_error(self, error: str) -> None:
        """Add a non-fatal error."""
        self.errors.append(error)
        self.updated_at = datetime.now()

    def add_subdomain(self, subdomain: str) -> None:
        """Add a discovered subdomain."""
        if subdomain not in self.subdomains:
            self.subdomains.append(subdomain)
            self.stats.subdomains_discovered += 1

    def add_subdomains(self, subdomains: list[str]) -> int:
        """Add multiple subdomains, returns count of new ones."""
        existing = set(self.subdomains)
        new_subs = [s for s in subdomains if s not in existing]
        self.subdomains.extend(new_subs)
        self.stats.subdomains_discovered += len(new_subs)
        return len(new_subs)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return self.model_dump(mode="json")


class ScanResult(BaseModel):
    """
    Final scan result for reporting.
    """

    scan_id: str
    domain: str
    timestamp: datetime = Field(default_factory=datetime.now)
    duration_seconds: float = 0.0

    # Results
    subdomains: list[str] = Field(default_factory=list)
    hosts: list[dict[str, Any]] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)

    # Statistics
    stats: ScanStats = Field(default_factory=ScanStats)

    # Configuration used
    config: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_scan(cls, scan: Scan) -> "ScanResult":
        """Create ScanResult from completed Scan."""
        return cls(
            scan_id=scan.scan_id,
            domain=scan.domain,
            timestamp=scan.completed_at or datetime.now(),
            duration_seconds=scan.duration_seconds,
            subdomains=scan.subdomains,
            hosts=scan.hosts,
            findings=scan.findings,
            stats=scan.stats,
            config=scan.config,
        )


class DiffReport(BaseModel):
    """
    Delta report between two scans.
    """

    # New discoveries
    new_subdomains: list[str] = Field(default_factory=list)
    removed_subdomains: list[str] = Field(default_factory=list)

    # Findings
    new_findings: list[dict[str, Any]] = Field(default_factory=list)
    resolved_findings: list[dict[str, Any]] = Field(default_factory=list)

    # Comparison metadata
    previous_scan_id: Optional[str] = None
    current_scan_id: Optional[str] = None
    previous_date: Optional[datetime] = None
    current_date: Optional[datetime] = None

    # Deltas
    subdomain_delta: int = 0
    finding_delta: int = 0

    def calculate_deltas(self) -> None:
        """Calculate delta values."""
        self.subdomain_delta = len(self.new_subdomains) - len(self.removed_subdomains)
        self.finding_delta = len(self.new_findings) - len(self.resolved_findings)

    @property
    def has_changes(self) -> bool:
        """Check if there are any changes."""
        return bool(
            self.new_subdomains or
            self.removed_subdomains or
            self.new_findings or
            self.resolved_findings
        )
