"""Checkpoint manager for scan state persistence and resume capability."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field

from reconductor.core.database import Database
from reconductor.core.logger import get_logger

logger = get_logger(__name__)


class ScanState(BaseModel):
    """Scan state model."""
    scan_id: str
    domain: str
    phase: int = 0
    status: str = "pending"
    started_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    checkpoint_data: dict[str, Any] = Field(default_factory=dict)
    error_message: Optional[str] = None


class SubdomainState(BaseModel):
    """Subdomain state model."""
    subdomain: str
    scan_id: str
    phase: int = 0
    status: str = "pending"
    source: Optional[str] = None
    retry_count: int = 0
    last_error: Optional[str] = None
    data: dict[str, Any] = Field(default_factory=dict)


class CheckpointManager:
    """
    Manages scan state persistence for crash recovery.

    Provides checkpoint/resume capability for long-running scans,
    ensuring no data loss on interruption.
    """

    def __init__(self, db: Database):
        """
        Initialize checkpoint manager.

        Args:
            db: Database instance for persistence
        """
        self.db = db

    async def create_scan(
        self,
        scan_id: str,
        domain: str,
        config: Optional[dict[str, Any]] = None,
    ) -> ScanState:
        """
        Create a new scan with initial state.

        Args:
            scan_id: Unique scan identifier
            domain: Target domain
            config: Scan configuration

        Returns:
            The created ScanState
        """
        await self.db.create_scan(scan_id, domain, config)

        state = ScanState(
            scan_id=scan_id,
            domain=domain,
            phase=0,
            status="in_progress",
            started_at=datetime.now(),
            updated_at=datetime.now(),
        )

        logger.info(
            "Scan checkpoint created",
            scan_id=scan_id,
            domain=domain,
        )

        return state

    async def get_resume_point(self, domain: str) -> Optional[ScanState]:
        """
        Find the last checkpoint for a domain to resume from.

        Args:
            domain: Target domain to find checkpoint for

        Returns:
            ScanState if resumable checkpoint found, None otherwise
        """
        scans = await self.db.get_incomplete_scans(domain)

        if not scans:
            return None

        # Get the most recent incomplete scan
        scan = scans[0]

        # Get the latest checkpoint data
        checkpoint = await self.db.fetch_one(
            """
            SELECT * FROM checkpoints
            WHERE scan_id = ?
            ORDER BY created_at DESC LIMIT 1
            """,
            (scan["scan_id"],),
        )

        checkpoint_data = {}
        if checkpoint:
            checkpoint_data = json.loads(checkpoint["checkpoint_data"] or "{}")

        state = ScanState(
            scan_id=scan["scan_id"],
            domain=scan["domain"],
            phase=scan["phase"],
            status=scan["status"],
            started_at=datetime.fromisoformat(scan["started_at"]) if scan["started_at"] else None,
            updated_at=datetime.fromisoformat(scan["updated_at"]) if scan["updated_at"] else None,
            checkpoint_data=checkpoint_data,
            error_message=scan.get("error_message"),
        )

        logger.info(
            "Found resumable scan",
            scan_id=state.scan_id,
            domain=domain,
            phase=state.phase,
            status=state.status,
        )

        return state

    async def create_checkpoint(
        self,
        scan_id: str,
        phase: int,
        data: dict[str, Any],
    ) -> None:
        """
        Save a scan checkpoint for resume capability.

        Args:
            scan_id: Scan identifier
            phase: Current phase number
            data: Checkpoint data to save
        """
        now = datetime.now().isoformat()

        await self.db.execute(
            """
            INSERT INTO checkpoints (scan_id, phase, checkpoint_data, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (scan_id, phase, json.dumps(data), now),
        )
        await self.db.commit()

        # Also update the scan status
        await self.db.update_scan_status(scan_id, "in_progress", phase=phase)

        logger.debug(
            "Checkpoint created",
            scan_id=scan_id,
            phase=phase,
            data_keys=list(data.keys()),
        )

    async def update_phase(
        self,
        scan_id: str,
        phase: int,
        status: str = "in_progress",
    ) -> None:
        """
        Update the current phase of a scan.

        Args:
            scan_id: Scan identifier
            phase: New phase number
            status: New status (default: in_progress)
        """
        await self.db.update_scan_status(scan_id, status, phase=phase)
        logger.info("Phase updated", scan_id=scan_id, phase=phase, status=status)

    async def mark_completed(self, scan_id: str) -> None:
        """
        Mark a scan as completed.

        Args:
            scan_id: Scan identifier
        """
        await self.db.update_scan_status(scan_id, "completed")
        logger.info("Scan marked completed", scan_id=scan_id)

    async def mark_failed(self, scan_id: str, error: str) -> None:
        """
        Mark a scan as failed.

        Args:
            scan_id: Scan identifier
            error: Error message
        """
        await self.db.update_scan_status(scan_id, "failed", error=error)
        logger.error("Scan marked failed", scan_id=scan_id, error=error)

    async def add_subdomains(
        self,
        scan_id: str,
        subdomains: list[tuple[str, str]],  # (subdomain, source)
    ) -> int:
        """
        Add discovered subdomains to the checkpoint.

        Args:
            scan_id: Scan identifier
            subdomains: List of (subdomain, source) tuples

        Returns:
            Number of subdomains added
        """
        count = await self.db.add_subdomains(scan_id, subdomains)
        logger.debug(
            "Subdomains checkpointed",
            scan_id=scan_id,
            count=count,
        )
        return count

    async def update_subdomain_status(
        self,
        subdomain: str,
        scan_id: str,
        phase: int,
        status: str,
        data: Optional[dict[str, Any]] = None,
        error: Optional[str] = None,
    ) -> None:
        """
        Update the processing status of a subdomain.

        Args:
            subdomain: The subdomain being processed
            scan_id: Scan identifier
            phase: Current phase
            status: New status (pending, discovered, validated, scanned, failed)
            data: Optional data to store
            error: Optional error message
        """
        await self.db.update_subdomain_status(
            subdomain=subdomain,
            scan_id=scan_id,
            status=status,
            phase=phase,
            data=data,
            error=error,
        )

    async def get_pending_subdomains(
        self,
        scan_id: str,
        phase: int,
    ) -> list[str]:
        """
        Get subdomains pending processing for a specific phase.

        Args:
            scan_id: Scan identifier
            phase: Phase number

        Returns:
            List of pending subdomain names
        """
        rows = await self.db.fetch_all(
            """
            SELECT subdomain FROM subdomains
            WHERE scan_id = ? AND phase < ? AND status != 'failed'
            """,
            (scan_id, phase),
        )
        return [row["subdomain"] for row in rows]

    async def get_completed_count(self, scan_id: str, phase: int) -> int:
        """
        Get count of subdomains completed for a phase.

        Args:
            scan_id: Scan identifier
            phase: Phase number

        Returns:
            Count of completed subdomains
        """
        row = await self.db.fetch_one(
            """
            SELECT COUNT(*) as count FROM subdomains
            WHERE scan_id = ? AND phase >= ?
            """,
            (scan_id, phase),
        )
        return row["count"] if row else 0

    async def list_incomplete_scans(self) -> list[ScanState]:
        """
        List all incomplete scans across all domains.

        Returns:
            List of incomplete ScanState objects
        """
        scans = await self.db.get_incomplete_scans()

        states = []
        for scan in scans:
            state = ScanState(
                scan_id=scan["scan_id"],
                domain=scan["domain"],
                phase=scan["phase"],
                status=scan["status"],
                started_at=datetime.fromisoformat(scan["started_at"]) if scan["started_at"] else None,
                updated_at=datetime.fromisoformat(scan["updated_at"]) if scan["updated_at"] else None,
                error_message=scan.get("error_message"),
            )
            states.append(state)

        return states

    async def cleanup_old_checkpoints(
        self,
        scan_id: str,
        keep_last: int = 5,
    ) -> None:
        """
        Clean up old checkpoints to save space.

        Args:
            scan_id: Scan identifier
            keep_last: Number of recent checkpoints to keep
        """
        await self.db.execute(
            """
            DELETE FROM checkpoints
            WHERE scan_id = ?
            AND id NOT IN (
                SELECT id FROM checkpoints
                WHERE scan_id = ?
                ORDER BY created_at DESC
                LIMIT ?
            )
            """,
            (scan_id, scan_id, keep_last),
        )
        await self.db.commit()
