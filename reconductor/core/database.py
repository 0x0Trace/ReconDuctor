"""SQLite database management for scan state persistence."""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, AsyncGenerator, Optional

import aiosqlite

from reconductor.core.logger import get_logger

logger = get_logger(__name__)


SCHEMA_SQL = """
-- Scan state table
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    phase INTEGER DEFAULT 0,
    status TEXT DEFAULT 'pending',
    started_at TEXT,
    updated_at TEXT,
    completed_at TEXT,
    config_json TEXT,
    error_message TEXT
);

-- Subdomain state table
CREATE TABLE IF NOT EXISTS subdomains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subdomain TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    phase INTEGER DEFAULT 0,
    status TEXT DEFAULT 'pending',
    source TEXT,
    retry_count INTEGER DEFAULT 0,
    last_error TEXT,
    data_json TEXT,
    created_at TEXT,
    updated_at TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id),
    UNIQUE(subdomain, scan_id)
);

-- Host state table
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    url TEXT,
    scheme TEXT DEFAULT 'https',
    port INTEGER DEFAULT 443,
    ipv4_addresses TEXT,
    ipv6_addresses TEXT,
    technologies TEXT,
    cdn_provider TEXT,
    is_alive BOOLEAN DEFAULT 0,
    status_code INTEGER,
    title TEXT,
    data_json TEXT,
    created_at TEXT,
    updated_at TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id),
    UNIQUE(hostname, scan_id)
);

-- Findings table
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    finding_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    target TEXT NOT NULL,
    template_id TEXT,
    title TEXT,
    description TEXT,
    evidence TEXT,
    data_json TEXT,
    created_at TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
);

-- Checkpoints table for resume capability
CREATE TABLE IF NOT EXISTS checkpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    phase INTEGER NOT NULL,
    checkpoint_data TEXT,
    created_at TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
);

-- Resolver health table
CREATE TABLE IF NOT EXISTS resolver_health (
    resolver TEXT PRIMARY KEY,
    is_healthy BOOLEAN DEFAULT 1,
    last_check TEXT,
    success_count INTEGER DEFAULT 0,
    failure_count INTEGER DEFAULT 0
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_subdomains_scan_id ON subdomains(scan_id);
CREATE INDEX IF NOT EXISTS idx_subdomains_status ON subdomains(status);
CREATE INDEX IF NOT EXISTS idx_hosts_scan_id ON hosts(scan_id);
CREATE INDEX IF NOT EXISTS idx_hosts_is_alive ON hosts(is_alive);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_checkpoints_scan_id ON checkpoints(scan_id);
"""


class Database:
    """Async SQLite database manager."""

    def __init__(self, db_path: Path):
        """
        Initialize database manager.

        Args:
            db_path: Path to the SQLite database file
        """
        self.db_path = db_path
        self._connection: Optional[aiosqlite.Connection] = None

    async def connect(self) -> None:
        """Connect to the database and initialize schema."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = await aiosqlite.connect(self.db_path)
        self._connection.row_factory = aiosqlite.Row
        await self._connection.executescript(SCHEMA_SQL)
        await self._connection.commit()
        logger.info("Database connected", path=str(self.db_path))

    async def close(self) -> None:
        """Close the database connection."""
        if self._connection:
            await self._connection.close()
            self._connection = None
            logger.info("Database connection closed")

    @asynccontextmanager
    async def transaction(self) -> AsyncGenerator[aiosqlite.Connection, None]:
        """Context manager for database transactions."""
        if not self._connection:
            raise RuntimeError("Database not connected")
        try:
            yield self._connection
            await self._connection.commit()
        except Exception:
            await self._connection.rollback()
            raise

    async def execute(
        self,
        sql: str,
        params: tuple[Any, ...] | dict[str, Any] = (),
    ) -> aiosqlite.Cursor:
        """Execute a SQL statement."""
        if not self._connection:
            raise RuntimeError("Database not connected")
        return await self._connection.execute(sql, params)

    async def executemany(
        self,
        sql: str,
        params_list: list[tuple[Any, ...]],
    ) -> aiosqlite.Cursor:
        """Execute a SQL statement with multiple parameter sets."""
        if not self._connection:
            raise RuntimeError("Database not connected")
        return await self._connection.executemany(sql, params_list)

    async def fetch_one(
        self,
        sql: str,
        params: tuple[Any, ...] | dict[str, Any] = (),
    ) -> Optional[aiosqlite.Row]:
        """Fetch a single row."""
        cursor = await self.execute(sql, params)
        return await cursor.fetchone()

    async def fetch_all(
        self,
        sql: str,
        params: tuple[Any, ...] | dict[str, Any] = (),
    ) -> list[aiosqlite.Row]:
        """Fetch all rows."""
        cursor = await self.execute(sql, params)
        return await cursor.fetchall()

    async def commit(self) -> None:
        """Commit current transaction."""
        if self._connection:
            await self._connection.commit()

    # Scan operations
    async def create_scan(
        self,
        scan_id: str,
        domain: str,
        config: Optional[dict[str, Any]] = None,
    ) -> None:
        """Create a new scan record."""
        now = datetime.now().isoformat()
        await self.execute(
            """
            INSERT INTO scans (scan_id, domain, status, started_at, updated_at, config_json)
            VALUES (?, ?, 'in_progress', ?, ?, ?)
            """,
            (scan_id, domain, now, now, json.dumps(config or {})),
        )
        await self.commit()
        logger.info("Scan created", scan_id=scan_id, domain=domain)

    async def update_scan_status(
        self,
        scan_id: str,
        status: str,
        phase: Optional[int] = None,
        error: Optional[str] = None,
    ) -> None:
        """Update scan status."""
        now = datetime.now().isoformat()
        sql_parts = ["UPDATE scans SET status = ?, updated_at = ?"]
        params: list[Any] = [status, now]

        if phase is not None:
            sql_parts.append(", phase = ?")
            params.append(phase)

        if error:
            sql_parts.append(", error_message = ?")
            params.append(error)

        if status == "completed":
            sql_parts.append(", completed_at = ?")
            params.append(now)

        sql_parts.append(" WHERE scan_id = ?")
        params.append(scan_id)

        await self.execute("".join(sql_parts), tuple(params))
        await self.commit()

    async def get_scan(self, scan_id: str) -> Optional[dict[str, Any]]:
        """Get scan by ID."""
        row = await self.fetch_one(
            "SELECT * FROM scans WHERE scan_id = ?",
            (scan_id,),
        )
        return dict(row) if row else None

    async def get_incomplete_scans(self, domain: Optional[str] = None) -> list[dict[str, Any]]:
        """Get all incomplete scans, optionally filtered by domain."""
        if domain:
            rows = await self.fetch_all(
                """
                SELECT * FROM scans
                WHERE domain = ? AND status NOT IN ('completed', 'failed')
                ORDER BY updated_at DESC
                """,
                (domain,),
            )
        else:
            rows = await self.fetch_all(
                """
                SELECT * FROM scans
                WHERE status NOT IN ('completed', 'failed')
                ORDER BY updated_at DESC
                """,
            )
        return [dict(row) for row in rows]

    # Subdomain operations
    async def add_subdomains(
        self,
        scan_id: str,
        subdomains: list[tuple[str, str]],  # (subdomain, source)
    ) -> int:
        """Add multiple subdomains in batch."""
        now = datetime.now().isoformat()
        await self.executemany(
            """
            INSERT OR IGNORE INTO subdomains
            (subdomain, scan_id, source, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            [(sub, scan_id, source, now, now) for sub, source in subdomains],
        )
        await self.commit()
        return len(subdomains)

    async def update_subdomain_status(
        self,
        subdomain: str,
        scan_id: str,
        status: str,
        phase: Optional[int] = None,
        data: Optional[dict[str, Any]] = None,
        error: Optional[str] = None,
    ) -> None:
        """Update subdomain status."""
        now = datetime.now().isoformat()
        sql_parts = ["UPDATE subdomains SET status = ?, updated_at = ?"]
        params: list[Any] = [status, now]

        if phase is not None:
            sql_parts.append(", phase = ?")
            params.append(phase)

        if data:
            sql_parts.append(", data_json = ?")
            params.append(json.dumps(data))

        if error:
            sql_parts.append(", last_error = ?, retry_count = retry_count + 1")
            params.append(error)

        sql_parts.append(" WHERE subdomain = ? AND scan_id = ?")
        params.extend([subdomain, scan_id])

        await self.execute("".join(sql_parts), tuple(params))
        await self.commit()

    async def get_subdomains(
        self,
        scan_id: str,
        status: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Get subdomains for a scan."""
        if status:
            rows = await self.fetch_all(
                "SELECT * FROM subdomains WHERE scan_id = ? AND status = ?",
                (scan_id, status),
            )
        else:
            rows = await self.fetch_all(
                "SELECT * FROM subdomains WHERE scan_id = ?",
                (scan_id,),
            )
        return [dict(row) for row in rows]

    # Host operations
    async def add_host(
        self,
        scan_id: str,
        hostname: str,
        data: dict[str, Any],
    ) -> None:
        """Add or update a host."""
        now = datetime.now().isoformat()
        await self.execute(
            """
            INSERT INTO hosts (
                hostname, scan_id, url, scheme, port,
                ipv4_addresses, ipv6_addresses, technologies,
                cdn_provider, is_alive, status_code, title,
                data_json, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hostname, scan_id) DO UPDATE SET
                url = excluded.url,
                ipv4_addresses = excluded.ipv4_addresses,
                ipv6_addresses = excluded.ipv6_addresses,
                technologies = excluded.technologies,
                cdn_provider = excluded.cdn_provider,
                is_alive = excluded.is_alive,
                status_code = excluded.status_code,
                title = excluded.title,
                data_json = excluded.data_json,
                updated_at = excluded.updated_at
            """,
            (
                hostname,
                scan_id,
                data.get("url"),
                data.get("scheme", "https"),
                data.get("port", 443),
                json.dumps(data.get("ipv4_addresses", [])),
                json.dumps(data.get("ipv6_addresses", [])),
                json.dumps(data.get("technologies", [])),
                data.get("cdn_provider"),
                data.get("is_alive", False),
                data.get("status_code"),
                data.get("title"),
                json.dumps(data),
                now,
                now,
            ),
        )
        await self.commit()

    async def get_live_hosts(self, scan_id: str) -> list[dict[str, Any]]:
        """Get all live hosts for a scan."""
        rows = await self.fetch_all(
            "SELECT * FROM hosts WHERE scan_id = ? AND is_alive = 1",
            (scan_id,),
        )
        return [dict(row) for row in rows]

    # Finding operations
    async def add_finding(
        self,
        scan_id: str,
        finding_type: str,
        severity: str,
        target: str,
        data: dict[str, Any],
    ) -> None:
        """Add a security finding."""
        now = datetime.now().isoformat()
        await self.execute(
            """
            INSERT INTO findings (
                scan_id, finding_type, severity, target,
                template_id, title, description, evidence,
                data_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                finding_type,
                severity,
                target,
                data.get("template_id"),
                data.get("title"),
                data.get("description"),
                data.get("evidence"),
                json.dumps(data),
                now,
            ),
        )
        await self.commit()

    async def get_findings(
        self,
        scan_id: str,
        severity: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Get findings for a scan."""
        if severity:
            rows = await self.fetch_all(
                "SELECT * FROM findings WHERE scan_id = ? AND severity = ?",
                (scan_id, severity),
            )
        else:
            rows = await self.fetch_all(
                "SELECT * FROM findings WHERE scan_id = ?",
                (scan_id,),
            )
        return [dict(row) for row in rows]
