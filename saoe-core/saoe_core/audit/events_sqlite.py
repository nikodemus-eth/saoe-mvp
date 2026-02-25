"""SQLite-backed audit log with replay protection.

FT-002: ``envelope_id`` has a UNIQUE constraint — duplicate envelope_ids raise
:class:`ReplayAttackError` at INSERT time.

WAL journal mode is enabled so readers do not block the writer.
"""
import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class ReplayAttackError(RuntimeError):
    """Raised when an envelope_id is submitted that has already been seen."""


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class AuditEvent:
    """A single audit event to be written to the events database."""

    event_type: str
    timestamp_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    envelope_id: str | None = None
    session_id: str | None = None
    sender_id: str | None = None
    receiver_id: str | None = None
    template_id: str | None = None
    agent_id: str | None = None
    details: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# DDL
# ---------------------------------------------------------------------------

_CREATE_EVENTS = """
CREATE TABLE IF NOT EXISTS audit_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type      TEXT NOT NULL,
    envelope_id     TEXT,
    session_id      TEXT,
    sender_id       TEXT,
    receiver_id     TEXT,
    template_id     TEXT,
    agent_id        TEXT,
    timestamp_utc   TEXT NOT NULL,
    details_json    TEXT
);
"""

# Partial index: UNIQUE only where envelope_id IS NOT NULL (FT-002).
_CREATE_ENVELOPE_IDX = """
CREATE UNIQUE INDEX IF NOT EXISTS idx_envelope_id
    ON audit_events (envelope_id)
    WHERE envelope_id IS NOT NULL;
"""

_CREATE_SESSION_IDX = """
CREATE INDEX IF NOT EXISTS idx_sender_event_ts
    ON audit_events (sender_id, event_type, timestamp_utc);
"""


# ---------------------------------------------------------------------------
# AuditLog
# ---------------------------------------------------------------------------


class AuditLog:
    """Append-only SQLite audit log.

    Each call to :meth:`emit` opens, uses, and closes a connection, which is
    safe for multi-process use (each agent runs in its own process).

    Parameters
    ----------
    db_path:
        Path to the SQLite database file.  Created if it does not exist.
    """

    def __init__(self, db_path: Path) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(_CREATE_EVENTS)
            conn.execute(_CREATE_ENVELOPE_IDX)
            conn.execute(_CREATE_SESSION_IDX)
            conn.commit()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def emit(self, event: AuditEvent) -> None:
        """Insert *event* into the audit log.

        Raises
        ------
        ReplayAttackError
            If ``event.envelope_id`` is not None and has already been recorded.
        """
        details_json = json.dumps(event.details) if event.details is not None else None
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO audit_events
                        (event_type, envelope_id, session_id, sender_id,
                         receiver_id, template_id, agent_id, timestamp_utc, details_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.event_type,
                        event.envelope_id,
                        event.session_id,
                        event.sender_id,
                        event.receiver_id,
                        event.template_id,
                        event.agent_id,
                        event.timestamp_utc,
                        details_json,
                    ),
                )
                conn.commit()
        except sqlite3.IntegrityError as exc:
            if event.envelope_id and "envelope_id" in str(exc).lower():
                raise ReplayAttackError(
                    f"Replay detected: envelope_id {event.envelope_id!r} already processed"
                ) from exc
            # Re-raise other integrity errors (shouldn't happen with current schema).
            raise

    def has_envelope_id(self, envelope_id: str) -> bool:
        """Return True if *envelope_id* has already been recorded."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM audit_events WHERE envelope_id = ? LIMIT 1",
                (envelope_id,),
            ).fetchone()
        return row is not None

    def query_session_count(self, sender_id: str, window_hours: int = 1) -> int:
        """Count VALIDATED events for *sender_id* within the last *window_hours*."""
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*)
                FROM audit_events
                WHERE sender_id = ?
                  AND event_type = 'validated'
                  AND timestamp_utc >= datetime('now', ? || ' hours')
                """,
                (sender_id, f"-{window_hours}"),
            ).fetchone()
        return row[0] if row else 0

    def recent_events(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return the most recent *limit* events as dicts (for the log viewer)."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, event_type, envelope_id, session_id, sender_id,
                       receiver_id, template_id, agent_id, timestamp_utc, details_json
                FROM audit_events
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        cols = [
            "id", "event_type", "envelope_id", "session_id", "sender_id",
            "receiver_id", "template_id", "agent_id", "timestamp_utc", "details_json",
        ]
        return [dict(zip(cols, row)) for row in rows]
