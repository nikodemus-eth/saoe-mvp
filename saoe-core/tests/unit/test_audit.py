"""Tests for saoe_core.audit.events_sqlite and ledger_stub."""
import time
from pathlib import Path

import pytest

from saoe_core.audit.events_sqlite import AuditEvent, AuditLog, ReplayAttackError


# ---------------------------------------------------------------------------
# Basic emit and query
# ---------------------------------------------------------------------------


def test_emit_and_query(tmp_audit_db: AuditLog) -> None:
    event = AuditEvent(
        event_type="validated",
        envelope_id="env-001",
        session_id="sess-001",
        sender_id="intake_agent",
        receiver_id="sanitization_agent",
        template_id="blog_article_intent",
        agent_id="sanitization_agent",
        details={"step": "12"},
    )
    tmp_audit_db.emit(event)
    assert tmp_audit_db.has_envelope_id("env-001")


def test_has_envelope_id_false_when_absent(tmp_audit_db: AuditLog) -> None:
    assert not tmp_audit_db.has_envelope_id("nonexistent")


def test_emit_null_envelope_id_allowed(tmp_audit_db: AuditLog) -> None:
    """Non-envelope events (e.g., TOOL_CALLED) have no envelope_id."""
    event = AuditEvent(event_type="tool_executed", agent_id="text_formatter_agent")
    tmp_audit_db.emit(event)  # must not raise


def test_multiple_null_envelope_ids_allowed(tmp_audit_db: AuditLog) -> None:
    """Multiple events with NULL envelope_id must not violate UNIQUE constraint."""
    for i in range(5):
        tmp_audit_db.emit(AuditEvent(event_type="tool_executed", agent_id="agent"))


# ---------------------------------------------------------------------------
# FT-002: Replay protection
# ---------------------------------------------------------------------------


def test_duplicate_envelope_id_raises_replay_error(tmp_audit_db: AuditLog) -> None:
    event = AuditEvent(
        event_type="validated",
        envelope_id="dup-env-001",
        agent_id="sanitization_agent",
    )
    tmp_audit_db.emit(event)
    with pytest.raises(ReplayAttackError):
        tmp_audit_db.emit(
            AuditEvent(event_type="validated", envelope_id="dup-env-001", agent_id="agent")
        )


def test_replay_check_via_has_envelope_id(tmp_audit_db: AuditLog) -> None:
    tmp_audit_db.emit(
        AuditEvent(event_type="validated", envelope_id="seen-001", agent_id="agent")
    )
    assert tmp_audit_db.has_envelope_id("seen-001")
    assert not tmp_audit_db.has_envelope_id("not-seen")


# ---------------------------------------------------------------------------
# Session quota query
# ---------------------------------------------------------------------------


def test_query_session_count_returns_correct_count(tmp_audit_db: AuditLog) -> None:
    sender = "intake_agent"
    for i in range(3):
        tmp_audit_db.emit(
            AuditEvent(
                event_type="validated",
                envelope_id=f"q-env-{i}",
                sender_id=sender,
                agent_id="sanitization_agent",
            )
        )
    count = tmp_audit_db.query_session_count(sender, window_hours=1)
    assert count == 3


def test_query_session_count_different_sender(tmp_audit_db: AuditLog) -> None:
    tmp_audit_db.emit(
        AuditEvent(
            event_type="validated",
            envelope_id="sc-env-1",
            sender_id="sender_a",
            agent_id="agent",
        )
    )
    assert tmp_audit_db.query_session_count("sender_b", window_hours=1) == 0


# ---------------------------------------------------------------------------
# LedgerStub
# ---------------------------------------------------------------------------


def test_ledger_stub_append_returns_hash(tmp_path: Path) -> None:
    from saoe_core.audit.ledger_stub import LedgerStub

    ledger = LedgerStub(tmp_path / "ledger.jsonl")
    h = ledger.append({"event": "test", "data": "value"})
    assert isinstance(h, str)
    assert len(h) == 64  # hex SHA-256


def test_ledger_stub_persists_records(tmp_path: Path) -> None:
    from saoe_core.audit.ledger_stub import LedgerStub

    path = tmp_path / "ledger.jsonl"
    ledger = LedgerStub(path)
    ledger.append({"event": "first"})
    ledger.append({"event": "second"})
    lines = path.read_text().strip().splitlines()
    assert len(lines) == 2
