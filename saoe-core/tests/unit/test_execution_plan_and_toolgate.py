"""Tests for saoe_core.toolgate — signed ExecutionPlan enforcement.

Covers work-order test: test_execution_plan_and_toolgate.
"""
import uuid
from datetime import datetime, timezone

import nacl.exceptions
import pytest

from saoe_core.crypto.keyring import generate_keypair, hash_verify_key, sign_bytes
from saoe_core.toolgate.toolgate import (
    ExecutionPlan,
    IssuerKeyMismatchError,
    ToolArgSchemaError,
    ToolCall,
    ToolGate,
    UnknownToolError,
    plan_canonical_bytes,
    sign_plan,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_plan(
    tool_calls: list[ToolCall],
    issuer_sk,
    session_id: str | None = None,
    issuer_id: str = "over_agent",
) -> ExecutionPlan:
    return sign_plan(
        plan_id=str(uuid.uuid4()),
        session_id=session_id or str(uuid.uuid4()),
        issuer_id=issuer_id,
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
        tool_calls=tool_calls,
        signing_key=issuer_sk,
    )


def _make_gate(over_agent_keypair, audit=None):
    from saoe_core.audit.events_sqlite import AuditLog
    from pathlib import Path
    import tempfile

    if audit is None:
        db = Path(tempfile.mktemp(suffix=".db"))
        audit = AuditLog(db)

    sk, vk = over_agent_keypair
    pin = hash_verify_key(vk)
    gate = ToolGate(issuer_verify_key=vk, issuer_pin=pin, audit_log=audit)
    return gate, sk


def _echo_tool(args: dict, context: dict) -> dict:
    return {"echoed": args["message"]}


ECHO_SCHEMA = {
    "type": "object",
    "required": ["message"],
    "properties": {"message": {"type": "string"}},
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_valid_plan_executes_and_returns_result(over_agent_keypair, tmp_audit_db) -> None:
    gate, issuer_sk = _make_gate(over_agent_keypair, tmp_audit_db)
    gate.register_tool("echo", _echo_tool, ECHO_SCHEMA)

    tc = ToolCall(
        tool_call_id=str(uuid.uuid4()),
        tool_name="echo",
        args={"message": "hello"},
    )
    plan = _make_plan([tc], issuer_sk)
    results = gate.execute(plan, context={})
    assert results[0]["echoed"] == "hello"


# ---------------------------------------------------------------------------
# Missing plan (no plan passed)
# ---------------------------------------------------------------------------


def test_unsigned_plan_rejected(over_agent_keypair, tmp_audit_db) -> None:
    gate, issuer_sk = _make_gate(over_agent_keypair, tmp_audit_db)
    gate.register_tool("echo", _echo_tool, ECHO_SCHEMA)

    # Build a plan with a bad signature (wrong key)
    bad_sk, _ = generate_keypair()
    tc = ToolCall(tool_call_id=str(uuid.uuid4()), tool_name="echo", args={"message": "x"})
    bad_plan = _make_plan([tc], bad_sk)  # signed with wrong key

    with pytest.raises(nacl.exceptions.BadSignatureError):
        gate.execute(bad_plan, context={})


# ---------------------------------------------------------------------------
# Wrong tool name
# ---------------------------------------------------------------------------


def test_unknown_tool_in_plan_rejected(over_agent_keypair, tmp_audit_db) -> None:
    gate, issuer_sk = _make_gate(over_agent_keypair, tmp_audit_db)
    gate.register_tool("echo", _echo_tool, ECHO_SCHEMA)

    tc = ToolCall(
        tool_call_id=str(uuid.uuid4()),
        tool_name="rm_rf",  # not registered
        args={"message": "x"},
    )
    plan = _make_plan([tc], issuer_sk)
    with pytest.raises(UnknownToolError):
        gate.execute(plan, context={})


# ---------------------------------------------------------------------------
# Args schema mismatch
# ---------------------------------------------------------------------------


def test_args_schema_mismatch_rejected(over_agent_keypair, tmp_audit_db) -> None:
    gate, issuer_sk = _make_gate(over_agent_keypair, tmp_audit_db)
    gate.register_tool("echo", _echo_tool, ECHO_SCHEMA)

    tc = ToolCall(
        tool_call_id=str(uuid.uuid4()),
        tool_name="echo",
        args={"not_message": "wrong key"},  # missing required "message"
    )
    plan = _make_plan([tc], issuer_sk)
    with pytest.raises(ToolArgSchemaError):
        gate.execute(plan, context={})


# ---------------------------------------------------------------------------
# FT-006: Issuer key mismatch aborts at init
# ---------------------------------------------------------------------------


def test_issuer_key_mismatch_raises_at_init() -> None:
    _, vk = generate_keypair()
    _, other_vk = generate_keypair()
    wrong_pin = hash_verify_key(other_vk)

    from saoe_core.audit.events_sqlite import AuditLog
    from pathlib import Path
    import tempfile
    audit = AuditLog(Path(tempfile.mktemp(suffix=".db")))

    with pytest.raises(IssuerKeyMismatchError):
        ToolGate(issuer_verify_key=vk, issuer_pin=wrong_pin, audit_log=audit)
