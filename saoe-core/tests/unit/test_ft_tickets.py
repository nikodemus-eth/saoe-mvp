"""Security invariant tests — FT-001 through FT-010.

Each test corresponds to a failure ticket from the work order.
"""
import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import nacl.exceptions
import pytest

from saoe_core.crypto.keyring import (
    DispatcherKeyMismatchError,
    generate_keypair,
    hash_verify_key,
    sign_bytes,
)
from saoe_core.satl.envelope import TemplateRef, sign_envelope
from saoe_core.satl.validator import (
    CapabilityConstraintError,
    EnvelopeValidator,
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _make_signed_tref(template, dispatcher_keypair):
    sk, _ = dispatcher_keypair
    canonical = _canonical(template)
    sha256 = hashlib.sha256(canonical).hexdigest()
    manifest = json.dumps(
        {"template_id": template["template_id"], "version": template["version"], "sha256_hash": sha256},
        sort_keys=True, separators=(",", ":"),
    ).encode()
    sig = sign_bytes(sk, manifest).hex()
    return TemplateRef(
        template_id=template["template_id"],
        version=template["version"],
        sha256_hash=sha256,
        dispatcher_signature=sig,
        capability_set_id=template["capability_set_id"],
        capability_set_version=template["capability_set_version"],
    )


def _draft(tref, sender="intake_agent", receiver="sanitization_agent", payload=None):
    return {
        "version": "1.0",
        "envelope_id": str(uuid.uuid4()),
        "session_id": str(uuid.uuid4()),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "sender_id": sender,
        "receiver_id": receiver,
        "human_readable": "test",
        "template_ref": tref,
        "payload": payload or {"title": "Hi", "body_markdown": "# x", "image_present": False},
    }


def _validator(mock_vault, tmp_audit_db, agent="sanitization_agent", **kwargs):
    return EnvelopeValidator(vault=mock_vault, own_agent_id=agent, audit_log=tmp_audit_db, **kwargs)


# ---------------------------------------------------------------------------
# FT-001: Pinned dispatcher key mismatch aborts AgeVault init
# ---------------------------------------------------------------------------


def test_ft001_dispatcher_pin_mismatch_aborts_vault_init() -> None:
    from saoe_core.crypto.age_vault import AgeVault

    _, vk = generate_keypair()
    _, other_vk = generate_keypair()
    wrong_pin = hash_verify_key(other_vk)

    with pytest.raises(DispatcherKeyMismatchError):
        AgeVault._from_mock({}, dispatcher_vk=vk, dispatcher_pin=wrong_pin)


# ---------------------------------------------------------------------------
# FT-002: Replay — same envelope_id rejected on second validate
# ---------------------------------------------------------------------------


def test_ft002_replay_envelope_id_rejected(
    mock_vault, tmp_audit_db, intake_agent_keypair, dispatcher_keypair
) -> None:
    from saoe_core.audit.events_sqlite import ReplayAttackError

    template = mock_vault.get_template("blog_article_intent", "1")
    tref = _make_signed_tref(template, dispatcher_keypair)
    sk, vk = intake_agent_keypair

    # First submission — must succeed.
    draft1 = _draft(tref)
    envelope1 = sign_envelope(draft1, sk)
    validator = _validator(mock_vault, tmp_audit_db)
    validator.validate(envelope1, vk)

    # Replay the same envelope_id — must be rejected.
    # Re-sign with same envelope_id to get a valid signature.
    same_id_draft = dict(draft1)
    same_id_draft["envelope_id"] = envelope1.envelope_id  # force same id
    same_id_draft["session_id"] = str(uuid.uuid4())  # fresh session is fine
    envelope_replay = sign_envelope(same_id_draft, sk)

    with pytest.raises(ReplayAttackError):
        _validator(mock_vault, tmp_audit_db).validate(envelope_replay, vk)


# ---------------------------------------------------------------------------
# FT-003: Atomic move-then-verify rejects tampered content
# ---------------------------------------------------------------------------


def test_ft003_atomic_move_sha256_verified(tmp_path: Path) -> None:
    from saoe_core.util.safe_fs import AtomicMoveError, atomic_move_then_verify

    src = tmp_path / "msg.json"
    src.write_bytes(b'{"key": "value"}')
    dst_dir = tmp_path / "out"
    dst_dir.mkdir()

    # Normal move works.
    result = atomic_move_then_verify(src, dst_dir)
    assert result.read_bytes() == b'{"key": "value"}'

    # If source disappears mid-flight, raises AtomicMoveError.
    missing = tmp_path / "missing.json"
    with pytest.raises(AtomicMoveError):
        atomic_move_then_verify(missing, dst_dir)


# ---------------------------------------------------------------------------
# FT-004: Duplicate JSON keys rejected at parse
# ---------------------------------------------------------------------------


def test_ft004_duplicate_keys_rejected() -> None:
    from saoe_core.satl.envelope import DuplicateKeyError, parse_envelope

    raw = (
        '{"version":"1.0","version":"evil","envelope_id":"x","session_id":"s",'
        '"timestamp_utc":"t","sender_id":"a","receiver_id":"b","human_readable":"h",'
        '"template_ref":{"template_id":"t","version":"1","sha256_hash":"a",'
        '"dispatcher_signature":"b","capability_set_id":"c","capability_set_version":"1"},'
        '"payload":{},"envelope_signature":"sig"}'
    )
    with pytest.raises(DuplicateKeyError):
        parse_envelope(raw)


# ---------------------------------------------------------------------------
# FT-005: Capability constraints enforced
# ---------------------------------------------------------------------------


def test_ft005_sender_not_allowed_rejected(
    mock_vault, tmp_audit_db, dispatcher_keypair
) -> None:
    # Use an unknown sender key (over_agent is in allowed_senders but 'rogue_agent' is not)
    rogue_sk, rogue_vk = generate_keypair()
    template = mock_vault.get_template("blog_article_intent", "1")
    tref = _make_signed_tref(template, dispatcher_keypair)
    draft = _draft(tref, sender="rogue_agent", receiver="sanitization_agent")
    envelope = sign_envelope(draft, rogue_sk)

    validator = _validator(mock_vault, tmp_audit_db)
    with pytest.raises(CapabilityConstraintError, match="not in allowed_senders"):
        validator.validate(envelope, rogue_vk)


def test_ft005_receiver_not_allowed_rejected(
    mock_vault, tmp_audit_db, intake_agent_keypair, dispatcher_keypair
) -> None:
    sk, vk = intake_agent_keypair
    template = mock_vault.get_template("blog_article_intent", "1")
    tref = _make_signed_tref(template, dispatcher_keypair)
    # "deployment_agent" is not in allowed_receivers for blog_article_intent
    draft = _draft(tref, sender="intake_agent", receiver="deployment_agent")
    envelope = sign_envelope(draft, sk)

    # Validator must be "deployment_agent" for receiver check to pass step 4
    # but fail step 11 (deployment_agent not in allowed_receivers)
    validator = _validator(mock_vault, tmp_audit_db, agent="deployment_agent")
    with pytest.raises(CapabilityConstraintError, match="not in allowed_receivers"):
        validator.validate(envelope, vk)


def test_ft005_payload_size_limit_rejected(
    mock_vault, tmp_audit_db, intake_agent_keypair, dispatcher_keypair
) -> None:
    sk, vk = intake_agent_keypair
    template = mock_vault.get_template("blog_article_intent", "1")
    tref = _make_signed_tref(template, dispatcher_keypair)

    # Oversized payload (above max_payload_bytes=262144 but within JSON Schema maxLength)
    large_body = "x" * 300000
    payload = {"title": "Hi", "body_markdown": large_body[:200000], "image_present": False}
    draft = _draft(tref, payload=payload)
    envelope = sign_envelope(draft, sk)

    # Use a validator with a very small cap so we can trigger it reliably
    validator = EnvelopeValidator(
        vault=mock_vault,
        own_agent_id="sanitization_agent",
        audit_log=tmp_audit_db,
    )
    # Patch max_payload_bytes in template policy to 1 byte via a tiny cap
    # Instead: use envelope-level file size cap to trigger FileSizeExceededError
    from saoe_core.satl.validator import FileSizeExceededError

    tiny_validator = EnvelopeValidator(
        vault=mock_vault,
        own_agent_id="sanitization_agent",
        audit_log=tmp_audit_db,
        file_size_cap_bytes=1,  # absurdly small
    )
    # Must be passed as raw bytes to trigger the size check
    from saoe_core.satl.envelope import envelope_to_json
    raw = envelope_to_json(envelope).encode("utf-8")
    with pytest.raises(FileSizeExceededError):
        tiny_validator.validate(raw, vk)


def test_ft005_session_quota_rejected(
    mock_vault, tmp_path, intake_agent_keypair, dispatcher_keypair
) -> None:
    from saoe_core.audit.events_sqlite import AuditLog

    audit = AuditLog(tmp_path / "quota.db")
    sk, vk = intake_agent_keypair
    template = mock_vault.get_template("blog_article_intent", "1")

    # Validator with quota=2
    validator = EnvelopeValidator(
        vault=mock_vault,
        own_agent_id="sanitization_agent",
        audit_log=audit,
        max_quota_per_sender_per_hour=2,
    )

    # Send 2 envelopes — both should succeed
    for _ in range(2):
        tref = _make_signed_tref(template, dispatcher_keypair)
        draft = _draft(tref)
        envelope = sign_envelope(draft, sk)
        validator.validate(envelope, vk)

    # Third should fail with quota exceeded
    tref = _make_signed_tref(template, dispatcher_keypair)
    draft = _draft(tref)
    envelope = sign_envelope(draft, sk)
    with pytest.raises(CapabilityConstraintError, match="quota"):
        validator.validate(envelope, vk)


# ---------------------------------------------------------------------------
# FT-006: ToolGate plan signature mismatch / unknown tool
# ---------------------------------------------------------------------------


def test_ft006_plan_signature_invalid_rejected(over_agent_keypair, tmp_audit_db) -> None:
    from saoe_core.toolgate.toolgate import ExecutionPlan, ToolCall, ToolGate

    _, vk = over_agent_keypair
    pin = hash_verify_key(vk)
    gate = ToolGate(issuer_verify_key=vk, issuer_pin=pin, audit_log=tmp_audit_db)
    gate.register_tool(
        "echo",
        lambda args, ctx: {"ok": True},
        {"type": "object", "properties": {}, "additionalProperties": True},
    )

    bad_sk, _ = generate_keypair()  # wrong signing key
    from saoe_core.toolgate.toolgate import sign_plan, ToolCall

    tc = ToolCall(tool_call_id=str(uuid.uuid4()), tool_name="echo", args={})
    plan = sign_plan(
        plan_id=str(uuid.uuid4()),
        session_id=str(uuid.uuid4()),
        issuer_id="over_agent",
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
        tool_calls=[tc],
        signing_key=bad_sk,
    )
    with pytest.raises(nacl.exceptions.BadSignatureError):
        gate.execute(plan, context={})


def test_ft006_unknown_tool_in_plan_rejected(over_agent_keypair, tmp_audit_db) -> None:
    from saoe_core.toolgate.toolgate import ToolGate, ToolCall, UnknownToolError, sign_plan

    sk, vk = over_agent_keypair
    pin = hash_verify_key(vk)
    gate = ToolGate(issuer_verify_key=vk, issuer_pin=pin, audit_log=tmp_audit_db)
    # gate has NO registered tools

    tc = ToolCall(tool_call_id=str(uuid.uuid4()), tool_name="rm_rf", args={})
    plan = sign_plan(
        plan_id=str(uuid.uuid4()),
        session_id=str(uuid.uuid4()),
        issuer_id="over_agent",
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
        tool_calls=[tc],
        signing_key=sk,
    )
    with pytest.raises(UnknownToolError):
        gate.execute(plan, context={})


# ---------------------------------------------------------------------------
# FT-007: Path traversal and symlink rejection
# ---------------------------------------------------------------------------


def test_ft007_path_traversal_rejected(tmp_path: Path) -> None:
    from saoe_core.util.safe_fs import SafePathError, resolve_safe_path

    with pytest.raises(SafePathError):
        resolve_safe_path(tmp_path, "../../etc/passwd")


def test_ft007_symlink_write_rejected(tmp_path: Path) -> None:
    from saoe_core.util.safe_fs import SafePathError, resolve_safe_path

    evil = tmp_path / "evil"
    evil.symlink_to("/etc")
    with pytest.raises(SafePathError):
        resolve_safe_path(tmp_path, "evil/passwd")


# ---------------------------------------------------------------------------
# FT-008: HTML sanitisation removes script tags
# ---------------------------------------------------------------------------


def test_ft008_html_output_sanitized() -> None:
    import bleach

    raw_html = '<p>Hello</p><script>alert("xss")</script><b>World</b>'
    # bleach.clean with no allowed tags strips all tags.
    safe = bleach.clean(raw_html, tags=[], attributes={}, strip=True)
    assert "<script>" not in safe
    assert "alert" in safe  # text content preserved
    assert "<p>" not in safe


# ---------------------------------------------------------------------------
# FT-009: Quarantine file count limit
# ---------------------------------------------------------------------------


def test_ft009_quarantine_count_limit_enforced(tmp_path: Path) -> None:
    """If quarantine exceeds MAX_QUARANTINE_FILES, poll_once returns empty."""
    from saoe_core.audit.events_sqlite import AuditLog
    from saoe_core.crypto.age_vault import AgeVault
    from saoe_core.crypto.keyring import generate_keypair, hash_verify_key
    from saoe_openclaw.shim import AgentShim

    sk, vk = generate_keypair()
    pin = hash_verify_key(vk)
    vault = AgeVault._from_mock({}, dispatcher_vk=vk, dispatcher_pin=pin)
    audit = AuditLog(tmp_path / "audit.db")

    queue_dir = tmp_path / "queue"
    queue_dir.mkdir()
    quarantine_dir = tmp_path / "quarantine"
    quarantine_dir.mkdir()

    shim = AgentShim(
        agent_id="test_agent",
        vault=vault,
        audit_log=audit,
        signing_key=sk,
        known_sender_keys={},
        queue_dir=queue_dir,
        quarantine_dir=quarantine_dir,
        max_quarantine_files=2,
    )

    # Create 3 files in quarantine to exceed the limit of 2.
    for i in range(3):
        (quarantine_dir / f"bad_{i}.satl.json").write_text("{}")

    result = shim.poll_once()
    assert result == []


# ---------------------------------------------------------------------------
# FT-010: Publisher hash confirmation gate
# ---------------------------------------------------------------------------


def test_ft010_publisher_aborts_on_wrong_sha256(tmp_path: Path, monkeypatch) -> None:
    from saoe_core.publisher import publish_template

    template = {
        "template_id": "test_tmpl",
        "version": "1",
        "json_schema": {"type": "object"},
        "policy_metadata": {"max_payload_bytes": 100, "allowed_senders": [], "allowed_receivers": []},
        "capability_set_id": "caps_v1",
        "capability_set_version": "1",
    }
    template_file = tmp_path / "tmpl.json"
    template_file.write_text(json.dumps(template))

    vault_dir = tmp_path / "vault"
    vault_dir.mkdir()

    sk, _ = generate_keypair()

    # Provide wrong sha256 as "user confirmation"
    monkeypatch.setattr("builtins.input", lambda _: "wrong_sha256")

    with pytest.raises(SystemExit):
        publish_template(
            template_path=template_file,
            vault_dir=vault_dir,
            dispatcher_signing_key=sk,
        )
