"""Tests for saoe_core.satl.envelope — sign/verify and duplicate-key rejection.

Covers work-order test: test_envelope_sign_verify.
"""
import json
import uuid
from datetime import datetime, timezone

import nacl.exceptions
import pytest

from saoe_core.satl.envelope import (
    DuplicateKeyError,
    EnvelopeParseError,
    SATLEnvelope,
    TemplateRef,
    canonical_bytes,
    parse_envelope,
    sign_envelope,
    verify_envelope_signature,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _template_ref() -> TemplateRef:
    return TemplateRef(
        template_id="blog_article_intent",
        version="1",
        sha256_hash="a" * 64,
        dispatcher_signature="b" * 128,
        capability_set_id="caps_v1",
        capability_set_version="1",
    )


def _draft(sender_id: str = "intake_agent", receiver_id: str = "sanitization_agent") -> dict:
    return {
        "version": "1.0",
        "envelope_id": str(uuid.uuid4()),
        "session_id": str(uuid.uuid4()),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "sender_id": sender_id,
        "receiver_id": receiver_id,
        "human_readable": "A blog article intent",
        "template_ref": _template_ref(),
        "payload": {
            "title": "Hello SAOE",
            "body_markdown": "# Test\nThis is a test.",
            "image_present": False,
        },
    }


# ---------------------------------------------------------------------------
# Sign and verify round-trip
# ---------------------------------------------------------------------------


def test_sign_and_verify_round_trip(intake_agent_keypair) -> None:
    sk, vk = intake_agent_keypair
    draft = _draft()
    envelope = sign_envelope(draft, sk)
    verify_envelope_signature(envelope, vk)  # must not raise


def test_tamper_payload_fails_verification(intake_agent_keypair) -> None:
    sk, vk = intake_agent_keypair
    draft = _draft()
    envelope = sign_envelope(draft, sk)

    # Tamper with the payload after signing
    tampered = SATLEnvelope(
        version=envelope.version,
        envelope_id=envelope.envelope_id,
        session_id=envelope.session_id,
        timestamp_utc=envelope.timestamp_utc,
        sender_id=envelope.sender_id,
        receiver_id=envelope.receiver_id,
        human_readable=envelope.human_readable,
        template_ref=envelope.template_ref,
        payload={"title": "TAMPERED", "body_markdown": "evil", "image_present": True},
        envelope_signature=envelope.envelope_signature,
    )
    with pytest.raises(nacl.exceptions.BadSignatureError):
        verify_envelope_signature(tampered, vk)


def test_tamper_human_readable_fails_verification(intake_agent_keypair) -> None:
    """human_readable is covered by the signature even though it is ignored by execution."""
    sk, vk = intake_agent_keypair
    draft = _draft()
    envelope = sign_envelope(draft, sk)

    tampered = SATLEnvelope(
        version=envelope.version,
        envelope_id=envelope.envelope_id,
        session_id=envelope.session_id,
        timestamp_utc=envelope.timestamp_utc,
        sender_id=envelope.sender_id,
        receiver_id=envelope.receiver_id,
        human_readable="TAMPERED DESCRIPTION",
        template_ref=envelope.template_ref,
        payload=envelope.payload,
        envelope_signature=envelope.envelope_signature,
    )
    with pytest.raises(nacl.exceptions.BadSignatureError):
        verify_envelope_signature(tampered, vk)


def test_wrong_verify_key_fails(intake_agent_keypair, over_agent_keypair) -> None:
    sk, _ = intake_agent_keypair
    _, wrong_vk = over_agent_keypair
    draft = _draft()
    envelope = sign_envelope(draft, sk)
    with pytest.raises(nacl.exceptions.BadSignatureError):
        verify_envelope_signature(envelope, wrong_vk)


# ---------------------------------------------------------------------------
# canonical_bytes
# ---------------------------------------------------------------------------


def test_canonical_bytes_excludes_envelope_signature(intake_agent_keypair) -> None:
    sk, _ = intake_agent_keypair
    draft = _draft()
    envelope = sign_envelope(draft, sk)
    cb = canonical_bytes(envelope)
    parsed = json.loads(cb)
    assert "envelope_signature" not in parsed


def test_canonical_bytes_is_deterministic(intake_agent_keypair) -> None:
    sk, _ = intake_agent_keypair
    draft = _draft()
    envelope = sign_envelope(draft, sk)
    assert canonical_bytes(envelope) == canonical_bytes(envelope)


# ---------------------------------------------------------------------------
# FT-004: Duplicate key rejection
# ---------------------------------------------------------------------------


def test_duplicate_top_level_key_rejected() -> None:
    raw = '{"version": "1.0", "version": "evil"}'
    with pytest.raises(DuplicateKeyError):
        parse_envelope(raw)


def test_duplicate_nested_key_rejected() -> None:
    # Build JSON with duplicate nested key by hand (json.dumps de-duplicates).
    raw = (
        '{"version":"1.0","envelope_id":"x","session_id":"s",'
        '"timestamp_utc":"t","sender_id":"a","receiver_id":"b",'
        '"human_readable":"h","template_ref":{"template_id":"t","template_id":"evil",'
        '"version":"1","sha256_hash":"a","dispatcher_signature":"b",'
        '"capability_set_id":"c","capability_set_version":"1"},'
        '"payload":{},"envelope_signature":"sig"}'
    )
    with pytest.raises(DuplicateKeyError):
        parse_envelope(raw)


def test_valid_envelope_parses(intake_agent_keypair) -> None:
    sk, _ = intake_agent_keypair
    draft = _draft()
    envelope = sign_envelope(draft, sk)
    cb = canonical_bytes(envelope)
    # We need the full envelope JSON with signature for parse_envelope.
    env_dict = json.loads(cb)
    env_dict["envelope_signature"] = envelope.envelope_signature
    raw = json.dumps(env_dict)
    result = parse_envelope(raw)
    assert isinstance(result, SATLEnvelope)
    assert result.sender_id == "intake_agent"


def test_invalid_json_raises_parse_error() -> None:
    with pytest.raises(EnvelopeParseError):
        parse_envelope("not json at all {{{")
