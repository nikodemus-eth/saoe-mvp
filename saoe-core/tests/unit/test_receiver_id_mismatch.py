"""Tests for receiver_id validation — step 4 of the 12-step validator.

Covers work-order test: test_receiver_id_mismatch.
"""
import hashlib
import json
import uuid
from datetime import datetime, timezone

import pytest

from saoe_core.crypto.keyring import sign_bytes
from saoe_core.satl.envelope import TemplateRef, sign_envelope
from saoe_core.satl.validator import EnvelopeValidator, ReceiverMismatchError


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


def _draft(tref, receiver_id):
    return {
        "version": "1.0",
        "envelope_id": str(uuid.uuid4()),
        "session_id": str(uuid.uuid4()),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "sender_id": "intake_agent",
        "receiver_id": receiver_id,
        "human_readable": "test",
        "template_ref": tref,
        "payload": {"title": "Hello", "body_markdown": "# x", "image_present": False},
    }


def test_receiver_mismatch_raises_before_any_tool_execution(
    mock_vault, tmp_audit_db, intake_agent_keypair, dispatcher_keypair
) -> None:
    template = mock_vault.get_template("blog_article_intent", "1")
    tref = _make_signed_tref(template, dispatcher_keypair)
    # Send to 'over_agent' but validator is running as 'sanitization_agent'
    draft = _draft(tref, receiver_id="over_agent")
    sk, vk = intake_agent_keypair
    envelope = sign_envelope(draft, sk)

    validator = EnvelopeValidator(
        vault=mock_vault, own_agent_id="sanitization_agent", audit_log=tmp_audit_db
    )
    with pytest.raises(ReceiverMismatchError):
        validator.validate(envelope, vk)


def test_correct_receiver_passes(
    mock_vault, tmp_audit_db, intake_agent_keypair, dispatcher_keypair
) -> None:
    template = mock_vault.get_template("blog_article_intent", "1")
    tref = _make_signed_tref(template, dispatcher_keypair)
    draft = _draft(tref, receiver_id="sanitization_agent")
    sk, vk = intake_agent_keypair
    envelope = sign_envelope(draft, sk)

    validator = EnvelopeValidator(
        vault=mock_vault, own_agent_id="sanitization_agent", audit_log=tmp_audit_db
    )
    result = validator.validate(envelope, vk)
    assert result.receiver_id == "sanitization_agent"
