"""Tests for payload JSON Schema validation — step 10 of 12.

Covers work-order test: test_payload_schema_rejection.
"""
import hashlib
import json
import uuid
from datetime import datetime, timezone

import pytest

from saoe_core.crypto.keyring import sign_bytes
from saoe_core.satl.envelope import TemplateRef, sign_envelope
from saoe_core.satl.validator import EnvelopeValidator, PayloadSchemaError


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


def _draft(tref, payload):
    return {
        "version": "1.0",
        "envelope_id": str(uuid.uuid4()),
        "session_id": str(uuid.uuid4()),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "sender_id": "intake_agent",
        "receiver_id": "sanitization_agent",
        "human_readable": "test",
        "template_ref": tref,
        "payload": payload,
    }


def _build_validator(mock_vault, tmp_audit_db):
    return EnvelopeValidator(
        vault=mock_vault,
        own_agent_id="sanitization_agent",
        audit_log=tmp_audit_db,
    )


def test_additional_properties_rejected(
    mock_vault, tmp_audit_db, intake_agent_keypair, dispatcher_keypair
) -> None:
    """additionalProperties: false in schema means extra keys must be rejected."""
    template = mock_vault.get_template("blog_article_intent", "1")
    tref = _make_signed_tref(template, dispatcher_keypair)
    payload = {
        "title": "Hello",
        "body_markdown": "# Test",
        "image_present": False,
        "INJECTED_EXTRA_KEY": "evil",  # not in schema
    }
    sk, vk = intake_agent_keypair
    envelope = sign_envelope(_draft(tref, payload), sk)

    with pytest.raises(PayloadSchemaError):
        _build_validator(mock_vault, tmp_audit_db).validate(envelope, vk)


def test_missing_required_field_rejected(
    mock_vault, tmp_audit_db, intake_agent_keypair, dispatcher_keypair
) -> None:
    template = mock_vault.get_template("blog_article_intent", "1")
    tref = _make_signed_tref(template, dispatcher_keypair)
    payload = {
        "title": "Hello",
        # body_markdown missing
        "image_present": False,
    }
    sk, vk = intake_agent_keypair
    envelope = sign_envelope(_draft(tref, payload), sk)

    with pytest.raises(PayloadSchemaError):
        _build_validator(mock_vault, tmp_audit_db).validate(envelope, vk)


def test_valid_payload_passes(
    mock_vault, tmp_audit_db, intake_agent_keypair, dispatcher_keypair
) -> None:
    template = mock_vault.get_template("blog_article_intent", "1")
    tref = _make_signed_tref(template, dispatcher_keypair)
    payload = {"title": "Hello", "body_markdown": "# Test", "image_present": False}
    sk, vk = intake_agent_keypair
    envelope = sign_envelope(_draft(tref, payload), sk)
    result = _build_validator(mock_vault, tmp_audit_db).validate(envelope, vk)
    assert result.envelope.payload["title"] == "Hello"
