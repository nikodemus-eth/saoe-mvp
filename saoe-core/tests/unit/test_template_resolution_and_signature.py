"""Tests for validator template/capset resolution and dispatcher signature checks.

Covers work-order test: test_template_resolution_and_signature.
"""
import hashlib
import json
import uuid
from datetime import datetime, timezone

import pytest

from saoe_core.crypto.keyring import hash_verify_key, sign_bytes
from saoe_core.satl.envelope import TemplateRef, sign_envelope
from saoe_core.satl.validator import (
    DispatcherSigError,
    EnvelopeValidator,
    TemplateSha256MismatchError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _build_validator(mock_vault, tmp_audit_db, own_agent="sanitization_agent"):
    return EnvelopeValidator(
        vault=mock_vault,
        own_agent_id=own_agent,
        audit_log=tmp_audit_db,
    )


def _make_draft(
    template: dict,
    template_ref: TemplateRef,
    sender_id: str = "intake_agent",
    receiver_id: str = "sanitization_agent",
    payload: dict | None = None,
) -> dict:
    return {
        "version": "1.0",
        "envelope_id": str(uuid.uuid4()),
        "session_id": str(uuid.uuid4()),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "sender_id": sender_id,
        "receiver_id": receiver_id,
        "human_readable": "test",
        "template_ref": template_ref,
        "payload": payload or {
            "title": "Hello",
            "body_markdown": "# Test",
            "image_present": False,
        },
    }


def _make_template_ref(template: dict, dispatcher_keypair) -> TemplateRef:
    """Build a correctly signed TemplateRef for the given template dict."""
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


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_valid_envelope_passes_all_steps(
    mock_vault, tmp_audit_db, intake_agent_keypair, dispatcher_keypair
) -> None:
    from saoe_core.crypto.age_vault import AgeVault
    from saoe_core.crypto.keyring import hash_verify_key

    # Build the template from the mock vault contents
    template = mock_vault.get_template("blog_article_intent", "1")
    tref = _make_template_ref(template, dispatcher_keypair)
    draft = _make_draft(template, tref)
    sk, vk = intake_agent_keypair

    envelope = sign_envelope(draft, sk)
    validator = _build_validator(mock_vault, tmp_audit_db)
    result = validator.validate(envelope, vk)
    assert result.envelope.sender_id == "intake_agent"


# ---------------------------------------------------------------------------
# Step 6: sha256 mismatch
# ---------------------------------------------------------------------------


def test_sha256_mismatch_rejected(
    mock_vault, tmp_audit_db, intake_agent_keypair, dispatcher_keypair
) -> None:
    template = mock_vault.get_template("blog_article_intent", "1")
    tref = _make_template_ref(template, dispatcher_keypair)
    bad_tref = TemplateRef(
        template_id=tref.template_id,
        version=tref.version,
        sha256_hash="a" * 64,  # wrong hash
        dispatcher_signature=tref.dispatcher_signature,
        capability_set_id=tref.capability_set_id,
        capability_set_version=tref.capability_set_version,
    )
    draft = _make_draft(template, bad_tref)
    sk, vk = intake_agent_keypair
    envelope = sign_envelope(draft, sk)
    validator = _build_validator(mock_vault, tmp_audit_db)
    with pytest.raises(TemplateSha256MismatchError):
        validator.validate(envelope, vk)


# ---------------------------------------------------------------------------
# Step 7: dispatcher signature mismatch
# ---------------------------------------------------------------------------


def test_dispatcher_sig_mismatch_rejected(
    mock_vault, tmp_audit_db, intake_agent_keypair, dispatcher_keypair, over_agent_keypair
) -> None:
    template = mock_vault.get_template("blog_article_intent", "1")
    # Sign the manifest with the wrong key (over_agent instead of dispatcher)
    wrong_sk, _ = over_agent_keypair
    canonical = _canonical(template)
    sha256 = hashlib.sha256(canonical).hexdigest()
    manifest = json.dumps(
        {"template_id": template["template_id"], "version": template["version"], "sha256_hash": sha256},
        sort_keys=True, separators=(",", ":"),
    ).encode()
    wrong_sig = sign_bytes(wrong_sk, manifest).hex()

    bad_tref = TemplateRef(
        template_id=template["template_id"],
        version=template["version"],
        sha256_hash=sha256,
        dispatcher_signature=wrong_sig,
        capability_set_id=template["capability_set_id"],
        capability_set_version=template["capability_set_version"],
    )
    draft = _make_draft(template, bad_tref)
    sk, vk = intake_agent_keypair
    envelope = sign_envelope(draft, sk)
    validator = _build_validator(mock_vault, tmp_audit_db)
    with pytest.raises(DispatcherSigError):
        validator.validate(envelope, vk)


# ---------------------------------------------------------------------------
# Template not found in vault
# ---------------------------------------------------------------------------


def test_template_not_found_rejected(
    mock_vault, tmp_audit_db, intake_agent_keypair, dispatcher_keypair
) -> None:
    from saoe_core.satl.validator import VaultResolutionError

    template = mock_vault.get_template("blog_article_intent", "1")
    tref = _make_template_ref(template, dispatcher_keypair)
    bad_tref = TemplateRef(
        template_id="nonexistent_template",
        version="1",
        sha256_hash=tref.sha256_hash,
        dispatcher_signature=tref.dispatcher_signature,
        capability_set_id=tref.capability_set_id,
        capability_set_version=tref.capability_set_version,
    )
    draft = _make_draft(template, bad_tref)
    sk, vk = intake_agent_keypair
    envelope = sign_envelope(draft, sk)
    validator = _build_validator(mock_vault, tmp_audit_db)
    with pytest.raises(VaultResolutionError):
        validator.validate(envelope, vk)
