"""Red team Section 6: Break-glass bypass checks.

Verifies that no environment variables, undocumented flags, or runtime
conditions can disable or weaken the 12-step SATL validation pipeline.

Expected outcome for every test: validation still rejects or validation still
runs — the env var / flag has NO effect on security enforcement.
"""
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

import nacl.exceptions
import pytest

from saoe_core.satl.envelope import sign_envelope, envelope_to_json, parse_envelope
from saoe_core.satl.validator import (
    EnvelopeValidator,
    FileSizeExceededError,
    PayloadSchemaError,
)
from saoe_core.crypto.keyring import generate_keypair


# ---------------------------------------------------------------------------
# Fixtures — minimal inline stubs so we don't need a real vault
# ---------------------------------------------------------------------------

# Import the conftest fixtures via the test infrastructure:
# These tests live under tests/unit/ and rely on conftest.py fixtures.
# We directly create validator instances with mock vault for Section 6 tests.


def _make_mock_vault(template: dict, capset: dict, dispatcher_sk):
    """Build a minimal mock vault that returns the given template and capset."""
    from saoe_core.crypto.keyring import sign_bytes
    import hashlib, json

    def canonical_bytes(obj):
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()

    dispatcher_vk = dispatcher_sk.verify_key
    template_hash = hashlib.sha256(canonical_bytes(template)).hexdigest()
    manifest = json.dumps(
        {"template_id": template["template_id"], "version": template["version"], "sha256_hash": template_hash},
        sort_keys=True, separators=(",", ":"),
    ).encode()
    dispatcher_sig = sign_bytes(dispatcher_sk, manifest).hex()

    vault = MagicMock()
    vault.get_template.return_value = template
    vault.get_capability_set.return_value = capset
    vault.get_dispatcher_verify_key.return_value = dispatcher_vk
    return vault, template_hash, dispatcher_sig


def _minimal_template(allowed_senders, allowed_receivers):
    return {
        "template_id": "test_template",
        "version": "1",
        "json_schema": {
            "type": "object",
            "required": ["data"],
            "properties": {"data": {"type": "string"}},
            "additionalProperties": False,
        },
        "policy_metadata": {
            "max_payload_bytes": 10_000,
            "allowed_senders": allowed_senders,
            "allowed_receivers": allowed_receivers,
        },
    }


def _minimal_capset():
    return {"capability_set_id": "caps_test", "version": "1"}


# ---------------------------------------------------------------------------
# Section 6.1: SAOE_DISABLE_VALIDATION env var has no effect
# ---------------------------------------------------------------------------


def test_disable_validation_env_var_does_not_bypass_signature_check(tmp_path):
    """SAOE_DISABLE_VALIDATION=1 must NOT disable envelope signature verification.

    Even with this env var set, a tampered envelope must still raise
    nacl.exceptions.BadSignatureError.
    """
    from saoe_core.audit.events_sqlite import AuditLog
    from saoe_core.crypto.keyring import DISPATCHER_KEY_HASH_PIN
    from saoe_core.crypto.keyring import generate_keypair

    sender_sk, sender_vk = generate_keypair()
    dispatcher_sk, dispatcher_vk = generate_keypair()

    capset = _minimal_capset()
    template = _minimal_template(["sender_agent"], ["receiver_agent"])
    vault, template_hash, dispatcher_sig = _make_mock_vault(template, capset, dispatcher_sk)

    from saoe_core.crypto.keyring import hash_verify_key
    with patch("saoe_core.crypto.keyring.DISPATCHER_KEY_HASH_PIN", hash_verify_key(dispatcher_vk)):
        audit = AuditLog(tmp_path / "events.db")
        validator = EnvelopeValidator(
            vault=vault,
            own_agent_id="receiver_agent",
            audit_log=audit,
        )

    # Build a valid envelope then tamper with the payload
    from saoe_core.satl.envelope import TemplateRef
    import uuid, json
    from datetime import datetime, timezone

    draft = {
        "version": "1.0",
        "envelope_id": str(uuid.uuid4()),
        "session_id": "sess-break-glass-001",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "sender_id": "sender_agent",
        "receiver_id": "receiver_agent",
        "human_readable": "",
        "template_ref": TemplateRef(
            template_id="test_template",
            version="1",
            sha256_hash=template_hash,
            dispatcher_signature=dispatcher_sig,
            capability_set_id="caps_test",
            capability_set_version="1",
        ),
        "payload": {"data": "hello"},
    }
    envelope = sign_envelope(draft, sender_sk)
    raw_json = envelope_to_json(envelope)

    # Tamper: replace the data value in the raw JSON
    tampered_json = raw_json.replace('"hello"', '"TAMPERED"')

    # Set env var that might be used as a bypass
    with patch.dict(os.environ, {"SAOE_DISABLE_VALIDATION": "1"}):
        with pytest.raises(nacl.exceptions.BadSignatureError):
            validator.validate(tampered_json.encode(), sender_vk)


def test_disable_validation_env_var_does_not_bypass_size_check():
    """SAOE_DISABLE_VALIDATION=1 must NOT bypass the file size cap.

    An oversized envelope must raise FileSizeExceededError regardless
    of any environment variable.
    """
    from saoe_core.audit.events_sqlite import AuditLog
    from saoe_core.crypto.keyring import generate_keypair, hash_verify_key
    from unittest.mock import patch, MagicMock
    import tempfile

    sender_sk, sender_vk = generate_keypair()
    dispatcher_sk, _ = generate_keypair()

    template = _minimal_template(["s"], ["r"])
    capset = _minimal_capset()
    vault, _, _ = _make_mock_vault(template, capset, dispatcher_sk)

    with tempfile.TemporaryDirectory() as tmpdir:
        audit = AuditLog(Path(tmpdir) / "events.db")
        validator = EnvelopeValidator(
            vault=vault,
            own_agent_id="receiver_agent",
            audit_log=audit,
            file_size_cap_bytes=100,  # very small cap
        )

        # Build a payload that exceeds the cap
        oversized_raw = b"x" * 200

        with patch.dict(os.environ, {"SAOE_DISABLE_VALIDATION": "1"}):
            with pytest.raises(FileSizeExceededError):
                validator.validate(oversized_raw, sender_vk)


# ---------------------------------------------------------------------------
# Section 6.2: Empty or missing signature does not bypass sig check
# ---------------------------------------------------------------------------


def test_empty_signature_rejected(tmp_path):
    """An envelope with an empty string for envelope_signature must be rejected.

    Some implementations might special-case "" to skip signature verification.
    Verify this does not happen.
    """
    from saoe_core.audit.events_sqlite import AuditLog
    from saoe_core.crypto.keyring import generate_keypair, hash_verify_key
    from saoe_core.satl.envelope import TemplateRef, envelope_to_json

    sender_sk, sender_vk = generate_keypair()
    dispatcher_sk, dispatcher_vk = generate_keypair()

    template = _minimal_template(["sender_agent"], ["receiver_agent"])
    capset = _minimal_capset()
    vault, template_hash, dispatcher_sig = _make_mock_vault(template, capset, dispatcher_sk)

    with patch("saoe_core.crypto.keyring.DISPATCHER_KEY_HASH_PIN", hash_verify_key(dispatcher_vk)):
        audit = AuditLog(tmp_path / "events.db")
        validator = EnvelopeValidator(
            vault=vault,
            own_agent_id="receiver_agent",
            audit_log=audit,
        )

    # Craft raw JSON with an empty envelope_signature
    import uuid, json
    from datetime import datetime, timezone

    payload_raw = {
        "version": "1.0",
        "envelope_id": str(uuid.uuid4()),
        "session_id": "sess-empty-sig",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "sender_id": "sender_agent",
        "receiver_id": "receiver_agent",
        "human_readable": "",
        "template_ref": {
            "template_id": "test_template",
            "version": "1",
            "sha256_hash": template_hash,
            "dispatcher_signature": dispatcher_sig,
            "capability_set_id": "caps_test",
            "capability_set_version": "1",
        },
        "payload": {"data": "hello"},
        "envelope_signature": "",  # EMPTY — must be rejected
    }
    raw = json.dumps(payload_raw).encode()

    # Empty hex string → bytes.fromhex("") = b"" → nacl will reject
    with pytest.raises(Exception):  # nacl.exceptions.BadSignatureError or ValueError
        validator.validate(raw, sender_vk)


def test_zero_bytes_signature_rejected(tmp_path):
    """An envelope with a 64-zero-byte hex signature must be rejected."""
    from saoe_core.audit.events_sqlite import AuditLog
    from saoe_core.crypto.keyring import generate_keypair, hash_verify_key
    from saoe_core.satl.envelope import TemplateRef

    sender_sk, sender_vk = generate_keypair()
    dispatcher_sk, dispatcher_vk = generate_keypair()

    template = _minimal_template(["sender_agent"], ["receiver_agent"])
    capset = _minimal_capset()
    vault, template_hash, dispatcher_sig = _make_mock_vault(template, capset, dispatcher_sk)

    with patch("saoe_core.crypto.keyring.DISPATCHER_KEY_HASH_PIN", hash_verify_key(dispatcher_vk)):
        audit = AuditLog(tmp_path / "events.db")
        validator = EnvelopeValidator(
            vault=vault,
            own_agent_id="receiver_agent",
            audit_log=audit,
        )

    import uuid, json
    from datetime import datetime, timezone

    payload_raw = {
        "version": "1.0",
        "envelope_id": str(uuid.uuid4()),
        "session_id": "sess-zero-sig",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "sender_id": "sender_agent",
        "receiver_id": "receiver_agent",
        "human_readable": "",
        "template_ref": {
            "template_id": "test_template",
            "version": "1",
            "sha256_hash": template_hash,
            "dispatcher_signature": dispatcher_sig,
            "capability_set_id": "caps_test",
            "capability_set_version": "1",
        },
        "payload": {"data": "hello"},
        "envelope_signature": "00" * 64,  # 64 zero bytes — must be rejected
    }
    raw = json.dumps(payload_raw).encode()

    with pytest.raises(nacl.exceptions.BadSignatureError):
        validator.validate(raw, sender_vk)
