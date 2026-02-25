"""Tests for saoe_core.crypto.age_vault — read-only vault with mock entries."""
import json
import shutil

import pytest

from saoe_core.crypto.age_vault import AgeVault, VaultEntryNotFoundError
from saoe_core.crypto.keyring import generate_keypair, hash_verify_key


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_mock_vault(dispatcher_keypair, entries: dict | None = None) -> AgeVault:
    """Build an AgeVault with mock entries, bypassing age CLI."""
    sk, vk = dispatcher_keypair
    pin = hash_verify_key(vk)
    mock_data = entries or {}
    return AgeVault._from_mock(mock_data, dispatcher_vk=vk, dispatcher_pin=pin)


def make_template_entry(template_id: str = "blog_article_intent", version: str = "1") -> dict:
    return {
        "template_id": template_id,
        "version": version,
        "json_schema": {
            "type": "object",
            "required": ["title"],
            "properties": {"title": {"type": "string"}},
            "additionalProperties": False,
        },
        "policy_metadata": {
            "max_payload_bytes": 1024,
            "allowed_senders": ["intake_agent"],
            "allowed_receivers": ["sanitization_agent"],
        },
        "capability_set_id": "caps_v1",
        "capability_set_version": "1",
    }


def make_capset_entry() -> dict:
    return {
        "capability_set_id": "caps_v1",
        "version": "1",
        "allowed_actions": [],
        "tool_permissions": [],
    }


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_get_template_returns_dict(dispatcher_keypair) -> None:
    template = make_template_entry()
    entries = {"template:blog_article_intent:1": json.dumps(template)}
    vault = make_mock_vault(dispatcher_keypair, entries)

    result = vault.get_template("blog_article_intent", "1")
    assert result["template_id"] == "blog_article_intent"


def test_get_capability_set_returns_dict(dispatcher_keypair) -> None:
    capset = make_capset_entry()
    entries = {"capset:caps_v1:1": json.dumps(capset)}
    vault = make_mock_vault(dispatcher_keypair, entries)

    result = vault.get_capability_set("caps_v1", "1")
    assert result["capability_set_id"] == "caps_v1"


def test_get_dispatcher_verify_key(dispatcher_keypair) -> None:
    _, vk = dispatcher_keypair
    vault = make_mock_vault(dispatcher_keypair, {})
    loaded_vk = vault.get_dispatcher_verify_key()
    assert bytes(loaded_vk) == bytes(vk)


# ---------------------------------------------------------------------------
# Not found
# ---------------------------------------------------------------------------


def test_get_template_not_found_raises(dispatcher_keypair) -> None:
    vault = make_mock_vault(dispatcher_keypair, {})
    with pytest.raises(VaultEntryNotFoundError):
        vault.get_template("nonexistent", "1")


def test_get_capset_not_found_raises(dispatcher_keypair) -> None:
    vault = make_mock_vault(dispatcher_keypair, {})
    with pytest.raises(VaultEntryNotFoundError):
        vault.get_capability_set("nonexistent", "1")


# ---------------------------------------------------------------------------
# FT-001: dispatcher pin mismatch aborts at init
# ---------------------------------------------------------------------------


def test_dispatcher_pin_mismatch_raises_at_init() -> None:
    _, vk = generate_keypair()
    _, other_vk = generate_keypair()
    wrong_pin = hash_verify_key(other_vk)  # pin for a different key
    from saoe_core.crypto.keyring import DispatcherKeyMismatchError

    with pytest.raises(DispatcherKeyMismatchError):
        AgeVault._from_mock({}, dispatcher_vk=vk, dispatcher_pin=wrong_pin)


# ---------------------------------------------------------------------------
# age CLI integration (skipped if age not on PATH)
# ---------------------------------------------------------------------------

AGE_AVAILABLE = shutil.which("age") is not None or shutil.which("/opt/homebrew/bin/age") is not None


@pytest.mark.skipif(not AGE_AVAILABLE, reason="age CLI not available")
def test_real_age_encrypt_decrypt(tmp_path, dispatcher_keypair) -> None:
    """Smoke test: age-keygen → encrypt → decrypt round trip."""
    import subprocess

    age_bin = shutil.which("age") or "/opt/homebrew/bin/age"
    age_keygen = age_bin + "-keygen" if not shutil.which("age-keygen") else shutil.which("age-keygen")
    age_keygen = age_keygen or "/opt/homebrew/bin/age-keygen"

    identity_file = tmp_path / "identity.txt"
    result = subprocess.run(
        [age_keygen, "-o", str(identity_file)],
        capture_output=True,
        check=True,
    )
    pub_line = [l for l in identity_file.read_text().splitlines() if "public key:" in l]
    assert pub_line, "Could not parse public key from age-keygen output"
    recipient = pub_line[0].split("public key:")[1].strip()

    plaintext = b'{"hello": "world"}'
    enc_file = tmp_path / "test.json.age"
    subprocess.run(
        [age_bin, "-r", recipient, "-o", str(enc_file)],
        input=plaintext,
        capture_output=True,
        check=True,
    )

    dec_result = subprocess.run(
        [age_bin, "--decrypt", "-i", str(identity_file), str(enc_file)],
        capture_output=True,
        check=True,
    )
    assert dec_result.stdout == plaintext
