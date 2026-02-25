"""Shared pytest fixtures for saoe-core tests."""
import json
from pathlib import Path

import pytest

from saoe_core.crypto.keyring import generate_keypair, hash_verify_key, sign_bytes
from saoe_core.crypto.age_vault import AgeVault


# ---------------------------------------------------------------------------
# Keypair fixtures (session-scoped for speed)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def dispatcher_keypair():
    """Fresh Ed25519 keypair for the dispatcher (signs templates and capsets)."""
    return generate_keypair()


@pytest.fixture(scope="session")
def over_agent_keypair():
    """Fresh Ed25519 keypair for over_agent (signs execution plans)."""
    return generate_keypair()


@pytest.fixture(scope="session")
def intake_agent_keypair():
    """Fresh Ed25519 keypair for intake_agent (signs envelopes)."""
    return generate_keypair()


@pytest.fixture(scope="session")
def sanitization_agent_keypair():
    """Fresh Ed25519 keypair for sanitization_agent."""
    return generate_keypair()


# ---------------------------------------------------------------------------
# Audit log fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_audit_db(tmp_path: Path):
    """A fresh AuditLog backed by a temp SQLite file."""
    from saoe_core.audit.events_sqlite import AuditLog

    return AuditLog(tmp_path / "audit.db")


# ---------------------------------------------------------------------------
# Mock vault helpers
# ---------------------------------------------------------------------------


def _canonical_json(obj: dict) -> str:
    """Deterministic JSON serialisation (sort_keys, no whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _make_template(template_id: str, version: str = "1") -> dict:
    return {
        "template_id": template_id,
        "version": version,
        "json_schema": {
            "type": "object",
            "required": ["title", "body_markdown", "image_present"],
            "properties": {
                "title": {"type": "string", "maxLength": 200},
                "body_markdown": {"type": "string", "maxLength": 200000},
                "image_present": {"type": "boolean"},
            },
            "additionalProperties": False,
        },
        "policy_metadata": {
            "max_payload_bytes": 262144,
            "allowed_senders": ["intake_agent", "sanitization_agent", "over_agent"],
            "allowed_receivers": ["sanitization_agent", "over_agent"],
        },
        "capability_set_id": "caps_blog_article_intent_v1",
        "capability_set_version": "1",
    }


def _make_capset(cap_set_id: str, version: str = "1") -> dict:
    return {
        "capability_set_id": cap_set_id,
        "version": version,
        "allowed_actions": [
            {
                "action_type": "compile_intent",
                "compiler_id": "over_agent_compiler_v1",
                "allowed_templates": ["blog_article_intent"],
            }
        ],
        "tool_permissions": [],
    }


@pytest.fixture(scope="session")
def mock_vault(dispatcher_keypair):
    """AgeVault backed by in-memory entries with the session dispatcher keypair."""
    sk, vk = dispatcher_keypair
    pin = hash_verify_key(vk)

    template = _make_template("blog_article_intent")
    capset = _make_capset("caps_blog_article_intent_v1")

    entries = {
        "template:blog_article_intent:1": _canonical_json(template),
        "capset:caps_blog_article_intent_v1:1": _canonical_json(capset),
    }
    return AgeVault._from_mock(entries, dispatcher_vk=vk, dispatcher_pin=pin)


# ---------------------------------------------------------------------------
# Known agent keys registry
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def agent_keys(
    dispatcher_keypair,
    over_agent_keypair,
    intake_agent_keypair,
    sanitization_agent_keypair,
):
    """Dict of agent_id → (signing_key, verify_key)."""
    return {
        "over_agent": over_agent_keypair,
        "intake_agent": intake_agent_keypair,
        "sanitization_agent": sanitization_agent_keypair,
    }


@pytest.fixture(scope="session")
def agent_verify_keys(agent_keys):
    """Dict of agent_id → verify_key only."""
    return {aid: vk for aid, (_, vk) in agent_keys.items()}
