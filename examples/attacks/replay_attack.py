#!/usr/bin/env python3
"""Attack: Replay a previously validated envelope_id.

Demonstrates that submitting the same envelope_id a second time is rejected
at step 12 (replay protection via SQLite UNIQUE constraint on 'validated' events).

Expected outcome: ReplayAttackError raised → attack BLOCKED.
Exit 0 if blocked (boundary held), exit 1 if breach.

Usage:
    python examples/attacks/replay_attack.py
"""
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

_REPO_ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(_REPO_ROOT / "saoe-core"))
sys.path.insert(0, str(_REPO_ROOT / "saoe-openclaw"))

import hashlib

from saoe_core.audit.events_sqlite import AuditLog, ReplayAttackError
from saoe_core.crypto.age_vault import AgeVault
from saoe_core.crypto.keyring import load_signing_key, load_verify_key
from saoe_core.satl.envelope import TemplateRef, sign_envelope
from saoe_core.satl.validator import EnvelopeValidator


def _build_tref(vault: AgeVault, vault_dir: Path) -> TemplateRef:
    template = vault.get_template("blog_article_intent", "1")
    canonical = json.dumps(template, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    sha256 = hashlib.sha256(canonical).hexdigest()
    manifest_path = vault_dir / "manifests" / "blog_article_intent_v1.manifest.json"
    sig_hex = json.loads(manifest_path.read_text())["dispatcher_signature"]
    return TemplateRef(
        template_id=template["template_id"],
        version=template["version"],
        sha256_hash=sha256,
        dispatcher_signature=sig_hex,
        capability_set_id=template["capability_set_id"],
        capability_set_version=template["capability_set_version"],
    )


def main() -> None:
    print("=" * 60)
    print("ATTACK: Replay Attack")
    print("=" * 60)
    print("Scenario: An attacker captures a valid, processed envelope and")
    print("          re-submits it with the same envelope_id to trigger")
    print("          duplicate processing.")
    print()

    # Load demo environment.
    demo_dir = _REPO_ROOT / "examples" / "demo"
    config_path = demo_dir / "demo_config.json"
    if not config_path.exists():
        print("ERROR: demo_config.json not found. Run setup_demo.py first.", file=sys.stderr)
        sys.exit(1)

    config = json.loads(config_path.read_text())
    keys_dir = Path(config["keys_dir"])
    vault_dir = Path(config["vault_dir"])
    identity_file = Path(config["age_identity_file"])
    dispatcher_pin = config["dispatcher_pin"]

    sk = load_signing_key(keys_dir / "agents_private" / "intake_agent.key")
    vk = load_verify_key(keys_dir / "agents_public" / "intake_agent.pub")

    vault = AgeVault(vault_dir=vault_dir, identity_file=identity_file, dispatcher_pin=dispatcher_pin)
    audit = AuditLog(Path(config["events_db"]))

    tref = _build_tref(vault, vault_dir)

    # Step 1: Create and submit a valid envelope (first submission — should succeed).
    fixed_envelope_id = str(uuid.uuid4())
    draft = {
        "version": "1.0",
        "envelope_id": fixed_envelope_id,
        "session_id": str(uuid.uuid4()),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "sender_id": "intake_agent",
        "receiver_id": "sanitization_agent",
        "human_readable": "Original submission",
        "template_ref": tref,
        "payload": {"title": "First", "body_markdown": "# First", "image_present": False},
    }

    envelope = sign_envelope(draft, sk)
    validator = EnvelopeValidator(
        vault=vault,
        own_agent_id="sanitization_agent",
        audit_log=audit,
    )

    print(f"[*] Submitting envelope_id={fixed_envelope_id[:16]}... (first time)")
    validator.validate(envelope, vk)
    print("[+] First submission accepted (expected).")
    print()

    # Step 2: Replay — re-submit the same envelope_id (a second fresh session, same ID).
    replay_draft = {
        "version": "1.0",
        "envelope_id": fixed_envelope_id,  # SAME envelope_id!
        "session_id": str(uuid.uuid4()),   # New session doesn't help
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "sender_id": "intake_agent",
        "receiver_id": "sanitization_agent",
        "human_readable": "Replay attempt",
        "template_ref": tref,
        "payload": {"title": "Replay", "body_markdown": "# Replay", "image_present": False},
    }

    replay_envelope = sign_envelope(replay_draft, sk)
    print(f"[*] Replaying same envelope_id={fixed_envelope_id[:16]}... (second time)")

    try:
        validator.validate(replay_envelope, vk)
        print("BREACH: Replay was ACCEPTED. Security boundary FAILED.", file=sys.stderr)
        sys.exit(1)
    except ReplayAttackError as exc:
        print(f"[+] ReplayAttackError raised: {exc}")
        print()
        print("BLOCKED: Replay rejected at step 12 (SQLite UNIQUE constraint on validated events).")
        print("         The attacker cannot re-process a consumed envelope_id.")
        sys.exit(0)
    except Exception as exc:
        print(f"UNEXPECTED ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
