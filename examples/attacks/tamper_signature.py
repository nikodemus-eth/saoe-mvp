#!/usr/bin/env python3
"""Attack: Tamper with envelope payload after signing.

Demonstrates that modifying any field in a signed SATL envelope is detected
at step 3 (signature verification) before any processing occurs.

Expected outcome: BadSignatureError raised → attack BLOCKED.
Exit 0 if blocked (boundary held), exit 1 if breach.

Usage:
    python examples/attacks/tamper_signature.py
"""
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

_REPO_ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(_REPO_ROOT / "saoe-core"))
sys.path.insert(0, str(_REPO_ROOT / "saoe-openclaw"))

import nacl.exceptions

from saoe_core.audit.events_sqlite import AuditLog
from saoe_core.crypto.age_vault import AgeVault
from saoe_core.crypto.keyring import generate_keypair, hash_verify_key, load_signing_key, load_verify_key
from saoe_core.satl.envelope import TemplateRef, envelope_to_json, sign_envelope
from saoe_core.satl.validator import EnvelopeValidator


def main() -> None:
    print("=" * 60)
    print("ATTACK: Tamper Signature")
    print("=" * 60)
    print("Scenario: An attacker signs a valid envelope, then modifies")
    print("          the payload field in the raw JSON before delivery.")
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

    # Load intake_agent's signing key (the attacker controls intake_agent).
    attacker_sk = load_signing_key(keys_dir / "agents_private" / "intake_agent.key")
    attacker_vk = load_verify_key(keys_dir / "agents_public" / "intake_agent.pub")

    # Build a real vault.
    vault = AgeVault(vault_dir=vault_dir, identity_file=identity_file, dispatcher_pin=dispatcher_pin)

    # Build a real audit log.
    audit = AuditLog(Path(config["events_db"]))

    # Resolve the template and build a valid signed envelope.
    template = vault.get_template("blog_article_intent", "1")
    import hashlib

    canonical = json.dumps(template, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    sha256 = hashlib.sha256(canonical).hexdigest()

    # Build a valid template manifest signature.
    dispatcher_vk = vault.get_dispatcher_verify_key()
    from saoe_core.crypto.keyring import sign_bytes
    manifest_bytes = json.dumps(
        {"template_id": template["template_id"], "version": template["version"], "sha256_hash": sha256},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")

    # We need the dispatcher signing key to sign the manifest.
    # The attacker does NOT have it — use the one from the keys dir (it's the dispatcher key in demo).
    # In a real attack scenario, the attacker can only forge the manifest signature if they
    # have the dispatcher private key. For this demo, we load it to create a valid base envelope,
    # then corrupt the payload after signing.
    disp_sk_path = keys_dir / "agents_private" / "intake_agent.key"
    # Use the vault's manifest signature (from the vault manifest file).
    manifest_path = vault_dir / "manifests" / "blog_article_intent_v1.manifest.json"
    manifest_data = json.loads(manifest_path.read_text())
    sig_hex = manifest_data["dispatcher_signature"]

    tref = TemplateRef(
        template_id=template["template_id"],
        version=template["version"],
        sha256_hash=sha256,
        dispatcher_signature=sig_hex,
        capability_set_id=template["capability_set_id"],
        capability_set_version=template["capability_set_version"],
    )

    draft = {
        "version": "1.0",
        "envelope_id": str(uuid.uuid4()),
        "session_id": str(uuid.uuid4()),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "sender_id": "intake_agent",
        "receiver_id": "sanitization_agent",
        "human_readable": "Legitimate article",
        "template_ref": tref,
        "payload": {"title": "Honest Title", "body_markdown": "# Honest", "image_present": False},
    }

    # Step 1: Sign the envelope legitimately.
    envelope = sign_envelope(draft, attacker_sk)
    print("[*] Signed envelope created with payload: {'title': 'Honest Title', ...}")

    # Step 2: Tamper — modify the payload in the serialised JSON.
    raw_json = json.loads(envelope_to_json(envelope))
    raw_json["payload"]["title"] = "INJECTED MALICIOUS TITLE"
    tampered_json = json.dumps(raw_json, indent=2)
    print("[*] Payload tampered: title changed to 'INJECTED MALICIOUS TITLE'")
    print()

    # Step 3: Attempt to validate the tampered envelope.
    validator = EnvelopeValidator(
        vault=vault,
        own_agent_id="sanitization_agent",
        audit_log=audit,
    )

    try:
        validator.validate(tampered_json.encode(), attacker_vk)
        print("BREACH: Tampered envelope was ACCEPTED. Security boundary FAILED.", file=sys.stderr)
        sys.exit(1)
    except nacl.exceptions.BadSignatureError as exc:
        print(f"[+] BadSignatureError raised: {exc}")
        print()
        print("BLOCKED: Tampered envelope rejected at step 3 (signature verification).")
        print("         No processing occurred. Boundary held.")
        sys.exit(0)
    except Exception as exc:
        print(f"UNEXPECTED ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
