#!/usr/bin/env python3
"""setup_demo.py: One-time demo environment initialisation.

Creates all keys, publishes all templates and capability sets to the vault,
writes demo_config.json, and makes the vault read-only.

Run once from the repo root:
    python examples/demo/setup_demo.py

Then follow the printed instructions to paste the key hash pins into
the source code (they cannot be auto-patched — that is FT-001 by design).

Re-running will regenerate keys and republish templates. The vault will be
made writable first, then read-only again at the end.
"""
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Path bootstrap
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(_REPO_ROOT / "saoe-core"))

from saoe_core.crypto.keyring import (  # noqa: E402
    generate_keypair,
    hash_verify_key,
    sign_bytes,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEMO_DIR = Path(__file__).parent
_TEMPLATES_DIR = _DEMO_DIR / "templates_plain"

_BASE = Path("/tmp/saoe")
_VAULT_DIR = _BASE / "vault"
_KEYS_DIR = _BASE / "keys"
_QUEUES_DIR = _BASE / "queues"
_QUARANTINE_DIR = _BASE / "quarantine"
_AGENT_STORES_DIR = _BASE / "agent_stores"
_OUTPUT_DIR = _BASE / "output"
_EVENTS_DB = _BASE / "events.db"
_AGE_IDENTITY = _VAULT_DIR / "age_identity.key"

_AGENT_IDS = [
    "intake_agent",
    "sanitization_agent",
    "over_agent",
    "text_formatter_agent",
    "image_filter_agent",
    "deployment_agent",
]

_CAPSETS = {
    "caps_blog_article_intent_v1": {
        "capability_set_id": "caps_blog_article_intent_v1",
        "version": "1",
        "allowed_actions": [
            {
                "action_type": "compile_intent",
                "compiler_id": "over_agent_compiler_v1",
                "allowed_templates": ["blog_article_intent"],
            }
        ],
        "tool_permissions": [],
    },
    "caps_image_process_intent_v1": {
        "capability_set_id": "caps_image_process_intent_v1",
        "version": "1",
        "allowed_actions": [
            {
                "action_type": "image_sanitize",
                "compiler_id": "over_agent_compiler_v1",
                "allowed_templates": ["image_process_intent"],
            }
        ],
        "tool_permissions": [
            {"tool": "image_sanitize", "allowed_args": ["input_path", "strip_exif", "resize_max", "output_format", "output_dir"]},
        ],
    },
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_age() -> str:
    age = shutil.which("age") or (
        "/opt/homebrew/bin/age" if Path("/opt/homebrew/bin/age").exists() else None
    )
    if age is None:
        print("ERROR: 'age' binary not found. Install with: brew install age", file=sys.stderr)
        sys.exit(1)
    return age


def _find_age_keygen() -> str:
    kg = shutil.which("age-keygen") or (
        "/opt/homebrew/bin/age-keygen"
        if Path("/opt/homebrew/bin/age-keygen").exists()
        else None
    )
    if kg is None:
        print("ERROR: 'age-keygen' not found. Install with: brew install age", file=sys.stderr)
        sys.exit(1)
    return kg


def _canonical_json_bytes(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _age_encrypt(age_bin: str, plaintext: bytes, recipient: str, out_path: Path) -> None:
    subprocess.run(
        [age_bin, "-r", recipient, "-o", str(out_path)],
        input=plaintext,
        capture_output=True,
        timeout=10,
        check=True,
    )


def _make_vault_writable() -> None:
    """Temporarily make the vault directory writable for re-setup."""
    if _VAULT_DIR.exists():
        for p in _VAULT_DIR.rglob("*"):
            try:
                p.chmod(p.stat().st_mode | stat.S_IWRITE | stat.S_IUSR)
            except Exception:
                pass
        _VAULT_DIR.chmod(_VAULT_DIR.stat().st_mode | stat.S_IWRITE | stat.S_IUSR)


def _make_vault_readonly() -> None:
    """Remove write permission from vault directory (FT-001)."""
    for p in _VAULT_DIR.rglob("*"):
        try:
            current = p.stat().st_mode
            p.chmod(current & ~(stat.S_IWRITE | stat.S_IWGRP | stat.S_IWOTH))
        except Exception:
            pass
    try:
        current = _VAULT_DIR.stat().st_mode
        _VAULT_DIR.chmod(current & ~(stat.S_IWRITE | stat.S_IWGRP | stat.S_IWOTH))
    except Exception:
        pass


def _publish_item(
    item_dict: dict,
    subdir: str,
    id_key: str,
    age_bin: str,
    age_recipient: str,
    dispatcher_sk,
) -> str:
    """Encrypt and sign one template or capset, write to vault. Return sha256."""
    item_id = item_dict[id_key]
    version = item_dict["version"]
    canonical = _canonical_json_bytes(item_dict)
    sha256 = _sha256_hex(canonical)

    out_dir = _VAULT_DIR / subdir
    out_dir.mkdir(parents=True, exist_ok=True)

    enc_path = out_dir / f"{item_id}_v{version}.json.age"
    _age_encrypt(age_bin, canonical, age_recipient, enc_path)

    # Sign the manifest for templates (capsets use same pattern).
    manifest_bytes = json.dumps(
        {"template_id": item_id, "version": version, "sha256_hash": sha256},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    sig_hex = sign_bytes(dispatcher_sk, manifest_bytes).hex()

    manifest = {
        "template_id": item_id,
        "version": version,
        "sha256_hash": sha256,
        "dispatcher_signature": sig_hex,
    }
    manifest_dir = _VAULT_DIR / "manifests"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    (manifest_dir / f"{item_id}_v{version}.manifest.json").write_text(json.dumps(manifest, indent=2))

    print(f"  Published {subdir}/{item_id}_v{version}  sha256={sha256[:16]}…")
    return sha256


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    print("=" * 60)
    print("SAOE Demo Setup")
    print("=" * 60)

    age_bin = _find_age()
    age_keygen_bin = _find_age_keygen()

    # ------------------------------------------------------------------
    # 1. Create directories
    # ------------------------------------------------------------------
    print("\n[1/7] Creating directories…")
    _make_vault_writable()
    for d in [
        _VAULT_DIR / "keys",
        _VAULT_DIR / "templates",
        _VAULT_DIR / "capsets",
        _VAULT_DIR / "manifests",
        _KEYS_DIR / "agents_private",
        _KEYS_DIR / "agents_public",
        _QUARANTINE_DIR,
        _OUTPUT_DIR,
        _AGENT_STORES_DIR,
    ]:
        d.mkdir(parents=True, exist_ok=True)

    # Separate queues per agent
    for aid in _AGENT_IDS:
        (_QUEUES_DIR / aid).mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # 2. Generate age identity key
    # ------------------------------------------------------------------
    print("\n[2/7] Generating age identity key…")
    result = subprocess.run(
        [age_keygen_bin, "-o", str(_AGE_IDENTITY)],
        capture_output=True, check=True,
    )
    # age-keygen writes key to file and prints public key to stderr:
    # e.g. "Public key: age1..."
    stderr_text = result.stderr.decode("utf-8", errors="replace")
    age_pubkey = None
    for line in stderr_text.splitlines():
        m = re.search(r"Public key:\s*(age1\S+)", line)
        if m:
            age_pubkey = m.group(1)
            break
    if age_pubkey is None:
        print(f"ERROR: Could not parse age public key from keygen output:\n{stderr_text}", file=sys.stderr)
        sys.exit(1)

    # Secure the identity file (must be 0600 for AgeVault).
    _AGE_IDENTITY.chmod(0o600)
    print(f"  age public key: {age_pubkey}")

    # ------------------------------------------------------------------
    # 3. Generate dispatcher keypair
    # ------------------------------------------------------------------
    print("\n[3/7] Generating dispatcher keypair…")
    dispatcher_sk, dispatcher_vk = generate_keypair()
    dispatcher_pin = hash_verify_key(dispatcher_vk)

    # Write dispatcher verify key to vault/keys/ (plaintext; agents load this at startup).
    disp_vk_path = _VAULT_DIR / "keys" / "dispatcher_verify.pub"
    disp_vk_path.write_bytes(bytes(dispatcher_vk))
    print(f"  Dispatcher verify key: {bytes(dispatcher_vk).hex()[:16]}…")
    print(f"  DISPATCHER_KEY_HASH_PIN = \"{dispatcher_pin}\"")

    # ------------------------------------------------------------------
    # 4. Generate agent keypairs
    # ------------------------------------------------------------------
    print("\n[4/7] Generating agent keypairs…")
    over_agent_vk = None
    for aid in _AGENT_IDS:
        sk, vk = generate_keypair()
        # Save signing key (raw 32-byte seed)
        sk_path = _KEYS_DIR / "agents_private" / f"{aid}.key"
        sk_path.write_bytes(sk.encode())  # nacl SigningKey.encode() = seed bytes
        sk_path.chmod(0o600)
        # Save verify key (raw 32-byte pubkey)
        vk_path = _KEYS_DIR / "agents_public" / f"{aid}.pub"
        vk_path.write_bytes(bytes(vk))
        print(f"  {aid}: vk={bytes(vk).hex()[:16]}…")
        if aid == "over_agent":
            over_agent_vk = vk

    issuer_pin = hash_verify_key(over_agent_vk)

    # ------------------------------------------------------------------
    # 5. Publish templates and capsets
    # ------------------------------------------------------------------
    print("\n[5/7] Publishing templates and capability sets…")

    template_files = sorted(_TEMPLATES_DIR.glob("*.v1.json"))
    if not template_files:
        print(f"ERROR: No template files found in {_TEMPLATES_DIR}", file=sys.stderr)
        sys.exit(1)

    for tfile in template_files:
        template = json.loads(tfile.read_text())
        _publish_item(template, "templates", "template_id", age_bin, age_pubkey, dispatcher_sk)

    for cap_set_id, capset in _CAPSETS.items():
        _publish_item(capset, "capsets", "capability_set_id", age_bin, age_pubkey, dispatcher_sk)

    # ------------------------------------------------------------------
    # 6. Make vault read-only (FT-001)
    # ------------------------------------------------------------------
    print("\n[6/7] Making vault read-only (FT-001)…")
    _make_vault_readonly()
    print(f"  Vault is now read-only: {_VAULT_DIR}")

    # ------------------------------------------------------------------
    # 7. Write demo_config.json
    # ------------------------------------------------------------------
    print("\n[7/7] Writing demo_config.json…")
    config = {
        "vault_dir": str(_VAULT_DIR),
        "keys_dir": str(_KEYS_DIR),
        "queues_dir": str(_QUEUES_DIR),
        "quarantine_dir": str(_QUARANTINE_DIR),
        "agent_stores_dir": str(_AGENT_STORES_DIR),
        "output_dir": str(_OUTPUT_DIR),
        "events_db": str(_EVENTS_DB),
        "age_identity_file": str(_AGE_IDENTITY),
        "dispatcher_pin": dispatcher_pin,
        "issuer_pin": issuer_pin,
    }
    config_path = _DEMO_DIR / "demo_config.json"
    config_path.write_text(json.dumps(config, indent=2))
    print(f"  Written: {config_path}")

    # ------------------------------------------------------------------
    # Done — print instructions
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("SETUP COMPLETE")
    print("=" * 60)
    print("""
Next steps:
  (these pins are ALREADY written to demo_config.json, but if you use
   the standalone keyring/toolgate modules they need to be patched in)

  DISPATCHER_KEY_HASH_PIN:
    """ + f'"{dispatcher_pin}"' + """
  (paste into saoe_core/crypto/keyring.py if using standalone modules)

  ISSUER_KEY_HASH_PIN (over_agent verify key hash):
    """ + f'"{issuer_pin}"' + """
  (paste into saoe_core/toolgate/toolgate.py if using standalone modules)

To start the demo pipeline, run each agent in a separate terminal:

  cd """ + str(_DEMO_DIR / "agents") + """
  python sanitization_agent.py
  python over_agent.py
  python text_formatter_agent.py
  python image_filter_agent.py
  python deployment_agent.py

  # In another terminal:
  python """ + str(_DEMO_DIR / "serve_log_viewer.py") + """ --db """ + str(_EVENTS_DB) + """

  # Trigger intake:
  python intake_agent.py --title "Hello SAOE" --markdown "# Test"

  # Check output:
  ls """ + str(_OUTPUT_DIR) + """
  open http://localhost:8080
""")


if __name__ == "__main__":
    main()
