"""Publisher command: ``saoe-publish-template``.

FT-010: Publisher requires the operator to type the template's sha256 hash
to confirm publication.  This prevents accidental or automated template
overwrites without human review.

Vault layout after publishing:
  vault/templates/<template_id>_v<version>.json.age
  vault/capsets/<cap_set_id>_v<version>.json.age
  vault/manifests/<template_id>_v<version>.manifest.json  (plaintext, signed)
"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import nacl.signing

from saoe_core.crypto.keyring import sign_bytes


# ---------------------------------------------------------------------------
# Core publishing logic
# ---------------------------------------------------------------------------


def _canonical_json_bytes(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def publish_template(
    template_path: Path,
    vault_dir: Path,
    dispatcher_signing_key: nacl.signing.SigningKey,
    age_identity_file: Path | None = None,
    age_recipient: str | None = None,
) -> str:
    """Publish a template to the vault with FT-010 confirmation gate.

    Parameters
    ----------
    template_path:
        Path to the plaintext template JSON file.
    vault_dir:
        Path to the vault directory.
    dispatcher_signing_key:
        Dispatcher's Ed25519 signing key.
    age_identity_file:
        age identity file for encryption (optional in no-age mode for tests).
    age_recipient:
        age public key recipient string for encryption.

    Returns
    -------
    str
        Hex SHA-256 of the published template.

    Raises
    ------
    SystemExit
        If the operator types the wrong sha256 (FT-010 gate).
    """
    raw = template_path.read_bytes()
    try:
        template = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"ERROR: Invalid JSON in template file: {exc}", file=sys.stderr)
        raise SystemExit(1)

    canonical = _canonical_json_bytes(template)
    sha256 = _sha256_hex(canonical)

    template_id = template["template_id"]
    version = template["version"]

    # Show existing manifest diff if template already exists in vault.
    manifest_path = vault_dir / "manifests" / f"{template_id}_v{version}.manifest.json"
    if manifest_path.exists():
        old_manifest = json.loads(manifest_path.read_text())
        print(f"\nEXISTING MANIFEST for {template_id} v{version}:")
        print(json.dumps(old_manifest, indent=2))
        print("\nNEW sha256:", sha256)
        print("DIFF: template is being UPDATED.")
    else:
        print(f"\nNEW template: {template_id} v{version}")
        print(f"sha256: {sha256}")

    # FT-010: Require operator to type the sha256 to confirm.
    print(
        "\nTo confirm publication, type the sha256 hash above and press Enter."
        "\n(Ctrl-C to abort)"
    )
    try:
        typed = input("sha256: ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\nAborted.", file=sys.stderr)
        raise SystemExit(0)

    if typed != sha256:
        print(
            f"\nERROR: sha256 mismatch. You typed:\n  {typed}\nExpected:\n  {sha256}\n"
            "Publication aborted.",
            file=sys.stderr,
        )
        raise SystemExit(1)

    # Build and sign the manifest.
    manifest_bytes = json.dumps(
        {"template_id": template_id, "version": version, "sha256_hash": sha256},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    sig_hex = sign_bytes(dispatcher_signing_key, manifest_bytes).hex()

    manifest = {
        "template_id": template_id,
        "version": version,
        "sha256_hash": sha256,
        "dispatcher_signature": sig_hex,
    }

    # Write files.
    (vault_dir / "templates").mkdir(parents=True, exist_ok=True)
    (vault_dir / "manifests").mkdir(parents=True, exist_ok=True)

    # Encrypt with age if available, else write plaintext (with a warning).
    age_bin = _find_age()
    enc_path = vault_dir / "templates" / f"{template_id}_v{version}.json.age"

    if age_bin and age_recipient:
        _age_encrypt(age_bin, canonical, age_recipient, enc_path)
    else:
        # Plaintext mode (no age in test environments).
        enc_path.write_bytes(canonical)
        print("WARNING: age not configured — template stored in plaintext.", file=sys.stderr)

    # Write plaintext manifest (signed).
    manifest_path.write_text(json.dumps(manifest, indent=2))

    print(f"\nPublished: {template_id} v{version}")
    print(f"  Template: {enc_path}")
    print(f"  Manifest: {manifest_path}")
    return sha256


def _find_age() -> str | None:
    import shutil
    return shutil.which("age") or (
        "/opt/homebrew/bin/age"
        if Path("/opt/homebrew/bin/age").exists()
        else None
    )


def _age_encrypt(age_bin: str, plaintext: bytes, recipient: str, out_path: Path) -> None:
    result = subprocess.run(
        [age_bin, "-r", recipient, "-o", str(out_path)],
        input=plaintext,
        capture_output=True,
        timeout=10,
        check=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"age encrypt failed: {result.stderr.decode()}")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Entry point for ``saoe-publish-template`` command."""
    import argparse

    from saoe_core.crypto.keyring import load_signing_key

    parser = argparse.ArgumentParser(description="Publish a template to the SAOE vault.")
    parser.add_argument("template", type=Path, help="Path to template JSON file")
    parser.add_argument("vault_dir", type=Path, help="Path to vault directory")
    parser.add_argument("signing_key", type=Path, help="Dispatcher signing key file (32-byte raw)")
    parser.add_argument("--age-recipient", help="age public key recipient for encryption")
    args = parser.parse_args()

    sk = load_signing_key(args.signing_key)
    publish_template(
        template_path=args.template,
        vault_dir=args.vault_dir,
        dispatcher_signing_key=sk,
        age_recipient=args.age_recipient,
    )
