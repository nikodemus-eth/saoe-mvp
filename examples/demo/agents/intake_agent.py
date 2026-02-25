#!/usr/bin/env python3
"""intake_agent: CLI → quarantine intent envelope.

One-shot agent: takes CLI arguments and drops a signed SATL envelope
into the sanitization_agent queue.

Usage:
  python intake_agent.py --title "Hello SAOE" --markdown "# Test"
  python intake_agent.py --title "Hello" --markdown "# Test" --image /path/to.jpg
"""
import argparse
import json
import sys
from pathlib import Path

# Add saoe-core and saoe-openclaw to path if running directly
_REPO_ROOT = Path(__file__).parents[3]
sys.path.insert(0, str(_REPO_ROOT / "saoe-core"))
sys.path.insert(0, str(_REPO_ROOT / "saoe-openclaw"))

import nacl.signing
from saoe_core.crypto.keyring import (
    hash_verify_key,
    load_signing_key,
    sign_bytes,
)
from saoe_core.satl.envelope import TemplateRef, envelope_to_json, sign_envelope
from saoe_core.audit.events_sqlite import AuditEvent, AuditLog
import uuid
from datetime import datetime, timezone


def load_demo_config(demo_dir: Path) -> dict:
    config_file = demo_dir / "demo_config.json"
    return json.loads(config_file.read_text())


def main() -> None:
    parser = argparse.ArgumentParser(description="SAOE intake agent")
    parser.add_argument("--title", required=True, help="Article title")
    parser.add_argument("--markdown", required=True, help="Article body in Markdown")
    parser.add_argument("--image", help="Optional path to image file")
    parser.add_argument("--demo-dir", type=Path, default=Path(__file__).parent.parent,
                        help="Path to the demo directory (default: examples/demo/)")
    args = parser.parse_args()

    demo_dir = args.demo_dir
    config = load_demo_config(demo_dir)
    keys_dir = Path(config["keys_dir"])
    queues_dir = Path(config["queues_dir"])

    # Load intake_agent signing key
    sk = load_signing_key(keys_dir / "agents_private" / "intake_agent.key")

    # Load dispatcher manifest for template_ref
    manifest_path = Path(config["vault_dir"]) / "manifests" / "blog_article_intent_v1.manifest.json"
    manifest = json.loads(manifest_path.read_text())

    image_present = args.image is not None
    payload = {
        "title": args.title,
        "body_markdown": args.markdown,
        "image_present": image_present,
    }

    template_ref = TemplateRef(
        template_id=manifest["template_id"],
        version=manifest["version"],
        sha256_hash=manifest["sha256_hash"],
        dispatcher_signature=manifest["dispatcher_signature"],
        capability_set_id="caps_blog_article_intent_v1",
        capability_set_version="1",
    )

    session_id = str(uuid.uuid4())
    draft = {
        "version": "1.0",
        "envelope_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "sender_id": "intake_agent",
        "receiver_id": "sanitization_agent",
        "human_readable": f"Blog article: {args.title}",
        "template_ref": template_ref,
        "payload": payload,
    }

    envelope = sign_envelope(draft, sk)
    out_dir = queues_dir / "sanitization_agent"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"{envelope.envelope_id}.satl.json"
    out_file.write_text(envelope_to_json(envelope))

    print(f"[intake_agent] Submitted session_id={session_id}")
    print(f"[intake_agent] Envelope: {out_file}")

    if image_present:
        # Also send an image intent envelope to the image branch
        img_manifest_path = (
            Path(config["vault_dir"]) / "manifests" / "image_process_intent_v1.manifest.json"
        )
        if img_manifest_path.exists():
            img_manifest = json.loads(img_manifest_path.read_text())
            img_tref = TemplateRef(
                template_id=img_manifest["template_id"],
                version=img_manifest["version"],
                sha256_hash=img_manifest["sha256_hash"],
                dispatcher_signature=img_manifest["dispatcher_signature"],
                capability_set_id="caps_image_process_intent_v1",
                capability_set_version="1",
            )
            img_payload = {
                "input_image_path_token": str(args.image),
                "strip_exif": True,
                "resize_max": 1024,
                "output_format": "jpg",
            }
            img_draft = {
                "version": "1.0",
                "envelope_id": str(uuid.uuid4()),
                "session_id": session_id,
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "sender_id": "intake_agent",
                "receiver_id": "sanitization_agent",
                "human_readable": f"Image for: {args.title}",
                "template_ref": img_tref,
                "payload": img_payload,
            }
            img_envelope = sign_envelope(img_draft, sk)
            img_file = out_dir / f"{img_envelope.envelope_id}.satl.json"
            img_file.write_text(envelope_to_json(img_envelope))
            print(f"[intake_agent] Image envelope: {img_file}")


if __name__ == "__main__":
    main()
