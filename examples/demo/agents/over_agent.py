#!/usr/bin/env python3
"""over_agent: intent → ExecutionPlan + branch envelopes.

Dispatches on template_id:
  blog_article_intent  → text ExecutionPlan → text_formatter_agent
  image_process_intent → image ExecutionPlan → image_filter_agent

This separation ensures each envelope type carries only the fields it
actually has (blog_article_intent does NOT carry input_image_path_token,
which is only present in image_process_intent).
"""
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from _agent_base import build_shim, load_config
from saoe_core.crypto.keyring import load_signing_key
from saoe_core.satl.envelope import TemplateRef
from saoe_core.satl.validator import ValidationResult
from saoe_core.toolgate.toolgate import ToolCall, sign_plan


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _plan_to_dict(plan) -> dict:
    return {
        "plan_id": plan.plan_id,
        "session_id": plan.session_id,
        "issuer_id": plan.issuer_id,
        "timestamp_utc": plan.timestamp_utc,
        "tool_calls": [
            {"tool_call_id": tc.tool_call_id, "tool_name": tc.tool_name, "args": tc.args}
            for tc in plan.tool_calls
        ],
        "issuer_signature": plan.issuer_signature,
    }


def _agent_store(config: dict) -> Path:
    store = Path(config["agent_stores_dir"]) / "over_agent"
    store.mkdir(parents=True, exist_ok=True)
    return store


def _load_manifest(vault_dir: Path, name: str) -> dict:
    return json.loads((vault_dir / "manifests" / name).read_text())


# ---------------------------------------------------------------------------
# Branch handlers
# ---------------------------------------------------------------------------

def handle_blog_article(result: ValidationResult, shim, config: dict, sk) -> None:
    """blog_article_intent → text ExecutionPlan → text_formatter_agent."""
    payload = result.envelope.payload
    queues_dir = Path(config["queues_dir"])
    vault_dir = Path(config["vault_dir"])

    text_call = ToolCall(
        tool_call_id=str(uuid.uuid4()),
        tool_name="markdown_to_html",
        args={"markdown": payload["body_markdown"]},
    )
    plan = sign_plan(
        plan_id=str(uuid.uuid4()),
        session_id=result.session_id,
        issuer_id="over_agent",
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
        tool_calls=[text_call],
        signing_key=sk,
    )
    plan_json = json.dumps(_plan_to_dict(plan))
    (_agent_store(config) / f"{result.session_id}.plan.json").write_text(plan_json)

    manifest = _load_manifest(vault_dir, "blog_article_intent_v1.manifest.json")
    tref = TemplateRef(
        template_id=manifest["template_id"],
        version=manifest["version"],
        sha256_hash=manifest["sha256_hash"],
        dispatcher_signature=manifest["dispatcher_signature"],
        capability_set_id="caps_blog_article_intent_v1",
        capability_set_version="1",
    )

    shim.send_envelope(
        receiver_id="text_formatter_agent",
        receiver_queue_dir=queues_dir / "text_formatter_agent",
        template_ref=tref,
        payload={
            "title": payload["title"],
            "body_markdown": payload["body_markdown"],
            "image_present": payload["image_present"],
        },
        session_id=result.session_id,
        human_readable=f"Text branch: {payload['title']}",
    )
    print(f"[over_agent] Compiled plan + forwarded text branch, session={result.session_id}")


def handle_image_process(result: ValidationResult, shim, config: dict, sk) -> None:
    """image_process_intent → image ExecutionPlan → image_filter_agent.

    input_image_path_token from the envelope payload is the actual image path.
    """
    payload = result.envelope.payload
    queues_dir = Path(config["queues_dir"])
    vault_dir = Path(config["vault_dir"])

    input_path = payload.get("input_image_path_token", "")
    img_call = ToolCall(
        tool_call_id=str(uuid.uuid4()),
        tool_name="image_sanitize",
        args={
            "input_path": input_path,
            "strip_exif": True,
            "resize_max": 1024,
            "output_format": "jpg",
            "output_dir": str(Path(config["output_dir"])),
        },
    )
    img_plan = sign_plan(
        plan_id=str(uuid.uuid4()),
        session_id=result.session_id,
        issuer_id="over_agent",
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
        tool_calls=[img_call],
        signing_key=sk,
    )
    img_plan_json = json.dumps(_plan_to_dict(img_plan))
    (_agent_store(config) / f"{result.session_id}.img_plan.json").write_text(img_plan_json)

    manifest = _load_manifest(vault_dir, "image_process_intent_v1.manifest.json")
    img_tref = TemplateRef(
        template_id=manifest["template_id"],
        version=manifest["version"],
        sha256_hash=manifest["sha256_hash"],
        dispatcher_signature=manifest["dispatcher_signature"],
        capability_set_id="caps_image_process_intent_v1",
        capability_set_version="1",
    )

    shim.send_envelope(
        receiver_id="image_filter_agent",
        receiver_queue_dir=queues_dir / "image_filter_agent",
        template_ref=img_tref,
        payload={
            "input_image_path_token": input_path,
            "strip_exif": True,
            "resize_max": 1024,
            "output_format": "jpg",
        },
        session_id=result.session_id,
        human_readable="Image branch",
    )
    print(f"[over_agent] Compiled img plan + forwarded image branch, session={result.session_id}")


# ---------------------------------------------------------------------------
# Main dispatcher
# ---------------------------------------------------------------------------

def handle(result: ValidationResult, shim, config: dict) -> None:
    keys_dir = Path(config["keys_dir"])
    sk = load_signing_key(keys_dir / "agents_private" / "over_agent.key")

    template_id = result.envelope.template_ref.template_id
    if template_id == "blog_article_intent":
        handle_blog_article(result, shim, config, sk)
    elif template_id == "image_process_intent":
        handle_image_process(result, shim, config, sk)
    else:
        print(
            f"[over_agent] Unknown template_id={template_id!r}, "
            f"skipping session={result.session_id}"
        )


def main() -> None:
    config = load_config()
    shim = build_shim("over_agent")
    shim.run_forever(lambda r: handle(r, shim, config))


if __name__ == "__main__":
    main()
