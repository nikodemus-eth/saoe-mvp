#!/usr/bin/env python3
"""over_agent: intent → ExecutionPlan + branch envelopes.

Receives validated intent envelopes, compiles an ExecutionPlan,
and forwards branch envelopes to text_formatter_agent and image_filter_agent.
"""
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from _agent_base import build_shim, load_config
from saoe_core.audit.events_sqlite import AuditEvent
from saoe_core.crypto.keyring import hash_verify_key, load_signing_key
from saoe_core.satl.envelope import TemplateRef
from saoe_core.satl.validator import ValidationResult
from saoe_core.toolgate.toolgate import ToolCall, sign_plan


def handle(result: ValidationResult, shim, config: dict) -> None:
    queues_dir = Path(config["queues_dir"])
    keys_dir = Path(config["keys_dir"])
    vault_dir = Path(config["vault_dir"])
    payload = result.envelope.payload

    # Load over_agent's signing key (for signing ExecutionPlan)
    over_agent_sk = load_signing_key(keys_dir / "agents_private" / "over_agent.key")

    # Build ExecutionPlan for text branch
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
        signing_key=over_agent_sk,
    )
    plan_json = json.dumps({
        "plan_id": plan.plan_id,
        "session_id": plan.session_id,
        "issuer_id": plan.issuer_id,
        "timestamp_utc": plan.timestamp_utc,
        "tool_calls": [
            {"tool_call_id": tc.tool_call_id, "tool_name": tc.tool_name, "args": tc.args}
            for tc in plan.tool_calls
        ],
        "issuer_signature": plan.issuer_signature,
    })

    # Load manifests for branch templates
    manifest_dir = Path(vault_dir) / "manifests"
    text_manifest = json.loads((manifest_dir / "blog_article_intent_v1.manifest.json").read_text())

    text_tref = TemplateRef(
        template_id=text_manifest["template_id"],
        version=text_manifest["version"],
        sha256_hash=text_manifest["sha256_hash"],
        dispatcher_signature=text_manifest["dispatcher_signature"],
        capability_set_id="caps_blog_article_intent_v1",
        capability_set_version="1",
    )

    # Forward to text_formatter_agent with the execution plan embedded
    text_payload = {
        "title": payload["title"],
        "body_markdown": payload["body_markdown"],
        "image_present": payload["image_present"],
        "_execution_plan": plan_json,  # passed as context
    }

    # Note: the template schema has additionalProperties:false, so we only send
    # the schema-valid fields and attach the plan separately in context.
    # For MVP we embed the plan reference as a special field passed via metadata.
    # Full production would use a dedicated execution_plan template.
    schema_payload = {
        "title": payload["title"],
        "body_markdown": payload["body_markdown"],
        "image_present": payload["image_present"],
    }

    # Write the execution plan to the agent store for text_formatter_agent to pick up
    agent_store = Path(config["agent_stores_dir"]) / "over_agent"
    agent_store.mkdir(parents=True, exist_ok=True)
    plan_file = agent_store / f"{result.session_id}.plan.json"
    plan_file.write_text(plan_json)

    shim.send_envelope(
        receiver_id="text_formatter_agent",
        receiver_queue_dir=queues_dir / "text_formatter_agent",
        template_ref=text_tref,
        payload=schema_payload,
        session_id=result.session_id,
        human_readable=f"Text branch: {payload['title']}",
    )
    print(f"[over_agent] Compiled plan + forwarded text branch, session={result.session_id}")

    # If image is present, forward image branch too
    if payload.get("image_present"):
        img_manifest_path = manifest_dir / "image_process_intent_v1.manifest.json"
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
            img_call = ToolCall(
                tool_call_id=str(uuid.uuid4()),
                tool_name="image_sanitize",
                args={
                    "input_path": payload.get("input_image_path_token", ""),
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
                signing_key=over_agent_sk,
            )
            img_plan_json = json.dumps({
                "plan_id": img_plan.plan_id,
                "session_id": img_plan.session_id,
                "issuer_id": img_plan.issuer_id,
                "timestamp_utc": img_plan.timestamp_utc,
                "tool_calls": [
                    {"tool_call_id": tc.tool_call_id, "tool_name": tc.tool_name, "args": tc.args}
                    for tc in img_plan.tool_calls
                ],
                "issuer_signature": img_plan.issuer_signature,
            })
            plan_file2 = agent_store / f"{result.session_id}.img_plan.json"
            plan_file2.write_text(img_plan_json)

            shim.send_envelope(
                receiver_id="image_filter_agent",
                receiver_queue_dir=queues_dir / "image_filter_agent",
                template_ref=img_tref,
                payload={
                    "input_image_path_token": payload.get("input_image_path_token", ""),
                    "strip_exif": True,
                    "resize_max": 1024,
                    "output_format": "jpg",
                },
                session_id=result.session_id,
                human_readable="Image branch",
            )
            print(f"[over_agent] Forwarded image branch, session={result.session_id}")


def main() -> None:
    config = load_config()
    shim = build_shim("over_agent")
    shim.run_forever(lambda r: handle(r, shim, config))


if __name__ == "__main__":
    main()
