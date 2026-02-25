#!/usr/bin/env python3
"""text_formatter_agent: markdown_to_html via ToolGate → deploy/text queue."""
import json
from pathlib import Path

import bleach
import markdown

from _agent_base import build_shim, load_config
from saoe_core.audit.events_sqlite import AuditEvent
from saoe_core.crypto.keyring import hash_verify_key, load_verify_key
from saoe_core.satl.envelope import TemplateRef
from saoe_core.satl.validator import ValidationResult
from saoe_core.toolgate.toolgate import ExecutionPlan, ToolCall, ToolGate, sign_plan


# ---------------------------------------------------------------------------
# Tool implementation (FT-008: safe HTML via bleach)
# ---------------------------------------------------------------------------

_ALLOWED_TAGS = list(bleach.sanitizer.ALLOWED_TAGS) + [
    "h1", "h2", "h3", "h4", "h5", "h6",
    "pre", "code", "blockquote", "br", "hr",
    "table", "thead", "tbody", "tr", "th", "td",
]
_ALLOWED_ATTRS = dict(bleach.sanitizer.ALLOWED_ATTRIBUTES)


def markdown_to_html_tool(args: dict, context: dict) -> dict:
    """Convert Markdown to sanitized HTML (FT-008)."""
    md_text = args["markdown"]
    raw_html = markdown.markdown(md_text, extensions=["fenced_code", "tables"])
    safe_html = bleach.clean(raw_html, tags=_ALLOWED_TAGS, attributes=_ALLOWED_ATTRS, strip=True)
    return {"html_fragment": safe_html}


_MD_TO_HTML_SCHEMA = {
    "type": "object",
    "required": ["markdown"],
    "properties": {"markdown": {"type": "string", "maxLength": 200000}},
    "additionalProperties": False,
}


def _load_toolgate(config: dict) -> tuple[ToolGate, object]:
    from saoe_core.audit.events_sqlite import AuditLog

    keys_dir = Path(config["keys_dir"])
    over_agent_vk = load_verify_key(keys_dir / "agents_public" / "over_agent.pub")
    over_agent_pin = hash_verify_key(over_agent_vk)
    audit = AuditLog(Path(config["events_db"]))

    gate = ToolGate(issuer_verify_key=over_agent_vk, issuer_pin=over_agent_pin, audit_log=audit)
    gate.register_tool("markdown_to_html", markdown_to_html_tool, _MD_TO_HTML_SCHEMA)
    return gate, audit


def _load_plan(config: dict, session_id: str) -> ExecutionPlan | None:
    """Load the execution plan written by over_agent for this session."""
    plan_file = Path(config["agent_stores_dir"]) / "over_agent" / f"{session_id}.plan.json"
    if not plan_file.exists():
        return None
    plan_data = json.loads(plan_file.read_text())
    tool_calls = tuple(
        ToolCall(
            tool_call_id=tc["tool_call_id"],
            tool_name=tc["tool_name"],
            args=tc["args"],
        )
        for tc in plan_data["tool_calls"]
    )
    return ExecutionPlan(
        plan_id=plan_data["plan_id"],
        session_id=plan_data["session_id"],
        issuer_id=plan_data["issuer_id"],
        timestamp_utc=plan_data["timestamp_utc"],
        tool_calls=tool_calls,
        issuer_signature=plan_data["issuer_signature"],
    )


def handle(result: ValidationResult, shim, config: dict, gate: ToolGate) -> None:
    queues_dir = Path(config["queues_dir"])
    payload = result.envelope.payload

    plan = _load_plan(config, result.session_id)
    if plan is None:
        print(f"[text_formatter_agent] No plan found for session={result.session_id}, skipping")
        return

    tool_results = gate.execute(plan, context={})
    html_fragment = tool_results[0]["html_fragment"]

    # Load deploy manifest
    manifest_dir = Path(config["vault_dir"]) / "manifests"
    manifest = json.loads((manifest_dir / "blog_article_intent_v1.manifest.json").read_text())
    tref = TemplateRef(
        template_id=manifest["template_id"],
        version=manifest["version"],
        sha256_hash=manifest["sha256_hash"],
        dispatcher_signature=manifest["dispatcher_signature"],
        capability_set_id="caps_blog_article_intent_v1",
        capability_set_version="1",
    )

    shim.send_envelope(
        receiver_id="deployment_agent",
        receiver_queue_dir=queues_dir / "deployment_agent",
        template_ref=tref,
        payload={
            "title": payload["title"],
            "body_markdown": html_fragment,  # HTML stored in body_markdown field
            "image_present": payload["image_present"],
        },
        session_id=result.session_id,
        human_readable="HTML fragment",
    )
    print(f"[text_formatter_agent] Sent HTML fragment, session={result.session_id}")


def main() -> None:
    config = load_config()
    gate, _ = _load_toolgate(config)
    shim = build_shim("text_formatter_agent")
    shim.run_forever(lambda r: handle(r, shim, config, gate))


if __name__ == "__main__":
    main()
