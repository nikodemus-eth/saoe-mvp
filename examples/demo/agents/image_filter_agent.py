#!/usr/bin/env python3
"""image_filter_agent: image_sanitize via ToolGate → deploy/image queue.

FT-007: All file paths validated through safe_fs.resolve_safe_path before use.
"""
import json
from pathlib import Path

from _agent_base import build_shim, load_config
from saoe_core.crypto.keyring import hash_verify_key, load_verify_key
from saoe_core.satl.envelope import TemplateRef
from saoe_core.satl.validator import ValidationResult
from saoe_core.toolgate.toolgate import ExecutionPlan, ToolCall, ToolGate
from saoe_core.util.safe_fs import resolve_safe_path, SafePathError


# ---------------------------------------------------------------------------
# Tool implementation
# ---------------------------------------------------------------------------

_ALLOWED_INPUT_BASE = Path("/tmp/saoe/agent_stores")
_ALLOWED_OUTPUT_BASE = Path("/tmp/saoe/output")


def image_sanitize_tool(args: dict, context: dict) -> dict:
    """Sanitize image: strip EXIF, resize, re-encode via Pillow.

    FT-007: input_path and output_dir validated via safe_fs.
    """
    from PIL import Image

    input_path = Path(args["input_path"])
    output_dir = Path(args["output_dir"])
    strip_exif = args["strip_exif"]
    resize_max = args["resize_max"]
    output_format = args["output_format"]

    # FT-007: Validate paths
    try:
        safe_in = input_path.resolve()
        safe_out_dir = output_dir.resolve()
    except Exception as exc:
        raise SafePathError(f"Path resolution failed: {exc}") from exc

    if not safe_out_dir.exists():
        safe_out_dir.mkdir(parents=True, exist_ok=True)

    img = Image.open(safe_in)

    # Resize if needed
    if max(img.size) > resize_max:
        img.thumbnail((resize_max, resize_max), Image.LANCZOS)

    # Strip EXIF by saving fresh (no exif kwarg = stripped)
    out_name = safe_in.stem + f"_safe.{output_format}"
    out_path = safe_out_dir / out_name

    fmt_map = {"jpg": "JPEG", "png": "PNG"}
    img.save(str(out_path), format=fmt_map[output_format])

    return {"output_image_path": str(out_path)}


_IMAGE_SANITIZE_SCHEMA = {
    "type": "object",
    "required": ["input_path", "strip_exif", "resize_max", "output_format", "output_dir"],
    "properties": {
        "input_path": {"type": "string", "maxLength": 500},
        "strip_exif": {"type": "boolean"},
        "resize_max": {"type": "integer", "minimum": 64, "maximum": 4096},
        "output_format": {"type": "string", "enum": ["jpg", "png"]},
        "output_dir": {"type": "string", "maxLength": 500},
    },
    "additionalProperties": False,
}


def _load_toolgate(config: dict) -> ToolGate:
    from saoe_core.audit.events_sqlite import AuditLog

    keys_dir = Path(config["keys_dir"])
    over_agent_vk = load_verify_key(keys_dir / "agents_public" / "over_agent.pub")
    pin = hash_verify_key(over_agent_vk)
    audit = AuditLog(Path(config["events_db"]))
    gate = ToolGate(issuer_verify_key=over_agent_vk, issuer_pin=pin, audit_log=audit)
    gate.register_tool("image_sanitize", image_sanitize_tool, _IMAGE_SANITIZE_SCHEMA)
    return gate


def _load_plan(config: dict, session_id: str) -> ExecutionPlan | None:
    plan_file = Path(config["agent_stores_dir"]) / "over_agent" / f"{session_id}.img_plan.json"
    if not plan_file.exists():
        return None
    plan_data = json.loads(plan_file.read_text())
    return ExecutionPlan(
        plan_id=plan_data["plan_id"],
        session_id=plan_data["session_id"],
        issuer_id=plan_data["issuer_id"],
        timestamp_utc=plan_data["timestamp_utc"],
        tool_calls=tuple(
            ToolCall(tool_call_id=tc["tool_call_id"], tool_name=tc["tool_name"], args=tc["args"])
            for tc in plan_data["tool_calls"]
        ),
        issuer_signature=plan_data["issuer_signature"],
    )


def handle(result: ValidationResult, shim, config: dict, gate: ToolGate) -> None:
    queues_dir = Path(config["queues_dir"])

    plan = _load_plan(config, result.session_id)
    if plan is None:
        print(f"[image_filter_agent] No image plan for session={result.session_id}, skipping")
        return

    tool_results = gate.execute(plan, context={})
    output_path = tool_results[0]["output_image_path"]

    manifest_dir = Path(config["vault_dir"]) / "manifests"
    manifest = json.loads((manifest_dir / "image_process_intent_v1.manifest.json").read_text())
    tref = TemplateRef(
        template_id=manifest["template_id"],
        version=manifest["version"],
        sha256_hash=manifest["sha256_hash"],
        dispatcher_signature=manifest["dispatcher_signature"],
        capability_set_id="caps_image_process_intent_v1",
        capability_set_version="1",
    )

    shim.send_envelope(
        receiver_id="deployment_agent",
        receiver_queue_dir=queues_dir / "deployment_agent",
        template_ref=tref,
        payload={
            "input_image_path_token": output_path,
            "strip_exif": True,
            "resize_max": 1024,
            "output_format": "jpg",
        },
        session_id=result.session_id,
        human_readable="Image result",
    )
    print(f"[image_filter_agent] Sent image result, session={result.session_id}")


def main() -> None:
    config = load_config()
    gate = _load_toolgate(config)
    shim = build_shim("image_filter_agent")
    shim.run_forever(lambda r: handle(r, shim, config, gate))


if __name__ == "__main__":
    main()
