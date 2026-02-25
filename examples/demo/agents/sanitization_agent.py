#!/usr/bin/env python3
"""sanitization_agent: validates and forwards intent envelopes to over_agent."""
import json
import sys
from pathlib import Path

from _agent_base import build_shim, load_config
from saoe_core.satl.envelope import TemplateRef

from saoe_core.satl.validator import ValidationResult


def handle(result: ValidationResult, shim, config: dict) -> None:
    queues_dir = Path(config["queues_dir"])
    payload = result.envelope.payload
    tref = result.envelope.template_ref

    shim.send_envelope(
        receiver_id="over_agent",
        receiver_queue_dir=queues_dir / "over_agent",
        template_ref=tref,
        payload=payload,
        session_id=result.session_id,
        human_readable="Sanitized: " + result.envelope.human_readable,
    )
    print(f"[sanitization_agent] Forwarded session={result.session_id} to over_agent")


def main() -> None:
    config = load_config()
    shim = build_shim("sanitization_agent")
    shim.run_forever(lambda r: handle(r, shim, config))


if __name__ == "__main__":
    main()
