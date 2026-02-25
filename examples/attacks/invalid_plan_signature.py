#!/usr/bin/env python3
"""Attack: Execute a ToolGate plan signed by an unauthorised key.

Demonstrates that ToolGate rejects ExecutionPlans whose issuer_signature
does not verify against the pinned issuer (over_agent) public key.

Expected outcome: BadSignatureError raised → attack BLOCKED, tool never invoked.
Exit 0 if blocked (boundary held), exit 1 if breach.

Usage:
    python examples/attacks/invalid_plan_signature.py
"""
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

_REPO_ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(_REPO_ROOT / "saoe-core"))

import nacl.exceptions

from saoe_core.audit.events_sqlite import AuditLog
from saoe_core.crypto.keyring import generate_keypair, hash_verify_key, load_verify_key
from saoe_core.toolgate.toolgate import ToolCall, ToolGate, sign_plan


def main() -> None:
    print("=" * 60)
    print("ATTACK: Invalid Plan Signature")
    print("=" * 60)
    print("Scenario: An attacker forges an ExecutionPlan signed with their")
    print("          own private key instead of over_agent's pinned key.")
    print("          The plan requests execution of a dangerous tool.")
    print()

    # Generate the legitimate over_agent keypair and pin it.
    legit_sk, legit_vk = generate_keypair()
    issuer_pin = hash_verify_key(legit_vk)

    # The attacker has their own keypair.
    attacker_sk, _ = generate_keypair()

    # Set up a ToolGate pinned to the legitimate key.
    import tempfile
    with tempfile.TemporaryDirectory(prefix="saoe_attack_") as tmpdir:
        audit = AuditLog(Path(tmpdir) / "audit.db")

        gate = ToolGate(
            issuer_verify_key=legit_vk,
            issuer_pin=issuer_pin,
            audit_log=audit,
        )

        # Track if the tool was called.
        tool_called = False

        def dangerous_tool(args: dict, context: dict) -> dict:
            nonlocal tool_called
            tool_called = True
            print("  BREACH: dangerous_tool was executed!", file=sys.stderr)
            return {"executed": True}

        gate.register_tool(
            "dangerous_tool",
            dangerous_tool,
            {"type": "object", "properties": {}, "additionalProperties": True},
        )

        # Attacker creates a plan signed with their own (wrong) key.
        tc = ToolCall(
            tool_call_id=str(uuid.uuid4()),
            tool_name="dangerous_tool",
            args={},
        )
        forged_plan = sign_plan(
            plan_id=str(uuid.uuid4()),
            session_id=str(uuid.uuid4()),
            issuer_id="over_agent",         # claims to be over_agent
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            tool_calls=[tc],
            signing_key=attacker_sk,        # but signed with attacker's key
        )

        print("[*] Forged plan created (signed with attacker's private key, not over_agent's).")
        print("[*] Attempting to execute dangerous_tool via forged plan...")

        try:
            gate.execute(forged_plan, context={})
            if tool_called:
                print("BREACH: Tool was executed despite invalid plan signature.", file=sys.stderr)
            else:
                print("BREACH: execute() returned without raising, but tool not called.", file=sys.stderr)
            sys.exit(1)
        except nacl.exceptions.BadSignatureError as exc:
            print(f"[+] BadSignatureError raised: {exc}")
            print()
            assert not tool_called, "Tool must NOT have been called"
            print("BLOCKED: Forged plan rejected at plan signature verification (before any tool call).")
            print("         dangerous_tool was never invoked.")
            sys.exit(0)
        except Exception as exc:
            print(f"UNEXPECTED ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
