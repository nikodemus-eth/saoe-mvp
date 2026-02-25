"""ToolGate: signed ExecutionPlan enforcement and tool dispatch.

FT-006: Plan signature verified against pinned issuer key at init.
FT-007: Tools that touch the filesystem must use safe_fs.resolve_safe_path.

No tool may be invoked without a valid, signed ExecutionPlan.
"""
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

import jsonschema
import nacl.exceptions
import nacl.signing

from saoe_core.audit.events_sqlite import AuditEvent, AuditLog
from saoe_core.crypto.keyring import assert_key_pin, hash_verify_key, sign_bytes, verify_bytes


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class IssuerKeyMismatchError(RuntimeError):
    """Raised when the issuer verify key does not match the pinned hash (FT-006)."""


class UnknownToolError(KeyError):
    """Raised when a plan references a tool not in the ToolGate registry."""


class ToolArgSchemaError(ValueError):
    """Raised when tool args do not conform to the registered schema."""


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolCall:
    """A single tool invocation within an ExecutionPlan."""

    tool_call_id: str
    tool_name: str
    args: dict[str, Any]


@dataclass(frozen=True)
class ExecutionPlan:
    """Signed execution plan emitted by over_agent."""

    plan_id: str
    session_id: str
    issuer_id: str
    timestamp_utc: str
    tool_calls: tuple[ToolCall, ...]
    issuer_signature: str  # hex; absent from the bytes that were signed
    schema_version: str = "1.0"


# ---------------------------------------------------------------------------
# Canonical bytes and signing
# ---------------------------------------------------------------------------


def plan_canonical_bytes(plan: ExecutionPlan) -> bytes:
    """Return canonical bytes for signing — excludes ``issuer_signature``."""
    d: dict[str, Any] = {
        "schema_version": plan.schema_version,
        "plan_id": plan.plan_id,
        "session_id": plan.session_id,
        "issuer_id": plan.issuer_id,
        "timestamp_utc": plan.timestamp_utc,
        "tool_calls": [
            {
                "tool_call_id": tc.tool_call_id,
                "tool_name": tc.tool_name,
                "args": tc.args,
            }
            for tc in plan.tool_calls
        ],
    }
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sign_plan(
    plan_id: str,
    session_id: str,
    issuer_id: str,
    timestamp_utc: str,
    tool_calls: list[ToolCall],
    signing_key: nacl.signing.SigningKey,
    schema_version: str = "1.0",
) -> ExecutionPlan:
    """Build and sign an :class:`ExecutionPlan`."""
    plan = ExecutionPlan(
        plan_id=plan_id,
        session_id=session_id,
        issuer_id=issuer_id,
        timestamp_utc=timestamp_utc,
        tool_calls=tuple(tool_calls),
        issuer_signature="",
        schema_version=schema_version,
    )
    sig = sign_bytes(signing_key, plan_canonical_bytes(plan)).hex()
    return ExecutionPlan(
        plan_id=plan.plan_id,
        session_id=plan.session_id,
        issuer_id=plan.issuer_id,
        timestamp_utc=plan.timestamp_utc,
        tool_calls=plan.tool_calls,
        issuer_signature=sig,
        schema_version=plan.schema_version,
    )


# ---------------------------------------------------------------------------
# ToolGate
# ---------------------------------------------------------------------------


@dataclass
class _ToolEntry:
    fn: Callable[[dict, dict], dict]
    args_schema: dict[str, Any]


class ToolGate:
    """Enforce signed ExecutionPlan before dispatching any tool call.

    Parameters
    ----------
    issuer_verify_key:
        Public key of the plan issuer (over_agent).  Verified against *issuer_pin* at init.
    issuer_pin:
        Hex SHA-256 of the issuer verify key bytes (FT-006).
    audit_log:
        Audit log for recording tool execution events.
    """

    def __init__(
        self,
        issuer_verify_key: nacl.signing.VerifyKey,
        issuer_pin: str,
        audit_log: AuditLog,
    ) -> None:
        # FT-006: Abort if issuer key does not match pinned hash.
        from saoe_core.crypto.keyring import DispatcherKeyMismatchError

        try:
            assert_key_pin(issuer_verify_key, issuer_pin)
        except DispatcherKeyMismatchError as exc:
            raise IssuerKeyMismatchError(str(exc)) from exc
        self._issuer_vk = issuer_verify_key
        self._audit = audit_log
        self._tools: dict[str, _ToolEntry] = {}

    def register_tool(
        self,
        name: str,
        fn: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]],
        args_schema: dict[str, Any],
    ) -> None:
        """Register a tool callable with its JSON Schema for args validation."""
        self._tools[name] = _ToolEntry(fn=fn, args_schema=args_schema)

    def execute(
        self,
        plan: ExecutionPlan,
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Execute all tool calls in *plan*.

        Steps for each tool call:
        1. Verify plan signature (once, before any calls).
        2. Assert tool name is registered.
        3. Validate args against registered schema.
        4. Call tool, emit audit event.

        Returns
        -------
        list[dict]
            Results from each tool call in order.

        Raises
        ------
        nacl.exceptions.BadSignatureError
            If the plan signature is invalid.
        UnknownToolError
            If a tool name in the plan is not registered.
        ToolArgSchemaError
            If args do not conform to the tool's schema.
        """
        # Step 1: Verify plan signature once before doing anything.
        sig_bytes = bytes.fromhex(plan.issuer_signature)
        verify_bytes(self._issuer_vk, plan_canonical_bytes(plan), sig_bytes)

        results: list[dict[str, Any]] = []
        for tc in plan.tool_calls:
            # Step 2: Assert tool is registered.
            if tc.tool_name not in self._tools:
                raise UnknownToolError(
                    f"Tool {tc.tool_name!r} not in registry. "
                    f"Available: {list(self._tools)}"
                )
            entry = self._tools[tc.tool_name]

            # Step 3: Validate args schema.
            try:
                jsonschema.validate(instance=tc.args, schema=entry.args_schema)
            except jsonschema.ValidationError as exc:
                raise ToolArgSchemaError(
                    f"Args schema error for tool {tc.tool_name!r}: {exc.message}"
                ) from exc

            # Step 4: Execute tool.
            result = entry.fn(tc.args, context)

            # Emit audit event.
            self._audit.emit(
                AuditEvent(
                    event_type="tool_executed",
                    session_id=plan.session_id,
                    agent_id=plan.issuer_id,
                    details={
                        "plan_id": plan.plan_id,
                        "tool_call_id": tc.tool_call_id,
                        "tool_name": tc.tool_name,
                    },
                )
            )

            results.append(result)

        return results
