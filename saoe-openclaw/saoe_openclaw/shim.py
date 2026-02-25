"""AgentShim: standardised SAOE agent lifecycle.

Provides:
- Directory polling loop (FT-009: quarantine file count limit)
- Envelope signing and sending
- Integration with AgeVault, EnvelopeValidator, AuditLog

OpenClaw integration notes:
  - workspace_mapper: maps OpenClaw workspace paths → per-agent encrypted stores (TODO)
  - satl_adapter: generates/validates SATL envelopes for OpenClaw messages (TODO)
  - shim: intercepts send, receive, tool invocation hooks (stubs below)

See docs/SAOE_Context_v1.1.md for full OpenClaw choke-point documentation.
"""
import signal
import time
from pathlib import Path
from typing import Callable

import nacl.signing

from saoe_core.audit.events_sqlite import AuditEvent, AuditLog
from saoe_core.crypto.age_vault import AgeVault
from saoe_core.satl.envelope import (
    SATLEnvelope,
    TemplateRef,
    envelope_to_json,
    sign_envelope,
)
from saoe_core.satl.validator import EnvelopeValidator, ValidationResult
from saoe_core.util.safe_fs import atomic_move_then_verify


# Default caps.
_DEFAULT_MAX_QUARANTINE_FILES = 50
_DEFAULT_POLL_INTERVAL = 0.5


class AgentShim:
    """Standardised lifecycle for a SAOE agent.

    Parameters
    ----------
    agent_id:
        Unique identifier for this agent instance.
    vault:
        Read-only vault for template/capset resolution.
    audit_log:
        Shared audit log.
    signing_key:
        This agent's Ed25519 signing key (used to sign outbound envelopes).
    known_sender_keys:
        Dict of ``agent_id → VerifyKey`` for all agents that may send to this one.
    queue_dir:
        Inbox directory to poll for incoming ``.satl.json`` files.
    quarantine_dir:
        Temporary directory for files under validation (FT-003).
    max_quarantine_files:
        Maximum number of files allowed in quarantine (FT-009).
        Returns empty list from poll_once if exceeded.
    file_size_cap_bytes:
        Passed to EnvelopeValidator.
    max_quota_per_sender_per_hour:
        Passed to EnvelopeValidator.
    """

    def __init__(
        self,
        agent_id: str,
        vault: AgeVault,
        audit_log: AuditLog,
        signing_key: nacl.signing.SigningKey,
        known_sender_keys: dict[str, nacl.signing.VerifyKey],
        queue_dir: Path,
        quarantine_dir: Path,
        max_quarantine_files: int = _DEFAULT_MAX_QUARANTINE_FILES,
        file_size_cap_bytes: int = 1 * 1024 * 1024,
        max_quota_per_sender_per_hour: int = 1000,
    ) -> None:
        self._agent_id = agent_id
        self._vault = vault
        self._audit = audit_log
        self._signing_key = signing_key
        self._known_sender_keys = known_sender_keys
        self._queue_dir = Path(queue_dir)
        self._quarantine_dir = Path(quarantine_dir)
        self._max_quarantine = max_quarantine_files
        self._validator = EnvelopeValidator(
            vault=vault,
            own_agent_id=agent_id,
            audit_log=audit_log,
            file_size_cap_bytes=file_size_cap_bytes,
            max_quota_per_sender_per_hour=max_quota_per_sender_per_hour,
        )
        self._running = False

    # ------------------------------------------------------------------
    # Polling
    # ------------------------------------------------------------------

    def poll_once(self) -> list[ValidationResult]:
        """Scan ``queue_dir`` for envelopes and validate each one.

        FT-009: If quarantine file count >= max_quarantine_files, return [] immediately.
        FT-003: Each file is atomically moved to quarantine before validation.

        Returns
        -------
        list[ValidationResult]
            Successfully validated envelopes.  Failed envelopes stay in quarantine.
        """
        # FT-009: Check quarantine count before processing anything.
        quarantine_count = len(list(self._quarantine_dir.glob("*.satl.json")))
        if quarantine_count >= self._max_quarantine:
            self._audit.emit(
                AuditEvent(
                    event_type="quarantine_limit_exceeded",
                    agent_id=self._agent_id,
                    details={"count": quarantine_count, "max": self._max_quarantine},
                )
            )
            return []

        results: list[ValidationResult] = []

        for env_file in sorted(self._queue_dir.glob("*.satl.json")):
            try:
                # FT-003: Atomic move to quarantine first, validate from there.
                quarantine_path = atomic_move_then_verify(env_file, self._quarantine_dir)
                raw_bytes = quarantine_path.read_bytes()

                # Determine sender_id from raw JSON to look up verify key.
                import json

                raw_parsed = json.loads(raw_bytes)
                sender_id = raw_parsed.get("sender_id", "")
                sender_vk = self._known_sender_keys.get(sender_id)
                if sender_vk is None:
                    self._audit.emit(
                        AuditEvent(
                            event_type="rejected",
                            agent_id=self._agent_id,
                            details={"reason": "unknown_sender", "sender_id": sender_id},
                        )
                    )
                    continue

                result = self._validator.validate(raw_bytes, sender_vk)
                # Success: remove from quarantine.
                quarantine_path.unlink(missing_ok=True)
                results.append(result)

            except Exception as exc:
                # Leave in quarantine, record rejection.
                self._audit.emit(
                    AuditEvent(
                        event_type="rejected",
                        agent_id=self._agent_id,
                        details={"reason": type(exc).__name__, "detail": str(exc)[:500]},
                    )
                )

        return results

    # ------------------------------------------------------------------
    # Sending
    # ------------------------------------------------------------------

    def send_envelope(
        self,
        receiver_id: str,
        receiver_queue_dir: Path,
        template_ref: TemplateRef,
        payload: dict,
        session_id: str,
        human_readable: str = "",
    ) -> SATLEnvelope:
        """Build, sign, and write an envelope to ``receiver_queue_dir``."""
        import uuid
        from datetime import datetime, timezone

        draft = {
            "version": "1.0",
            "envelope_id": str(uuid.uuid4()),
            "session_id": session_id,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "sender_id": self._agent_id,
            "receiver_id": receiver_id,
            "human_readable": human_readable,
            "template_ref": template_ref,
            "payload": payload,
        }
        envelope = sign_envelope(draft, self._signing_key)

        out_file = Path(receiver_queue_dir) / f"{envelope.envelope_id}.satl.json"
        out_file.write_text(envelope_to_json(envelope))

        self._audit.emit(
            AuditEvent(
                event_type="forwarded",
                envelope_id=envelope.envelope_id,
                session_id=session_id,
                sender_id=self._agent_id,
                receiver_id=receiver_id,
                agent_id=self._agent_id,
            )
        )
        return envelope

    # ------------------------------------------------------------------
    # Run loop
    # ------------------------------------------------------------------

    def run_forever(
        self,
        handler: Callable[[ValidationResult], None],
        poll_interval_seconds: float = _DEFAULT_POLL_INTERVAL,
    ) -> None:
        """Poll queue_dir and call *handler* for each validated envelope.

        Handles SIGTERM for graceful shutdown.
        Exceptions from *handler* are caught and logged — the loop does not die.
        """
        self._running = True

        def _stop(signum, frame):  # noqa: ANN001
            self._running = False

        signal.signal(signal.SIGTERM, _stop)

        print(f"[{self._agent_id}] Starting. Watching: {self._queue_dir}")
        try:
            while self._running:
                for result in self.poll_once():
                    try:
                        handler(result)
                    except Exception as exc:
                        self._audit.emit(
                            AuditEvent(
                                event_type="handler_error",
                                agent_id=self._agent_id,
                                session_id=result.session_id,
                                details={"error": str(exc)[:500]},
                            )
                        )
                time.sleep(poll_interval_seconds)
        except KeyboardInterrupt:
            pass
        finally:
            print(f"[{self._agent_id}] Stopped.")


# ---------------------------------------------------------------------------
# OpenClaw integration stubs (scaffold for future integration)
# ---------------------------------------------------------------------------


class WorkspaceMapper:
    """TODO (OpenClaw): Maps OpenClaw workspace paths to per-agent encrypted stores.

    Interception point: Override ``map_path`` to redirect OpenClaw workspace
    accesses through SAOE's per-agent encrypted storage.
    """

    def map_path(self, openclaw_path: str) -> Path:
        raise NotImplementedError(
            "WorkspaceMapper is a scaffold stub. "
            "Implement mapping from OpenClaw paths to SAOE agent stores."
        )


class SATLAdapter:
    """TODO (OpenClaw): Generates and validates SATL envelopes for OpenClaw messages.

    Interception point: Wrap ``send`` and ``receive`` hooks to envelope/de-envelope
    all inter-agent messages through SATL.
    """

    def wrap_outbound(self, message: dict, template_ref: TemplateRef) -> SATLEnvelope:
        raise NotImplementedError("SATLAdapter.wrap_outbound: implement for OpenClaw.")

    def unwrap_inbound(self, envelope: SATLEnvelope) -> dict:
        raise NotImplementedError("SATLAdapter.unwrap_inbound: implement for OpenClaw.")


class OpenClawShim:
    """TODO (OpenClaw): Intercepts send, receive, and tool invocation hooks.

    Choke points to implement when OpenClaw internals are available:
    1. send hook: wrap outbound dict in SATL envelope via SATLAdapter.
    2. receive hook: validate inbound SATL envelope via AgentShim.validate.
    3. tool_invoke hook: route all tool calls through ToolGate with signed plan.

    See docs/SAOE_Context_v1.1.md for full architecture.
    """

    def on_send(self, message: dict) -> None:
        raise NotImplementedError("OpenClawShim.on_send: implement for OpenClaw send hook.")

    def on_receive(self, raw: bytes) -> dict:
        raise NotImplementedError("OpenClawShim.on_receive: implement for OpenClaw receive hook.")

    def on_tool_invoke(self, tool_name: str, args: dict) -> dict:
        raise NotImplementedError(
            "OpenClawShim.on_tool_invoke: implement for OpenClaw tool hook."
        )
