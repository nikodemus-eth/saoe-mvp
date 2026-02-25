"""SATL envelope: data model, canonical serialisation, signing, and parsing.

FT-004: Duplicate JSON keys are rejected at parse time.

Canonical JSON rules (used for both signing and hashing):
  ``json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True)``
  encoded as UTF-8.
"""
import json
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

import nacl.exceptions
import nacl.signing

from saoe_core.crypto.keyring import sign_bytes, verify_bytes


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class DuplicateKeyError(ValueError):
    """Raised when a JSON object contains a duplicate key (FT-004)."""


class EnvelopeParseError(ValueError):
    """Raised when envelope JSON cannot be parsed or is structurally invalid."""


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TemplateRef:
    """Reference to a signed template in the vault."""

    template_id: str
    version: str
    sha256_hash: str  # hex SHA-256 of canonical template JSON
    dispatcher_signature: str  # hex Ed25519 signature over the template manifest
    capability_set_id: str
    capability_set_version: str


@dataclass(frozen=True)
class SATLEnvelope:
    """Immutable SATL envelope.  ``envelope_signature`` covers all other fields."""

    version: str
    envelope_id: str
    session_id: str
    timestamp_utc: str
    sender_id: str
    receiver_id: str
    human_readable: str  # IGNORED by execution logic; covered by signature
    template_ref: TemplateRef
    payload: dict[str, Any]  # type: ignore[type-arg]
    envelope_signature: str  # hex; absent from the bytes that were signed


# ---------------------------------------------------------------------------
# Canonical JSON helpers
# ---------------------------------------------------------------------------


def _canonical_json(obj: Any) -> str:
    """Deterministic JSON serialisation with sorted keys and no whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonical_bytes(envelope: SATLEnvelope) -> bytes:
    """Return the canonical bytes of *envelope* for signing/verification.

    ``envelope_signature`` is excluded; all other fields are included.
    ``human_readable`` is included so its value is covered by the signature.
    """
    d: dict[str, Any] = {
        "version": envelope.version,
        "envelope_id": envelope.envelope_id,
        "session_id": envelope.session_id,
        "timestamp_utc": envelope.timestamp_utc,
        "sender_id": envelope.sender_id,
        "receiver_id": envelope.receiver_id,
        "human_readable": envelope.human_readable,
        "template_ref": {
            "template_id": envelope.template_ref.template_id,
            "version": envelope.template_ref.version,
            "sha256_hash": envelope.template_ref.sha256_hash,
            "dispatcher_signature": envelope.template_ref.dispatcher_signature,
            "capability_set_id": envelope.template_ref.capability_set_id,
            "capability_set_version": envelope.template_ref.capability_set_version,
        },
        "payload": envelope.payload,
    }
    return _canonical_json(d).encode("utf-8")


# ---------------------------------------------------------------------------
# Signing and verification
# ---------------------------------------------------------------------------


def sign_envelope(
    draft: dict[str, Any],
    signing_key: nacl.signing.SigningKey,
) -> SATLEnvelope:
    """Build a :class:`SATLEnvelope` from *draft* and sign it.

    Parameters
    ----------
    draft:
        All envelope fields except ``envelope_signature``.
        ``template_ref`` may be a :class:`TemplateRef` instance or a plain dict.
    signing_key:
        Sender's Ed25519 signing key.

    Returns
    -------
    SATLEnvelope
        Immutable envelope with ``envelope_signature`` set.
    """
    tref = draft["template_ref"]
    if isinstance(tref, TemplateRef):
        template_ref = tref
    else:
        template_ref = TemplateRef(**tref)

    envelope = SATLEnvelope(
        version=draft["version"],
        envelope_id=draft.get("envelope_id", str(uuid.uuid4())),
        session_id=draft["session_id"],
        timestamp_utc=draft.get(
            "timestamp_utc",
            datetime.now(timezone.utc).isoformat(),
        ),
        sender_id=draft["sender_id"],
        receiver_id=draft["receiver_id"],
        human_readable=draft.get("human_readable", ""),
        template_ref=template_ref,
        payload=dict(draft["payload"]),
        envelope_signature="",  # placeholder while we compute bytes
    )

    data = canonical_bytes(envelope)
    sig_bytes = sign_bytes(signing_key, data)
    sig_hex = sig_bytes.hex()

    return SATLEnvelope(
        version=envelope.version,
        envelope_id=envelope.envelope_id,
        session_id=envelope.session_id,
        timestamp_utc=envelope.timestamp_utc,
        sender_id=envelope.sender_id,
        receiver_id=envelope.receiver_id,
        human_readable=envelope.human_readable,
        template_ref=envelope.template_ref,
        payload=envelope.payload,
        envelope_signature=sig_hex,
    )


def verify_envelope_signature(
    envelope: SATLEnvelope,
    sender_verify_key: nacl.signing.VerifyKey,
) -> None:
    """Verify the ``envelope_signature`` field.

    Raises
    ------
    nacl.exceptions.BadSignatureError
        If the signature is invalid or does not match the envelope contents.
    """
    data = canonical_bytes(envelope)
    try:
        sig_bytes = bytes.fromhex(envelope.envelope_signature)
    except ValueError as exc:
        raise nacl.exceptions.BadSignatureError(
            f"envelope_signature is not valid hex: {exc}"
        ) from exc
    verify_bytes(sender_verify_key, data, sig_bytes)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """``object_pairs_hook`` for :func:`json.loads` that rejects duplicate keys."""
    d: dict[str, Any] = {}
    for k, v in pairs:
        if k in d:
            raise DuplicateKeyError(f"Duplicate JSON key: {k!r}")
        d[k] = v
    return d


def parse_envelope(raw_json: str | bytes) -> SATLEnvelope:
    """Parse *raw_json* into a :class:`SATLEnvelope`.

    FT-004: Duplicate keys at any nesting level raise :class:`DuplicateKeyError`.

    Raises
    ------
    DuplicateKeyError
        If any JSON object contains duplicate keys.
    EnvelopeParseError
        If the JSON is invalid or required fields are missing.
    """
    try:
        data = json.loads(raw_json, object_pairs_hook=_reject_duplicate_keys)
    except DuplicateKeyError:
        raise
    except json.JSONDecodeError as exc:
        raise EnvelopeParseError(f"Invalid JSON: {exc}") from exc

    try:
        tref_data = data["template_ref"]
        template_ref = TemplateRef(
            template_id=tref_data["template_id"],
            version=tref_data["version"],
            sha256_hash=tref_data["sha256_hash"],
            dispatcher_signature=tref_data["dispatcher_signature"],
            capability_set_id=tref_data["capability_set_id"],
            capability_set_version=tref_data["capability_set_version"],
        )
        return SATLEnvelope(
            version=data["version"],
            envelope_id=data["envelope_id"],
            session_id=data["session_id"],
            timestamp_utc=data["timestamp_utc"],
            sender_id=data["sender_id"],
            receiver_id=data["receiver_id"],
            human_readable=data["human_readable"],
            template_ref=template_ref,
            payload=data["payload"],
            envelope_signature=data["envelope_signature"],
        )
    except KeyError as exc:
        raise EnvelopeParseError(f"Missing required envelope field: {exc}") from exc


def envelope_to_json(envelope: SATLEnvelope) -> str:
    """Serialise a :class:`SATLEnvelope` to JSON string for writing to disk."""
    d: dict[str, Any] = {
        "version": envelope.version,
        "envelope_id": envelope.envelope_id,
        "session_id": envelope.session_id,
        "timestamp_utc": envelope.timestamp_utc,
        "sender_id": envelope.sender_id,
        "receiver_id": envelope.receiver_id,
        "human_readable": envelope.human_readable,
        "template_ref": {
            "template_id": envelope.template_ref.template_id,
            "version": envelope.template_ref.version,
            "sha256_hash": envelope.template_ref.sha256_hash,
            "dispatcher_signature": envelope.template_ref.dispatcher_signature,
            "capability_set_id": envelope.template_ref.capability_set_id,
            "capability_set_version": envelope.template_ref.capability_set_version,
        },
        "payload": envelope.payload,
        "envelope_signature": envelope.envelope_signature,
    }
    return json.dumps(d, indent=2)
