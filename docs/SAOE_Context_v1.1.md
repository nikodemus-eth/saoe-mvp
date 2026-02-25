# SAOE Architecture Context

**Document:** SAOE_Context_v1.1.md
**Version:** 1.1
**Date:** 2026-02-24

---

## 1. What is SAOE?

The **Secure Agent Operating Environment** (SAOE) is a framework for running multi-agent AI pipelines with strong containment properties. The core design principle is:

> **Agents emit intent, not action.**

No agent directly calls a tool, modifies a file, or talks to another service. Every observable effect is mediated through:
1. A **signed intent envelope** (SATL) — describing what the agent wants to do.
2. A **signed execution plan** (ToolGate) — authorizing specific tool calls.
3. A **read-only vault** (age-encrypted) — providing the ground truth for allowed schemas and capability sets.

---

## 2. Core Components

### 2.1 SATL — Secure Agent Transport Layer

SATL is the message format for inter-agent communication.

**File:** `saoe_core/satl/envelope.py`

Each message is a `SATLEnvelope` containing:
- Envelope metadata: `envelope_id`, `session_id`, `timestamp_utc`, `sender_id`, `receiver_id`.
- A `TemplateRef`: identifies the template that governs the message schema. Includes a sha256 hash of the template (from the vault) and a dispatcher signature.
- A `payload`: arbitrary dict validated against the template's JSON Schema.
- An `envelope_signature`: Ed25519 signature by the sender over the canonical JSON of all other fields.
- A `human_readable` field: free text for operators; included in the signed bytes to prevent tampering.

**Canonical JSON:** `json.dumps(obj, sort_keys=True, separators=(',',':'), ensure_ascii=True).encode('utf-8')` — used consistently for signing, hashing, and comparison.

### 2.2 Envelope Validator — 12-Step Pipeline

**File:** `saoe_core/satl/validator.py`

Every envelope arriving at an agent passes through 12 sequential checks before the agent's handler is called. Any failure raises a typed exception and causes the envelope to remain in quarantine. **Default deny.**

| Step | Check | FT Ticket |
|------|-------|-----------|
| 1 | File size ≤ cap (1 MiB default) | — |
| 2 | JSON parsed with duplicate-key rejection | FT-004 |
| 3 | Ed25519 signature verified with sender's public key | — |
| 4 | `receiver_id` matches this agent's ID | — |
| 5 | Template resolved from vault (age-decrypt) | — |
| 6 | Template sha256 matches `template_ref.sha256_hash` | — |
| 7 | Dispatcher signature over template manifest verified | FT-001 |
| 8 | Capability set resolved from vault | — |
| 9 | (MVP: capset trusted if vault is read-only; see PG-002) | — |
| 10 | Payload validated against template JSON Schema | — |
| 11 | Sender/receiver allow-lists, max payload bytes, hourly quota | FT-005 |
| 12 | Replay check: `envelope_id` INSERT (UNIQUE constraint) | FT-002 |

### 2.3 Age Vault

**File:** `saoe_core/crypto/age_vault.py`

A read-only repository of age-encrypted template and capability set JSON files. The dispatcher's verify key is stored in plaintext (`vault/keys/dispatcher_verify.pub`) and loaded at startup; its SHA-256 hash is pinned as a module-level constant in `keyring.py` (FT-001).

At runtime, the vault directory is `chmod -R a-w` (FT-001). Decryption uses the `age` CLI subprocess with a per-deployment identity file (`0600` permissions).

Unit tests use `AgeVault._from_mock(entries, ...)` to bypass the `age` CLI.

### 2.4 ToolGate

**File:** `saoe_core/toolgate/toolgate.py`

ToolGate enforces that **only tool calls explicitly authorized in a signed `ExecutionPlan` are executed**.

An `ExecutionPlan` is:
- A list of `ToolCall` objects (tool name + args).
- A SHA-256 (canonical JSON) signed by the issuer (over_agent) with its Ed25519 key.
- The issuer verify key hash is pinned at ToolGate construction time (FT-006).

When `gate.execute(plan)` is called:
1. The plan's signature is verified against the pinned issuer key.
2. Each `ToolCall.tool_name` is checked against the registered tool registry.
3. Each `ToolCall.args` is validated against the tool's JSON Schema.
4. The tool function is called and the result logged to the audit database.

### 2.5 AgentShim

**File:** `saoe_openclaw/saoe_openclaw/shim.py`

`AgentShim` provides the standard lifecycle for each demo agent:
- **`poll_once()`**: Scans the agent's inbox directory for `.satl.json` files. Each file is atomically moved to quarantine (FT-003) before validation. On validation success, the file is removed from quarantine and a `ValidationResult` is returned.
- **`send_envelope()`**: Builds, signs, and writes a new envelope to the receiver's inbox directory.
- **`run_forever(handler)`**: Runs the polling loop with SIGTERM graceful shutdown. Handler exceptions are caught and logged; the loop does not die.

Quarantine file count cap (FT-009): if `len(quarantine/*.satl.json) >= max_quarantine_files`, `poll_once()` returns immediately without processing new envelopes.

---

## 3. Agent Pipeline

```
CLI input
    │
    ▼
intake_agent          (one-shot: creates envelope, sends to sanitization_agent)
    │
    ▼
sanitization_agent    (validates, forwards to over_agent)
    │
    ▼
over_agent            (compiles ExecutionPlan, branches to text and/or image paths)
    │
    ├──────────────────────────────────────────┐
    ▼                                          ▼
text_formatter_agent                   image_filter_agent
(markdown_to_html via ToolGate)        (image_sanitize via ToolGate)
    │                                          │
    └──────────────────────┬───────────────────┘
                           ▼
                    deployment_agent
                    (SQLite join → HTML output)
                           │
                           ▼
              /tmp/saoe/output/{session_id}.html
```

**Session ID:** A UUID generated by `intake_agent` and propagated unchanged through all envelopes. All agents can correlate work by session_id.

**Execution Plans:** Written by `over_agent` to `agent_stores/over_agent/{session_id}.plan.json` (for text) and `.img_plan.json` (for image). Formatter agents pick them up by session_id before calling ToolGate.

---

## 4. Key Management

| Key | Type | Location | Who Holds It |
|-----|------|----------|--------------|
| Dispatcher signing key | Ed25519 seed (32 bytes) | Offline | Operator only |
| Dispatcher verify key | Ed25519 pubkey (32 bytes) | `vault/keys/dispatcher_verify.pub` | All agents (via AgeVault) |
| Per-agent signing key | Ed25519 seed | `keys/agents_private/{agent_id}.key` (0600) | Each agent |
| Per-agent verify key | Ed25519 pubkey | `keys/agents_public/{agent_id}.pub` | All agents (for sender verification) |
| age identity file | age secret key | `vault/age_identity.key` (0600) | All agents (for vault decryption) |

All keys are stored as raw binary (32 bytes), not PEM or base64. PyNaCl loads them natively.

---

## 5. OpenClaw Integration Points

The `saoe-openclaw` package provides stubs for future integration with the Claude OpenClaw framework:

- **`WorkspaceMapper`**: Maps OpenClaw workspace paths to per-agent encrypted stores. Not yet implemented; raises `NotImplementedError`.
- **`SATLAdapter`**: Wraps/unwraps inter-agent messages in SATL envelopes when using OpenClaw's native message passing. Not yet implemented.
- **`OpenClawShim`**: Intercepts `on_send`, `on_receive`, and `on_tool_invoke` hooks. Not yet implemented.

When OpenClaw internals become available, these stubs are the integration choke points described in the SAOE architecture document.

---

## 6. Security Invariants (Summary)

All FT-001 through FT-010 tickets are implemented and covered by `tests/unit/test_ft_tickets.py`.

| Ticket | Invariant | Module |
|--------|-----------|--------|
| FT-001 | Dispatcher verify key hash pinned at startup | `age_vault.py`, `keyring.py` |
| FT-002 | `envelope_id` UNIQUE constraint prevents replay | `events_sqlite.py` |
| FT-003 | Atomic move-then-verify before validation | `safe_fs.py`, `shim.py` |
| FT-004 | Duplicate JSON key raises before any processing | `envelope.py` |
| FT-005 | Sender/receiver allow-lists; payload size; quota | `validator.py` |
| FT-006 | ToolGate issuer key pinned; mismatch raises at init | `toolgate.py` |
| FT-007 | All file paths validated for traversal + symlinks | `safe_fs.py` |
| FT-008 | All rendered HTML passes through `bleach.clean()` | `text_formatter_agent.py`, `deployment_agent.py`, `serve_log_viewer.py` |
| FT-009 | Quarantine file count cap prevents resource exhaustion | `shim.py` |
| FT-010 | Template publish requires typing the sha256 to confirm | `publisher.py` |
