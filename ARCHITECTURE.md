# SAOE Architecture

_Reflects actual implementation as of 2026-02-25._

---

## Overview

SAOE (Secure Agent Operating Environment) is a multi-agent pipeline where agents **never generate executable actions directly**. Instead, each agent emits a **SATL intent envelope** that declares what it wants to happen. A compiler agent (over_agent) translates approved intents into **signed ExecutionPlans**. A **ToolGate** enforces the plan before any tool call reaches the filesystem or network.

The result: every side effect in the system is traceable to a signed, audited, replay-protected intent.

---

## Layers

```
┌─────────────────────────────────────────────────────────────┐
│                        Intake                               │
│  intake_agent.py — CLI intake → SATL envelope → queue      │
└─────────────────────────┬───────────────────────────────────┘
                           │  .satl.json (signed)
┌─────────────────────────▼───────────────────────────────────┐
│                    Sanitization                             │
│  sanitization_agent.py — 12-step validation → forward      │
└─────────────────────────┬───────────────────────────────────┘
                           │  .satl.json (re-signed)
┌─────────────────────────▼───────────────────────────────────┐
│                   Orchestration                             │
│  over_agent.py — validates intent → emits ExecutionPlan     │
│               — routes to specialist agents                 │
└────────────┬──────────────────────────────┬─────────────────┘
             │ text .satl.json              │ image .satl.json
┌────────────▼──────────┐       ┌───────────▼─────────────────┐
│  text_formatter_agent │       │  image_filter_agent         │
│  ToolGate: markdown   │       │  ToolGate: image_sanitize   │
│  → HTML fragment      │       │  → sanitized image          │
└────────────┬──────────┘       └───────────┬─────────────────┘
             │ tool_result .satl.json        │ tool_result .satl.json
┌────────────▼──────────────────────────────▼─────────────────┐
│                    Deployment                               │
│  deployment_agent.py — joins parts → /tmp/saoe/output/      │
└─────────────────────────────────────────────────────────────┘
```

---

## Key Components

### `saoe_core/satl/envelope.py` — SATL Envelope

- **`SATLEnvelope`**: frozen dataclass; `envelope_signature` covers all other fields including `human_readable`.
- **`canonical_bytes()`**: deterministic JSON (sorted keys, no whitespace, ensure_ascii) → UTF-8.
- **`_reject_duplicate_keys()`**: `object_pairs_hook` for `json.loads` — rejects any duplicate key at any nesting level (FT-004).
- **`sign_envelope()`**: builds + signs in one call; caller never sees an unsigned envelope.

### `saoe_core/satl/validator.py` — 12-Step Validator

Validation is **default deny**: every step must pass. Any failure raises a specific exception and stops processing.

| Step | Check |
|------|-------|
| 1 | File size ≤ cap (1 MiB default) |
| 2 | Strict JSON parse (duplicate keys rejected) |
| 3 | Envelope signature verified (Ed25519) |
| 4 | `receiver_id` matches own agent ID |
| 5 | Template resolved from read-only vault |
| 6 | Template sha256 matches `template_ref.sha256_hash` |
| 7 | Dispatcher signature over template manifest verified |
| 8 | Capability set resolved from vault |
| 9 | Capability set integrity verified |
| 10 | Payload validated against template JSON Schema |
| 11 | Capability constraints (allowed senders/receivers, payload size, per-sender quota) |
| 12 | Replay check: `envelope_id` inserted into audit log under UNIQUE constraint |

### `saoe_core/crypto/keyring.py` — Key Pinning

- Ed25519 via PyNaCl; raw 32-byte binary on disk.
- `DISPATCHER_KEY_HASH_PIN`: module-level constant; hex SHA-256 of dispatcher verify key bytes. Vault init aborts if loaded key does not match.
- Same mechanism for `ISSUER_KEY_HASH_PIN` (over_agent key) in ToolGate.

### `saoe_core/crypto/age_vault.py` — Read-Only Vault

- Wraps the `age` CLI for decryption of templates and capability sets.
- On init: checks `os.access(vault_dir, os.W_OK) == False`. Vault is never writable at runtime.
- Tests use `AgeVault._from_mock({...})` to inject in-memory templates without age.

### `saoe_core/audit/events_sqlite.py` — Audit Log

- WAL-mode SQLite; one `emit()` per event; each call opens + closes a connection (multi-process safe).
- **Replay guard**: `UNIQUE INDEX idx_envelope_id ON audit_events(envelope_id) WHERE envelope_id IS NOT NULL AND event_type = 'validated'`. Second `validated` with same ID raises `ReplayAttackError`.
- `forwarded`/`rejected` events may share an `envelope_id` — this is intentional (audit trail for each hop).

### `saoe_core/util/safe_fs.py` — Path Safety

- `resolve_safe_path(base_dir, untrusted)`:
  1. Walk all components below `base_dir` checking `is_symlink()` **before** `resolve()`.
  2. Then call `resolve()`.
  3. Assert resolved path is under `base_dir`.
- `atomic_move_then_verify(src, dst_dir)`: read once → write to temp → verify sha256 → atomic `os.replace()` → delete source.

### `saoe_core/toolgate/toolgate.py` — ToolGate

- `ToolGate.__init__`: verifies issuer key against pinned hash. Aborts if mismatch.
- `ToolGate.execute(plan, context)`:
  1. Verify `plan.issuer_signature` (once, before any tool calls).
  2. For each `ToolCall`: assert registered, validate args schema, call, emit audit event.
- No tool call is reachable without a valid signed plan.

### `saoe_openclaw/saoe_openclaw/shim.py` — AgentShim

- `poll_once()`: FT-009 quarantine file count check → glob queue dir → `atomic_move_then_verify` each file to quarantine → validate from quarantine copy → on success, delete from quarantine.
- `send_envelope()`: builds + signs outbound envelope, writes to receiver's queue dir, emits `forwarded` audit event.
- `run_forever()`: SIGTERM-aware polling loop; handler exceptions are caught and logged.

---

## Filesystem Layout (Runtime)

```
/tmp/saoe/
  vault/
    age_identity.key         (mode 0600 — required by age CLI)
    keys/
      dispatcher_verify.pub  (read-only)
    templates/
      blog_article_intent_v1.json.age
      ...
    capsets/
      caps_blog_article_intent_v1.json.age
      ...
    manifests/
      blog_article_intent_v1.manifest.json  (plaintext, dispatcher-signed)
      ...
  keys/
    agents_private/
      intake_agent.key       (mode 0600)
      ...
    agents_public/
      intake_agent.pub
      ...
  queues/
    sanitization_agent/      (incoming .satl.json files)
    over_agent/
    text_formatter_agent/
    image_filter_agent/
    deployment_agent/
  quarantine/                (files under validation)
  agent_stores/
    over_agent/              ({session_id}.plan.json)
  output/                    ({session_id}.html — final assembled articles)
  events.db                  (WAL SQLite audit log)
```

---

## Data Flow: Text Article

1. **intake_agent**: CLI args → SATL envelope (template: `blog_article_intent`) → `queues/sanitization_agent/`.
2. **sanitization_agent**: validates → `queues/over_agent/`.
3. **over_agent**: validates → emits `ExecutionPlan` (tool: `markdown_to_html`) → writes plan to `agent_stores/over_agent/` → sends envelope (template: `blog_article_intent`) → `queues/text_formatter_agent/`.
4. **text_formatter_agent**: validates → loads plan from store → ToolGate executes `markdown_to_html` → sends result envelope → `queues/deployment_agent/`.
5. **deployment_agent**: validates → writes HTML to `output/{session_id}.html` (atomic).

---

## Security Properties (Enforced)

| Property | Mechanism |
|----------|-----------|
| Envelope integrity | Ed25519 signature over canonical bytes |
| Key substitution prevention | SHA-256 hash pinning at startup |
| Replay prevention | SQLite UNIQUE partial index on `validated` events |
| Template tampering prevention | sha256 + dispatcher signature on every resolve |
| Capability enforcement | Default-deny: absent field = most restrictive |
| TOCTOU prevention | File read-once, atomic promote to quarantine |
| Path traversal prevention | `safe_fs.resolve_safe_path` pre-resolve symlink walk |
| XSS prevention | bleach + strict CSP on all log viewer responses |
| Quarantine flood prevention | File count cap before any processing |
| Accidental template publish | sha256 typed confirmation gate |

---

## Production Gaps

See `docs/production_gaps.md` for an explicit list of what this MVP does not claim to provide.
