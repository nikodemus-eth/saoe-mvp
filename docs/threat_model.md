# SAOE Threat Model

**Version:** 1.1 (RT-Hardened)
**Date:** 2026-02-25 (updated after red team pass)
**Scope:** SAOE MVP — macOS demo environment

---

## 1. Overview

The Secure Agent Operating Environment (SAOE) is a file-based multi-agent pipeline where:

- Agents communicate only via signed SATL envelopes (no direct function calls, shared memory, or network sockets between agents).
- Tool execution is gated by signed `ExecutionPlan` objects; no tool runs without a plan signed by the pinned issuer key.
- Templates and capability sets reside in a read-only, age-encrypted vault signed by a pinned dispatcher key.

The primary threat surface is **compromised sub-agents**: an agent that has been jailbroken, hallucinated into unsafe behaviour, or replaced by a malicious process.

---

## 2. Assets

| Asset | Sensitivity | Protection Mechanism |
|-------|-------------|----------------------|
| Dispatcher signing key | Critical | Held offline; never loaded by runtime agents |
| over_agent signing key (issuer) | High | Loaded only by over_agent; path 0600 |
| Agent signing keys | Medium | One key per agent; path 0600 |
| age identity file | High | 0600; decrypts vault on demand |
| Template vault | High | Read-only at runtime; age-encrypted; dispatcher-signed manifests |
| Audit log (SQLite) | Medium | Append-only; WAL mode; UNIQUE replay guard |
| Processed content | Low-Medium | Sanitized before storage; output HTML is bleach-cleaned |

---

## 3. Threat Actors

### 3.1 Compromised Sub-Agent
An agent that produces malicious output (injected content, path traversal attempts, oversized payloads, forged sender IDs).

**Controls:**
- Every envelope is signature-verified before processing (step 3).
- Sender/receiver allow-lists enforced per template capability set (step 11, FT-005).
- Payload schema validated against vault template (step 10).
- Path traversal blocked by `safe_fs.resolve_safe_path()` (FT-007).
- Quarantine file count cap prevents resource exhaustion (FT-009).

### 3.2 Replay Attacker
Re-submits a previously captured valid envelope.

**Controls:**
- `envelope_id` has a UNIQUE partial index in the audit SQLite table (FT-002).
- The INSERT in step 12 is the authoritative replay guard; `has_envelope_id()` is only a fast path.

### 3.3 Vault Tamperer
Attempts to substitute a malicious template or capability set in the vault.

**Controls:**
- Vault directory is `chmod -R a-w` after setup (FT-001).
- Each template's sha256 is checked at validation time against the envelope's `template_ref.sha256_hash` (step 6).
- The dispatcher signature over `{template_id, version, sha256_hash}` is verified with the pinned key (step 7, FT-001).

### 3.4 Duplicate-Key JSON Attacker
Sends an envelope with duplicate JSON keys to exploit parser ambiguity.

**Controls:**
- `json.loads(..., object_pairs_hook=_reject_duplicate_keys)` raises `DuplicateKeyError` on first duplicate (FT-004).

### 3.5 Schema Smuggling Attacker
Crafts a payload that passes schema validation but carries semantic content that triggers unsafe downstream behaviour.

**Controls:**
- JSON Schema validates structure and types; `additionalProperties: false` on all templates rejects unknown fields.
- `text_formatter_agent` sanitizes markdown output through `bleach.clean()` with an explicit tag+attribute allowlist before producing `html_body`.
- `deployment_agent` **re-sanitizes `html_body` through a second `bleach.clean()` call** (defense-in-depth — RT-3.1 fix, 2026-02-25). A compromised or buggy `text_formatter_agent` cannot inject `<script>` or event-handler attributes into the final HTML. Test: `test_assemble_html_body_script_injection_blocked`.

**Residual Risk (Production Gap):**
- Schema-valid markdown that generates visually misleading but syntactically safe content (typosquatting, phishing text) is not blocked automatically; requires human review of output.

### 3.6 Tool Argument Injection
An agent attempts to pass unexpected or path-traversal arguments to a ToolGate tool.

**Controls:**
- ToolGate validates each tool's args against a registered JSON Schema before execution.
- `image_sanitize` validates paths via `safe_fs.resolve_safe_path()` (FT-007).
- `additionalProperties: false` in all tool schemas rejects unknown args.

### 3.7 Publisher Substitution Attack
An operator is tricked into publishing a malicious template by a script that auto-fills the sha256 confirmation.

**Controls:**
- `saoe-publish-template` requires the operator to *type* the sha256 hash (FT-010).
- A script cannot bypass this without operator interaction; the `input()` call blocks automation.

### 3.8 Log Viewer XSS
The log viewer renders audit event data; an attacker who controls an agent could inject script via event fields.

**Controls:**
- All dynamic values pass through `bleach.clean(text, tags=[], strip=True)` before HTML insertion (FT-008).
- Strict `Content-Security-Policy: default-src 'none'` header on every response.
- `X-Frame-Options: DENY` prevents clickjacking.

### 3.9 Output Path Traversal via `session_id` *(RT-2.3 — patched 2026-02-25)*
`deployment_agent._write_output_atomically` used `session_id` directly as a filename component with no validation. A compromised `sanitization_agent` or `over_agent` could craft `session_id = "../evil"` to write `output_dir.parent/evil.html`, or `session_id = "/etc/cron.d/saoe"` to write an arbitrary absolute path. Confirmed in red team pass: the unpatched code produced `FileNotFoundError: [Errno 2] No such file or directory: '/etc/cron.d/saoe.tmp'`, proving the write was attempted.

**Controls (post-patch):**
- `_SESSION_ID_RE = re.compile(r"[A-Za-z0-9_\-]{1,128}")` is applied via `fullmatch()` at the entry point of `_write_output_atomically`; raises `ValueError` immediately on any character that could escape the output directory (path separators, dots, null bytes, etc.).
- Tests: `test_write_output_atomically_rejects_path_traversal`, `test_write_output_atomically_rejects_absolute_session_id`.

---

## 4. Trust Boundaries

```
[Operator terminal]
    │  (runs setup_demo.py; types sha256 at FT-010 gate)
    ▼
[Dispatcher signing key]   ←── offline; never in runtime process
    │
    ▼
[Vault (age-encrypted, read-only)] ← signed manifests
    │
    ├─► intake_agent
    │       │ SATL envelope (signed)
    │       ▼
    │   sanitization_agent
    │       │ SATL envelope (signed)
    │       ▼
    │   over_agent  ──► signs ExecutionPlan (issuer key)
    │       │
    │   ┌───┴──────────────┐
    │   ▼                  ▼
    │   text_formatter    image_filter
    │   (ToolGate)        (ToolGate)
    │       │                  │
    │       └─────┬────────────┘
    │             ▼
    │        deployment_agent
    │             │
    │             ▼
    │        /tmp/saoe/output/{session_id}.html
    │
    └─► [Audit log / Log viewer] (read-only view)
```

Each arrow represents a file-based SATL envelope. No direct calls cross trust boundaries.

---

## 5. Out-of-Scope Threats

- OS-level privilege escalation (assumed OS is not compromised).
- Physical access to the machine running the demo.
- Network-level attacks (the demo runs entirely on localhost with no network services except the log viewer bound to 127.0.0.1).
- Cryptographic breaks in Ed25519 or SHA-256.
