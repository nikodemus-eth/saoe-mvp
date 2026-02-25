# LESSONS LEARNED LOG — SAOE MVP Publish-Readiness Phase

_Maintained under: docs/logs/LESSONS_LEARNED_LOG.md_

---

## 2026-02-24 — MVP Build (Phase 1)

### Environment
- **Python 3.12 unavailable.** Only 3.13.12 at `/opt/homebrew/bin/python3.13`. `requires-python = ">=3.12"` satisfied by 3.13.
- **Homebrew not in default PATH.** Both `age` and `brew` live under `/opt/homebrew/bin/`. All subprocess calls use the full path explicitly.
- **`age-keygen` refuses to overwrite an existing key file.** On re-setup, the old identity key must be `chmod 0600` then `unlink()`-ed before calling `age-keygen -o`.

### Crypto / Key Management
- **`stat.S_IUSR` does not exist in Python's `stat` module.** The correct constant for "owner write" is `stat.S_IWUSR`. Using a non-existent constant raises `AttributeError` at runtime, not at import time.
- **AgeVault requires identity file mode exactly `0600`, not `0400`.** The `_make_vault_readonly()` sweep stripped the write bit from every file in the vault directory, turning `0600` → `0400` on the identity key. Fix: skip `_AGE_IDENTITY` in the sweep and explicitly `chmod(0o600)` it.
- **Ed25519 keys stored as raw 32-byte binary** (PyNaCl format). `SigningKey.encode()` returns the 32-byte seed; `VerifyKey` bytes are accessed via `bytes(vk)`.

### SATL / Audit Log
- **UNIQUE index on `envelope_id` must be scoped to `event_type = 'validated'`.** Originally the index covered all event types. `send_envelope()` logs a `forwarded` event with the outgoing envelope's ID; when the receiving agent then tries to INSERT a `validated` event with the same ID, the UNIQUE constraint fires a false `ReplayAttackError`. Fix: `WHERE envelope_id IS NOT NULL AND event_type = 'validated'`.
- **SQLite `IntegrityError` message format.** The error text is `"UNIQUE constraint failed: audit_events.envelope_id"` — does not contain the index name `idx_envelope_id`. Detection must check for `"envelope_id"` in the lowercased error string.

### Path / Filesystem
- **`Path.resolve()` follows symlinks before you can check them.** The original `safe_fs` implementation called `resolve()` first, erasing symlinks from the path. Fix: walk the path components with `is_symlink()` *before* calling `resolve()`.
- **Atomic write pattern for HTML output:** write to `{path}.tmp` then `rename()` to the final path. This prevents readers from seeing partial files.
- **`rglob("*.satl.json")` on a non-existent directory raises `FileNotFoundError`.** Guard with `if dir.exists()` or use `try/except` around the glob in setup cleanup code.

### Pipeline Design
- **Replay protection semantics:** an envelope can only be *validated* once. It is valid for a `forwarded` or `rejected` event to share the same `envelope_id` — the audit trail needs to record the hop on both ends.
- **Execution plan delivery:** `over_agent` writes `{session_id}.plan.json` to `agent_stores/over_agent/` for `text_formatter_agent` to pick up by session ID. This decouples the plan from the SATL envelope (whose schema has `additionalProperties: false`).
- **Demo quick-start: always run `setup_demo.py` before starting agents.** Setup clears stale queue files, the audit DB, and agent store JSON from previous runs. Skipping setup leaves old `envelope_id`s in the DB, which triggers replay errors on the first new message.
- **Shell inline comments (`#`) in multi-line commands cause zsh errors** when pasted verbatim into a terminal. Never include `# comment` on the same line as a command in user-facing shell snippets.

### Testing
- **`ToolGate` raises `DispatcherKeyMismatchError` from `assert_key_pin()`** but the test expected `IssuerKeyMismatchError`. Fix: wrap in `try/except DispatcherKeyMismatchError` and re-raise as `IssuerKeyMismatchError` in `ToolGate.__init__`.
- **Test-first discipline paid off:** all three runtime bugs (symlink detection, SQLite error message format, key mismatch exception type) were caught by tests written before implementation, ensuring they were fixed before moving on.

---

## 2026-02-25 — Publish-Readiness Phase (Phase 2)

### Documentation
- **Testing plans must precede code.** Writing UNIT_TEST_PLAN, E2E_TEST_PLAN, and BUILD_TEST_PLAN before touching implementation files forces explicit specification of every boundary condition before implementation decisions hide them.
- **`DISPATCHER_KEY_HASH_PIN` sentinel value.** The source constant is intentionally left as `"UNSET_PIN_REPLACE_AFTER_RUNNING_SETUP_DEMO"` so that any deployment that skips `setup_demo.py` fails immediately at vault init rather than silently using the wrong key.

### Attack Scripts
- **Attack scripts must import the production code path** — not re-implement it — so they test the real boundary, not a mock. Using `subprocess` or direct Python imports against the live vault/audit ensures that the rejection actually happens in the enforcement layer.
- **Replay attack requires a valid envelope.** The replay attack script must first inject a valid envelope (letting it pass step 1–11), then replay the same `envelope_id`. This proves the replay guard is on the *validated* event, not just a pre-check.
- **Path traversal test must use a real `AgentShim` context** so that `safe_fs.resolve_safe_path` is called by the actual production function, not a unit test mock.

### Code Style
- **Bare `except Exception:` in `serve_log_viewer.py`** intentionally silences database read failures to keep the viewer available even when the DB is corrupted or locked. Acceptable for MVP viewer; document as production gap.
