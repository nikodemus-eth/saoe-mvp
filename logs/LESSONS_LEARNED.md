# Lessons Learned — SAOE MVP

## Environment

- **Python 3.12 unavailable.** Work order specified 3.12 but only 3.13.12 was present at `/opt/homebrew/bin/python3.13`. `requires-python = ">=3.12"` in pyproject.toml is satisfied by 3.13.
- **Homebrew not in default PATH.** Both `age` and `brew` live under `/opt/homebrew/bin/`, which is not in the subprocess environment. All subprocess calls use the full path explicitly.
- **age-keygen refuses to overwrite an existing key file.** On re-setup, the old identity key must be `chmod 0600` then `unlink()`-ed before calling `age-keygen -o`.

## Crypto / Key Management

- **`stat.S_IUSR` does not exist in Python's `stat` module.** The correct constant for "owner write" is `stat.S_IWUSR`. Using a non-existent constant raises `AttributeError` at runtime, not at import time.
- **AgeVault requires identity file mode exactly `0600`, not `0400`.** The `_make_vault_readonly()` sweep stripped the write bit from every file in the vault directory, turning `0600` → `0400` on the identity key. Fix: skip `_AGE_IDENTITY` in the sweep and explicitly `chmod(0o600)` it.
- **Ed25519 keys stored as raw 32-byte binary** (PyNaCl format), not PEM or base64. `SigningKey.encode()` returns the 32-byte seed; `VerifyKey` bytes are accessed via `bytes(vk)`.

## SATL / Audit Log

- **UNIQUE index on `envelope_id` must be scoped to `event_type = 'validated'`.** Originally the index covered all event types. `send_envelope()` logs a `forwarded` event with the outgoing envelope's ID; when the receiving agent then tries to INSERT a `validated` event with the same ID, the UNIQUE constraint fires a false `ReplayAttackError`. Fix: `WHERE envelope_id IS NOT NULL AND event_type = 'validated'`.
- **SQLite `IntegrityError` message format.** The error text is `"UNIQUE constraint failed: audit_events.envelope_id"` — does not contain the index name `idx_envelope_id`. Detection must check for `"envelope_id"` in the lowercased error string.

## Path / Filesystem

- **`Path.resolve()` follows symlinks before you can check them.** The original `safe_fs` implementation called `resolve()` first, erasing symlinks from the path. Fix: walk the path components with `is_symlink()` *before* calling `resolve()`.
- **Atomic write pattern for HTML output:** write to `{path}.tmp` then `rename()` to the final path. This prevents readers from seeing partial files.
- **`rglob("*.satl.json")` on a non-existent directory raises `FileNotFoundError`.** Guard with `if dir.exists()` or use `try/except` around the glob in setup cleanup code.

## Pipeline Design

- **Replay protection semantics:** an envelope can only be *validated* once (preventing re-processing). It is valid for a `forwarded` or `rejected` event to share the same `envelope_id` — the audit trail needs to record the hop on both ends.
- **Execution plan delivery:** `over_agent` writes `{session_id}.plan.json` to `agent_stores/over_agent/` for `text_formatter_agent` to pick up by session ID. This decouples the plan from the SATL envelope (whose schema has `additionalProperties: false`).
- **Demo quick-start: always run `setup_demo.py` before starting agents.** Setup clears stale queue files, the audit DB, and agent store JSON from previous runs. Skipping setup leaves old `envelope_id`s in the DB, which triggers replay errors on the first new message.
- **Shell inline comments (`#`) in multi-line commands cause zsh errors** when pasted verbatim into a terminal. Never include `# comment` on the same line as a command in user-facing shell snippets.

## Testing

- **`ToolGate` raises `DispatcherKeyMismatchError` from `assert_key_pin()`** but the test expected `IssuerKeyMismatchError`. Fix: wrap in `try/except DispatcherKeyMismatchError` and re-raise as `IssuerKeyMismatchError` in `ToolGate.__init__`.
- **Test-first discipline paid off:** all three runtime bugs (symlink detection, SQLite error message format, key mismatch exception type) were caught by tests written before implementation, ensuring they were fixed before moving on.

## OpenClaw Gateway

- **`KeepAlive: true` (boolean) in the LaunchAgent plist causes a 10-second restart loop.** When the gateway exits with code 1 (e.g., "port already in use"), launchd unconditionally respawns it every ~10 seconds (the default throttle interval). Fix: use `KeepAlive: {SuccessfulExit: false, Crashed: true}` with `ThrottleInterval: 5` so launchd only respawns on actual crashes, not clean exits. Edit `/Users/nikodemus/Library/LaunchAgents/ai.openclaw.gateway.plist` directly; the OpenClaw installer generates the old boolean form even on v2026.2.x. Apply with `launchctl bootout gui/$UID/ai.openclaw.gateway && launchctl bootstrap gui/$UID ~/Library/LaunchAgents/ai.openclaw.gateway.plist`.
- **The restart loop has two cooperating causes.** (1) The plist `KeepAlive: true` makes launchd respawn on any exit. (2) The OpenClaw desktop app / webchat connection loop calls `openclaw gateway start` on a ~10-second health-check timer rather than probing port 18789 first. Both must be addressed; fixing only the plist reduces restarts but does not stop the desktop app's repeated start attempts.
- **`openclaw gateway stop` uses `launchctl bootout`,** which unloads the job from launchd entirely. After `bootout`, `KeepAlive` is irrelevant — the gateway will not auto-restart until you run `launchctl bootstrap ... .plist` again. This is separate from just killing the process.

## OpenClaw Memory / Embeddings

- **Do not use `memorySearch.provider = "local"` on macOS without first approving native builds.** The `local` provider runs GGUF models via `node-llama-cpp` and requires `pnpm approve-builds` + `pnpm rebuild node-llama-cpp`. Without that, the provider silently falls back to remote (OpenAI / Google / Voyage / Mistral) if `fallback` is not `"none"`.
- **The cleanest local-only embedding setup reuses the existing Ollama instance.** Use `provider: "openai"` (OpenAI-compatible API) with `remote.baseUrl: "http://127.0.0.1:11434/v1/"` and a dummy `apiKey`. Pull `nomic-embed-text` via `ollama pull nomic-embed-text`. Set `fallback: "none"` to hard-fail rather than silently calling a cloud provider if Ollama is unreachable.
- **Config keys (set via `openclaw config set`):**
  - `agents.defaults.memorySearch.provider` = `openai`
  - `agents.defaults.memorySearch.remote.baseUrl` = `http://127.0.0.1:11434/v1/`
  - `agents.defaults.memorySearch.remote.apiKey` = `ollama-local`
  - `agents.defaults.memorySearch.model` = `nomic-embed-text`
  - `agents.defaults.memorySearch.fallback` = `none`
- **All five keys require a gateway restart to apply** (`openclaw gateway stop && openclaw gateway start`).
