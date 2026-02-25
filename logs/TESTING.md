# Testing Log — SAOE MVP

## Unit Tests

| Test File | Run Date | Result | Notes |
|-----------|----------|--------|-------|
| test_safe_fs.py | 2026-02-24 | ✅ 11/11 PASS | Symlink detection fixed: check BEFORE Path.resolve() |
| test_keyring.py | 2026-02-24 | ✅ 10/10 PASS | |
| test_age_vault.py | 2026-02-24 | ✅ 7/7 PASS | Including real age CLI test |
| test_envelope_sign_verify.py | 2026-02-24 | ✅ 10/10 PASS | |
| test_template_resolution_and_signature.py | 2026-02-24 | ✅ 4/4 PASS | |
| test_receiver_id_mismatch.py | 2026-02-24 | ✅ 2/2 PASS | |
| test_payload_schema_rejection.py | 2026-02-24 | ✅ 3/3 PASS | |
| test_execution_plan_and_toolgate.py | 2026-02-24 | ✅ 5/5 PASS | IssuerKeyMismatchError wrapping fixed |
| test_audit.py | 2026-02-24 | ✅ 10/10 PASS | SQLite IntegrityError message format fixed |
| test_ft_tickets.py | 2026-02-24 | ✅ 15/15 PASS | All FT-001..010 invariants verified |

**Total unit: 77/77 PASS** — Python 3.13.12, pytest 9.0.2

## E2E Tests

| Test File | Run Date | Result | Notes |
|-----------|----------|--------|-------|
| test_deployment_join_completeness.py | 2026-02-24 | ✅ 6/6 PASS | Join logic, XSS escape, path = session_id |

**Total E2E: 6/6 PASS**

## Security Validation (Red Team Pass — 2026-02-25)

> All changes documented in this section were implemented and validated prior to v0.1.0 tagging.

### What was tested

A structured adversarial pass was run against the full pipeline using the TDD
red-green cycle. Each RT item had a failing test written *before* any fix was
applied. 32 new tests were added across 5 new files:

| Test File | RT items covered | Tests | Type |
|-----------|-----------------|-------|------|
| `test_deployment_agent_unit.py` (extended) | RT-2.3, RT-3.1 | 4 | RED→GREEN (drove fixes) |
| `test_text_formatter_security.py` | RT-3.2 | 6 | Confirmatory |
| `test_image_decompression_bomb.py` | RT-4.1 | 3 | Confirmatory |
| `test_log_viewer_security.py` | RT-5.1 | 10 | Confirmatory |
| `test_rt_break_glass.py` | Section 6 | 4 | Confirmatory |
| `test_rt_size_bombs.py` | RT-1.4 | 5 | Confirmatory |

### Vulnerabilities found and patched

**RT-2.3 — Path traversal via `session_id` (FIXED)**

`_write_output_atomically` used `session_id` directly as a filename component
with no validation. `session_id = "../evil"` wrote `output_dir.parent/evil.html`.
`session_id = "/etc/cron.d/saoe"` attempted to write to that system path.

Fix: `_SESSION_ID_RE = re.compile(r"[A-Za-z0-9_\-]{1,128}")` — validates
`session_id` at the entry point of `_write_output_atomically`; raises
`ValueError` immediately if any unsafe character is present.

**RT-3.1 — HTML injection via `html_body` (FIXED — defense-in-depth)**

`_assemble_html` passed `html_body` straight to the final HTML with the comment
"already sanitized by text_formatter_agent". A compromised or buggy
`text_formatter_agent` could inject `<script>` or `onclick=` attributes into
every article.

Fix: `_assemble_html` now re-sanitizes `html_body` through
`bleach.clean(tags=_HTML_BODY_ALLOWED_TAGS, attributes=_HTML_BODY_ALLOWED_ATTRS,
strip=True)` before assembly. Defense-in-depth — the formatter's output is no
longer implicitly trusted.

### Items confirmed protected (no code changes needed)

| RT item | Confirmed protection |
|---------|---------------------|
| RT-1.1 Replay | FT-002 SQLite UNIQUE on `envelope_id` |
| RT-1.2 Template confusion | Steps 6–7: sha256 + dispatcher sig verification |
| RT-1.3 Duplicate keys | `object_pairs_hook` in `parse_envelope` |
| RT-1.4 Size / field bombs | File cap (step 1) + `maxLength` schema (step 10) |
| RT-2.1 Forged plan | ToolGate plan signature verification |
| RT-2.2 Tool allowlist | `UnknownToolError` in ToolGate |
| RT-3.2 `javascript:` URIs | bleach 6.x strips unsafe href schemes automatically |
| RT-4.1 Decompression bomb | Pillow `MAX_IMAGE_PIXELS` active and untampered |
| RT-5.1 Audit log injection | `_s()` bleach-cleans every audit event column in log viewer |
| Section 6 Break-glass | No env-var bypass; empty/zero signatures rejected by nacl |

### Result

| Suite | Run Date | Result |
|-------|----------|--------|
| Full test suite (post-red-team) | 2026-02-25 | ✅ **150/150 PASS** |
| Pre-red-team baseline tag | `pre-red-team-baseline` | 118/118 PASS |

Commit: `928e317` — merged to main via PR #2.

**Related PRs:**
- [PR #1 — TDD demo agent tests](https://github.com/nikodemus-eth/saoe-mvp/pull/1): Added `test_deployment_agent_unit.py`, `test_image_decompression_bomb.py` baseline, and E2E join completeness tests.
- [PR #2 — Red-team fixes + 32 security tests](https://github.com/nikodemus-eth/saoe-mvp/pull/2): Introduced `_SESSION_ID_RE` path guard (RT-2.3) and bleach re-sanitization of `html_body` (RT-3.1); added all confirmatory tests.

---

## Grand Total: 150/150 PASS

## Acceptance Tests (manual)

| Command | Run Date | Result | Notes |
|---------|----------|--------|-------|
| intake_agent --title "Hello SAOE" | PENDING | — | Requires running setup_demo.py first |
| /tmp/saoe/output/{session_id}.html exists | PENDING | — | Requires full pipeline |
| Log viewer at localhost:8080 | PENDING | — | Run serve_log_viewer.py |
| Invalid envelope stays in quarantine | PENDING | — | Drop tampered envelope into queue |

## Test Failures and Fixes

| Test | Failure | Root Cause | Fix |
|------|---------|------------|-----|
| test_resolve_safe_path_rejects_symlink_component | Symlink not detected | `Path.resolve()` follows + erases symlinks before check | Added `_check_no_symlinks_unresolved()` that walks components BEFORE resolve() |
| test_duplicate_envelope_id_raises_replay_error | `ReplayAttackError` not raised | SQLite error message is `"UNIQUE constraint failed: audit_events.envelope_id"`, not `"idx_envelope_id"` | Changed check to `"envelope_id" in str(exc).lower()` |
| test_issuer_key_mismatch_raises_at_init | `IssuerKeyMismatchError` not raised | `assert_key_pin()` raises `DispatcherKeyMismatchError` generically | Wrapped in ToolGate.__init__; re-raise as `IssuerKeyMismatchError` |
