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

## Grand Total: 83/83 PASS

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
