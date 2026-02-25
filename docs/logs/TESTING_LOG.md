# TESTING LOG — SAOE MVP Publish-Readiness Phase

_Maintained under: docs/logs/TESTING_LOG.md_
_Updated: 2026-02-25_

---

## Unit Tests

### Command
```
cd /Users/nikodemus/Documents/SAOE
source .venv/bin/activate
pytest saoe-core/tests/unit/ -v
```

### Results

| Test File | Tests | Pass | Fail | Status |
|-----------|-------|------|------|--------|
| test_safe_fs.py | 9 | 9 | 0 | ✅ PASS |
| test_keyring.py | 10 | 10 | 0 | ✅ PASS |
| test_age_vault.py | 7 | 7 | 0 | ✅ PASS |
| test_envelope_sign_verify.py | 10 | 10 | 0 | ✅ PASS |
| test_template_resolution_and_signature.py | 4 | 4 | 0 | ✅ PASS |
| test_receiver_id_mismatch.py | 2 | 2 | 0 | ✅ PASS |
| test_payload_schema_rejection.py | 3 | 3 | 0 | ✅ PASS |
| test_execution_plan_and_toolgate.py | 5 | 5 | 0 | ✅ PASS |
| test_audit.py | 10 | 10 | 0 | ✅ PASS |
| test_ft_tickets.py | 17 | 17 | 0 | ✅ PASS |

**Total unit: 77/77 passed.**

### Console Output (final line)
```
============================== 83 passed in 0.70s ==============================
```

---

## E2E Tests

### Command
```
pytest saoe-core/tests/e2e/ -v
```

| Test | Pass | Status |
|------|------|--------|
| test_text_only_one_part_produces_html | ✅ | ✅ PASS |
| test_image_article_one_part_no_output | ✅ | ✅ PASS |
| test_image_article_two_parts_produces_html | ✅ | ✅ PASS |
| test_output_path_matches_session_id | ✅ | ✅ PASS |
| test_xss_title_is_escaped | ✅ | ✅ PASS |
| test_image_only_no_output | ✅ | ✅ PASS |

**Total E2E: 6/6 passed.**

---

## Attack Scripts

### tamper_signature.py

**Command:** `python examples/attacks/tamper_signature.py`

| Step | Outcome |
|------|---------|
| Signed envelope created | OK |
| Payload tampered (title changed) | Done |
| Validation attempted | BadSignatureError raised |
| Tool never invoked | Confirmed |

**Result:** `BLOCKED: Tampered envelope rejected at step 3 (signature verification).`
**Exit code:** 0 ✅

---

### replay_attack.py

**Command:** `python examples/attacks/replay_attack.py`

| Step | Outcome |
|------|---------|
| First submission (valid) | Accepted (expected) |
| Replay with same envelope_id | ReplayAttackError raised |
| Audit DB | rejected event recorded |

**Result:** `BLOCKED: Replay rejected at step 12 (SQLite UNIQUE constraint on validated events).`
**Exit code:** 0 ✅

---

### path_traversal.py

**Command:** `python examples/attacks/path_traversal.py`

| Attempt | Outcome |
|---------|---------|
| `../../etc/passwd` (traversal) | SafePathError — BLOCKED |
| `subdir/../../etc/shadow` (nested) | SafePathError — BLOCKED |
| symlink `evil` → `/etc`, then `evil/passwd` | SafePathError — BLOCKED |
| Absolute path `/etc/passwd` injected | SafePathError — BLOCKED |
| Legitimate `article.html` | ALLOWED (correct) |

**Result:** `BLOCKED: All traversal attempts rejected. Path enforcement held.`
**Exit code:** 0 ✅

---

### invalid_plan_signature.py

**Command:** `python examples/attacks/invalid_plan_signature.py`

| Step | Outcome |
|------|---------|
| ToolGate initialised with legitimate key | OK |
| Forged plan created (attacker key) | Done |
| execute() called | BadSignatureError raised |
| Tool never invoked | Confirmed (tool_called == False) |

**Result:** `BLOCKED: Forged plan rejected at plan signature verification (before any tool call).`
**Exit code:** 0 ✅

---

## Full Suite Summary

| Suite | Total | Pass | Fail | Status |
|-------|-------|------|------|--------|
| Unit | 77 | 77 | 0 | ✅ COMPLETE |
| E2E | 6 | 6 | 0 | ✅ COMPLETE |
| Attack scripts | 4 | 4 (all blocked) | 0 | ✅ COMPLETE |

**Grand total: 83 tests passing, 4 attack scripts demonstrating boundary enforcement.**
