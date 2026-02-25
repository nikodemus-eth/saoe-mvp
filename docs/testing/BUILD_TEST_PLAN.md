# Build Test Plan — SAOE MVP Publish-Readiness Phase

_Created: 2026-02-25_

This document maps each code component to the tests that verify it, and specifies the build sequence.

---

## Build Sequence

Each row shows what to implement and which tests must pass before proceeding.

| # | Component | Implementation Action | Tests to Run |
|---|-----------|----------------------|--------------|
| 1 | `util/safe_fs.py` | Path traversal guard, symlink rejection, atomic move | `test_safe_fs.py` |
| 2 | `crypto/keyring.py` | Ed25519 keypair, pin checking, sign/verify | `test_keyring.py` |
| 3 | `crypto/age_vault.py` | Read-only vault, `_from_mock()` bypass, pin enforcement | `test_age_vault.py` |
| 4 | `satl/envelope.py` | Canonical bytes, frozen dataclass, duplicate-key rejection | `test_envelope_sign_verify.py` |
| 5 | `satl/validator.py` | 12-step pipeline, default deny, replay guard | `test_template_resolution_and_signature.py`, `test_receiver_id_mismatch.py`, `test_payload_schema_rejection.py`, `test_ft_tickets.py` (FT-001..005) |
| 6 | `audit/events_sqlite.py` | WAL mode, UNIQUE partial index on validated events | `test_audit.py`, `test_ft_tickets.py` (FT-002) |
| 7 | `toolgate/toolgate.py` | Plan signature verification, tool registry, arg schema | `test_execution_plan_and_toolgate.py`, `test_ft_tickets.py` (FT-006, 007) |
| 8 | `publisher.py` | SHA-256 confirmation gate, publish event | `test_ft_tickets.py` (FT-010) |
| 9 | `saoe_openclaw/shim.py` | AgentShim polling loop, quarantine cap | `test_ft_tickets.py` (FT-009) |
| 10 | Demo agents | All 5 agents + serve_log_viewer | E2E: `test_deployment_join_completeness.py` |
| 11 | Attack scripts | `examples/attacks/*.py` | Run each manually; verify rejection + logged reason |
| 12 | Documentation | README, ARCHITECTURE.md, SECURITY_INVARIANTS.md | Review only (no automated test) |

---

## Test-to-Security-Invariant Mapping

### Key Pinning (FT-001, FT-006)

| Implementation | Test |
|----------------|------|
| `assert_key_pin()` in `keyring.py` | `test_keyring.py::test_assert_key_pin_wrong` |
| `AgeVault._from_mock()` with wrong pin | `test_ft_tickets.py::test_ft001_dispatcher_pin_mismatch_aborts_vault_init` |
| `ToolGate.__init__` re-raises as `IssuerKeyMismatchError` | `test_ft_tickets.py::test_ft006_plan_signature_invalid_rejected` |

### Replay Defense (FT-002)

| Implementation | Test |
|----------------|------|
| UNIQUE partial index on `audit_events.envelope_id` where `event_type='validated'` | `test_ft_tickets.py::test_ft002_replay_envelope_id_rejected` |
| `forwarded` events with same ID allowed | `test_audit.py::test_forwarded_shares_envelope_id_allowed` |

### TOCTOU-Safe Promote (FT-003)

| Implementation | Test |
|----------------|------|
| `atomic_move_then_verify()` reads src once, verifies sha256 | `test_ft_tickets.py::test_ft003_atomic_move_sha256_verified` |
| `AgentShim.poll_once()` reads only from quarantine copy | `test_ft_tickets.py::test_ft009_quarantine_count_limit_enforced` |

### Strict JSON Parsing (FT-004)

| Implementation | Test |
|----------------|------|
| `_reject_duplicate_keys` object_pairs_hook | `test_ft_tickets.py::test_ft004_duplicate_keys_rejected` |
| Applied at every nesting level | `test_envelope_sign_verify.py::test_duplicate_keys_raises_duplicate_key_error` |

### Capability Constraints (FT-005)

| Implementation | Test |
|----------------|------|
| `allowed_senders` enforcement (default deny empty list) | `test_ft_tickets.py::test_ft005_sender_not_allowed_rejected` |
| `allowed_receivers` enforcement | `test_ft_tickets.py::test_ft005_receiver_not_allowed_rejected` |
| `max_payload_bytes` enforcement | `test_ft_tickets.py::test_ft005_payload_size_limit_rejected` |
| Per-sender quota | `test_ft_tickets.py::test_ft005_session_quota_rejected` |

### ToolGate Path Enforcement (FT-007)

| Implementation | Test |
|----------------|------|
| `resolve_safe_path()` traversal block | `test_ft_tickets.py::test_ft007_path_traversal_rejected` |
| Symlink rejection (pre-resolve check) | `test_ft_tickets.py::test_ft007_symlink_write_rejected` |

### Sanitization (FT-008)

| Implementation | Test |
|----------------|------|
| `bleach.clean(tags=[], strip=True)` | `test_ft_tickets.py::test_ft008_html_output_sanitized` |
| CSP header on every response | E2E Scenario 5 |

### Publisher Confirmation Gate (FT-010)

| Implementation | Test |
|----------------|------|
| `publish_template()` aborts on wrong sha256 input | `test_ft_tickets.py::test_ft010_publisher_aborts_on_wrong_sha256` |

---

## Attack Script Verification

Each script under `examples/attacks/` must:
1. Exit non-zero (or print explicit failure message).
2. Not crash an agent.
3. Produce a `rejected` audit event (where applicable).

| Script | Expected Rejection | Audit Event |
|--------|-------------------|-------------|
| `tamper_signature.py` | `BadSignatureError` at validator step 3 | `rejected` with `reason: BadSignatureError` |
| `replay_attack.py` | `ReplayAttackError` at validator step 12 | `rejected` with `reason: ReplayAttackError` |
| `path_traversal.py` | `SafePathError` from `safe_fs` | No audit event (blocked before ToolGate) |
| `invalid_plan_signature.py` | `BadSignatureError` at ToolGate execute step 1 | `rejected` at ToolGate level |

---

## Completion Gate

Work is complete only when:
1. `pytest saoe-core/tests/` shows 0 failures.
2. All four attack scripts demonstrate the expected rejection.
3. TESTING_LOG.md is updated with actual output for each run.
4. INSTALL_LOG.md, LESSONS_LEARNED_LOG.md are current.
