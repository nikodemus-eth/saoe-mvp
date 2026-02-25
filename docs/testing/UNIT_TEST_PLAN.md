# Unit Test Plan — SAOE MVP Publish-Readiness Phase

_Created: 2026-02-25_
_Maps to: saoe-core/tests/unit/_

---

## Coverage Matrix

Each row maps a security invariant to the test file and function that proves enforcement.

| ID | Invariant | Test File | Test Function(s) |
|----|-----------|-----------|-----------------|
| FT-001 | Pinned dispatcher key mismatch aborts vault init | test_ft_tickets.py | `test_ft001_dispatcher_pin_mismatch_aborts_vault_init` |
| FT-002 | Replay — same envelope_id rejected on second validate | test_ft_tickets.py | `test_ft002_replay_envelope_id_rejected` |
| FT-003 | Atomic move-then-verify rejects tampered/missing content | test_ft_tickets.py | `test_ft003_atomic_move_sha256_verified` |
| FT-004 | Duplicate JSON keys rejected at parse | test_ft_tickets.py | `test_ft004_duplicate_keys_rejected` |
| FT-005a | Unknown sender rejected by capability constraints | test_ft_tickets.py | `test_ft005_sender_not_allowed_rejected` |
| FT-005b | Disallowed receiver rejected | test_ft_tickets.py | `test_ft005_receiver_not_allowed_rejected` |
| FT-005c | Oversized payload rejected | test_ft_tickets.py | `test_ft005_payload_size_limit_rejected` |
| FT-005d | Per-sender session quota enforced | test_ft_tickets.py | `test_ft005_session_quota_rejected` |
| FT-006a | Invalid plan signature rejected by ToolGate | test_ft_tickets.py | `test_ft006_plan_signature_invalid_rejected` |
| FT-006b | Unknown tool in plan rejected | test_ft_tickets.py | `test_ft006_unknown_tool_in_plan_rejected` |
| FT-007a | Path traversal (`../`) rejected | test_ft_tickets.py | `test_ft007_path_traversal_rejected` |
| FT-007b | Symlink write rejected | test_ft_tickets.py | `test_ft007_symlink_write_rejected` |
| FT-008 | HTML sanitization strips script tags | test_ft_tickets.py | `test_ft008_html_output_sanitized` |
| FT-009 | Quarantine file count limit enforced | test_ft_tickets.py | `test_ft009_quarantine_count_limit_enforced` |
| FT-010 | Publisher aborts on wrong sha256 confirmation | test_ft_tickets.py | `test_ft010_publisher_aborts_on_wrong_sha256` |

---

## Additional Unit Tests

### Envelope Signing and Verification (`test_envelope_sign_verify.py`)

| Test | Description |
|------|-------------|
| `test_sign_and_verify_roundtrip` | Valid envelope signs and verifies without error |
| `test_tamper_payload_fails` | Modifying `payload` field after signing causes `BadSignatureError` |
| `test_tamper_human_readable_fails` | Modifying `human_readable` causes `BadSignatureError` |
| `test_duplicate_keys_raises_duplicate_key_error` | Duplicate key at any nesting level raises `DuplicateKeyError` |
| `test_parse_missing_field_raises` | Missing required field raises `EnvelopeParseError` |

### Template Resolution and Dispatcher Signature (`test_template_resolution_and_signature.py`)

| Test | Description |
|------|-------------|
| `test_template_resolved_from_vault` | Valid template resolves and sha256 matches |
| `test_template_hash_mismatch_rejected` | Altered template sha256 raises `TemplateSha256MismatchError` |
| `test_dispatcher_sig_mismatch_rejected` | Wrong dispatcher sig raises `DispatcherSigError` |

### Receiver ID Mismatch (`test_receiver_id_mismatch.py`)

| Test | Description |
|------|-------------|
| `test_wrong_receiver_id_rejected` | `receiver_id` ≠ `own_agent_id` raises `ReceiverMismatchError` before vault is consulted |

### Payload Schema (`test_payload_schema_rejection.py`)

| Test | Description |
|------|-------------|
| `test_additional_properties_rejected` | `additionalProperties: false` enforced |
| `test_missing_required_field_rejected` | Missing required field raises `PayloadSchemaError` |

### ExecutionPlan and ToolGate (`test_execution_plan_and_toolgate.py`)

| Test | Description |
|------|-------------|
| `test_no_plan_raises` | Calling execute without a plan raises |
| `test_valid_plan_executes` | Correctly signed plan with registered tool succeeds |
| `test_wrong_tool_name_raises` | Unregistered tool raises `UnknownToolError` |
| `test_wrong_args_raises` | Args violating schema raises `ToolArgSchemaError` |

### Audit Log (`test_audit.py`)

| Test | Description |
|------|-------------|
| `test_emit_and_query` | Emitted events are queryable |
| `test_replay_raises_on_duplicate_validated` | Second `validated` emit with same `envelope_id` raises `ReplayAttackError` |
| `test_forwarded_shares_envelope_id_allowed` | `forwarded` event with same `envelope_id` does NOT raise |

### Safe FS (`test_safe_fs.py`)

| Test | Description |
|------|-------------|
| `test_normal_path_allowed` | Path within base resolves |
| `test_traversal_rejected` | `../../etc/passwd` raises `SafePathError` |
| `test_symlink_rejected` | Symlink in path raises `SafePathError` |
| `test_atomic_move_normal` | File moves atomically and sha256 matches |
| `test_atomic_move_missing_source` | Missing source raises `AtomicMoveError` |

### Keyring (`test_keyring.py`)

| Test | Description |
|------|-------------|
| `test_generate_keypair` | Returns `(SigningKey, VerifyKey)` |
| `test_sign_and_verify_roundtrip` | Signature verifies with correct key |
| `test_verify_wrong_key_fails` | Wrong verify key raises `BadSignatureError` |
| `test_assert_key_pin_correct` | Correct hash does not raise |
| `test_assert_key_pin_wrong` | Wrong hash raises `DispatcherKeyMismatchError` |

### Age Vault (`test_age_vault.py`)

| Test | Description |
|------|-------------|
| `test_mock_vault_template_resolve` | Mock vault returns injected template |
| `test_mock_vault_entry_not_found` | Missing template raises `VaultEntryNotFoundError` |
| `test_dispatcher_pin_mismatch` | Wrong pin raises `DispatcherKeyMismatchError` at init |
| `test_write_blocked_on_readonly_vault` | Write attempt to read-only vault raises |

---

## Acceptance Criteria

All tests must:
1. Run with `pytest saoe-core/tests/unit/ -v` from the repo root.
2. Pass without requiring network access.
3. Not modify any files outside of `tmp_path` pytest fixtures.
4. Negative tests must **raise** the expected exception — not silently pass.
