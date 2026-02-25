# Security Invariants — SAOE MVP

_Each invariant is backed by at least one passing automated test._
_Invariants without a test are not claimed._

---

## Invariant Table

| ID | Invariant | Test(s) | Status |
|----|-----------|---------|--------|
| SI-01 | A loaded dispatcher verify key that does not match the pinned SHA-256 hash causes vault initialisation to abort. No envelope is validated before the abort. | `test_ft001_dispatcher_pin_mismatch_aborts_vault_init` | ✅ TESTED |
| SI-02 | An envelope whose `envelope_id` has already produced a `validated` audit event is rejected with `ReplayAttackError` before any handler is invoked. | `test_ft002_replay_envelope_id_rejected` | ✅ TESTED |
| SI-03 | A file moved from queue to quarantine is read exactly once for SHA-256 verification. Processing reads only from the quarantine copy. The original queue file is deleted. | `test_ft003_atomic_move_sha256_verified` | ✅ TESTED |
| SI-04 | A JSON object containing a duplicate key at any nesting level raises `DuplicateKeyError` and is not parsed into an envelope. | `test_ft004_duplicate_keys_rejected` | ✅ TESTED |
| SI-05a | An envelope whose `sender_id` is not in the template's `allowed_senders` list is rejected with `CapabilityConstraintError`. | `test_ft005_sender_not_allowed_rejected` | ✅ TESTED |
| SI-05b | An envelope whose `receiver_id` is not in the template's `allowed_receivers` list is rejected with `CapabilityConstraintError`. | `test_ft005_receiver_not_allowed_rejected` | ✅ TESTED |
| SI-05c | An envelope whose serialised payload exceeds `max_payload_bytes` is rejected with `FileSizeExceededError` or `CapabilityConstraintError`. | `test_ft005_payload_size_limit_rejected` | ✅ TESTED |
| SI-05d | A sender that has exceeded its per-hour validation quota is rejected with `CapabilityConstraintError`. | `test_ft005_session_quota_rejected` | ✅ TESTED |
| SI-06a | An `ExecutionPlan` whose `issuer_signature` does not verify against the pinned issuer verify key is rejected with `BadSignatureError` before any tool call is made. | `test_ft006_plan_signature_invalid_rejected` | ✅ TESTED |
| SI-06b | A plan referencing a tool name not in the ToolGate registry is rejected with `UnknownToolError`. | `test_ft006_unknown_tool_in_plan_rejected` | ✅ TESTED |
| SI-07a | A relative path containing `../` components that would resolve outside the allowed base directory is rejected with `SafePathError`. | `test_ft007_path_traversal_rejected` | ✅ TESTED |
| SI-07b | A path component that is a symlink is rejected with `SafePathError` before the symlink is followed. | `test_ft007_symlink_write_rejected` | ✅ TESTED |
| SI-08 | HTML content passing through `bleach.clean(tags=[], strip=True)` has all HTML tags removed, including `<script>` tags. | `test_ft008_html_output_sanitized` | ✅ TESTED |
| SI-09 | When the quarantine directory contains ≥ `max_quarantine_files` files, `poll_once()` returns an empty list without processing any new envelopes. | `test_ft009_quarantine_count_limit_enforced` | ✅ TESTED |
| SI-10 | `publish_template()` calls `sys.exit(1)` if the operator types a SHA-256 string that does not match the template's actual canonical SHA-256. | `test_ft010_publisher_aborts_on_wrong_sha256` | ✅ TESTED |
| SI-11 | An envelope whose `receiver_id` does not match the validating agent's own ID is rejected with `ReceiverMismatchError` at step 4, before the vault is consulted. | `test_wrong_receiver_id_rejected` | ✅ TESTED |
| SI-12 | An envelope whose `envelope_signature` does not verify against the claimed sender's public key is rejected with `BadSignatureError` at step 3. | `test_tamper_payload_fails`, `tamper_signature.py` | ✅ TESTED |
| SI-13 | A template whose sha256 in the vault does not match the hash in the envelope's `template_ref` is rejected with `TemplateSha256MismatchError` at step 6. | `test_template_hash_mismatch_rejected` | ✅ TESTED |
| SI-14 | A template manifest whose dispatcher signature does not verify is rejected with `DispatcherSigError` at step 7. | `test_dispatcher_sig_mismatch_rejected` | ✅ TESTED |
| SI-15 | An envelope payload that violates the template's JSON Schema is rejected with `PayloadSchemaError` at step 10. | `test_additional_properties_rejected`, `test_missing_required_field_rejected` | ✅ TESTED |
| SI-16 | `forwarded` and `rejected` events with the same `envelope_id` as a prior `validated` event do not raise `ReplayAttackError`. | `test_forwarded_shares_envelope_id_allowed` | ✅ TESTED |

---

## What Is NOT Claimed

The following properties are **not** enforced by this MVP and are explicitly out of scope:

| Property | Reason Not Claimed |
|----------|--------------------|
| Agent process isolation | Agents share a filesystem; no OS-level sandboxing |
| Encrypted inter-agent transport | Envelopes are written as plaintext `.satl.json` files |
| Runtime vault write protection | `chmod -R a-w` is advisory; root can bypass |
| Key revocation | No CRL or key rotation mechanism |
| Distributed consensus | SQLite is single-node; no multi-writer audit log |
| Rate limiting beyond per-sender quota | No IP-level or connection-level rate limiting |
| Confidentiality of payload contents | Payloads are plaintext in the queue files |
| Timing-safe comparison | SHA-256 pin comparison uses Python string `!=` |

See `docs/production_gaps.md` for the full gap analysis.

---

## Test Execution

All invariants above are verified by:

```
pytest saoe-core/tests/ -v
```

Attack scripts also exercise SI-02, SI-07, SI-12, SI-06a:

```
python examples/attacks/tamper_signature.py
python examples/attacks/replay_attack.py
python examples/attacks/path_traversal.py
python examples/attacks/invalid_plan_signature.py
```

Each attack script exits 0 if the boundary held, 1 if breached.
