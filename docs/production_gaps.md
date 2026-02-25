# SAOE Production Gaps

**Version:** 1.0
**Date:** 2026-02-24

This document lists known gaps between the MVP demo and a production-ready deployment. Each gap is a deliberate MVP simplification that would need to be addressed before operating in a production environment.

---

## PG-001: Polling Loop vs. Event-Driven IPC

**MVP behaviour:**
- `AgentShim.run_forever()` uses `time.sleep(0.5)` polling.
- Polling latency: up to 500 ms per message; CPU usage proportional to poll frequency.

**Production fix:**
- Replace with `inotify` (Linux) or `kqueue/FSEvents` (macOS) for zero-latency, zero-idle-CPU file-system event delivery.
- Or replace the file-based queue entirely with a Unix domain socket or named pipe for direct agent-to-agent communication.

---

## PG-002: Capability Set Signature Not Verified at Runtime

**MVP behaviour:**
- Validator step 9 reads the capability set from the vault but does not verify a dispatcher signature over the capset content.
- The capset is trusted if the vault is read-only and the dispatcher key is pinned (FT-001).

**Production fix:**
- Store a separate signed manifest for each capset (same pattern as template manifests).
- Verify the capset sha256 + dispatcher signature in step 9 before trusting the capset content.

---

## PG-003: No Key Rotation Mechanism

**MVP behaviour:**
- Dispatcher and agent signing keys are generated once by `setup_demo.py` and never rotated.
- Key compromise requires re-running setup (which re-generates all keys and re-publishes all templates).

**Production fix:**
- Implement key rotation ceremony: generate new key, publish with old key's signature, then switch.
- Add key expiry fields to manifests and validate at runtime.
- Use a Hardware Security Module (HSM) or TPM for the dispatcher signing key.

---

## PG-004: Vault Read-Only Enforcement is Advisory

**MVP behaviour:**
- `chmod -R a-w vault/` prevents accidental writes but does not prevent a root process from writing.
- On macOS, `SIP` (System Integrity Protection) does not apply to user directories.

**Production fix:**
- Mount the vault on a read-only filesystem (e.g., `squashfs` loop mount, or an immutable S3-backed store).
- Add runtime write-access assertion: `AgeVault.__init__` already calls `_validate_identity_file_permissions()` — extend to assert `not os.access(vault_dir, os.W_OK)`.

---

## PG-005: Audit Log is Append-Only by Convention, Not Enforcement

**MVP behaviour:**
- SQLite WAL mode + `INSERT`-only API provides logical append-only behaviour.
- A process with filesystem access can delete or corrupt the database.

**Production fix:**
- Use an immutable ledger with cryptographic chaining (e.g., a hash-chain where each row includes `SHA-256(previous_row)`).
- Or push audit events to an external, write-once log service.
- `ledger_stub.py` is a skeleton for this future implementation.

---

## PG-006: Single-Machine, In-Process Agents

**MVP behaviour:**
- All agents run as separate Python processes on the same machine, communicating via `/tmp/saoe/`.
- No network isolation; a compromised agent can read other agents' queue directories directly.

**Production fix:**
- Run each agent in its own container or VM with no filesystem visibility into other agents' queues.
- Use namespaced, permission-restricted directories (`chmod 700`, owned by each agent's service user).
- Or replace file-based IPC with a message broker that enforces access control per-queue.

---

## PG-007: No Attestation of Agent Identity at Startup

**MVP behaviour:**
- Agent identity is asserted by the signing key on disk. Anyone who can read `/tmp/saoe/keys/agents_private/` can impersonate any agent.

**Production fix:**
- Bind agent signing keys to process identity via TPM attestation or kernel key ring (`keyctl`).
- Alternatively, use a secrets manager (HashiCorp Vault, AWS Secrets Manager) that releases keys only to attested processes.

---

## PG-008: age Identity File is Shared Among All Agents

**MVP behaviour:**
- All agents use the same `age_identity.key` to decrypt vault templates.
- A compromised agent can decrypt all vault contents.

**Production fix:**
- Issue per-agent age identities.
- Encrypt each template with the recipient set containing only the agents that need it.
- This requires per-agent capability-scoped vault entries.

---

## PG-009: Tool Supply Chain Not Verified

**MVP behaviour:**
- Tools registered with `ToolGate` (e.g., `markdown_to_html`, `image_sanitize`) are Python functions in the agent process.
- No verification that the tool binary/module matches an expected hash.

**Production fix:**
- Hash each tool's implementation at registration time and assert against a manifest signed by the dispatcher.
- Or use compiled, signed binaries executed as subprocesses with strict argument whitelisting.

---

## PG-010: No Rate Limiting on Intake

**MVP behaviour:**
- `intake_agent.py` accepts input from any CLI invocation with no authentication.
- The per-sender quota in `EnvelopeValidator` is 1000/hour (effectively unlimited).

**Production fix:**
- Add authentication to the intake endpoint (e.g., a shared secret or TLS client certificate).
- Set a realistic per-sender quota (e.g., 10/minute for human operators, 100/minute for automated pipelines).
- Add global queue depth limits to prevent resource exhaustion.

---

## PG-011: Output HTML Served with `file://` Image Paths

**MVP behaviour:**
- `deployment_agent` writes `<img src="/tmp/saoe/output/photo_safe.jpg">` with local filesystem paths.
- The log viewer serves the HTML, but the image `src` points to a local path not served over HTTP.

**Production fix:**
- Serve processed images from the log viewer under `/output/img/<session_id>/`.
- Or upload processed artifacts to a content-addressed store and use stable URLs.
