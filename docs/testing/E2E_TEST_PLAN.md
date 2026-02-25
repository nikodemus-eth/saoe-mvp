# E2E Test Plan — SAOE MVP Publish-Readiness Phase

_Created: 2026-02-25_

---

## Prerequisites

1. Fresh clone (or `git clean -fdx && git checkout .`).
2. `python3.13 -m venv .venv && source .venv/bin/activate`.
3. `pip install -e saoe-core -e saoe-openclaw`.
4. `python examples/demo/setup_demo.py` — generates keys, vault, `demo_config.json`.

---

## Scenario 1 — Valid Intent Produces Output

**Purpose:** Prove the full happy path: intake → sanitization → over_agent → text_formatter → deployment → HTML.

**Steps:**
1. Start all 5 agents as background processes.
2. Run `python examples/demo/agents/intake_agent.py --title "E2E Test" --markdown "# Hello"`.
3. Wait up to 10 seconds for pipeline to complete.
4. Assert `/tmp/saoe/output/{session_id}.html` exists and contains "Hello".
5. Query events DB and assert 8 audit events present (`validated`, `forwarded`×3, `tool_executed`, `validated` at deployment).

**Pass criteria:**
- HTML file written to `/tmp/saoe/output/`.
- Audit DB contains ≥ 8 events for the session.
- Log viewer (`http://127.0.0.1:8080/`) renders without error.

---

## Scenario 2 — Tampered Envelope Rejected

**Purpose:** Prove that signature tampering is detected before any processing.

**Steps:**
1. Capture a valid `.satl.json` envelope from `intake_agent` (copy before it's consumed).
2. Modify the `payload.title` field directly in the JSON file (invalidates signature).
3. Drop the tampered file into the `sanitization_agent` queue directory.
4. Wait for the poll cycle.
5. Assert the file is moved to quarantine (not deleted).
6. Query audit DB: assert a `rejected` event with `reason: BadSignatureError` is recorded.
7. Assert no `validated` event is logged for this envelope_id.

**Pass criteria:**
- Envelope remains in quarantine.
- `rejected` event in audit DB with correct reason.
- No output HTML written for the tampered session.

---

## Scenario 3 — Replay Rejected

**Purpose:** Prove that re-submitting the same envelope_id is blocked at step 12.

**Steps:**
1. Submit a valid envelope and let it fully validate (Scenario 1).
2. Write the same `.satl.json` file (with the same `envelope_id`) back into the `sanitization_agent` queue.
3. Wait for the poll cycle.
4. Assert the replay is rejected.
5. Query audit DB: assert a `rejected` event with `reason: ReplayAttackError`.

**Pass criteria:**
- `rejected` event in audit DB with `ReplayAttackError` reason.
- Only one `validated` event for the `envelope_id`.

---

## Scenario 4 — Path Traversal Rejected

**Purpose:** Prove that `safe_fs.resolve_safe_path` blocks traversal at the ToolGate layer.

**Steps:**
1. Run `python examples/attacks/path_traversal.py`.
2. Assert the script exits non-zero.
3. Assert the output includes `SafePathError`.
4. Assert no files were written outside `/tmp/saoe/output/`.

**Pass criteria:**
- Script exits with error.
- `SafePathError` message printed.
- No traversal file created.

---

## Scenario 5 — Log Viewer Safely Displays Events

**Purpose:** Prove that XSS content in audit fields is neutralised by bleach.

**Steps:**
1. Manually insert a row into the audit DB with `details_json = '{"reason": "<script>alert(1)</script>"}'`.
2. Fetch `http://127.0.0.1:8080/` and assert the response body does not contain `<script>`.
3. Assert the `Content-Security-Policy` header is present and includes `default-src 'none'`.

**Pass criteria:**
- `<script>` tag absent from viewer response.
- CSP header present.

---

## Automated E2E Test

The file `saoe-core/tests/e2e/test_deployment_join_completeness.py` covers Scenario 1 in isolation (no running agents, direct function calls):

- Two parts inserted → HTML assembled.
- One part inserted → no output (join not yet complete).
- Output path matches `session_id`.

---

## Acceptance Criteria

1. All scenarios run from a clean environment with documented commands.
2. Each rejection is logged in the audit DB (not silently dropped).
3. No process exits uncleanly (no unhandled exceptions in agents).
4. All assertions verified before marking scenario complete in TESTING_LOG.
