# SAOE — Secure Agent Operating Environment

A multi-agent pipeline that enforces signed, audited, replay-protected intent envelopes before any side effect occurs. Agents declare intent; a compiler generates signed plans; a ToolGate enforces them.

**This is an MVP demonstrating security architecture concepts.** See [Production Gaps](#production-gaps) for what is not claimed.

---

## What SAOE Does

- Every inter-agent message is a **SATL envelope**: cryptographically signed, schema-validated, and replay-protected.
- Agents **never produce executable actions directly** — they emit intent.
- A compiler agent (over_agent) translates validated intent into a **signed ExecutionPlan**.
- A **ToolGate** verifies the plan signature before any tool call reaches the filesystem.
- Every event — validation, forwarding, rejection, execution — is written to an **append-only audit log**.

## What SAOE Does Not Claim

- OS-level process isolation (agents share a filesystem)
- Encrypted inter-agent transport (queue files are plaintext JSON)
- Key revocation or rotation
- Distributed audit log
- Protection against a compromised agent process

---

## 5-Minute Reproducible Demo

### Prerequisites

- macOS (tested on macOS 14+)
- Python 3.12+ (`python3.13 -m venv` recommended)
- `age` CLI: `brew install age`

### Step 1: Setup

```
git clone https://github.com/nikodemus-eth/saoe-mvp
cd saoe-mvp
python3.13 -m venv .venv
source .venv/bin/activate
pip install -e saoe-core -e saoe-openclaw
python examples/demo/setup_demo.py
```

Setup generates keys, encrypts templates into the vault, writes `examples/demo/demo_config.json`.

### Step 2: Start Agents

In separate terminals (or background with `&`):

```
source .venv/bin/activate
cd examples/demo/agents
python sanitization_agent.py &
python over_agent.py &
python text_formatter_agent.py &
python image_filter_agent.py &
python deployment_agent.py &
python ../serve_log_viewer.py --db /tmp/saoe/events.db &
```

### Step 3: Submit a Valid Intent → Verify Output

```
python examples/demo/agents/intake_agent.py --title "Hello SAOE" --markdown "# Hello world"
```

Within ~3 seconds:

```
ls /tmp/saoe/output/
open http://localhost:8080
```

Expected: one `.html` file in `/tmp/saoe/output/`; audit log shows 8 events (validated, forwarded×3, tool_executed, validated at deployment).

### Step 4: Tamper an Envelope → Rejection Logged

```
python examples/attacks/tamper_signature.py
```

Expected output ends with: `BLOCKED: Tampered envelope rejected at step 3 (signature verification).`

### Step 5: Replay an Envelope → Rejection Logged

```
python examples/attacks/replay_attack.py
```

Expected output ends with: `BLOCKED: Replay rejected at step 12 (SQLite UNIQUE constraint on validated events).`

### Step 6: Path Traversal Attempt → Rejection Logged

```
python examples/attacks/path_traversal.py
```

Expected output ends with: `BLOCKED: All traversal attempts rejected. Path enforcement held.`

### Step 7: Forged Plan Signature → Tool Not Invoked

```
python examples/attacks/invalid_plan_signature.py
```

Expected output ends with: `BLOCKED: Forged plan rejected at plan signature verification (before any tool call).`

---

## Running Tests

```
pytest saoe-core/tests/ -v
```

83 tests (77 unit + 6 E2E). All must pass before shipping.

---

## Repository Layout

```
saoe-core/           Core library (validator, vault, toolgate, audit, safe_fs)
  saoe_core/
    util/safe_fs.py          Path traversal + TOCTOU guard
    crypto/keyring.py        Ed25519 + pinned key hash
    crypto/age_vault.py      Read-only encrypted vault
    satl/envelope.py         SATL envelope dataclass + signing
    satl/validator.py        12-step default-deny validation
    audit/events_sqlite.py   WAL SQLite audit log + replay guard
    toolgate/toolgate.py     Signed ExecutionPlan enforcement
    publisher.py             Template publish with sha256 confirmation gate
  tests/
    unit/                    77 unit tests (FT-001 through FT-010 + more)
    e2e/                     6 end-to-end tests

saoe-openclaw/       AgentShim (polling loop, send/receive, quarantine)

examples/
  demo/
    agents/                  6 demo agents + intake CLI
    setup_demo.py            Key generation + vault initialisation
    serve_log_viewer.py      Audit log web viewer (bleach + CSP)
  attacks/                   4 adversarial demonstration scripts

docs/
  ARCHITECTURE.md            Actual implementation architecture
  SECURITY_INVARIANTS.md     All enforced invariants + test mapping
  threat_model.md            Threat model and assumptions
  production_gaps.md         Explicit list of MVP limitations
  testing/
    UNIT_TEST_PLAN.md
    E2E_TEST_PLAN.md
    BUILD_TEST_PLAN.md
  logs/
    INSTALL_LOG.md
    LESSONS_LEARNED_LOG.md
    TESTING_LOG.md
```

---

## Security Invariants

16 enforced invariants with passing tests. See [SECURITY_INVARIANTS.md](SECURITY_INVARIANTS.md).

---

## Production Gaps

This MVP is a security architecture demonstrator, not a production system. See [docs/production_gaps.md](docs/production_gaps.md) for the explicit gap list.
