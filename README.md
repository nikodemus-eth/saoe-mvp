# SAOE — Secure Agent Operating Environment

**v0.1.0 RT-Hardened** • MVP Release Candidate

A capability-constrained, schema-enforced multi-agent pipeline.
Every action is authorized by a **signed ExecutionPlan**. Every message travels in a **SATL envelope**. Default-deny ToolGate. Full audit trail. Red-team validated.

![Python](https://img.shields.io/badge/Python-3.12+-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-MVP--RC-orange)

---

## Quick Start (One-Command Docker Demo)

```bash
git clone https://github.com/nikodemus-eth/saoe-mvp.git
cd saoe-mvp/examples/demo

# Bootstrap once
docker compose run --rm setup

# Start pipeline + live Log Viewer
docker compose up -d sanitization over-agent text-formatter image-filter deployment log-viewer

# Trigger a blog post (text + optional image)
docker compose run --rm intake --text "Secure agents just got hardened."
```

Open `http://localhost:8080` → watch the live audit trail and final HTML article appear.

---

## What SAOE Guarantees (v0.1.0)

- **SATL Transport** — signed envelopes, canonical template vault, no sender-trusted schemas
- **Deterministic ExecutionPlan** — intent → signed plan → ToolGate only
- **ToolGate** — default-deny, explicit allowlist, argument schema validation
- **Replay & Tamper Protection** — `envelope_id` UNIQUE + signature verification
- **Output Controls** — regex-validated `session_id`, realpath, final bleach re-sanitization (RT-2.3 & RT-3.1 fixed)
- **Red-Team Hardened** — +32 adversarial tests, 150/150 pass, 2 high-impact vulns remediated

See [SECURITY_INVARIANTS.md](SECURITY_INVARIANTS.md) (16 enforced invariants) and [docs/threat_model.md](docs/threat_model.md).

---

## 5-Minute Local Demo (non-Docker)

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

150 tests (77 unit + 6 E2E + 32 adversarial + 35 confirmatory). All pass.

---

## Repository Structure

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
    demo/                    32 adversarial + 35 confirmatory security tests

saoe-openclaw/       AgentShim (polling loop, send/receive, quarantine)

examples/
  demo/
    agents/                  6 demo agents + intake CLI
    setup_demo.py            Key generation + vault initialisation
    serve_log_viewer.py      Audit log web viewer (bleach + CSP)
  attacks/                   4 adversarial demonstration scripts

docs/
  threat_model.md            Threat model v1.1 (RT-Hardened) — invariants + test mapping
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

## Production Gaps (Honest & Explicit)

This is an architectural demonstrator, not production software. See [docs/production_gaps.md](docs/production_gaps.md) for the complete list (no HSM, no mTLS, no container sandboxing, etc.).

---

## Red-Team Hardening Summary

| | |
|---|---|
| Pre-red-team | 118 tests |
| Post-red-team | 150 tests (+32 adversarial) |
| Pass rate | 150/150 |

Key fixes:
- **RT-2.3 Path traversal** → strict regex + realpath on `session_id`
- **RT-3.1 XSS** → final re-sanitization in `deployment_agent`

Full details → [docs/threat_model.md](docs/threat_model.md) and [logs/TESTING.md](logs/TESTING.md)

---

## Security Invariants

16+ enforced invariants with passing tests. See [docs/threat_model.md](docs/threat_model.md) for the full list with test references.

---

## Next Steps (Roadmap)

- Immutable Merkle audit ledger
- mTLS + WireGuard inter-agent transport
- Per-agent container isolation
- Vault-backed key rotation

Contributions welcome — see CONTRIBUTING.md (coming in v0.1.1).

---

Made for OpenClaw users, self-hosters, and anyone who wants agents that can't quietly do bad things.

⭐ Star if this moves the needle for secure agent pipelines.
