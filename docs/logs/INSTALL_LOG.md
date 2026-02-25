# INSTALL LOG — SAOE MVP Publish-Readiness Phase

_Maintained under: docs/logs/INSTALL_LOG.md_
_Started: 2026-02-25_

---

## 1. Prerequisites

| Step | Status | Notes |
|------|--------|-------|
| Python ≥ 3.12 available | ✅ COMPLETE | Python 3.13.12 at `/opt/homebrew/bin/python3.13` |
| `age` CLI available | ✅ COMPLETE | age 1.3.1 at `/opt/homebrew/bin/age` |
| `git` available | ✅ COMPLETE | System git |

## 2. Environment Setup

| Step | Status | Notes |
|------|--------|-------|
| Create venv | ✅ COMPLETE | `python3.13 -m venv .venv` from repo root |
| `pip install -e saoe-core` | ✅ COMPLETE | Installs PyNaCl, jsonschema, Pillow, markdown, bleach |
| `pip install -e saoe-openclaw` | ✅ COMPLETE | Installs saoe-core as dep |

## 3. Demo Initialization

| Step | Status | Notes |
|------|--------|-------|
| `python examples/demo/setup_demo.py` | ✅ COMPLETE | Keys generated, vault published, demo_config.json written |
| Vault read-only enforced | ✅ COMPLETE | age_identity.key exempt (must stay 0600) |
| `demo_config.json` written | ✅ COMPLETE | dispatcher_pin and issuer_pin auto-written |

## 4. Agent Startup

| Step | Status | Notes |
|------|--------|-------|
| `sanitization_agent.py` | ✅ COMPLETE | No exceptions |
| `over_agent.py` | ✅ COMPLETE | No exceptions |
| `text_formatter_agent.py` | ✅ COMPLETE | No exceptions |
| `image_filter_agent.py` | ✅ COMPLETE | No exceptions |
| `deployment_agent.py` | ✅ COMPLETE | No exceptions |
| `serve_log_viewer.py` | ✅ COMPLETE | Serves at http://127.0.0.1:8080 |

## 5. Publish-Readiness Phase

| Step | Status | Notes |
|------|--------|-------|
| Testing plans written (UNIT, E2E, BUILD) | ✅ COMPLETE | docs/testing/ |
| Attack scripts created | ✅ COMPLETE | examples/attacks/ |
| README.md written | ✅ COMPLETE | 5-minute demo instructions |
| ARCHITECTURE.md written | ✅ COMPLETE | docs/ARCHITECTURE.md |
| SECURITY_INVARIANTS.md written | ✅ COMPLETE | docs/SECURITY_INVARIANTS.md |
| Code style fixes | ✅ COMPLETE | No bare except, no silent failures |
| All 83 unit + E2E tests pass | ✅ COMPLETE | see TESTING_LOG.md |
| Attack scripts fail safely | ✅ COMPLETE | see TESTING_LOG.md |

## Quick-Start (after initial install)

```
source .venv/bin/activate
python examples/demo/setup_demo.py
cd examples/demo/agents
python sanitization_agent.py &
python over_agent.py &
python text_formatter_agent.py &
python image_filter_agent.py &
python deployment_agent.py &
python ../serve_log_viewer.py --db /tmp/saoe/events.db &
python intake_agent.py --title "Hello SAOE" --markdown "# Hello world"
```
