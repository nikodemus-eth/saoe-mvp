# Install Log — SAOE MVP

## Prerequisites

| Step | Status | Notes |
|------|--------|-------|
| Check Python version | COMPLETE | Python 3.13.12 at /opt/homebrew/bin/python3.13 (3.12 unavailable; 3.13 used) |
| Install age CLI | COMPLETE | age 1.3.1 via `brew install age`; located at /opt/homebrew/bin/age |

## Environment Setup

| Step | Status | Notes |
|------|--------|-------|
| Create venv with Python 3.13 | COMPLETE | `python3.13 -m venv .venv` from repo root |
| pip install -e saoe-core | COMPLETE | Installs PyNaCl, jsonschema, Pillow, markdown, bleach |
| pip install -e saoe-openclaw | COMPLETE | Installs saoe-core as a dependency |

## Demo Initialization

| Step | Status | Notes |
|------|--------|-------|
| python examples/demo/setup_demo.py | COMPLETE | Generates all keys, publishes templates to vault, writes demo_config.json |
| Vault read-only enforced | COMPLETE | `chmod -R a-w /tmp/saoe/vault` (age_identity.key exempted — must stay 0600) |
| demo_config.json written | COMPLETE | Written to examples/demo/demo_config.json (gitignored) |
| Pins in demo_config.json | COMPLETE | dispatcher_pin and issuer_pin written automatically — no manual keyring.py edit needed for demo |

## Agent Startup

| Step | Status | Notes |
|------|--------|-------|
| Start sanitization_agent | COMPLETE | `python examples/demo/agents/sanitization_agent.py` |
| Start over_agent | COMPLETE | `python examples/demo/agents/over_agent.py` |
| Start text_formatter_agent | COMPLETE | `python examples/demo/agents/text_formatter_agent.py` |
| Start image_filter_agent | COMPLETE | `python examples/demo/agents/image_filter_agent.py` |
| Start deployment_agent | COMPLETE | `python examples/demo/agents/deployment_agent.py` |
| Start log viewer | COMPLETE | `python examples/demo/serve_log_viewer.py --db /tmp/saoe/events.db` |

## Verification

| Step | Status | Notes |
|------|--------|-------|
| Fire test article via intake_agent | COMPLETE | `python examples/demo/agents/intake_agent.py --title "Hello SAOE" --markdown "# Hello"` |
| Output HTML written | COMPLETE | /tmp/saoe/output/{session_id}.html — assembled by deployment_agent |
| 8 audit events in DB | COMPLETE | validated → forwarded × 3 hops → tool_executed → forwarded → validated |
| Log viewer at http://localhost:8080 | COMPLETE | Shows audit table; /output/ lists assembled articles |
| All 83 tests pass | COMPLETE | 77 unit + 6 E2E; `pytest saoe-core/tests/` |

## Quick-start (after initial install)

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
python intake_agent.py --title "My Article" --markdown "# Hello world"
```
