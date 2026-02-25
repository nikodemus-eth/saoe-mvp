"""conftest.py for e2e tests.

Adds the demo agents directory and demo root to sys.path so agent modules
(deployment_agent, over_agent, etc.) can be imported directly in tests.
"""
import sys
from pathlib import Path

# Resolve paths relative to this file:
# saoe-core/tests/e2e/conftest.py → repo root is 3 levels up
_REPO_ROOT = Path(__file__).parents[3]
_AGENTS_DIR = _REPO_ROOT / "examples" / "demo" / "agents"
_DEMO_DIR = _REPO_ROOT / "examples" / "demo"

for _p in [str(_AGENTS_DIR), str(_DEMO_DIR)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)
