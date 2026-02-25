# Install Log — SAOE MVP

| Step | Status | Notes |
|------|--------|-------|
| Check Python version | COMPLETE | Python 3.13.12 at /opt/homebrew/bin/python3.13 (3.12 unavailable; 3.13 used per compatibility) |
| Install age CLI | COMPLETE | age 1.3.1 installed via brew; located at /opt/homebrew/bin/age |
| Create venv with Python 3.13 | PENDING | |
| pip install -e saoe-core | PENDING | |
| pip install -e saoe-openclaw | PENDING | |
| python examples/demo/setup_demo.py | PENDING | |
| Paste DISPATCHER_KEY_HASH_PIN into keyring.py | PENDING | Manual step — setup_demo.py prints the value |
| Paste ISSUER_KEY_HASH_PIN into toolgate.py | PENDING | Manual step — setup_demo.py prints the value |
| Verify agents run | PENDING | |
| Verify log viewer at http://localhost:8080 | PENDING | |
