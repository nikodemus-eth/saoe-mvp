# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| v0.1.0 (current `main`) | ✅ |
| Earlier commits | ❌ |

## Reporting a Vulnerability

Please open a **private security advisory** via GitHub:
[github.com/nikodemus-eth/saoe-mvp/security/advisories/new](https://github.com/nikodemus-eth/saoe-mvp/security/advisories/new)

We aim to respond within **48 hours** and to publish a fix within **7 days** for confirmed issues.

Please include:
- A description of the vulnerability and its potential impact
- Steps to reproduce (or a minimal proof-of-concept)
- Which component is affected (`satl/`, `toolgate/`, `deployment_agent`, etc.)

## Scope

This is an **MVP architectural demonstrator**. Production gaps are explicitly documented in [docs/production_gaps.md](docs/production_gaps.md). Do not run SAOE in untrusted or production environments without additional controls (HSM, mTLS, container isolation, key rotation — none of which are present in v0.1.0).

## Security Hardening History

| Tag | Tests | Notes |
|-----|-------|-------|
| `pre-red-team-baseline` | 118/118 | Baseline before adversarial pass |
| `v0.1.0` | 150/150 | +32 adversarial tests; RT-2.3 + RT-3.1 patched |

See [docs/threat_model.md](docs/threat_model.md) for the full threat model (v1.1 RT-Hardened) and [logs/TESTING.md](logs/TESTING.md) for the red-team pass details.
