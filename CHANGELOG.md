# Changelog

All notable changes to SAOE are documented here.

## [v0.1.0] — 2026-02-25 — RT-Hardened

### Added
- Red-team pass complete: +32 adversarial tests (150/150 total)
- **RT-2.3 fix**: `_SESSION_ID_RE` strict regex + `fullmatch()` guard in `_write_output_atomically` — prevents path traversal via crafted `session_id`
- **RT-3.1 fix**: defense-in-depth `bleach.clean()` re-sanitization of `html_body` in `deployment_agent._assemble_html` — prevents XSS if `text_formatter_agent` is compromised or buggy
- Confirmatory tests for RT-3.2 (`javascript:` / `data:` URI stripping), RT-4.1 (Pillow decompression bomb guard), RT-5.1 (log viewer XSS via audit event fields), RT-1.4 (size + structure bombs), Section 6 (break-glass bypass attempts)
- `docs/threat_model.md` v1.1 (RT-Hardened): new §3.9 for RT-2.3; updated §3.5 for RT-3.1 defense-in-depth
- `logs/TESTING.md` Security Validation section: full RT pass results table, confirmed-protected items, Related PRs links
- MIT License

### Fixed
- `deployment_agent`: `session_id` path traversal (RT-2.3) — confirmed exploit attempt at `/etc/cron.d/saoe` during red team pass
- `deployment_agent`: `html_body` accepted without re-sanitization (RT-3.1)

### Baseline (pre-red-team)
- Tag: `pre-red-team-baseline` — 118/118 tests
- SATL envelope validation (12-step, default-deny)
- ExecutionPlan + ToolGate with pinned issuer key
- age-encrypted read-only vault with dispatcher-signed manifests
- WAL SQLite audit log with replay protection
- `safe_fs` path traversal + symlink guard
- 6 demo agents + log viewer (bleach + CSP)
- 4 adversarial demonstration scripts
