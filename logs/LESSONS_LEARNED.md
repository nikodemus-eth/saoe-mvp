# Lessons Learned — SAOE MVP

## Environment
- Python 3.12 specified in work order but unavailable on this machine. Python 3.13.12 used instead. `requires-python = ">=3.12"` retained in pyproject.toml as both 3.13 satisfies it.
- `age` CLI not in PATH by default on macOS with Homebrew; installed to `/opt/homebrew/bin/age`. All subprocess calls must use the full path or ensure PATH includes `/opt/homebrew/bin`.
- `brew` command also not in PATH by default; located at `/opt/homebrew/bin/brew`.
