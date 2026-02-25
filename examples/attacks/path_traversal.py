#!/usr/bin/env python3
"""Attack: Attempt directory traversal and symlink escape via ToolGate path args.

Demonstrates that safe_fs.resolve_safe_path blocks:
  1. Directory traversal: ``../../etc/passwd``
  2. Symlink escape: a symlink pointing outside the allowed directory
  3. Absolute path injection: ``/etc/passwd``

Expected outcome: SafePathError raised for each attempt → attack BLOCKED.
Exit 0 if all attacks blocked, exit 1 if any breach.

Usage:
    python examples/attacks/path_traversal.py
"""
import sys
import tempfile
from pathlib import Path

_REPO_ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(_REPO_ROOT / "saoe-core"))

from saoe_core.util.safe_fs import SafePathError, resolve_safe_path


def _try_traversal(base_dir: Path, untrusted: str, label: str) -> bool:
    """Return True if attack was blocked (SafePathError raised)."""
    try:
        result = resolve_safe_path(base_dir, untrusted)
        print(f"  BREACH [{label}]: resolve_safe_path returned {result} — boundary FAILED.")
        return False
    except SafePathError as exc:
        print(f"  BLOCKED [{label}]: SafePathError: {exc}")
        return True
    except Exception as exc:
        print(f"  ERROR [{label}]: Unexpected: {type(exc).__name__}: {exc}")
        return False


def main() -> None:
    print("=" * 60)
    print("ATTACK: Path Traversal and Symlink Escape")
    print("=" * 60)
    print("Scenario: An attacker supplies crafted output paths to a tool")
    print("          call to read or write files outside the allowed directory.")
    print()

    breaches = 0

    with tempfile.TemporaryDirectory(prefix="saoe_attack_") as tmpdir:
        base = Path(tmpdir) / "output"
        base.mkdir()

        # --- Test 1: Directory traversal with ../ ---
        print("[1] Directory traversal: ../../etc/passwd")
        if not _try_traversal(base, "../../etc/passwd", "traversal ../"):
            breaches += 1

        # --- Test 2: Nested traversal ---
        print("[2] Nested traversal: subdir/../../etc/shadow")
        if not _try_traversal(base, "subdir/../../etc/shadow", "nested traversal"):
            breaches += 1

        # --- Test 3: Symlink escape ---
        print("[3] Symlink escape: 'evil' → /etc")
        evil_link = base / "evil"
        evil_link.symlink_to("/etc")
        if not _try_traversal(base, "evil/passwd", "symlink escape"):
            breaches += 1
        evil_link.unlink()

        # --- Test 4: Absolute path (outside base) ---
        print("[4] Absolute path injected as relative: /etc/passwd")
        if not _try_traversal(base, "/etc/passwd", "absolute path"):
            breaches += 1

        # --- Test 5: Legitimate path allowed ---
        print("[5] Legitimate relative path: article.html (should be allowed)")
        try:
            result = resolve_safe_path(base, "article.html")
            print(f"  ALLOWED [legitimate]: resolved to {result.name} (expected)")
        except SafePathError as exc:
            print(f"  ERROR [legitimate]: Legitimate path rejected: {exc}")
            breaches += 1

    print()
    if breaches == 0:
        print("BLOCKED: All traversal attempts rejected. Path enforcement held.")
        sys.exit(0)
    else:
        print(f"BREACH: {breaches} attack(s) succeeded. Security boundary FAILED.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
