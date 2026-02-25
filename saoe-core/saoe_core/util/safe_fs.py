"""Safe filesystem utilities: path traversal guard and atomic move-then-verify.

FT-007: Path traversal and symlink attack prevention.
FT-003: Atomic move-then-verify to prevent TOCTOU swaps.
"""
import hashlib
import os
import shutil
import tempfile
from pathlib import Path


class SafePathError(ValueError):
    """Raised when a resolved path escapes the allowed base directory or traverses a symlink."""


class AtomicMoveError(OSError):
    """Raised when atomic_move_then_verify fails."""


def resolve_safe_path(base_dir: Path, untrusted: str) -> Path:
    """Resolve *untrusted* relative path against *base_dir*.

    Rules (strict mode):
    - The resolved path must be inside *base_dir* (no ``../`` escapes).
    - No component of the path from *base_dir* onwards may be a symlink.

    Parameters
    ----------
    base_dir:
        Trusted base directory.  Need not exist yet.
    untrusted:
        Relative path string from untrusted input.

    Returns
    -------
    Path
        Resolved absolute path guaranteed to be inside *base_dir*.

    Raises
    ------
    SafePathError
        If the path escapes *base_dir* or any component is a symlink.
    """
    base = Path(base_dir).resolve()

    # Build the unresolved join first, so we can inspect each component for symlinks
    # BEFORE following them.
    unresolved = base / untrusted

    # Walk each component from base down and reject any symlink.
    _check_no_symlinks_unresolved(base, unresolved)

    # Now resolve (follows any remaining non-symlink indirections like ".." in paths).
    try:
        candidate = unresolved.resolve()
    except Exception as exc:
        raise SafePathError(f"Cannot resolve path: {untrusted!r}") from exc

    # Confirm the resolved path is inside base_dir.
    try:
        candidate.relative_to(base)
    except ValueError:
        raise SafePathError(
            f"Path {untrusted!r} escapes base directory {base}"
        )

    return candidate


def _check_no_symlinks_unresolved(base: Path, joined: Path) -> None:
    """Walk every path component of *joined* that is below *base* and reject symlinks.

    This must be called BEFORE ``Path.resolve()`` because resolve() follows symlinks
    and erases them from the path, making them undetectable afterward.
    """
    # Collect segments to check: start from joined, walk up to base (exclusive).
    to_check: list[Path] = []
    current = joined
    while current != base and current != current.parent:
        to_check.append(current)
        current = current.parent

    # Check from outermost to innermost so we catch dangling symlinks early.
    for p in reversed(to_check):
        if p.exists() and p.is_symlink():
            raise SafePathError(
                f"Symlink detected in path: {p} — symlinks are not permitted"
            )


def atomic_move_then_verify(src: Path, dst_dir: Path) -> Path:
    """Atomically move *src* into *dst_dir* and verify the copy's SHA-256 matches.

    Steps:
    1. Read source bytes and compute SHA-256.
    2. Write to a temporary file in *dst_dir*.
    3. Verify the temp file's SHA-256 matches.
    4. Atomically rename temp → final path.
    5. Remove original *src*.

    FT-003: Validation must read *src* exactly once.  After this function returns,
    the caller works only from the returned path — never re-reads *src*.

    Parameters
    ----------
    src:
        Source file to move.
    dst_dir:
        Destination directory (must exist).

    Returns
    -------
    Path
        Final destination path.

    Raises
    ------
    AtomicMoveError
        If source is missing, SHA-256 verification fails, or any OS error occurs.
    """
    if not src.exists():
        raise AtomicMoveError(f"Source file not found: {src}")

    try:
        data = src.read_bytes()
    except OSError as exc:
        raise AtomicMoveError(f"Cannot read source {src}: {exc}") from exc

    expected_sha256 = hashlib.sha256(data).hexdigest()

    final_path = dst_dir / src.name

    # Write to a temp file in the same directory (same filesystem → rename is atomic).
    tmp_fd, tmp_path_str = tempfile.mkstemp(dir=dst_dir, prefix=f"_tmp_{src.name}_")
    tmp_path = Path(tmp_path_str)
    try:
        with os.fdopen(tmp_fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())

        # Verify the written bytes.
        written = tmp_path.read_bytes()
        actual_sha256 = hashlib.sha256(written).hexdigest()
        if actual_sha256 != expected_sha256:
            raise AtomicMoveError(
                f"SHA-256 mismatch after write: expected {expected_sha256}, got {actual_sha256}"
            )

        # Atomic rename on POSIX (os.replace is POSIX-atomic).
        os.replace(tmp_path, final_path)

    except AtomicMoveError:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        raise
    except OSError as exc:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        raise AtomicMoveError(f"Atomic move failed: {exc}") from exc

    # Remove the original source file.
    try:
        src.unlink()
    except OSError:
        pass  # best-effort; file already moved

    return final_path
