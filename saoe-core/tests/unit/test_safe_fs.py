"""Tests for saoe_core.util.safe_fs — path traversal, symlink, and atomic move."""
import hashlib
import os
from pathlib import Path

import pytest

from saoe_core.util.safe_fs import (
    AtomicMoveError,
    SafePathError,
    atomic_move_then_verify,
    resolve_safe_path,
)


# ---------------------------------------------------------------------------
# resolve_safe_path
# ---------------------------------------------------------------------------


def test_resolve_safe_path_happy(tmp_path: Path) -> None:
    result = resolve_safe_path(tmp_path, "subdir/file.txt")
    assert result == tmp_path / "subdir" / "file.txt"


def test_resolve_safe_path_rejects_traversal(tmp_path: Path) -> None:
    with pytest.raises(SafePathError):
        resolve_safe_path(tmp_path, "../outside.txt")


def test_resolve_safe_path_rejects_absolute_escape(tmp_path: Path) -> None:
    with pytest.raises(SafePathError):
        resolve_safe_path(tmp_path, "/etc/passwd")


def test_resolve_safe_path_rejects_double_dot_deep(tmp_path: Path) -> None:
    with pytest.raises(SafePathError):
        resolve_safe_path(tmp_path, "a/b/../../../../../../etc/passwd")


def test_resolve_safe_path_rejects_symlink_outside(tmp_path: Path) -> None:
    """A symlink inside base_dir that points outside must be rejected."""
    evil_link = tmp_path / "evil"
    evil_link.symlink_to("/etc")
    with pytest.raises(SafePathError):
        resolve_safe_path(tmp_path, "evil/passwd")


def test_resolve_safe_path_rejects_symlink_component(tmp_path: Path) -> None:
    """Even a symlink to a safe dir should be rejected (strict mode)."""
    safe_target = tmp_path / "real_dir"
    safe_target.mkdir()
    link = tmp_path / "link_to_real"
    link.symlink_to(safe_target)
    with pytest.raises(SafePathError):
        resolve_safe_path(tmp_path, "link_to_real/file.txt")


def test_resolve_safe_path_nested_ok(tmp_path: Path) -> None:
    nested = tmp_path / "a" / "b" / "c"
    result = resolve_safe_path(tmp_path, "a/b/c/file.json")
    assert result == nested / "file.json"


# ---------------------------------------------------------------------------
# atomic_move_then_verify
# ---------------------------------------------------------------------------


def test_atomic_move_creates_file(tmp_path: Path) -> None:
    src = tmp_path / "src.json"
    src.write_bytes(b'{"key": "value"}')
    dst_dir = tmp_path / "dst"
    dst_dir.mkdir()

    result = atomic_move_then_verify(src, dst_dir)

    assert result.exists()
    assert result.read_bytes() == b'{"key": "value"}'
    assert not src.exists()  # source removed after move


def test_atomic_move_removes_source(tmp_path: Path) -> None:
    src = tmp_path / "src.dat"
    src.write_bytes(b"hello world")
    dst_dir = tmp_path / "out"
    dst_dir.mkdir()

    atomic_move_then_verify(src, dst_dir)
    assert not src.exists()


def test_atomic_move_raises_if_src_missing(tmp_path: Path) -> None:
    dst_dir = tmp_path / "out"
    dst_dir.mkdir()
    with pytest.raises(AtomicMoveError):
        atomic_move_then_verify(tmp_path / "nonexistent.json", dst_dir)


def test_atomic_move_sha256_verified(tmp_path: Path) -> None:
    """The dst file sha256 must equal the src sha256."""
    src = tmp_path / "msg.bin"
    data = b"important data" * 100
    src.write_bytes(data)
    dst_dir = tmp_path / "promoted"
    dst_dir.mkdir()

    result = atomic_move_then_verify(src, dst_dir)

    expected_hash = hashlib.sha256(data).hexdigest()
    actual_hash = hashlib.sha256(result.read_bytes()).hexdigest()
    assert actual_hash == expected_hash
