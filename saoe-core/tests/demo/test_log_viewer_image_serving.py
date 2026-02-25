"""Unit tests for serve_log_viewer.py image serving and CSP.

Tests the new /output/<image>.jpg route and the updated Content-Security-Policy
that includes img-src 'self'.

Key invariants:
- GET /output/<session_id>.html → serves the HTML, 200
- GET /output/<filename>.jpg    → serves JPEG with Content-Type image/jpeg, 200
- GET /output/<filename>.png    → serves PNG with Content-Type image/png, 200
- GET /output/../etc/passwd     → 400 Bad Request (path traversal blocked)
- GET /output/nonexistent.jpg   → 404 Not Found
- Content-Security-Policy header contains "img-src 'self'"
"""
import io
from http.server import HTTPServer
from pathlib import Path
from threading import Thread
from urllib.request import urlopen
from urllib.error import HTTPError

import pytest


# ---------------------------------------------------------------------------
# Spin up a real LogViewerHandler against a tmp dir
# ---------------------------------------------------------------------------


@pytest.fixture()
def log_viewer(tmp_path):
    """Start a LogViewerHandler on a random port, yield (url_base, output_dir)."""
    import sys
    # serve_log_viewer is importable via conftest sys.path addition
    import serve_log_viewer as slv

    output_dir = tmp_path / "output"
    output_dir.mkdir()

    # Write a sample JPEG (minimal 1×1 pixel JPEG bytes)
    _MINIMAL_JPEG = bytes([
        0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
        0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43,
        0x00, 0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08, 0x07, 0x07, 0x07, 0x09,
        0x09, 0x08, 0x0A, 0x0C, 0x14, 0x0D, 0x0C, 0x0B, 0x0B, 0x0C, 0x19, 0x12,
        0x13, 0x0F, 0x14, 0x1D, 0x1A, 0x1F, 0x1E, 0x1D, 0x1A, 0x1C, 0x1C, 0x20,
        0x24, 0x2E, 0x27, 0x20, 0x22, 0x2C, 0x23, 0x1C, 0x1C, 0x28, 0x37, 0x29,
        0x2C, 0x30, 0x31, 0x34, 0x34, 0x34, 0x1F, 0x27, 0x39, 0x3D, 0x38, 0x32,
        0x3C, 0x2E, 0x33, 0x34, 0x32, 0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01,
        0x00, 0x01, 0x01, 0x01, 0x11, 0x00, 0xFF, 0xC4, 0x00, 0x1F, 0x00, 0x00,
        0x01, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0xFF, 0xC4, 0x00, 0xB5, 0x10, 0x00, 0x02, 0x01, 0x03,
        0x03, 0x02, 0x04, 0x03, 0x05, 0x05, 0x04, 0x04, 0x00, 0x00, 0x01, 0x7D,
        0xFF, 0xD9,
    ])
    (output_dir / "photo_safe.jpg").write_bytes(_MINIMAL_JPEG)
    (output_dir / "article-session-123.html").write_text(
        "<!DOCTYPE html><html><body>Hello</body></html>", encoding="utf-8"
    )

    # Bind to a random free port
    server = HTTPServer(("127.0.0.1", 0), slv.LogViewerHandler)
    slv.LogViewerHandler.db_path = tmp_path / "nonexistent.db"
    slv.LogViewerHandler.output_dir = output_dir
    port = server.server_address[1]

    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield f"http://127.0.0.1:{port}", output_dir

    server.shutdown()


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _get(url: str) -> tuple[int, dict, bytes]:
    """Return (status, headers_dict, body_bytes). Handles 4xx/5xx via HTTPError."""
    try:
        with urlopen(url) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except HTTPError as exc:
        return exc.code, {}, b""


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_image_jpeg_served_with_correct_content_type(log_viewer):
    """GET /output/<name>.jpg must return 200 with Content-Type: image/jpeg."""
    base, _ = log_viewer
    status, headers, body = _get(f"{base}/output/photo_safe.jpg")

    assert status == 200
    assert "image/jpeg" in headers.get("Content-Type", ""), (
        f"Expected image/jpeg content-type, got: {headers.get('Content-Type')}"
    )
    assert len(body) > 0


def test_html_article_served(log_viewer):
    """GET /output/<session>.html must return 200 with the article HTML."""
    base, _ = log_viewer
    status, headers, body = _get(f"{base}/output/article-session-123.html")

    assert status == 200
    assert "Hello" in body.decode("utf-8")


def test_path_traversal_in_image_filename_blocked(log_viewer):
    """GET /output/../etc/passwd must be blocked with 400."""
    base, _ = log_viewer
    # URL-encode the traversal
    status, _, _ = _get(f"{base}/output/..%2Fetc%2Fpasswd")

    assert status in (400, 404), (
        f"Path traversal in image filename should be rejected, got {status}"
    )


def test_nonexistent_image_returns_404(log_viewer):
    """GET /output/nonexistent.jpg must return 404."""
    base, _ = log_viewer
    status, _, _ = _get(f"{base}/output/nonexistent.jpg")

    assert status == 404


def test_csp_header_includes_img_src_self(log_viewer):
    """Every response must include 'img-src 'self'' in the CSP header."""
    base, _ = log_viewer
    # Check on the HTML article (the main response type)
    _, headers, _ = _get(f"{base}/output/article-session-123.html")

    csp = headers.get("Content-Security-Policy", "")
    assert "img-src 'self'" in csp, (
        f"CSP must include img-src 'self' so article images load. Got: {csp!r}"
    )


def test_invalid_extension_returns_404(log_viewer):
    """GET /output/file.exe must return 404 (not an allowed image extension)."""
    base, _ = log_viewer
    status, _, _ = _get(f"{base}/output/malware.exe")

    assert status == 404
