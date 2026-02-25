"""Unit tests for deployment_agent pure functions.

Imports directly from the production agent module (not a copy of the logic)
so that any regression in the production code is caught immediately.

Key invariants tested:
- _assemble_html uses a relative URL (/output/<filename>) for <img src>,
  NOT the raw filesystem path.
- Two-image articles include the img tag; text-only articles do not.
- Malicious titles are bleach-sanitised.
- Responsive style attribute is present on the img tag.
"""
from pathlib import Path

import pytest

# deployment_agent is importable because examples/demo/agents/ is on sys.path
# via tests/demo/conftest.py
import deployment_agent as da


# ---------------------------------------------------------------------------
# _assemble_html — image URL format
# ---------------------------------------------------------------------------


def test_assemble_html_image_src_is_relative_url():
    """img src must be /output/<filename>, NOT an absolute filesystem path."""
    text_data = {
        "title": "Test Article",
        "html_body": "<p>Body text</p>",
        "image_present": True,
    }
    img_data = {"image_path": "/tmp/saoe/output/photo_safe.jpg"}

    html = da._assemble_html(text_data, img_data)

    assert 'src="/output/photo_safe.jpg"' in html, (
        "img src must be a relative URL (/output/<filename>), not the raw filesystem path"
    )
    assert "/tmp/saoe/output/" not in html, (
        "Raw filesystem path must not appear in the rendered HTML"
    )


def test_assemble_html_image_has_responsive_style():
    """img tag must carry max-width/height:auto so it scales on narrow viewports."""
    text_data = {
        "title": "Responsive Test",
        "html_body": "<p>ok</p>",
        "image_present": True,
    }
    img_data = {"image_path": "/tmp/saoe/output/img_safe.jpg"}

    html = da._assemble_html(text_data, img_data)

    assert "max-width:100%" in html
    assert "height:auto" in html


def test_assemble_html_no_image_tag_when_img_data_none():
    """Text-only articles must not contain an <img> tag."""
    text_data = {
        "title": "Text Only",
        "html_body": "<p>No image here</p>",
        "image_present": False,
    }

    html = da._assemble_html(text_data, None)

    assert "<img" not in html


def test_assemble_html_includes_body_text():
    """HTML body must include the html_body from text_data."""
    text_data = {
        "title": "Body Test",
        "html_body": "<p>Specific content 12345</p>",
        "image_present": False,
    }

    html = da._assemble_html(text_data, None)

    assert "<p>Specific content 12345</p>" in html


def test_assemble_html_title_sanitised_by_bleach():
    """Malicious <script> in the title must be stripped by bleach."""
    text_data = {
        "title": "<script>alert('xss')</script>Legit Title",
        "html_body": "<p>ok</p>",
        "image_present": False,
    }

    html = da._assemble_html(text_data, None)

    assert "<script>" not in html
    assert "Legit Title" in html


def test_assemble_html_correct_html_structure():
    """Output must be a valid HTML skeleton with doctype, head, and body."""
    text_data = {
        "title": "Structure Test",
        "html_body": "<p>ok</p>",
        "image_present": False,
    }

    html = da._assemble_html(text_data, None)

    assert "<!DOCTYPE html>" in html
    assert '<html lang="en">' in html
    assert "<title>Structure Test</title>" in html
    assert "<body>" in html


# ---------------------------------------------------------------------------
# _write_output_atomically
# ---------------------------------------------------------------------------


def test_write_output_atomically_creates_file(tmp_path):
    """The assembled HTML must be written atomically with the session_id as filename."""
    output_dir = tmp_path / "output"
    session_id = "test-session-unit-001"
    html = "<!DOCTYPE html><html><body>test</body></html>"

    out_path = da._write_output_atomically(output_dir, session_id, html)

    assert out_path == output_dir / f"{session_id}.html"
    assert out_path.exists()
    assert out_path.read_text(encoding="utf-8") == html


def test_write_output_atomically_no_temp_file_left(tmp_path):
    """No .tmp file should remain after a successful atomic write."""
    output_dir = tmp_path / "output"
    session_id = "test-session-unit-002"

    da._write_output_atomically(output_dir, session_id, "<html/>")

    tmp_files = list(output_dir.glob("*.tmp"))
    assert tmp_files == [], f"Unexpected .tmp files left behind: {tmp_files}"


# ---------------------------------------------------------------------------
# Security: path traversal in image_path field
# ---------------------------------------------------------------------------


def test_assemble_html_path_traversal_in_image_path_blocked():
    """image_path containing ../ must not produce a traversal in the img src.

    If image_path = '../../etc/passwd', the img src must be
    /output/passwd (filename only), never /output/../../etc/passwd.
    This protects against an attacker who controls the deploy_parts DB row.
    """
    text_data = {
        "title": "Traversal Test",
        "html_body": "<p>ok</p>",
        "image_present": True,
    }
    img_data = {"image_path": "../../etc/passwd"}

    html = da._assemble_html(text_data, img_data)

    assert "../" not in html, (
        "Path traversal sequence ../ must not appear in the assembled HTML"
    )
    assert 'src="/output/passwd"' in html, (
        "Only the filename should be used as the relative URL"
    )


# ---------------------------------------------------------------------------
# Security: XSS via image_path field
# ---------------------------------------------------------------------------


def test_assemble_html_xss_in_image_path_stripped():
    """Script tags in image_path must be stripped by bleach before insertion.

    If image_path = '<script>alert("xss")</script>evil.jpg', the rendered
    HTML must not contain <script>.
    This protects against an attacker who controls the deploy_parts DB row.
    """
    text_data = {
        "title": "XSS Image Path Test",
        "html_body": "<p>ok</p>",
        "image_present": True,
    }
    img_data = {"image_path": '<script>alert("xss")</script>evil.jpg'}

    html = da._assemble_html(text_data, img_data)

    assert "<script>" not in html, (
        "Script tag from image_path must be stripped before it reaches the HTML"
    )
