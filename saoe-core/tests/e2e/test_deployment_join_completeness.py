"""E2E test: deployment_agent join logic.

Tests that the deploy_parts SQLite join produces HTML output only when
all expected parts have arrived, and that the output path matches session_id.

This test exercises the join logic directly (not via the full agent polling loop)
to avoid requiring a running agent infrastructure.

Imports from the production deployment_agent module (via conftest sys.path addition)
so the test cannot diverge from the actual assembly logic.
"""
import sqlite3
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Import from production deployment_agent
# (conftest.py adds examples/demo/agents to sys.path)
# ---------------------------------------------------------------------------

import deployment_agent as da


# ---------------------------------------------------------------------------
# Thin test helpers — just DB setup/insert, no logic duplication
# ---------------------------------------------------------------------------


def _init_deploy_db(db_path: Path) -> None:
    """Initialise the deploy_parts schema using the production helper."""
    da._ensure_schema(db_path)


def _insert_part(db_path: Path, session_id: str, part_name: str, content: dict) -> None:
    """Insert a deploy part using the production upsert helper."""
    da._upsert_part(db_path, session_id, part_name, content)


def _check_and_assemble(db_path: Path, session_id: str, output_dir: Path) -> Path | None:
    """Delegate entirely to production functions — no logic duplication."""
    complete, text_data, img_data = da._check_completeness(db_path, session_id)
    if not complete:
        return None
    html = da._assemble_html(text_data, img_data)
    return da._write_output_atomically(output_dir, session_id, html)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_text_only_one_part_produces_html(tmp_path):
    """When image_present=False, a single text part yields HTML output."""
    db = tmp_path / "deploy.db"
    output_dir = tmp_path / "output"
    session_id = "sess-text-only-001"

    _init_deploy_db(db)
    _insert_part(db, session_id, "text", {
        "title": "Hello SAOE",
        "html_body": "<p>Test content</p>",
        "image_present": False,
    })

    out = _check_and_assemble(db, session_id, output_dir)

    assert out is not None, "Expected HTML to be written for text-only article"
    assert out.name == f"{session_id}.html", "Output filename must match session_id"
    content = out.read_text(encoding="utf-8")
    assert "Hello SAOE" in content
    assert "<p>Test content</p>" in content
    assert "<img" not in content, "No image tag expected for text-only article"


def test_image_article_one_part_no_output(tmp_path):
    """When image_present=True, only the text part arriving must NOT produce output."""
    db = tmp_path / "deploy.db"
    output_dir = tmp_path / "output"
    session_id = "sess-img-partial-001"

    _init_deploy_db(db)
    _insert_part(db, session_id, "text", {
        "title": "Image Article",
        "html_body": "<p>Body</p>",
        "image_present": True,
    })

    out = _check_and_assemble(db, session_id, output_dir)

    assert out is None, "Must not produce output when image part is still missing"
    assert not (output_dir / f"{session_id}.html").exists(), "Output file must not be created yet"


def test_image_article_two_parts_produces_html(tmp_path):
    """When image_present=True and both parts arrive, HTML with img tag is written."""
    db = tmp_path / "deploy.db"
    output_dir = tmp_path / "output"
    session_id = "sess-img-complete-001"

    _init_deploy_db(db)
    _insert_part(db, session_id, "text", {
        "title": "Full Article",
        "html_body": "<p>Article body here.</p>",
        "image_present": True,
    })
    _insert_part(db, session_id, "image", {
        "image_path": "/tmp/saoe/output/photo_safe.jpg",
    })

    out = _check_and_assemble(db, session_id, output_dir)

    assert out is not None, "Expected HTML when both parts present"
    assert out.name == f"{session_id}.html"
    content = out.read_text(encoding="utf-8")
    assert "Full Article" in content
    assert "<img" in content
    # Deployment agent uses a relative URL (filename only) — not the raw filesystem path
    assert 'src="/output/photo_safe.jpg"' in content, (
        "img src must be a relative URL, not a raw filesystem path"
    )
    assert "/tmp/saoe/output/photo_safe.jpg" not in content, (
        "Raw filesystem path must NOT appear in the rendered HTML"
    )


def test_output_path_matches_session_id(tmp_path):
    """The output HTML path must be exactly output_dir/{session_id}.html."""
    db = tmp_path / "deploy.db"
    output_dir = tmp_path / "output"
    session_id = "my-unique-session-42"

    _init_deploy_db(db)
    _insert_part(db, session_id, "text", {
        "title": "Path Test",
        "html_body": "<p>ok</p>",
        "image_present": False,
    })

    out = _check_and_assemble(db, session_id, output_dir)

    assert out == output_dir / f"{session_id}.html"


def test_xss_title_is_escaped(tmp_path):
    """Malicious title is sanitized via bleach before writing HTML."""
    db = tmp_path / "deploy.db"
    output_dir = tmp_path / "output"
    session_id = "sess-xss-title"

    _init_deploy_db(db)
    _insert_part(db, session_id, "text", {
        "title": "<script>alert('xss')</script>",
        "html_body": "<p>Safe body</p>",
        "image_present": False,
    })

    out = _check_and_assemble(db, session_id, output_dir)
    assert out is not None
    content = out.read_text(encoding="utf-8")
    assert "<script>" not in content


def test_image_only_no_output(tmp_path):
    """Image part arriving before text part must not produce output."""
    db = tmp_path / "deploy.db"
    output_dir = tmp_path / "output"
    session_id = "sess-img-first"

    _init_deploy_db(db)
    _insert_part(db, session_id, "image", {
        "image_path": "/tmp/saoe/output/photo_safe.jpg",
    })

    out = _check_and_assemble(db, session_id, output_dir)
    assert out is None, "Must not assemble without text part"
