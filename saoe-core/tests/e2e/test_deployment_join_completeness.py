"""E2E test: deployment_agent join logic.

Tests that the deploy_parts SQLite join produces HTML output only when
all expected parts have arrived, and that the output path matches session_id.

This test exercises the join logic directly (not via the full agent polling loop)
to avoid requiring a running agent infrastructure.
"""
import json
import sqlite3
from pathlib import Path

import bleach
import pytest


# ---------------------------------------------------------------------------
# Helpers mirroring deployment_agent internals
# ---------------------------------------------------------------------------


def _init_deploy_db(db_path: Path) -> None:
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS deploy_parts (
            session_id TEXT NOT NULL,
            part_name  TEXT NOT NULL,
            content    TEXT NOT NULL,
            PRIMARY KEY (session_id, part_name)
        )
    """)
    conn.commit()
    conn.close()


def _insert_part(db_path: Path, session_id: str, part_name: str, content: dict) -> None:
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "INSERT OR REPLACE INTO deploy_parts (session_id, part_name, content) VALUES (?, ?, ?)",
        (session_id, part_name, json.dumps(content)),
    )
    conn.commit()
    conn.close()


def _check_and_assemble(db_path: Path, session_id: str, output_dir: Path) -> Path | None:
    """Return output HTML path if complete, else None."""
    conn = sqlite3.connect(str(db_path))
    text_row = conn.execute(
        "SELECT content FROM deploy_parts WHERE session_id = ? AND part_name = 'text'",
        (session_id,),
    ).fetchone()
    if text_row is None:
        conn.close()
        return None

    text_data = json.loads(text_row[0])
    image_present = text_data.get("image_present", False)
    expected_parts = 2 if image_present else 1

    part_count = conn.execute(
        "SELECT COUNT(*) FROM deploy_parts WHERE session_id = ?",
        (session_id,),
    ).fetchone()[0]

    img_row = conn.execute(
        "SELECT content FROM deploy_parts WHERE session_id = ? AND part_name = 'image'",
        (session_id,),
    ).fetchone()
    conn.close()

    if part_count < expected_parts:
        return None

    title = bleach.clean(text_data["title"], tags=[], strip=True)
    html_body = text_data["html_body"]

    img_html = ""
    if img_row:
        img_data = json.loads(img_row[0])
        img_path = bleach.clean(img_data["image_path"], tags=[], strip=True)
        img_html = f'<img src="{img_path}" alt="Article image" />\n'

    full_html = (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        f"<head><meta charset=\"UTF-8\"><title>{title}</title></head>\n"
        "<body>\n"
        f"<h1>{title}</h1>\n"
        f"{img_html}"
        f"{html_body}\n"
        "</body>\n"
        "</html>\n"
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / f"{session_id}.html"
    tmp_path = out_path.with_suffix(".tmp")
    tmp_path.write_text(full_html, encoding="utf-8")
    tmp_path.rename(out_path)
    return out_path


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
    assert "/tmp/saoe/output/photo_safe.jpg" in content


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
