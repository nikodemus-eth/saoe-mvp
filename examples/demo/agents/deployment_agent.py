#!/usr/bin/env python3
"""deployment_agent: SQLite join on session_id → /tmp/saoe/output/{session_id}.html.

Receives tool results from text_formatter_agent (blog_article_intent template)
and image_filter_agent (image_process_intent template). Once all expected parts
arrive, assembles the final HTML and writes it atomically.
"""
import json
import re
import sqlite3
from pathlib import Path

import bleach

from _agent_base import build_shim, load_config
from saoe_core.satl.validator import ValidationResult


# ---------------------------------------------------------------------------
# Deploy-parts SQLite helpers
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Security constants
# ---------------------------------------------------------------------------

# RT-2.3: session_id must contain only safe filename characters.
# Rejects path separators, null bytes, and any character that could be used
# for path traversal or shell injection when used as a filename.
_SESSION_ID_RE = re.compile(r"[A-Za-z0-9_\-]{1,128}")

# RT-3.1: Allowed HTML tags for html_body defense-in-depth sanitization.
# Same allowlist as text_formatter_agent — deployment_agent re-sanitizes
# even though text_formatter_agent already sanitized, to prevent a
# compromised or buggy formatter from injecting scripts.
_HTML_BODY_ALLOWED_TAGS = list(bleach.sanitizer.ALLOWED_TAGS) + [
    "h1", "h2", "h3", "h4", "h5", "h6",
    "pre", "code", "blockquote", "br", "hr",
    "table", "thead", "tbody", "tr", "th", "td",
    "p", "div", "span",
]
_HTML_BODY_ALLOWED_ATTRS = dict(bleach.sanitizer.ALLOWED_ATTRIBUTES)


def _get_deploy_db_path(config: dict) -> Path:
    path = Path(config["agent_stores_dir"]) / "deployment_agent" / "deploy.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _ensure_schema(db_path: Path) -> None:
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


def _upsert_part(db_path: Path, session_id: str, part_name: str, content: dict) -> None:
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        "INSERT OR REPLACE INTO deploy_parts (session_id, part_name, content) VALUES (?, ?, ?)",
        (session_id, part_name, json.dumps(content)),
    )
    conn.commit()
    conn.close()


def _check_completeness(db_path: Path, session_id: str) -> tuple[bool, dict | None, dict | None]:
    """Return (complete, text_data, img_data).

    complete is True only when all expected parts are present.
    """
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")

    text_row = conn.execute(
        "SELECT content FROM deploy_parts WHERE session_id = ? AND part_name = 'text'",
        (session_id,),
    ).fetchone()

    if text_row is None:
        conn.close()
        return False, None, None

    text_data = json.loads(text_row[0])
    image_present = text_data.get("image_present", False)
    expected_parts = 2 if image_present else 1

    part_count = conn.execute(
        "SELECT COUNT(*) FROM deploy_parts WHERE session_id = ?",
        (session_id,),
    ).fetchone()[0]

    img_data = None
    if image_present:
        img_row = conn.execute(
            "SELECT content FROM deploy_parts WHERE session_id = ? AND part_name = 'image'",
            (session_id,),
        ).fetchone()
        if img_row:
            img_data = json.loads(img_row[0])

    conn.close()
    complete = part_count >= expected_parts
    return complete, text_data, img_data


def _assemble_html(text_data: dict, img_data: dict | None) -> str:
    """Assemble final HTML from text and optional image parts."""
    title = bleach.clean(text_data["title"], tags=[], strip=True)
    # RT-3.1: Defense-in-depth — re-sanitize html_body even though
    # text_formatter_agent is expected to have done so already.  A compromised
    # or buggy formatter must not be able to inject scripts into the final HTML.
    html_body = bleach.clean(
        text_data["html_body"],
        tags=_HTML_BODY_ALLOWED_TAGS,
        attributes=_HTML_BODY_ALLOWED_ATTRS,
        strip=True,
    )

    img_html = ""
    if img_data:
        # Use only the filename as a relative URL so the log viewer can serve it
        img_filename = bleach.clean(Path(img_data["image_path"]).name, tags=[], strip=True)
        img_html = f'<img src="/output/{img_filename}" alt="Article image" style="max-width:100%;height:auto;" />\n'

    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        f'<head><meta charset="UTF-8"><title>{title}</title></head>\n'
        "<body>\n"
        f"<h1>{title}</h1>\n"
        f"{img_html}"
        f"{html_body}\n"
        "</body>\n"
        "</html>\n"
    )


def _write_output_atomically(output_dir: Path, session_id: str, html: str) -> Path:
    # RT-2.3: Validate session_id before using it as a filename component.
    # Reject any session_id that contains path separators, dots, or other
    # characters that could cause writes outside of output_dir.
    if not _SESSION_ID_RE.fullmatch(session_id):
        raise ValueError(
            f"Unsafe session_id {session_id!r}: must match [A-Za-z0-9_\\-]{{1,128}}"
        )
    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / f"{session_id}.html"
    tmp_path = out_path.with_suffix(".tmp")
    tmp_path.write_text(html, encoding="utf-8")
    tmp_path.rename(out_path)
    return out_path


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------


def handle(result: ValidationResult, config: dict) -> None:
    session_id = result.session_id
    template_id = result.envelope.template_ref.template_id
    payload = result.envelope.payload

    db_path = _get_deploy_db_path(config)
    _ensure_schema(db_path)

    if template_id == "blog_article_intent":
        # From text_formatter_agent: HTML fragment stored in body_markdown field.
        part_name = "text"
        content = {
            "title": payload["title"],
            "html_body": payload["body_markdown"],
            "image_present": payload["image_present"],
        }
    elif template_id == "image_process_intent":
        # From image_filter_agent: processed image path.
        part_name = "image"
        content = {
            "image_path": payload["input_image_path_token"],
        }
    else:
        print(f"[deployment_agent] Unknown template {template_id!r}, session={session_id}")
        return

    _upsert_part(db_path, session_id, part_name, content)
    print(f"[deployment_agent] Stored {part_name!r} part, session={session_id}")

    complete, text_data, img_data = _check_completeness(db_path, session_id)
    if not complete:
        expected = 2 if (text_data and text_data.get("image_present")) else 1
        print(f"[deployment_agent] Waiting for more parts, session={session_id}")
        return

    html = _assemble_html(text_data, img_data)
    output_dir = Path(config["output_dir"])
    out_path = _write_output_atomically(output_dir, session_id, html)
    print(f"[deployment_agent] HTML written: {out_path}")


def main() -> None:
    config = load_config()
    shim = build_shim("deployment_agent")
    shim.run_forever(lambda r: handle(r, config))


if __name__ == "__main__":
    main()
