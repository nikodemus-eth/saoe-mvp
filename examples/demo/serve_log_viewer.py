#!/usr/bin/env python3
"""serve_log_viewer.py: Audit-log viewer with shared nav, session filter, and strict CSP.

FT-008: All dynamic content passes through bleach.clean() before HTML insertion.
        Every response includes a strict Content-Security-Policy.
        No JavaScript is served — the CSP forbids it.

Usage:
    python serve_log_viewer.py [--port 8080] [--db path/to/events.db]

Routes:
    /                           — Audit events table (last 200 rows)
    /?session=<uuid>            — Filter to a single session's events
    /output/                    — Grid of assembled output articles
    /output/<session_id>.html   — Serve an assembled article
    /output/<name>.jpg|png      — Serve an output image
"""
import argparse
import html
import re
import sqlite3
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import bleach
from html.parser import HTMLParser

_REPO_ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(_REPO_ROOT / "saoe-core"))

_DEFAULT_DB = Path("/tmp/saoe/events.db")
_DEFAULT_OUTPUT_DIR = Path("/tmp/saoe/output")
_DEFAULT_PORT = 8080
_INTAKE_PORT = 8090  # companion intake form server

# Strict CSP — no JS, no external resources.
_CSP = (
    "default-src 'none'; "
    "style-src 'unsafe-inline'; "
    "img-src 'self'; "
    "frame-ancestors 'none'"
)

_EVENT_COLUMNS = [
    "id", "event_type", "envelope_id", "session_id", "sender_id",
    "receiver_id", "template_id", "agent_id", "timestamp_utc", "details_json",
]

# Only canonical UUID4 values are accepted as session filter input.
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)

# ---------------------------------------------------------------------------
# Shared CSS (system fonts only — enforced by CSP default-src 'none')
# ---------------------------------------------------------------------------

_BASE_CSS = """\
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#080f1e;--surface:#0c1525;--surface-2:#111d30;
  --border:#1a2e4a;--border-sub:#0d1e38;
  --accent:#22d3ee;--accent-dim:rgba(34,211,238,.13);--accent-glow:rgba(34,211,238,.06);
  --text:#c8d4e0;--text-strong:#f0f4f8;--text-muted:#4a5d70;
  --green:#10b981;--amber:#f59e0b;--red:#ef4444;--blue:#60a5fa;
  --font-ui:ui-sans-serif,system-ui,-apple-system,'Helvetica Neue',sans-serif;
  --font-mono:ui-monospace,'Cascadia Mono','SF Mono','Fira Code','Menlo',monospace}
html{background:var(--bg);color:var(--text);font-family:var(--font-ui);
  font-size:14px;-webkit-font-smoothing:antialiased}
body{min-height:100vh;display:flex;flex-direction:column}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline;color:var(--accent)}
a:focus-visible{outline:2px solid var(--accent);outline-offset:3px;border-radius:2px}
code,pre{font-family:var(--font-mono)}

/* ── Skip link ────────────────────────────────────────────────────── */
.skip-link{
  position:absolute;left:-9999px;top:auto;width:1px;height:1px;overflow:hidden;
  background:var(--accent);color:var(--bg);font-weight:700;padding:10px 18px;
  border-radius:4px;text-decoration:none;z-index:9999;font-size:13px}
.skip-link:focus{
  position:fixed;left:16px;top:16px;width:auto;height:auto;
  outline:3px solid #fff;outline-offset:2px}

/* ── Nav ──────────────────────────────────────────────────────────── */
header[role=banner]{
  position:sticky;top:0;z-index:100;
  background:var(--surface);border-bottom:1px solid var(--border)}
nav[aria-label="Main navigation"]{
  display:flex;align-items:center;padding:0 24px;height:52px;
  max-width:1600px;margin:0 auto;width:100%;gap:8px}
.nav-brand{
  display:flex;align-items:center;gap:7px;margin-right:20px;flex-shrink:0;
  color:var(--accent);font-family:var(--font-mono);font-weight:700;
  font-size:.75rem;letter-spacing:.14em;text-transform:uppercase;text-decoration:none}
.nav-brand:focus-visible{outline:2px solid var(--accent);outline-offset:3px;border-radius:3px}
.nav-diamond{font-size:.6rem;opacity:.7}
nav ul[role=list]{display:flex;list-style:none;gap:2px}
nav ul[role=list] a{
  display:block;padding:5px 13px;border-radius:6px;
  color:var(--text-muted);font-size:.8rem;font-weight:500;
  transition:color .12s,background .12s;border:1px solid transparent;
  text-decoration:none}
nav ul[role=list] a:hover{color:var(--text);background:var(--surface-2)}
nav ul[role=list] a:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
nav ul[role=list] a[aria-current=page]{
  color:var(--accent);background:var(--accent-dim);
  border-color:rgba(34,211,238,.28)}

/* ── Main / Layout ────────────────────────────────────────────────── */
main{flex:1;padding:32px 24px;max-width:1600px;margin:0 auto;width:100%}
.page-header{margin-bottom:24px}
h1{font-size:1rem;font-weight:700;color:var(--text-strong);
  font-family:var(--font-mono);letter-spacing:.04em;margin-bottom:4px}
.page-meta{font-size:.75rem;color:var(--text-muted)}
.page-meta a{color:var(--text-muted)}
.page-meta a:hover{color:var(--accent)}

/* ── Filter banner ────────────────────────────────────────────────── */
.filter-banner{
  display:flex;align-items:center;flex-wrap:wrap;gap:10px;
  padding:11px 16px;margin-bottom:20px;
  background:var(--accent-dim);border:1px solid rgba(34,211,238,.28);
  border-radius:8px;font-size:.78rem}
.filter-label{color:var(--text-muted);font-weight:600;letter-spacing:.04em;font-size:.7rem;
  text-transform:uppercase}
.filter-sess{
  background:var(--surface-2);border:1px solid var(--border);
  padding:2px 9px;border-radius:4px;
  color:var(--accent);font-family:var(--font-mono);font-size:.72rem}
.filter-count{color:var(--text-muted);font-size:.75rem}
.filter-clear{
  margin-left:auto;padding:4px 12px;border-radius:5px;
  background:var(--surface-2);border:1px solid var(--border);
  color:var(--text);font-size:.74rem;font-weight:500;text-decoration:none}
.filter-clear:hover{border-color:var(--accent);color:var(--accent);text-decoration:none}

/* ── Table ────────────────────────────────────────────────────────── */
.table-wrap{
  overflow-x:auto;border:1px solid var(--border);border-radius:10px;
  /* Scrollable region — accessible via keyboard */}
table{
  border-collapse:collapse;width:100%;min-width:1100px;
  font-family:var(--font-mono);font-size:.7rem}
caption{
  caption-side:top;text-align:left;padding:11px 16px;
  font-family:var(--font-ui);font-size:.73rem;color:var(--text-muted);
  border-bottom:1px solid var(--border);
  background:var(--surface-2);border-radius:10px 10px 0 0}
thead tr{background:var(--surface-2)}
th[scope=col]{
  padding:9px 12px;text-align:left;font-weight:600;
  color:var(--text-muted);font-size:.63rem;letter-spacing:.07em;
  text-transform:uppercase;white-space:nowrap;
  border-bottom:1px solid var(--border)}
th[scope=col]:first-child{width:52px}
th[scope=col]:nth-child(2){width:128px}
th[scope=col]:nth-child(3),th[scope=col]:nth-child(4){width:88px}
th[scope=col]:nth-child(5),th[scope=col]:nth-child(6),
th[scope=col]:nth-child(7),th[scope=col]:nth-child(8){width:110px}
th[scope=col]:nth-child(9){width:138px}
th[scope=col]:nth-child(10){min-width:220px}
td{
  padding:8px 12px;border-bottom:1px solid var(--border-sub);
  color:var(--text);vertical-align:top;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
tbody tr:hover td{background:var(--accent-glow)}
tbody tr:last-child td{border-bottom:none}

/* ── Event type pills ─────────────────────────────────────────────── */
.evt{
  display:inline-block;padding:2px 8px;border-radius:99px;
  font-size:.63rem;font-weight:700;letter-spacing:.05em;white-space:nowrap}
.evt-validated{
  background:rgba(16,185,129,.14);color:#34d399;border:1px solid rgba(16,185,129,.3)}
.evt-rejected,.evt-blocked{
  background:rgba(239,68,68,.12);color:#f87171;border:1px solid rgba(239,68,68,.28)}
.evt-forwarded{
  background:rgba(96,165,250,.11);color:#93c5fd;border:1px solid rgba(96,165,250,.25)}
.evt-tool_executed{
  background:rgba(245,158,11,.11);color:#fbbf24;border:1px solid rgba(245,158,11,.28)}
.evt-quarantined{
  background:rgba(249,115,22,.11);color:#fb923c;border:1px solid rgba(249,115,22,.28)}
.evt-error{
  background:rgba(239,68,68,.12);color:#f87171;border:1px solid rgba(239,68,68,.28)}
.evt-other{
  background:var(--surface-2);color:var(--text-muted);border:1px solid var(--border)}

/* ── Session link ─────────────────────────────────────────────────── */
a.sess-link{
  color:var(--text-muted);font-family:var(--font-mono);font-size:.7rem}
a.sess-link:hover{color:var(--accent);text-decoration:none}

/* ── Empty state ──────────────────────────────────────────────────── */
.empty{
  text-align:center;padding:72px 24px;
  color:var(--text-muted);font-size:.82rem;line-height:1.6}
.empty-glyph{font-size:1.8rem;margin-bottom:10px;opacity:.4}

/* ── Output grid ──────────────────────────────────────────────────── */
.output-grid{
  display:grid;
  grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:14px}
.output-card{
  display:flex;align-items:flex-start;gap:14px;
  background:var(--surface);border:1px solid var(--border);border-radius:10px;
  padding:16px 18px;transition:border-color .15s,background .15s}
.output-card:hover{border-color:var(--accent);background:var(--surface-2)}
.card-thumbs{
  display:flex;flex-shrink:0;gap:4px;align-items:flex-start}
.card-thumb{
  width:64px;height:64px;object-fit:cover;border-radius:6px;
  display:block;background:var(--surface-2)}
.card-content{flex:1;min-width:0}
.card-title{
  display:block;font-weight:600;font-size:.82rem;
  color:var(--text-strong);text-decoration:none;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
  margin-bottom:5px}
.card-title:hover{color:var(--accent)}
.card-title:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:2px}
.card-preview{
  font-size:.75rem;color:var(--text-muted);line-height:1.5;
  /* 3-line clamp */
  display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;
  overflow:hidden;margin-bottom:6px}
.card-meta{font-size:.68rem;color:var(--text-muted)}

/* ── Footer ───────────────────────────────────────────────────────── */
footer{
  margin-top:auto;padding:18px 24px;font-size:.68rem;
  color:var(--text-muted);border-top:1px solid var(--border);
  text-align:center}
footer a{color:var(--text-muted)}
footer a:hover{color:var(--accent)}
"""


# ---------------------------------------------------------------------------
# Navigation
# ---------------------------------------------------------------------------


def _nav_html(current: str, log_port: int = _DEFAULT_PORT) -> str:
    """Shared top navigation bar. No JavaScript; pure HTML + CSS."""
    pages = [
        ("Intake",      f"http://localhost:{_INTAKE_PORT}/"),
        ("Log Viewer",  f"http://localhost:{log_port}/"),
        ("Output",      f"http://localhost:{log_port}/output/"),
    ]
    items = ""
    for label, href in pages:
        aria = ' aria-current="page"' if label == current else ""
        items += (
            f'<li><a href="{html.escape(href)}"{aria}>'
            f"{html.escape(label)}</a></li>\n"
        )
    return (
        '<a class="skip-link" href="#main-content">Skip to main content</a>\n'
        '<header role="banner">\n'
        '<nav aria-label="Main navigation">\n'
        f'<a class="nav-brand" href="http://localhost:{log_port}/" '
        f'aria-label="SAOE home">'
        '<span class="nav-diamond" aria-hidden="true">◆</span>'
        "<span>SAOE</span>"
        "</a>\n"
        f'<ul role="list">{items}</ul>\n'
        "</nav>\n"
        "</header>\n"
    )


# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------


def _query_recent_events(
    db_path: Path,
    limit: int = 200,
    session_filter: str | None = None,
) -> list[dict]:
    """Return audit events, optionally filtered to a single session (UUID-validated)."""
    if not db_path.exists():
        return []
    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        if session_filter and _UUID_RE.match(session_filter):
            # Chronological order for single-session drill-down.
            rows = conn.execute(
                """
                SELECT id, event_type, envelope_id, session_id, sender_id,
                       receiver_id, template_id, agent_id, timestamp_utc, details_json
                FROM audit_events
                WHERE session_id = ?
                ORDER BY id ASC
                LIMIT ?
                """,
                (session_filter, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT id, event_type, envelope_id, session_id, sender_id,
                       receiver_id, template_id, agent_id, timestamp_utc, details_json
                FROM audit_events
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as exc:
        print(f"[log_viewer] WARNING: Could not read audit DB: {exc}", file=sys.stderr)
        return []


def _s(text: object) -> str:
    """Sanitise *text* for safe insertion as HTML text content."""
    if text is None:
        return ""
    return bleach.clean(str(text), tags=[], strip=True)


def _attr(text: object) -> str:
    """HTML-escape *text* for safe use in a double-quoted HTML attribute."""
    return html.escape(str(text or ""), quote=True)


# ---------------------------------------------------------------------------
# Cell renderers
# ---------------------------------------------------------------------------


def _event_type_cell(event_type: object) -> str:
    safe = _s(event_type)
    slug = safe.lower().replace(" ", "_")
    known = {"validated", "rejected", "blocked", "forwarded", "tool_executed",
             "quarantined", "error"}
    cls = f"evt-{slug}" if slug in known else "evt-other"
    return f'<td><span class="evt {cls}">{safe}</span></td>'


def _session_id_cell(session_id: object) -> str:
    """Render session_id as a clickable filter link when it is a valid UUID."""
    raw = str(session_id or "")
    if not raw:
        return "<td></td>"
    if _UUID_RE.match(raw):
        short = html.escape(raw[:8])
        href = _attr(raw)
        return (
            f'<td><a class="sess-link" href="/?session={href}" '
            f'title="Filter to session {href}" '
            f'aria-label="Filter to session {href}">'
            f"{short}\u2026</a></td>"
        )
    return f"<td>{_s(raw)}</td>"


def _short_cell(val: object, max_len: int = 10) -> str:
    """Render a potentially-long value truncated to max_len chars."""
    raw = str(val or "")
    if len(raw) > max_len:
        return (
            f'<td title="{_attr(raw)}">'
            f"{_s(raw[:max_len])}\u2026</td>"
        )
    return f"<td>{_s(raw)}</td>"


def _details_cell(val: object, max_len: int = 90) -> str:
    """Render details_json truncated; full value accessible via title."""
    raw = str(val or "")
    trunc = raw[:max_len]
    ellipsis = "\u2026" if len(raw) > max_len else ""
    return (
        f'<td title="{_attr(raw)}">'
        f"{_s(trunc)}{ellipsis}</td>"
    )


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------


def _page_wrap(
    title: str,
    nav: str,
    body_inner: str,
    port: int = _DEFAULT_PORT,
) -> str:
    """Wrap body content in a full accessible HTML page."""
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="UTF-8">\n'
        '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
        f"<title>{html.escape(title)}</title>\n"
        f"<style>{_BASE_CSS}</style>\n"
        "</head>\n"
        "<body>\n"
        + nav
        + f'<main id="main-content">\n{body_inner}\n</main>\n'
        + '<footer>\n'
        + '<p>SAOE v0.1.0 RT-Hardened\u2002·\u2002'
        + f'<a href="http://localhost:{port}/">Log Viewer</a>\u2002·\u2002'
        + f'<a href="http://localhost:{_INTAKE_PORT}/">Intake</a></p>\n'
        + "</footer>\n"
        "</body>\n"
        "</html>\n"
    )


def _render_events_page(
    events: list[dict],
    session_filter: str | None = None,
    port: int = _DEFAULT_PORT,
) -> str:
    nav = _nav_html("Log Viewer", port)

    # Filter banner
    filter_html = ""
    if session_filter:
        n = len(events)
        filter_html = (
            '<div class="filter-banner" role="status" aria-live="polite">\n'
            '<span class="filter-label">Session</span>\n'
            f'<code class="filter-sess">{html.escape(session_filter)}</code>\n'
            f'<span class="filter-count">{n} event{"s" if n != 1 else ""}</span>\n'
            '<a href="/" class="filter-clear" '
            'aria-label="Clear session filter">\u00d7 Clear</a>\n'
            "</div>\n"
        )

    # Empty state
    if not events:
        if session_filter:
            empty_msg = "No events found for this session."
        else:
            empty_msg = (
                'No audit events yet. '
                f'Submit an article via the <a href="http://localhost:{_INTAKE_PORT}/">'
                'Intake</a> form to see the pipeline in action.'
            )
        table_html = (
            '<div class="empty" role="status">'
            '<div class="empty-glyph" aria-hidden="true">\u2205</div>'
            f"{empty_msg}"
            "</div>"
        )
    else:
        # Build rows
        rows = []
        for ev in events:
            cells = "".join([
                f'<td>{_s(ev.get("id"))}</td>',
                _event_type_cell(ev.get("event_type")),
                _short_cell(ev.get("envelope_id"), 8),
                _session_id_cell(ev.get("session_id")),
                f'<td>{_s(ev.get("sender_id"))}</td>',
                f'<td>{_s(ev.get("receiver_id"))}</td>',
                f'<td>{_s(ev.get("template_id"))}</td>',
                f'<td>{_s(ev.get("agent_id"))}</td>',
                # Trim microseconds from timestamp for readability
                f'<td>{_s(str(ev.get("timestamp_utc") or "")[:19])}</td>',
                _details_cell(ev.get("details_json")),
            ])
            rows.append(f"<tr>{cells}</tr>")
        rows_html = "\n".join(rows)

        headers = "".join(
            f'<th scope="col">{html.escape(col)}</th>'
            for col in _EVENT_COLUMNS
        )
        is_filtered = bool(session_filter)
        caption = (
            f"Audit trail for session {html.escape(session_filter)} "
            f"— {len(events)} event{'s' if len(events) != 1 else ''}, "
            "oldest first"
            if is_filtered
            else f"Last {len(events)} audit events — newest first"
        )
        table_html = (
            '<div class="table-wrap" '
            'role="region" aria-label="Audit events" tabindex="0">\n'
            "<table>\n"
            f"<caption>{caption}</caption>\n"
            f"<thead><tr>{headers}</tr></thead>\n"
            f"<tbody>\n{rows_html}\n</tbody>\n"
            "</table>\n"
            "</div>"
        )

    page_title = (
        f"Session {session_filter[:8]}\u2026 \u2014 SAOE Audit"
        if session_filter
        else "Audit Log \u2014 SAOE"
    )
    heading = "Session Audit Trail" if session_filter else "Audit Log"
    meta_text = (
        f'Session: <code class="filter-sess">{html.escape(session_filter)}</code>'
        if session_filter
        else 'Pipeline events \u2014 newest first'
    )

    body_inner = (
        '<div class="page-header">\n'
        f"<h1>{heading}</h1>\n"
        f'<p class="page-meta">{meta_text}'
        f'\u2002\u00b7\u2002<a href="/output/">Output articles</a></p>\n'
        "</div>\n"
        + filter_html
        + table_html
    )

    return _page_wrap(page_title, nav, body_inner, port)


class _ArticleParser(HTMLParser):
    """Extract title (first <h1>), preview text (first non-empty <p>), and <img> srcs."""

    def __init__(self) -> None:
        super().__init__()
        self.title: str = ""
        self.preview: str = ""
        self.images: list[str] = []
        self._tag_stack: list[str] = []
        self._buf: list[str] = []
        self._found_h1 = False
        self._found_p = False

    def handle_starttag(self, tag: str, attrs: list) -> None:
        self._tag_stack.append(tag)
        if tag == "img":
            attrs_d = dict(attrs)
            src = attrs_d.get("src", "").strip()
            if src:
                self.images.append(src)
        if (tag == "h1" and not self._found_h1) or (tag == "p" and not self._found_p):
            self._buf = []

    def handle_data(self, data: str) -> None:
        if self._tag_stack and self._tag_stack[-1] in ("h1", "p"):
            self._buf.append(data)

    def handle_endtag(self, tag: str) -> None:
        if self._tag_stack and self._tag_stack[-1] == tag:
            self._tag_stack.pop()
        if tag == "h1" and not self._found_h1:
            self.title = "".join(self._buf).strip()
            self._found_h1 = True
            self._buf = []
        elif tag == "p" and not self._found_p:
            text = "".join(self._buf).strip()
            if text:
                self.preview = text
                self._found_p = True
            self._buf = []


def _parse_article(content: str) -> dict:
    """Return {title, preview, images:[src,...]} extracted from article HTML."""
    parser = _ArticleParser()
    try:
        parser.feed(content)
    except Exception:
        pass
    return {
        "title":   parser.title,
        "preview": parser.preview,
        "images":  parser.images[:2],  # at most 2
    }


_IMG_NAME_RE = re.compile(r"[A-Za-z0-9_\-]+\.(jpg|jpeg|png)", re.IGNORECASE)


def _img_thumb_url(src: str) -> str | None:
    """Convert an img src (filesystem path or partial URL) to a /output/... URL."""
    if not src:
        return None
    # Already a clean server-relative path
    if src.startswith("/output/"):
        fname = src[len("/output/"):]
    else:
        # Take the last path component (handles /tmp/saoe/output/x.jpg, x.jpg, etc.)
        fname = src.rstrip("/").rsplit("/", 1)[-1]
    if fname and _IMG_NAME_RE.fullmatch(fname):
        return f"/output/{fname}"
    return None


def _render_output_listing(output_dir: Path, port: int = _DEFAULT_PORT) -> str:
    import datetime

    nav = _nav_html("Output", port)
    cards = ""
    if output_dir.exists():
        files = sorted(
            output_dir.glob("*.html"),
            key=lambda f: f.stat().st_mtime,
            reverse=True,
        )
        for f in files:
            safe_name  = _s(f.name)
            safe_href  = _attr(f.name)
            stat       = f.stat()
            size_kb    = stat.st_size / 1024
            mtime      = datetime.datetime.fromtimestamp(stat.st_mtime).strftime(
                "%Y-%m-%d %H:%M"
            )

            # Parse article for title, preview, and image srcs
            try:
                content = f.read_text(encoding="utf-8", errors="replace")
                info    = _parse_article(content)
            except Exception:
                info = {"title": "", "preview": "", "images": []}

            display_title = _s(info["title"]) or safe_name

            # Thumbnail(s)
            thumb_html = ""
            thumb_urls = [
                _img_thumb_url(src) for src in info["images"] if _img_thumb_url(src)
            ]
            if thumb_urls:
                thumb_parts = []
                for i, url in enumerate(thumb_urls[:2]):
                    safe_url = _attr(url)
                    label    = f"Thumbnail {i + 1} for {_attr(info['title'] or f.name)}"
                    thumb_parts.append(
                        f'<img class="card-thumb" src="{safe_url}" alt="{label}">'
                    )
                thumb_html = f'<div class="card-thumbs">{"".join(thumb_parts)}</div>\n'

            # Preview text
            preview_html = ""
            if info["preview"]:
                preview_html = (
                    f'<p class="card-preview">{_s(info["preview"])}</p>\n'
                )

            cards += (
                '<div class="output-card">\n'
                + thumb_html
                + '<div class="card-content">\n'
                + f'<a class="card-title" href="/output/{safe_href}">'
                + f"{display_title}</a>\n"
                + preview_html
                + f'<p class="card-meta">{mtime}\u2002\u00b7\u2002{size_kb:.1f}\u202fKB</p>\n'
                + "</div>\n"
                + "</div>\n"
            )

    if not cards:
        cards = (
            '<div class="empty" role="status">'
            '<div class="empty-glyph" aria-hidden="true">\u2205</div>'
            "No output articles yet. Submit one via the "
            f'<a href="http://localhost:{_INTAKE_PORT}/">Intake</a> form.'
            "</div>"
        )

    body_inner = (
        '<div class="page-header">\n'
        "<h1>Output Articles</h1>\n"
        '<p class="page-meta">Assembled by the SAOE pipeline'
        f'\u2002\u00b7\u2002<a href="/">Back to audit log</a></p>\n'
        "</div>\n"
        f'<div class="output-grid" aria-label="Output articles">\n{cards}</div>'
    )

    return _page_wrap("Output Articles \u2014 SAOE", nav, body_inner, port)


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------


class LogViewerHandler(BaseHTTPRequestHandler):
    """Minimal stdlib handler; db_path, output_dir, and port set as class attributes."""

    db_path: Path = _DEFAULT_DB
    output_dir: Path = _DEFAULT_OUTPUT_DIR
    port: int = _DEFAULT_PORT

    def log_message(self, fmt, *args):  # noqa: ANN001
        print(f"[log_viewer] {self.address_string()} {fmt % args}")

    def _send(
        self,
        status: int,
        body: str,
        content_type: str = "text/html; charset=utf-8",
    ) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Content-Security-Policy", _CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(encoded)

    def _error_page(self, title: str, message: str) -> str:
        nav = _nav_html("Log Viewer", self.port)
        body_inner = (
            '<div class="page-header">'
            f"<h1>{html.escape(title)}</h1>"
            f'<p class="page-meta">{html.escape(message)}</p>'
            "</div>"
        )
        return _page_wrap(f"{title} \u2014 SAOE", nav, body_inner, self.port)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query, keep_blank_values=False)

        # Validate session filter before using it anywhere.
        raw_session = (qs.get("session") or [None])[0]
        session_filter = (
            raw_session
            if (raw_session and _UUID_RE.match(raw_session))
            else None
        )

        if path in ("/", ""):
            events = _query_recent_events(
                self.db_path, session_filter=session_filter
            )
            body = _render_events_page(events, session_filter=session_filter, port=self.port)
            self._send(200, body)

        elif path in ("/output/", "/output"):
            body = _render_output_listing(self.output_dir, port=self.port)
            self._send(200, body)

        elif path.startswith("/output/") and path.endswith(".html"):
            filename = path[len("/output/"):]
            if not re.fullmatch(r"[A-Za-z0-9_\-]+\.html", filename):
                self._send(400, self._error_page("Bad Request", "Invalid filename."))
                return
            article_path = self.output_dir / filename
            if not article_path.exists():
                self._send(404, self._error_page("Not Found", "Article not found."))
                return
            # Articles were already sanitized by deployment_agent; serve as-is.
            body = article_path.read_text(encoding="utf-8")
            self._send(200, body)

        elif path.startswith("/output/") and any(
            path.endswith(ext) for ext in (".jpg", ".jpeg", ".png")
        ):
            filename = path[len("/output/"):]
            if not re.fullmatch(r"[A-Za-z0-9_\-]+\.(jpg|jpeg|png)", filename):
                self._send(400, self._error_page("Bad Request", "Invalid filename."))
                return
            img_path = self.output_dir / filename
            if not img_path.exists():
                self._send(404, self._error_page("Not Found", "Image not found."))
                return
            ext = filename.rsplit(".", 1)[-1].lower()
            content_type = "image/jpeg" if ext in ("jpg", "jpeg") else "image/png"
            img_bytes = img_path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(img_bytes)))
            self.send_header("Content-Security-Policy", _CSP)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(img_bytes)

        else:
            self._send(404, self._error_page("Not Found", "Page not found."))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description="SAOE audit log viewer")
    parser.add_argument("--port", type=int, default=_DEFAULT_PORT)
    parser.add_argument("--db", type=Path, default=_DEFAULT_DB)
    parser.add_argument("--output-dir", type=Path, default=_DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()

    LogViewerHandler.db_path = args.db
    LogViewerHandler.output_dir = args.output_dir
    LogViewerHandler.port = args.port

    server = HTTPServer(("127.0.0.1", args.port), LogViewerHandler)
    print(f"[log_viewer] Serving on http://127.0.0.1:{args.port}/")
    print(f"[log_viewer] DB:         {args.db}")
    print(f"[log_viewer] Output dir: {args.output_dir}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        print("[log_viewer] Stopped.")


if __name__ == "__main__":
    main()
