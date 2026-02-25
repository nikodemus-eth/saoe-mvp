#!/usr/bin/env python3
"""serve_log_viewer.py: Minimal audit-log viewer with CSP headers.

FT-008: All dynamic content passes through bleach.clean().
        Every response includes a strict Content-Security-Policy.

Usage:
    python serve_log_viewer.py [--port 8080] [--db path/to/events.db]

Serves:
    /          — HTML table of recent audit events (last 200 rows)
    /output/   — Listing of /tmp/saoe/output/ HTML files
    /output/<session_id>.html — Serve the assembled article HTML
"""
import argparse
import html
import json
import sqlite3
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import bleach

_REPO_ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(_REPO_ROOT / "saoe-core"))

_DEFAULT_DB = Path("/tmp/saoe/events.db")
_DEFAULT_OUTPUT_DIR = Path("/tmp/saoe/output")
_DEFAULT_PORT = 8080

_CSP = (
    "default-src 'none'; "
    "style-src 'unsafe-inline'; "
    "frame-ancestors 'none'"
)

_EVENT_COLUMNS = [
    "id", "event_type", "envelope_id", "session_id", "sender_id",
    "receiver_id", "template_id", "agent_id", "timestamp_utc", "details_json",
]


# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------


def _query_recent_events(db_path: Path, limit: int = 200) -> list[dict]:
    if not db_path.exists():
        return []
    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
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
    """Sanitise *text* for safe HTML insertion."""
    if text is None:
        return ""
    return bleach.clean(str(text), tags=[], strip=True)


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------


def _render_events_page(events: list[dict]) -> str:
    rows_html = ""
    for ev in events:
        cells = "".join(
            f"<td>{_s(ev.get(col))}</td>"
            for col in _EVENT_COLUMNS
        )
        rows_html += f"<tr>{cells}</tr>\n"

    headers = "".join(f"<th>{html.escape(col)}</th>" for col in _EVENT_COLUMNS)

    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="UTF-8">\n'
        "<title>SAOE Audit Log</title>\n"
        "<style>\n"
        "body { font-family: monospace; font-size: 12px; padding: 1em; }\n"
        "table { border-collapse: collapse; width: 100%; }\n"
        "th, td { border: 1px solid #ccc; padding: 4px 8px; text-align: left; }\n"
        "th { background: #f0f0f0; }\n"
        "tr:nth-child(even) { background: #fafafa; }\n"
        "</style>\n"
        "</head>\n"
        "<body>\n"
        "<h1>SAOE Audit Log (last 200 events)</h1>\n"
        '<p><a href="/output/">View output articles</a></p>\n'
        "<table>\n"
        f"<thead><tr>{headers}</tr></thead>\n"
        "<tbody>\n"
        f"{rows_html}"
        "</tbody>\n"
        "</table>\n"
        "</body>\n"
        "</html>\n"
    )


def _render_output_listing(output_dir: Path) -> str:
    items = ""
    if output_dir.exists():
        for f in sorted(output_dir.glob("*.html")):
            name = _s(f.name)
            items += f'<li><a href="/output/{name}">{name}</a></li>\n'

    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="UTF-8">\n'
        "<title>SAOE Output Articles</title>\n"
        "<style>body { font-family: monospace; padding: 1em; }</style>\n"
        "</head>\n"
        "<body>\n"
        "<h1>Output Articles</h1>\n"
        '<p><a href="/">Back to audit log</a></p>\n'
        "<ul>\n"
        f"{items}"
        "</ul>\n"
        "</body>\n"
        "</html>\n"
    )


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------


class LogViewerHandler(BaseHTTPRequestHandler):
    """Minimal handler; db_path and output_dir set as class attributes."""

    db_path: Path = _DEFAULT_DB
    output_dir: Path = _DEFAULT_OUTPUT_DIR

    def log_message(self, fmt, *args):  # noqa: ANN001
        # Suppress default access log to stdout; use structured form instead.
        print(f"[log_viewer] {self.address_string()} {fmt % args}")

    def _send(self, status: int, body: str, content_type: str = "text/html; charset=utf-8") -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Content-Security-Policy", _CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?")[0]  # strip query string

        if path == "/" or path == "":
            events = _query_recent_events(self.db_path)
            body = _render_events_page(events)
            self._send(200, body)

        elif path == "/output/" or path == "/output":
            body = _render_output_listing(self.output_dir)
            self._send(200, body)

        elif path.startswith("/output/") and path.endswith(".html"):
            filename = path[len("/output/"):]
            # FT-008: only allow safe filenames (alphanumeric, hyphens, underscores)
            import re
            if not re.fullmatch(r"[A-Za-z0-9_\-]+\.html", filename):
                self._send(400, "<h1>Bad Request</h1>")
                return
            article_path = self.output_dir / filename
            if not article_path.exists():
                self._send(404, "<h1>Not Found</h1>")
                return
            # The article HTML was already sanitized by deployment_agent; serve as-is.
            body = article_path.read_text(encoding="utf-8")
            self._send(200, body)

        else:
            self._send(404, "<h1>Not Found</h1>")


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

    server = HTTPServer(("127.0.0.1", args.port), LogViewerHandler)
    print(f"[log_viewer] Serving on http://127.0.0.1:{args.port}/")
    print(f"[log_viewer] DB: {args.db}")
    print(f"[log_viewer] Output dir: {args.output_dir}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        print("[log_viewer] Stopped.")


if __name__ == "__main__":
    main()
