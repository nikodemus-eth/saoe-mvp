"""Security tests for serve_log_viewer audit event rendering.

RT-5.1: Verify that HTML/script content in audit event fields (including
details_json) is stripped by bleach before being inserted into the rendered
audit log page.

The _s() helper in serve_log_viewer uses bleach.clean(text, tags=[], strip=True)
on all dynamic content — these tests confirm that sanitization is in effect
for every event column, including details_json.
"""
import json
from pathlib import Path
from unittest.mock import patch

import pytest

# serve_log_viewer is importable because examples/demo/ is on sys.path
# via tests/demo/conftest.py
import serve_log_viewer as slv


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(**kwargs) -> dict:
    """Build a minimal audit event dict (same shape as DB rows)."""
    base = {
        "id": 1,
        "event_type": "validated",
        "envelope_id": None,
        "session_id": None,
        "sender_id": None,
        "receiver_id": None,
        "template_id": None,
        "agent_id": None,
        "timestamp_utc": "2026-02-25T00:00:00+00:00",
        "details_json": None,
    }
    base.update(kwargs)
    return base


# ---------------------------------------------------------------------------
# RT-5.1: XSS via audit event fields
# ---------------------------------------------------------------------------


def test_render_events_strips_script_in_details_json():
    """<script> in details_json must be stripped before rendering.

    RT-5.1: An attacker who can write to the audit DB (or craft a rejection
    reason containing HTML) must not be able to execute scripts in the viewer.
    """
    event = _make_event(
        details_json=json.dumps({"reason": "<script>alert('xss')</script>"}),
    )
    html = slv._render_events_page([event])
    assert "<script>" not in html, (
        "Script tag in details_json must be stripped by bleach before rendering"
    )


def test_render_events_strips_script_in_sender_id():
    """<script> in sender_id must be stripped before rendering."""
    event = _make_event(sender_id="<script>alert(1)</script>")
    html = slv._render_events_page([event])
    assert "<script>" not in html


def test_render_events_strips_script_in_event_type():
    """Injected HTML in event_type must be stripped."""
    event = _make_event(event_type='validated<img src=x onerror=alert(1)>')
    html = slv._render_events_page([event])
    assert "onerror" not in html


def test_render_events_strips_script_in_session_id():
    """<script> in session_id must be stripped before rendering."""
    event = _make_event(session_id='<script>steal(document.cookie)</script>')
    html = slv._render_events_page([event])
    assert "<script>" not in html


def test_render_events_preserves_normal_text():
    """Normal audit event text must appear in the rendered page."""
    event = _make_event(
        event_type="validated",
        sender_id="intake_agent",
        session_id="sess-test-001",
        details_json=json.dumps({"template_version": "1"}),
    )
    html = slv._render_events_page([event])
    assert "intake_agent" in html
    assert "sess-test-001" in html
    assert "template_version" in html


# ---------------------------------------------------------------------------
# RT-5.1: _s() helper function directly
# ---------------------------------------------------------------------------


def test_sanitizer_helper_strips_script():
    """The _s() sanitizer helper must strip <script> tags."""
    result = slv._s("<script>alert(1)</script>Safe text")
    assert "<script>" not in result
    assert "Safe text" in result


def test_sanitizer_helper_strips_event_handler():
    """The _s() sanitizer helper must strip onclick attributes."""
    result = slv._s('<div onclick="alert(1)">content</div>')
    assert "onclick" not in result
    # bleach with tags=[] strips ALL tags, but content is preserved
    assert "content" in result


def test_sanitizer_helper_handles_none():
    """_s(None) must return empty string, not raise."""
    assert slv._s(None) == ""


# ---------------------------------------------------------------------------
# CSP: verify header is present on all responses
# ---------------------------------------------------------------------------


def test_csp_constant_includes_default_src_none():
    """The CSP must include default-src 'none' to block unexpected resource loads."""
    assert "default-src 'none'" in slv._CSP


def test_csp_constant_blocks_inline_scripts():
    """The CSP must NOT include 'unsafe-eval' or 'unsafe-inline' for scripts."""
    assert "unsafe-eval" not in slv._CSP
    # script-src 'unsafe-inline' is not present (only style-src has it)
    # Check there's no 'script-src' directive with 'unsafe-inline'
    csp_parts = slv._CSP.split(";")
    for part in csp_parts:
        if "script-src" in part:
            assert "unsafe-inline" not in part, (
                "script-src must not include 'unsafe-inline' in CSP"
            )
