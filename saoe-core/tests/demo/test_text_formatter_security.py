"""Security tests for text_formatter_agent.markdown_to_html_tool.

RT-3.2: Verify that dangerous URI schemes (javascript:, data:) in markdown
links are neutralised before reaching the HTML output.

bleach 6.x strips href attributes whose values contain unsafe URI schemes,
so these tests are confirmatory — they document existing protection and
will fail loudly if a bleach version regression ever removes it.
"""
import pytest

# text_formatter_agent is importable because examples/demo/agents/ is on
# sys.path via tests/demo/conftest.py
import text_formatter_agent as tfa


# ---------------------------------------------------------------------------
# RT-3.2: javascript: URI in markdown links
# ---------------------------------------------------------------------------


def test_markdown_javascript_href_stripped():
    """javascript: link href must not appear in the HTML output.

    bleach strips href attributes containing javascript: scheme.
    A link like [click me](javascript:alert(1)) must not produce an
    exploitable href in the output.
    """
    result = tfa.markdown_to_html_tool(
        {"markdown": "[click me](javascript:alert(1))"},
        {},
    )
    html = result["html_fragment"]
    assert "javascript:" not in html, (
        "javascript: URI scheme must be stripped from markdown links"
    )
    # The link text must still be present (bleach keeps the tag, strips the href)
    assert "click me" in html


def test_markdown_javascript_href_mixed_case_stripped():
    """javascript: scheme check is case-insensitive — JAVASCRIPT: must also be blocked."""
    result = tfa.markdown_to_html_tool(
        {"markdown": "[xss](JAVASCRIPT:alert(1))"},
        {},
    )
    html = result["html_fragment"]
    assert "javascript:" not in html.lower(), (
        "javascript: URI must be stripped regardless of case"
    )


def test_markdown_data_uri_href_stripped():
    """data: URI in a link href must be stripped.

    data: URIs can carry HTML/JS payloads and must not appear in the output.
    """
    result = tfa.markdown_to_html_tool(
        {"markdown": "[payload](data:text/html,<script>alert(1)</script>)"},
        {},
    )
    html = result["html_fragment"]
    assert "data:" not in html, (
        "data: URI scheme must be stripped from markdown links"
    )


def test_markdown_script_tag_stripped():
    """Raw <script> tags in markdown body must be stripped by bleach."""
    result = tfa.markdown_to_html_tool(
        {"markdown": "Normal text\n\n<script>alert('xss')</script>"},
        {},
    )
    html = result["html_fragment"]
    assert "<script>" not in html, (
        "Raw <script> tags must be stripped from markdown output"
    )
    assert "Normal text" in html


def test_markdown_inline_event_handler_stripped():
    """Inline event handlers injected via raw HTML in markdown must be stripped."""
    result = tfa.markdown_to_html_tool(
        {"markdown": '<p onclick="alert(1)">text</p>'},
        {},
    )
    html = result["html_fragment"]
    assert "onclick" not in html, (
        "onclick attribute must be stripped by bleach when html_body passes through markdown_to_html"
    )
    assert "text" in html


def test_markdown_normal_https_link_preserved():
    """Legitimate https: links must survive the sanitization pipeline."""
    result = tfa.markdown_to_html_tool(
        {"markdown": "[Safe link](https://example.com/page)"},
        {},
    )
    html = result["html_fragment"]
    assert "https://example.com/page" in html, (
        "Safe https: link href must not be stripped"
    )
    assert "Safe link" in html
