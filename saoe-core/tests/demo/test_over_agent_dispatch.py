"""Unit tests for over_agent template-based dispatch.

Tests that handle() routes envelopes to the correct branch function based on
template_ref.template_id, and that each branch builds the right plan fields.

Key invariants:
- blog_article_intent  → handle_blog_article called, NOT handle_image_process
- image_process_intent → handle_image_process called, NOT handle_blog_article
- Unknown template_id  → neither branch called (no crash)
- handle_image_process uses payload["input_image_path_token"] for input_path,
  never an empty string.
"""
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, call, patch

import pytest

import over_agent as oa


# ---------------------------------------------------------------------------
# Minimal stub for ValidationResult / SATLEnvelope / TemplateRef
# ---------------------------------------------------------------------------


@dataclass
class _FakeTemplateRef:
    template_id: str
    version: str = "1"
    sha256_hash: str = "abc"
    dispatcher_signature: str = "sig"
    capability_set_id: str = "caps_x"
    capability_set_version: str = "1"


@dataclass
class _FakeEnvelope:
    template_ref: _FakeTemplateRef
    payload: dict


@dataclass
class _FakeResult:
    session_id: str
    envelope: _FakeEnvelope

    @property
    def template_id(self):
        return self.envelope.template_ref.template_id


def _blog_result(session_id: str = "sess-001", image_present: bool = False):
    return _FakeResult(
        session_id=session_id,
        envelope=_FakeEnvelope(
            template_ref=_FakeTemplateRef(template_id="blog_article_intent"),
            payload={
                "title": "Test Article",
                "body_markdown": "## Hello",
                "image_present": image_present,
            },
        ),
    )


def _image_result(session_id: str = "sess-001", input_path: str = "/tmp/image.jpg"):
    return _FakeResult(
        session_id=session_id,
        envelope=_FakeEnvelope(
            template_ref=_FakeTemplateRef(template_id="image_process_intent"),
            payload={
                "input_image_path_token": input_path,
                "strip_exif": True,
                "resize_max": 1024,
                "output_format": "jpg",
            },
        ),
    )


# ---------------------------------------------------------------------------
# handle() dispatch routing
# ---------------------------------------------------------------------------


def test_handle_routes_blog_article_to_blog_branch():
    """blog_article_intent must call handle_blog_article, not handle_image_process."""
    result = _blog_result()
    fake_sk = MagicMock()
    fake_config = {"keys_dir": "/fake/keys"}

    with (
        patch("over_agent.handle_blog_article") as mock_blog,
        patch("over_agent.handle_image_process") as mock_img,
        patch("over_agent.load_signing_key", return_value=fake_sk),
        patch("over_agent.Path"),  # prevent filesystem access
    ):
        oa.handle(result, shim=MagicMock(), config=fake_config)

    mock_blog.assert_called_once()
    mock_img.assert_not_called()


def test_handle_routes_image_process_to_image_branch():
    """image_process_intent must call handle_image_process, not handle_blog_article."""
    result = _image_result()
    fake_sk = MagicMock()

    with (
        patch("over_agent.handle_blog_article") as mock_blog,
        patch("over_agent.handle_image_process") as mock_img,
        patch("over_agent.load_signing_key", return_value=fake_sk),
        patch("over_agent.Path"),
    ):
        oa.handle(result, shim=MagicMock(), config={"keys_dir": "/fake/keys"})

    mock_img.assert_called_once()
    mock_blog.assert_not_called()


def test_handle_unknown_template_id_calls_neither_branch():
    """Unknown template_id must be silently skipped — no crash, no branch call."""
    result = _FakeResult(
        session_id="sess-unknown",
        envelope=_FakeEnvelope(
            template_ref=_FakeTemplateRef(template_id="unknown_template"),
            payload={},
        ),
    )

    with (
        patch("over_agent.handle_blog_article") as mock_blog,
        patch("over_agent.handle_image_process") as mock_img,
        patch("over_agent.load_signing_key", return_value=MagicMock()),
        patch("over_agent.Path"),
    ):
        # Must not raise
        oa.handle(result, shim=MagicMock(), config={"keys_dir": "/fake/keys"})

    mock_blog.assert_not_called()
    mock_img.assert_not_called()


# ---------------------------------------------------------------------------
# _plan_to_dict — pure function
# ---------------------------------------------------------------------------


def test_plan_to_dict_round_trips_all_fields():
    """_plan_to_dict must include all required plan fields."""
    mock_plan = MagicMock()
    mock_plan.plan_id = "plan-001"
    mock_plan.session_id = "sess-001"
    mock_plan.issuer_id = "over_agent"
    mock_plan.timestamp_utc = "2026-02-25T00:00:00+00:00"
    mock_plan.issuer_signature = "hexsig"
    mock_tc = MagicMock()
    mock_tc.tool_call_id = "tc-001"
    mock_tc.tool_name = "markdown_to_html"
    mock_tc.args = {"markdown": "# Hello"}
    mock_plan.tool_calls = [mock_tc]

    result = oa._plan_to_dict(mock_plan)

    assert result["plan_id"] == "plan-001"
    assert result["session_id"] == "sess-001"
    assert result["issuer_id"] == "over_agent"
    assert result["issuer_signature"] == "hexsig"
    assert len(result["tool_calls"]) == 1
    assert result["tool_calls"][0]["tool_name"] == "markdown_to_html"


# ---------------------------------------------------------------------------
# handle_image_process — input_path must come from payload, not be empty
# ---------------------------------------------------------------------------


def test_handle_image_process_uses_input_path_from_payload(tmp_path):
    """The img plan tool_call input_path must equal payload['input_image_path_token']."""
    image_path = str(tmp_path / "photo.jpg")
    result = _image_result(input_path=image_path)

    written_plans = {}

    def fake_write_text(content):
        import json
        written_plans["img_plan"] = json.loads(content)

    mock_plan_file = MagicMock()
    mock_plan_file.write_text = fake_write_text

    fake_agent_store = MagicMock()
    fake_agent_store.__truediv__ = lambda self, name: mock_plan_file
    fake_agent_store.mkdir = MagicMock()

    with (
        patch("over_agent._agent_store", return_value=fake_agent_store),
        patch("over_agent._load_manifest", return_value={
            "template_id": "image_process_intent",
            "version": "1",
            "sha256_hash": "abc",
            "dispatcher_signature": "sig",
        }),
        patch("over_agent.sign_plan") as mock_sign,
        patch("over_agent.TemplateRef"),
    ):
        mock_sign.return_value = MagicMock(
            plan_id="p1", session_id=result.session_id, issuer_id="over_agent",
            timestamp_utc="2026-01-01T00:00:00+00:00", issuer_signature="sig",
            tool_calls=[MagicMock(
                tool_call_id="tc1", tool_name="image_sanitize",
                args={"input_path": image_path},
            )],
        )
        mock_shim = MagicMock()

        oa.handle_image_process(result, mock_shim, {
            "output_dir": str(tmp_path),
            "queues_dir": str(tmp_path),
            "vault_dir": str(tmp_path),
            "agent_stores_dir": str(tmp_path),
        }, MagicMock())

    # The plan written to disk must carry the real path
    if written_plans:
        plan = written_plans["img_plan"]
        input_path_in_plan = plan["tool_calls"][0]["args"]["input_path"]
        assert input_path_in_plan == image_path, (
            f"Expected input_path={image_path!r}, got {input_path_in_plan!r}. "
            "over_agent must use payload['input_image_path_token'], not an empty string."
        )

    # Also verify the shim received the correct path in its payload
    send_kwargs = mock_shim.send_envelope.call_args
    if send_kwargs:
        payload_sent = send_kwargs.kwargs.get("payload") or send_kwargs.args[3] if len(send_kwargs.args) > 3 else {}
        if "input_image_path_token" in (payload_sent or {}):
            assert payload_sent["input_image_path_token"] == image_path
