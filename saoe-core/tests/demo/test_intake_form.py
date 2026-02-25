"""Unit tests for serve_intake_form.py Flask endpoints.

Uses Flask's built-in test client so no real network socket is needed.
The _drop_envelope function is patched to avoid needing a real SAOE environment
(keys, vault, queues) — we only test the HTTP interface and payload logic.

Key invariants:
- GET  /            → 200 with form HTML containing required fields
- POST /submit      → 400 if title missing
- POST /submit      → 400 if body missing
- POST /submit      → session_id + image_count=0 for text-only articles
- POST /submit      → session_id + image_count=1 for 1-image articles
- POST /submit      → image_count=2 (composite) for 2-image articles; one JPEG saved
- Image compositing → output is JPEG, width = sum of both input widths (same height)
"""
import io
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from PIL import Image


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def app_client(tmp_path):
    """Flask test client with _drop_envelope and config/key loading mocked out."""
    import serve_intake_form as sif

    # Override uploads dir to tmp_path to avoid writing to /tmp/saoe/uploads
    sif._UPLOADS_DIR = tmp_path / "uploads"
    sif._UPLOADS_DIR.mkdir()

    with (
        patch.object(sif, "_load_config", return_value={
            "keys_dir": str(tmp_path / "keys"),
            "vault_dir": str(tmp_path / "vault"),
            "queues_dir": str(tmp_path / "queues"),
        }),
        patch.object(sif, "_load_intake_key", return_value=MagicMock()),
        patch.object(sif, "_load_manifest", return_value={
            "template_id": "blog_article_intent",
            "version": "1",
            "sha256_hash": "abc",
            "dispatcher_signature": "sig",
        }),
        patch.object(sif, "_drop_envelope"),
    ):
        sif.app.config["TESTING"] = True
        yield sif.app.test_client(), sif


# ---------------------------------------------------------------------------
# Helper: make an in-memory JPEG
# ---------------------------------------------------------------------------


def _make_jpeg(width: int = 100, height: int = 80, color=(128, 0, 0)) -> bytes:
    img = Image.new("RGB", (width, height), color)
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    return buf.getvalue()


# ---------------------------------------------------------------------------
# GET /
# ---------------------------------------------------------------------------


def test_index_returns_200(app_client):
    client, _ = app_client
    resp = client.get("/")
    assert resp.status_code == 200


def test_index_contains_form_fields(app_client):
    client, _ = app_client
    html = client.get("/").data.decode("utf-8")

    assert 'name="title"' in html, "Form must have a title input"
    assert 'name="body"' in html, "Form must have a body textarea"
    assert 'name="images"' in html, "Form must have image file inputs"


def test_index_references_submit_endpoint(app_client):
    client, _ = app_client
    html = client.get("/").data.decode("utf-8")
    # The JS fetch or form action must reference /submit
    assert "/submit" in html


# ---------------------------------------------------------------------------
# POST /submit — validation
# ---------------------------------------------------------------------------


def test_submit_missing_title_returns_400(app_client):
    client, _ = app_client
    resp = client.post("/submit", data={"body": "Some text"})
    assert resp.status_code == 400
    data = json.loads(resp.data)
    assert data["ok"] is False


def test_submit_missing_body_returns_400(app_client):
    client, _ = app_client
    resp = client.post("/submit", data={"title": "My Title"})
    assert resp.status_code == 400
    data = json.loads(resp.data)
    assert data["ok"] is False


def test_submit_more_than_2_images_returns_400(app_client):
    client, _ = app_client
    jpeg = _make_jpeg()
    resp = client.post("/submit", data={
        "title": "Too many images",
        "body": "text",
        "images": [
            (io.BytesIO(jpeg), f"img{i}.jpg") for i in range(3)
        ],
    }, content_type="multipart/form-data")
    assert resp.status_code == 400
    result = json.loads(resp.data)
    assert result["ok"] is False


# ---------------------------------------------------------------------------
# POST /submit — text-only article
# ---------------------------------------------------------------------------


def test_submit_text_only_returns_session_id(app_client):
    client, _ = app_client
    resp = client.post("/submit", data={
        "title": "My Article",
        "body": "Lorem ipsum dolor sit amet.",
    })
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert data["ok"] is True
    assert "session_id" in data
    assert data["image_count"] == 0


def test_submit_text_only_drops_one_envelope(app_client):
    """Text-only article must produce exactly one SATL envelope (blog_article_intent)."""
    client, sif = app_client
    with patch.object(sif, "_drop_envelope") as mock_drop:
        resp = client.post("/submit", data={
            "title": "Text only",
            "body": "Some body text.",
        })
    assert resp.status_code == 200
    assert mock_drop.call_count == 1, (
        f"Expected 1 envelope for text-only article, got {mock_drop.call_count}"
    )


# ---------------------------------------------------------------------------
# POST /submit — single image article
# ---------------------------------------------------------------------------


def test_submit_with_one_image_returns_image_count_1(app_client):
    client, _ = app_client
    jpeg = _make_jpeg()
    resp = client.post("/submit", data={
        "title": "One Image",
        "body": "Body text here.",
        "images": (io.BytesIO(jpeg), "photo.jpg"),
    }, content_type="multipart/form-data")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert data["ok"] is True
    assert data["image_count"] == 1


def test_submit_with_one_image_drops_two_envelopes(app_client):
    """Single-image article must drop: 1× blog_article_intent + 1× image_process_intent."""
    client, sif = app_client
    jpeg = _make_jpeg()
    with patch.object(sif, "_drop_envelope") as mock_drop:
        resp = client.post("/submit", data={
            "title": "One Image",
            "body": "Body text.",
            "images": (io.BytesIO(jpeg), "photo.jpg"),
        }, content_type="multipart/form-data")
    assert resp.status_code == 200
    assert mock_drop.call_count == 2, (
        f"Expected 2 envelopes (blog + image), got {mock_drop.call_count}"
    )


# ---------------------------------------------------------------------------
# POST /submit — two images (composite)
# ---------------------------------------------------------------------------


def test_submit_with_two_images_returns_image_count_2(app_client):
    client, _ = app_client
    jpeg_a = _make_jpeg(100, 80, (255, 0, 0))
    jpeg_b = _make_jpeg(120, 80, (0, 255, 0))
    resp = client.post("/submit", data={
        "title": "Two Images",
        "body": "Body text.",
        "images": [
            (io.BytesIO(jpeg_a), "img_a.jpg"),
            (io.BytesIO(jpeg_b), "img_b.jpg"),
        ],
    }, content_type="multipart/form-data")
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert data["ok"] is True
    assert data["image_count"] == 2


def test_submit_with_two_images_composites_to_single_jpeg(app_client, tmp_path):
    """Two images must be composited side-by-side → the saved JPEG is wider than either."""
    client, sif = app_client
    # 100×80 red + 120×80 green → composite should be ≥ 100+120 = 220 px wide
    jpeg_a = _make_jpeg(100, 80, (255, 0, 0))
    jpeg_b = _make_jpeg(120, 80, (0, 255, 0))

    saved_paths = []

    original_save = sif._save_as_jpeg

    def capture_save(img, session_id, suffix=""):
        path = original_save(img, session_id, suffix)
        saved_paths.append((path, img))
        return path

    with patch.object(sif, "_save_as_jpeg", side_effect=capture_save):
        resp = client.post("/submit", data={
            "title": "Two Images",
            "body": "Body.",
            "images": [
                (io.BytesIO(jpeg_a), "a.jpg"),
                (io.BytesIO(jpeg_b), "b.jpg"),
            ],
        }, content_type="multipart/form-data")

    assert resp.status_code == 200
    assert len(saved_paths) == 1, "Exactly one composited image should be saved"
    _path, composited_img = saved_paths[0]
    assert composited_img.width >= 200, (
        f"Composited width {composited_img.width} should be >= sum of both image widths"
    )


# ---------------------------------------------------------------------------
# _composite_side_by_side — pure function
# ---------------------------------------------------------------------------


def test_composite_side_by_side_width_equals_sum_of_both():
    """Composited image width must equal the sum of the two input widths (at matched height)."""
    import serve_intake_form as sif

    img_a = Image.new("RGB", (200, 100), (255, 0, 0))
    img_b = Image.new("RGB", (150, 100), (0, 255, 0))

    result = sif._composite_side_by_side(img_a, img_b)

    # At matching height 100, widths are 200 and 150 → total 350
    assert result.width == 350
    assert result.height == 100


def test_composite_side_by_side_normalises_height():
    """When images have different heights, the taller image is scaled down."""
    import serve_intake_form as sif

    img_a = Image.new("RGB", (100, 200), (255, 0, 0))   # taller
    img_b = Image.new("RGB", (100,  50), (0, 255, 0))   # shorter

    result = sif._composite_side_by_side(img_a, img_b)

    # Height normalised to min(200, 50) = 50
    assert result.height == 50
