"""Security tests for image_filter_agent against decompression bombs.

RT-4.1: An image whose dimensions exceed Pillow's MAX_IMAGE_PIXELS threshold
must be rejected — image_sanitize_tool must raise rather than silently
decompress a potentially multi-gigabyte image.

Pillow's built-in bomb detection:
  width * height > 2 * MAX_IMAGE_PIXELS  → DecompressionBombError (always raises)
  width * height > MAX_IMAGE_PIXELS      → DecompressionBombWarning (warning only)

These tests verify that bomb protection is:
  1. NOT disabled by image_sanitize_tool (no Image.MAX_IMAGE_PIXELS = None).
  2. Working: a tool call on an oversized image raises an exception.
  3. Not silently swallowed: the caller (shim) is expected to receive the error.
"""
import io
import warnings

import pytest
from PIL import Image

# image_filter_agent is importable via tests/demo/conftest.py sys.path injection
import image_filter_agent as ifa


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_jpeg(tmp_path, width: int, height: int) -> str:
    """Create a real JPEG file of the given dimensions."""
    img = Image.new("RGB", (width, height), (128, 64, 32))
    path = tmp_path / "test_image.jpg"
    img.save(str(path), format="JPEG")
    return str(path)


# ---------------------------------------------------------------------------
# RT-4.1: bomb protection via Pillow threshold
# ---------------------------------------------------------------------------


def test_image_sanitize_tool_bomb_threshold_is_active(tmp_path):
    """Pillow's MAX_IMAGE_PIXELS limit must NOT be disabled by image_sanitize_tool.

    Some code sets Image.MAX_IMAGE_PIXELS = None to skip the check.
    We verify the limit is still in force after image_sanitize_tool imports Pillow.
    """
    # Import the tool module (which imports Pillow at module load time)
    import importlib
    import image_filter_agent  # noqa: F401 — ensure module is loaded

    assert Image.MAX_IMAGE_PIXELS is not None, (
        "Image.MAX_IMAGE_PIXELS must not be set to None — "
        "doing so disables decompression bomb protection (RT-4.1)"
    )
    assert Image.MAX_IMAGE_PIXELS > 0, (
        "Image.MAX_IMAGE_PIXELS must be positive to enable bomb protection"
    )


def test_image_sanitize_tool_rejects_decompression_bomb(tmp_path):
    """An image exceeding MAX_IMAGE_PIXELS must raise, not be silently processed.

    We temporarily lower the bomb threshold so a small test JPEG triggers it,
    then verify that image_sanitize_tool raises rather than producing output.

    This confirms that the tool does NOT disable Pillow's bomb detection and
    does NOT catch DecompressionBombError in a broad except clause.
    """
    # Create a 100×100 image (10,000 pixels)
    img_path = _make_jpeg(tmp_path, 100, 100)
    output_dir = tmp_path / "output"

    original_limit = Image.MAX_IMAGE_PIXELS
    try:
        # Lower threshold so our 100×100 image is an "oversized" bomb
        # 100*100 = 10,000; we set limit to 5,000 so 10,000 > 2*5,000 → Error
        Image.MAX_IMAGE_PIXELS = 4_999

        with pytest.raises(Image.DecompressionBombError):
            ifa.image_sanitize_tool(
                {
                    "input_path": img_path,
                    "output_dir": str(output_dir),
                    "strip_exif": True,
                    "resize_max": 1024,
                    "output_format": "jpg",
                },
                {},
            )

        # Verify no output was written despite the attempt
        assert not output_dir.exists() or not list(output_dir.glob("*.jpg")), (
            "No output file must be written when a decompression bomb is detected"
        )
    finally:
        Image.MAX_IMAGE_PIXELS = original_limit


def test_image_sanitize_tool_normal_image_not_rejected(tmp_path):
    """A normal-sized image must be processed successfully (not a false positive)."""
    img_path = _make_jpeg(tmp_path, 200, 150)
    output_dir = tmp_path / "output"
    output_dir.mkdir()

    result = ifa.image_sanitize_tool(
        {
            "input_path": img_path,
            "output_dir": str(output_dir),
            "strip_exif": True,
            "resize_max": 1024,
            "output_format": "jpg",
        },
        {},
    )

    assert "output_image_path" in result
    assert result["output_image_path"].endswith(".jpg")
