#!/usr/bin/env python3
"""serve_intake_form.py — SAOE web intake form.

Serves a browser form that accepts:
  - Article title
  - Body text (paragraph)
  - 0, 1, or 2 images

If 2 images are uploaded they are composited side-by-side (Pillow) before
being passed into the pipeline — so the existing single-image SATL path is
reused without any schema changes.

On submit, signed SATL envelopes are dropped directly into the
sanitization_agent queue.  A JSON response with the session_id is returned
so the caller (or the result page) can poll for output.

Usage:
    python examples/demo/serve_intake_form.py [--port 8090]
"""
import argparse
import json
import sys
import uuid
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

# ---------------------------------------------------------------------------
# Path bootstrap (same pattern as other demo agents)
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).parents[2]
_DEMO_DIR = Path(__file__).parent
sys.path.insert(0, str(_REPO_ROOT / "saoe-core"))
sys.path.insert(0, str(_REPO_ROOT / "saoe-openclaw"))

from flask import Flask, jsonify, render_template_string, request
from PIL import Image

from saoe_core.crypto.keyring import load_signing_key
from saoe_core.satl.envelope import TemplateRef, envelope_to_json, sign_envelope

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_UPLOADS_DIR = Path("/tmp/saoe/uploads")
_MAX_IMAGE_BYTES = 20 * 1024 * 1024  # 20 MB per file
_COMPOSITE_MAX_SIDE = 1600  # pixels for composited image long edge

# ---------------------------------------------------------------------------
# HTML template (inline, single-file server)
# All dynamic content inserted via textContent / safe DOM methods (no innerHTML)
# ---------------------------------------------------------------------------
_FORM_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SAOE Article Intake</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 680px; margin: 48px auto; padding: 0 24px; background: #f5f5f5; }
  h1   { font-size: 1.5rem; color: #1a1a2e; margin-bottom: 4px; }
  p.sub { color: #555; font-size: .9rem; margin-top: 0; margin-bottom: 32px; }
  label { display: block; font-weight: 600; margin-bottom: 6px; color: #222; }
  input[type=text], textarea {
    width: 100%; box-sizing: border-box;
    border: 1px solid #ccc; border-radius: 6px;
    padding: 10px 12px; font-size: 1rem;
    background: #fff; margin-bottom: 24px;
  }
  textarea { min-height: 140px; resize: vertical; }
  .img-row { display: flex; gap: 16px; margin-bottom: 24px; }
  .img-slot { flex: 1; }
  .img-slot label { font-weight: 400; color: #444; }
  .hint { font-size: .8rem; color: #888; margin-top: 4px; }
  button[type=submit] {
    background: #1a1a2e; color: #fff; border: none;
    padding: 12px 28px; border-radius: 6px; font-size: 1rem;
    cursor: pointer; transition: opacity .15s;
  }
  button[type=submit]:hover { opacity: .85; }
  .badge { display: inline-block; background:#e8f5e9; color:#2e7d32;
           border-radius:4px; padding:2px 8px; font-size:.8rem; margin-left:8px; }
  #status { margin-top: 32px; padding: 20px; background: #fff; border-radius: 8px;
            border: 1px solid #ddd; display: none; }
  #status h2 { margin-top: 0; }
  #status a  { color: #1976d2; }
</style>
</head>
<body>
<h1>SAOE Article Intake <span class="badge">SATL-secured</span></h1>
<p class="sub">Submit an article. Content is signed, validated, and assembled by the SAOE agent pipeline.</p>

<form id="intake-form" enctype="multipart/form-data">
  <label for="title">Article Title</label>
  <input type="text" id="title" name="title" placeholder="e.g. The Future of AI" required maxlength="200">

  <label for="body">Body Text</label>
  <textarea id="body" name="body" placeholder="Write a paragraph or paste markdown\u2026" required></textarea>

  <label>Images <span style="font-weight:400;color:#666;">(0\u20132 optional)</span></label>
  <div class="img-row">
    <div class="img-slot">
      <label for="img0">Image 1</label>
      <input type="file" id="img0" name="images" accept="image/*">
      <p class="hint">JPEG, PNG, WebP \u2014 max 20 MB</p>
    </div>
    <div class="img-slot">
      <label for="img1">Image 2</label>
      <input type="file" id="img1" name="images" accept="image/*">
      <p class="hint">If both slots used, images are composited side-by-side.</p>
    </div>
  </div>

  <button type="submit">Submit to Pipeline \u2192</button>
</form>

<div id="status" role="status" aria-live="polite"></div>

<script>
/* Build DOM nodes safely — never concatenate user/server data into innerHTML */
function el(tag, props, children) {
  var node = document.createElement(tag);
  if (props) Object.assign(node, props);
  (children || []).forEach(function(c) {
    node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
  });
  return node;
}

document.getElementById('intake-form').addEventListener('submit', function(e) {
  e.preventDefault();
  var btn = e.target.querySelector('button[type=submit]');
  btn.textContent = 'Submitting\u2026';
  btn.disabled = true;

  var fd = new FormData(e.target);
  fetch('/submit', { method: 'POST', body: fd })
    .then(function(resp) { return resp.json(); })
    .then(function(data) {
      var box = document.getElementById('status');
      while (box.firstChild) box.removeChild(box.firstChild);
      box.style.display = 'block';

      if (data.ok) {
        var outputUrl = 'http://localhost:8080/output/' + data.session_id + '.html';
        var imageNote = data.image_count === 0
          ? 'Text-only article (no image).'
          : data.image_count === 1
            ? '1 image passed to image_filter_agent.'
            : '2 images composited side-by-side \u2192 passed to image_filter_agent.';

        box.appendChild(el('h2', {}, ['\u2705 Submitted to pipeline']));
        box.appendChild(el('p', {}, [el('strong', {}, ['Session ID: ']), el('code', {textContent: data.session_id})]));
        box.appendChild(el('p', {}, ['Output will appear at:']));
        box.appendChild(el('p', {}, [el('a', {href: outputUrl, target: '_blank', textContent: outputUrl})]));
        box.appendChild(el('p', {style: 'color:#888;font-size:.85rem'}, [imageNote]));
      } else {
        var errMsg = typeof data.error === 'string' ? data.error : JSON.stringify(data);
        box.appendChild(el('h2', {}, ['\u274c Error']));
        box.appendChild(el('pre', {textContent: errMsg}));
      }
    })
    .catch(function(err) {
      var box = document.getElementById('status');
      while (box.firstChild) box.removeChild(box.firstChild);
      box.style.display = 'block';
      box.appendChild(el('h2', {}, ['\u274c Network error']));
      box.appendChild(el('pre', {textContent: String(err)}));
    })
    .finally(function() {
      btn.textContent = 'Submit to Pipeline \u2192';
      btn.disabled = false;
    });
});
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Config / key helpers
# ---------------------------------------------------------------------------

def _load_config() -> dict:
    return json.loads((_DEMO_DIR / "demo_config.json").read_text())


def _load_intake_key(config: dict):
    return load_signing_key(Path(config["keys_dir"]) / "agents_private" / "intake_agent.key")


def _load_manifest(config: dict, name: str) -> dict:
    return json.loads((Path(config["vault_dir"]) / "manifests" / name).read_text())


# ---------------------------------------------------------------------------
# Image helpers
# ---------------------------------------------------------------------------

def _composite_side_by_side(img_a: Image.Image, img_b: Image.Image) -> Image.Image:
    """Place two images side-by-side at matched height."""
    h = min(img_a.height, img_b.height, _COMPOSITE_MAX_SIDE)

    def _fit(im: Image.Image) -> Image.Image:
        ratio = h / im.height
        return im.resize((int(im.width * ratio), h), Image.LANCZOS)

    ra, rb = _fit(img_a), _fit(img_b)
    composite = Image.new("RGB", (ra.width + rb.width, h), (255, 255, 255))
    composite.paste(ra, (0, 0))
    composite.paste(rb, (ra.width, 0))
    return composite


def _save_as_jpeg(img: Image.Image, session_id: str, suffix: str = "") -> Path:
    """Save a PIL image to the uploads dir as JPEG. Returns the path."""
    uploads = _UPLOADS_DIR / session_id
    uploads.mkdir(parents=True, exist_ok=True)
    out = uploads / f"image{suffix}.jpg"
    img.convert("RGB").save(str(out), format="JPEG")
    return out


# ---------------------------------------------------------------------------
# SATL envelope helper
# ---------------------------------------------------------------------------

def _drop_envelope(
    config: dict,
    sk,
    session_id: str,
    template_ref: TemplateRef,
    payload: dict,
    human_readable: str,
) -> None:
    """Sign and write an envelope into the sanitization_agent queue."""
    queues_dir = Path(config["queues_dir"])
    draft = {
        "version": "1.0",
        "envelope_id": str(uuid.uuid4()),
        "session_id": session_id,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "sender_id": "intake_agent",
        "receiver_id": "sanitization_agent",
        "human_readable": human_readable,
        "template_ref": template_ref,
        "payload": payload,
    }
    envelope = sign_envelope(draft, sk)
    out_dir = queues_dir / "sanitization_agent"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"{envelope.envelope_id}.satl.json"
    out_file.write_text(envelope_to_json(envelope))


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * _MAX_IMAGE_BYTES + 64 * 1024


@app.get("/")
def index():
    return render_template_string(_FORM_HTML)


@app.post("/submit")
def submit():
    title = (request.form.get("title") or "").strip()
    body = (request.form.get("body") or "").strip()

    if not title:
        return jsonify({"ok": False, "error": "title is required"}), 400
    if not body:
        return jsonify({"ok": False, "error": "body is required"}), 400

    # Collect uploaded image files (0-2)
    raw_files = request.files.getlist("images")
    valid_files = [f for f in raw_files if f and f.filename]
    if len(valid_files) > 2:
        return jsonify({"ok": False, "error": "maximum 2 images allowed"}), 400

    # Parse each image with Pillow
    pil_images: list[Image.Image] = []
    for f in valid_files:
        data = f.read(_MAX_IMAGE_BYTES + 1)
        if len(data) > _MAX_IMAGE_BYTES:
            return jsonify({"ok": False, "error": f"image file exceeds 20 MB limit"}), 400
        try:
            pil_images.append(Image.open(BytesIO(data)))
        except Exception as exc:
            return jsonify({"ok": False, "error": f"cannot read image: {exc}"}), 400

    session_id = str(uuid.uuid4())
    image_count = len(pil_images)

    # Produce a single image path for the pipeline (composite 2→1 if needed)
    final_image_path: Path | None = None
    if image_count == 2:
        composited = _composite_side_by_side(pil_images[0], pil_images[1])
        final_image_path = _save_as_jpeg(composited, session_id, "_composited")
    elif image_count == 1:
        final_image_path = _save_as_jpeg(pil_images[0], session_id)

    # Load config and signing key
    try:
        config = _load_config()
        sk = _load_intake_key(config)
    except Exception as exc:
        return jsonify({"ok": False, "error": f"config/key error: {exc}"}), 500

    image_present = final_image_path is not None

    # blog_article_intent envelope (always required)
    try:
        blog_manifest = _load_manifest(config, "blog_article_intent_v1.manifest.json")
    except Exception as exc:
        return jsonify({"ok": False, "error": f"manifest error: {exc}"}), 500

    blog_tref = TemplateRef(
        template_id=blog_manifest["template_id"],
        version=blog_manifest["version"],
        sha256_hash=blog_manifest["sha256_hash"],
        dispatcher_signature=blog_manifest["dispatcher_signature"],
        capability_set_id="caps_blog_article_intent_v1",
        capability_set_version="1",
    )
    _drop_envelope(
        config, sk, session_id, blog_tref,
        payload={"title": title, "body_markdown": body, "image_present": image_present},
        human_readable=f"Web intake: {title}",
    )

    # image_process_intent envelope (only when an image was uploaded)
    if image_present:
        try:
            img_manifest = _load_manifest(config, "image_process_intent_v1.manifest.json")
        except Exception as exc:
            return jsonify({"ok": False, "error": f"image manifest error: {exc}"}), 500

        img_tref = TemplateRef(
            template_id=img_manifest["template_id"],
            version=img_manifest["version"],
            sha256_hash=img_manifest["sha256_hash"],
            dispatcher_signature=img_manifest["dispatcher_signature"],
            capability_set_id="caps_image_process_intent_v1",
            capability_set_version="1",
        )
        _drop_envelope(
            config, sk, session_id, img_tref,
            payload={
                "input_image_path_token": str(final_image_path),
                "strip_exif": True,
                "resize_max": 1024,
                "output_format": "jpg",
            },
            human_readable=f"Image for: {title}",
        )

    print(f"[intake_form] Submitted session={session_id} images={image_count}")
    return jsonify({"ok": True, "session_id": session_id, "image_count": image_count})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="SAOE web intake form")
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    _UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[intake_form] Serving at http://{args.host}:{args.port}/")
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
