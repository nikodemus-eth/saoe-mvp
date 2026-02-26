#!/usr/bin/env python3
"""serve_intake_form.py — SAOE web intake form.

Serves a browser form that accepts:
  - Article title
  - Body text (paragraph / markdown)
  - 0, 1, or 2 images

If 2 images are uploaded they are composited side-by-side (Pillow) before
being passed into the pipeline — so the existing single-image SATL path is
reused without any schema changes.

On submit, signed SATL envelopes are dropped directly into the
sanitization_agent queue.  A JSON response with the session_id is returned
so the JS result panel can link to the output and audit log.

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
# Path bootstrap
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
_LOG_VIEWER_PORT = 8080
_MAX_IMAGE_BYTES = 20 * 1024 * 1024   # 20 MB per file
_COMPOSITE_MAX_SIDE = 1600             # pixels for composited image long edge

# ---------------------------------------------------------------------------
# HTML template  (system fonts, dark theme — matches serve_log_viewer.py)
# All dynamic content inserted via textContent / safe DOM methods (no innerHTML)
# ---------------------------------------------------------------------------
_FORM_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Article Intake \u2014 SAOE</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#080f1e;--surface:#0c1525;--surface-2:#111d30;
  --border:#1a2e4a;--border-sub:#0d1e38;
  --accent:#22d3ee;--accent-dim:rgba(34,211,238,.13);
  --text:#c8d4e0;--text-strong:#f0f4f8;--text-muted:#4a5d70;
  --green:#10b981;--red:#ef4444;
  --font-ui:ui-sans-serif,system-ui,-apple-system,'Helvetica Neue',sans-serif;
  --font-mono:ui-monospace,'Cascadia Mono','SF Mono','Fira Code','Menlo',monospace}
html{background:var(--bg);color:var(--text);font-family:var(--font-ui);
  font-size:14px;-webkit-font-smoothing:antialiased}
body{min-height:100vh;display:flex;flex-direction:column}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
a:focus-visible{outline:2px solid var(--accent);outline-offset:3px;border-radius:2px}
code{font-family:var(--font-mono)}

/* Skip link */
.skip-link{
  position:absolute;left:-9999px;top:auto;width:1px;height:1px;overflow:hidden;
  background:var(--accent);color:var(--bg);font-weight:700;padding:10px 18px;
  border-radius:4px;text-decoration:none;z-index:9999;font-size:13px}
.skip-link:focus{
  position:fixed;left:16px;top:16px;width:auto;height:auto;
  outline:3px solid #fff;outline-offset:2px}

/* Nav */
header[role=banner]{
  position:sticky;top:0;z-index:100;
  background:var(--surface);border-bottom:1px solid var(--border)}
nav[aria-label="Main navigation"]{
  display:flex;align-items:center;padding:0 24px;height:52px;
  max-width:960px;margin:0 auto;width:100%;gap:8px}
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
  border:1px solid transparent;text-decoration:none;
  transition:color .12s,background .12s}
nav ul[role=list] a:hover{color:var(--text);background:var(--surface-2)}
nav ul[role=list] a:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
nav ul[role=list] a[aria-current=page]{
  color:var(--accent);background:var(--accent-dim);
  border-color:rgba(34,211,238,.28)}

/* Layout */
main{flex:1;padding:40px 24px;max-width:680px;margin:0 auto;width:100%}
h1{font-size:1.15rem;font-weight:700;color:var(--text-strong);
  margin-bottom:4px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.page-sub{font-size:.8rem;color:var(--text-muted);margin-bottom:36px;margin-top:4px}
.badge{
  display:inline-flex;align-items:center;
  background:var(--accent-dim);color:var(--accent);
  border:1px solid rgba(34,211,238,.3);
  border-radius:4px;padding:2px 9px;
  font-size:.67rem;font-weight:700;letter-spacing:.06em;
  font-family:var(--font-mono);text-transform:uppercase}

/* Form */
.form-field{margin-bottom:24px}
label{
  display:block;font-weight:600;color:var(--text-strong);
  margin-bottom:6px;font-size:.83rem}
.label-opt{font-weight:400;color:var(--text-muted);font-size:.78rem}
input[type=text],textarea{
  width:100%;background:var(--surface-2);border:1px solid var(--border);
  border-radius:7px;padding:10px 13px;
  color:var(--text);font-size:.88rem;font-family:var(--font-ui);
  transition:border-color .15s,outline .15s}
input[type=text]:focus,textarea:focus{
  outline:2px solid var(--accent);outline-offset:0;border-color:transparent}
input[type=text]::placeholder,textarea::placeholder{color:var(--text-muted)}
textarea{min-height:150px;resize:vertical}
fieldset{
  border:1px solid var(--border);border-radius:8px;padding:16px 18px;
  margin-bottom:24px}
legend{
  font-weight:600;color:var(--text-strong);font-size:.83rem;
  padding:0 6px}
.img-row{display:flex;gap:16px;margin-top:12px}
.img-slot{flex:1}
.img-slot label{font-weight:400;font-size:.78rem;color:var(--text-muted);margin-bottom:4px}
input[type=file]{color:var(--text);font-size:.78rem;width:100%}
input[type=file]::file-selector-button{
  background:var(--surface-2);border:1px solid var(--border);
  color:var(--text);border-radius:4px;padding:4px 10px;
  font-size:.75rem;cursor:pointer;margin-right:8px}
input[type=file]::file-selector-button:hover{border-color:var(--accent);color:var(--accent)}
.hint{font-size:.73rem;color:var(--text-muted);margin-top:5px;line-height:1.5}

button[type=submit]{
  background:var(--accent);color:var(--bg);border:none;
  padding:11px 28px;border-radius:7px;font-size:.88rem;font-weight:700;
  cursor:pointer;transition:opacity .15s;letter-spacing:.02em}
button[type=submit]:hover{opacity:.88}
button[type=submit]:focus-visible{
  outline:3px solid var(--accent);outline-offset:3px}
button[type=submit]:disabled{opacity:.45;cursor:not-allowed}

/* Status panel */
#status{
  margin-top:28px;padding:20px 22px;
  background:var(--surface);border:1px solid var(--border);
  border-radius:10px;display:none}
#status h2{font-size:.95rem;margin-bottom:12px;color:var(--text-strong)}
#status p{font-size:.82rem;color:var(--text);margin-bottom:8px;line-height:1.5}
#status p:last-child{margin-bottom:0}
#status code{
  background:var(--surface-2);border:1px solid var(--border);
  padding:2px 7px;border-radius:4px;
  color:var(--accent);font-family:var(--font-mono);font-size:.75rem}
.img-note{color:var(--text-muted) !important;font-size:.78rem !important}
.log-link{
  display:inline-block;margin-top:6px;font-size:.82rem;
  color:var(--accent) !important}

/* Footer */
footer{
  margin-top:auto;padding:18px 24px;font-size:.68rem;
  color:var(--text-muted);border-top:1px solid var(--border);
  text-align:center}
footer a{color:var(--text-muted)}
footer a:hover{color:var(--accent)}
</style>
</head>
<body>

<a class="skip-link" href="#main-content">Skip to main content</a>

<header role="banner">
  <nav aria-label="Main navigation">
    <a class="nav-brand" href="http://localhost:%(log_port)s/"
       aria-label="SAOE home">
      <span class="nav-diamond" aria-hidden="true">&#9670;</span>
      <span>SAOE</span>
    </a>
    <ul role="list">
      <li><a href="http://localhost:%(intake_port)s/" aria-current="page">Intake</a></li>
      <li><a href="http://localhost:%(log_port)s/">Log Viewer</a></li>
      <li><a href="http://localhost:%(log_port)s/output/">Output</a></li>
    </ul>
  </nav>
</header>

<main id="main-content">
  <h1>Article Intake <span class="badge">SATL-secured</span></h1>
  <p class="page-sub">Submit an article. Content is signed, schema-validated, and assembled by the SAOE agent pipeline.</p>

  <form id="intake-form" enctype="multipart/form-data" novalidate>

    <div class="form-field">
      <label for="title">Article Title <span aria-hidden="true">*</span></label>
      <input type="text" id="title" name="title"
             placeholder="e.g. The Future of Secure Agents"
             required aria-required="true" maxlength="200"
             aria-describedby="title-hint">
      <p class="hint" id="title-hint">Up to 200 characters.</p>
    </div>

    <div class="form-field">
      <label for="body">Body Text <span aria-hidden="true">*</span></label>
      <textarea id="body" name="body"
                placeholder="Write a paragraph or paste Markdown\u2026"
                required aria-required="true"
                aria-describedby="body-hint"></textarea>
      <p class="hint" id="body-hint">Plain text or Markdown \u2014 up to 200\u202f000 characters.</p>
    </div>

    <fieldset>
      <legend>Images <span class="label-opt">(0\u20132, optional)</span></legend>
      <div class="img-row">
        <div class="img-slot">
          <label for="img0">Image 1</label>
          <input type="file" id="img0" name="images" accept="image/*"
                 aria-describedby="img-hint">
        </div>
        <div class="img-slot">
          <label for="img1">Image 2</label>
          <input type="file" id="img1" name="images" accept="image/*"
                 aria-describedby="img-hint">
        </div>
      </div>
      <p class="hint" id="img-hint">
        JPEG, PNG, or WebP \u2014 max 20\u202fMB each.
        If both slots are used, images are composited side-by-side before processing.
      </p>
    </fieldset>

    <button type="submit">Submit to Pipeline \u2192</button>
  </form>

  <div id="status" role="status" aria-live="polite" aria-atomic="true"></div>
</main>

<footer>
  <p>SAOE v0.1.0 RT-Hardened\u2002\u00b7\u2002
     <a href="http://localhost:%(log_port)s/">Log Viewer</a>\u2002\u00b7\u2002
     <a href="http://localhost:%(log_port)s/output/">Output</a></p>
</footer>

<script>
/* All DOM manipulation uses textContent / createElement — never innerHTML */
function el(tag, props, children) {
  var node = document.createElement(tag);
  if (props) {
    var allowed = ['href','target','rel','textContent','className',
                   'style','role','title','ariaLabel'];
    Object.keys(props).forEach(function(k) {
      if (allowed.indexOf(k) >= 0) node[k] = props[k];
    });
  }
  (children || []).forEach(function(c) {
    node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
  });
  return node;
}

document.getElementById('intake-form').addEventListener('submit', function(e) {
  e.preventDefault();
  var form = e.target;
  var btn  = form.querySelector('button[type=submit]');
  btn.textContent = 'Submitting\u2026';
  btn.disabled = true;

  var fd = new FormData(form);
  fetch('/submit', { method: 'POST', body: fd })
    .then(function(resp) { return resp.json(); })
    .then(function(data) {
      var box = document.getElementById('status');
      while (box.firstChild) box.removeChild(box.firstChild);
      box.style.display = 'block';

      if (data.ok) {
        var outputUrl = 'http://localhost:%(log_port)s/output/' + data.session_id + '.html';
        var logUrl    = 'http://localhost:%(log_port)s/?session=' + data.session_id;
        var imageNote = data.image_count === 0
          ? 'Text-only article \u2014 no image.'
          : data.image_count === 1
            ? '1 image passed to image_filter_agent.'
            : '2 images composited side-by-side \u2192 passed to image_filter_agent.';

        box.appendChild(el('h2', {}, ['\u2705 Submitted to pipeline']));
        box.appendChild(el('p', {}, [
          el('strong', {}, ['Session ID:\u2002']),
          el('code', {textContent: data.session_id})
        ]));
        box.appendChild(el('p', {}, [
          'Output article: ',
          el('a', {href: outputUrl, target: '_blank', rel: 'noopener',
                   textContent: outputUrl})
        ]));
        box.appendChild(el('a', {
          href: logUrl,
          target: '_blank',
          rel: 'noopener',
          className: 'log-link',
          textContent: '\u2192 Track pipeline events in audit log'
        }));
        box.appendChild(el('p', {className: 'img-note', role: 'note'}, [imageNote]));
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
    return load_signing_key(
        Path(config["keys_dir"]) / "agents_private" / "intake_agent.key"
    )


def _load_manifest(config: dict, name: str) -> dict:
    return json.loads(
        (Path(config["vault_dir"]) / "manifests" / name).read_text()
    )


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

# Port is set at startup; default allows template to render before main() runs.
_intake_port: int = 8090


@app.after_request
def add_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; "
        "style-src 'unsafe-inline'; "
        "script-src 'unsafe-inline'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.get("/")
def index():
    return render_template_string(
        _FORM_HTML % {
            "log_port": _LOG_VIEWER_PORT,
            "intake_port": _intake_port,
        }
    )


@app.post("/submit")
def submit():
    title = (request.form.get("title") or "").strip()
    body  = (request.form.get("body")  or "").strip()

    if not title:
        return jsonify({"ok": False, "error": "title is required"}), 400
    if not body:
        return jsonify({"ok": False, "error": "body is required"}), 400

    # Collect uploaded image files (0–2)
    raw_files   = request.files.getlist("images")
    valid_files = [f for f in raw_files if f and f.filename]
    if len(valid_files) > 2:
        return jsonify({"ok": False, "error": "maximum 2 images allowed"}), 400

    # Parse each image with Pillow
    pil_images: list[Image.Image] = []
    for f in valid_files:
        data = f.read(_MAX_IMAGE_BYTES + 1)
        if len(data) > _MAX_IMAGE_BYTES:
            return jsonify({"ok": False, "error": "image file exceeds 20 MB limit"}), 400
        try:
            pil_images.append(Image.open(BytesIO(data)))
        except Exception as exc:
            return jsonify({"ok": False, "error": f"cannot read image: {exc}"}), 400

    session_id  = str(uuid.uuid4())
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
        sk     = _load_intake_key(config)
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
    global _intake_port
    parser = argparse.ArgumentParser(description="SAOE web intake form")
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    _intake_port = args.port
    _UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[intake_form] Serving at http://{args.host}:{args.port}/")
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
