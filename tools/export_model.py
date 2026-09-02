#!/usr/bin/env python3
"""Re-export models/instrument.obj from the parametric source in viewer/model.js.

`viewer/model.js` is the source of truth for the enclosure. `instrument.obj` is
an export from it, and `diagrams/mechanical.svg` is generated from the export.
This tool closes the first link so the chain is reproducible end to end:

    viewer/model.js  --export_model.py-->  models/instrument.obj
                     --gen_mechanical.py-->  diagrams/mechanical.svg

It drives headless Chrome against the real viewer, so the geometry is produced
by the same three.js code path a person gets when they open the page — not by a
reimplementation that could drift.

    python tools/export_model.py [--out models/instrument.obj]

Requires Chrome or Chromium, and network access for the pinned three.js CDN.
"""

from __future__ import annotations

import argparse
import atexit
import http.server
import json
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VIEWER = ROOT / "viewer"

CHROME_CANDIDATES = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "google-chrome", "chromium", "chromium-browser", "chrome",
]

# A page that builds the model exactly as instrument.html does, then hands the
# OBJ back over HTTP. It reuses three-d-stage's own exporter rather than
# re-implementing OBJ serialisation.
EXPORT_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8">
<script type="importmap">{"imports":{
"three":"https://unpkg.com/three@0.184.0/build/three.module.js",
"three/addons/controls/OrbitControls.js":"https://unpkg.com/three@0.184.0/examples/jsm/controls/OrbitControls.js",
"three/addons/exporters/OBJExporter.js":"https://unpkg.com/three@0.184.0/examples/jsm/exporters/OBJExporter.js",
"three/addons/exporters/GLTFExporter.js":"https://unpkg.com/three@0.184.0/examples/jsm/exporters/GLTFExporter.js"
}}</script>
<style>html,body{margin:0;height:100%;background:#0c0c0b}three-d-stage{width:100vw;height:100vh}</style>
</head><body>
<three-d-stage name="instrument"></three-d-stage>
<script src="./three-d-stage.js"></script>
<script type="module">
async function run() {
  await import('./model.js');
  const stage = document.querySelector('three-d-stage');
  await stage.ready;
  // Wait for model.js to have installed the object.
  for (let i = 0; i < 200 && !stage._object; i++) await new Promise(r => setTimeout(r, 50));
  if (!stage._object) throw new Error('model never set an object');

  const MTL_NAME = '__MTL_NAME__';
  const mod = await import('three/addons/exporters/OBJExporter.js');
  const mats = stage._nameParts();
  const base = stage._basename || 'instrument';
  // mtllib has to name the file this run actually writes. Hardcoding the
  // stage's basename made `--out /tmp/foo.obj` emit foo.obj pointing at
  // instrument.mtl, beside a foo.mtl nothing referenced.
  const obj = 'mtllib ' + MTL_NAME + '\\n' + new mod.OBJExporter().parse(stage._object);

  // The MTL half of this used to be a second, hand-copied implementation of
  // three-d-stage's own writer, which is exactly how the two drift. Call the
  // stage's converter so the colour space cannot differ between the file the
  // download button produces and the file this tool commits.
  const srgb = (v) => stage._srgb8(v);
  let mtl = '# Exported by three-d-stage\\n';
  for (const m of mats) {
    const c = m.color || {r:0.8,g:0.8,b:0.8};
    const rough = typeof m.roughness === 'number' ? m.roughness : 0.5;
    const opacity = typeof m.opacity === 'number' ? m.opacity : 1;
    mtl += 'newmtl ' + m.name + '\\n';
    mtl += 'Kd ' + srgb(c.r) + ' ' + srgb(c.g) + ' ' + srgb(c.b) + '\\n';
    mtl += 'Ks 0.2000 0.2000 0.2000\\nNs ' + Math.round((1-rough)*200) + '\\n';
    mtl += 'd ' + opacity.toFixed(4) + '\\n\\n';
  }
  await fetch('/__export', {method:'POST', headers:{'X-Kind':'obj'}, body: obj});
  await fetch('/__export', {method:'POST', headers:{'X-Kind':'mtl'}, body: mtl});
  await fetch('/__done', {method:'POST', body:'ok'});
}
run().catch(async e => {
  await fetch('/__done', {method:'POST', body:'ERROR: ' + (e && e.message || e)});
});
</script>
</body></html>
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=str(ROOT / "models" / "instrument.obj"))
    ap.add_argument("--timeout", type=int, default=180)
    args = ap.parse_args()

    chrome = next((c for c in CHROME_CANDIDATES
                   if Path(c).exists() or shutil.which(c)), None)
    if not chrome:
        sys.exit("No Chrome or Chromium found. Install one, or export by hand "
                 "from viewer/instrument.html.")

    # Registered before anything can fail: a timed-out export otherwise
    # leaves a Chrome profile behind, and enough of those fill a disk.
    work = Path(tempfile.mkdtemp(prefix="cell-chrome-"))
    atexit.register(shutil.rmtree, work, True)
    atexit.register((VIEWER / "__export.html").unlink, True)
    (VIEWER / "__export.html").write_text(
        EXPORT_HTML.replace("__MTL_NAME__", Path(args.out).with_suffix(".mtl").name))
    captured: dict[str, bytes] = {}
    done = threading.Event()
    status = {"msg": "timed out"}

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=str(VIEWER), **kw)

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(n)
            if self.path == "/__export":
                captured[self.headers.get("X-Kind", "obj")] = body
            elif self.path == "/__done":
                status["msg"] = body.decode()
                done.set()
            self.send_response(204)
            self.end_headers()

        def log_message(self, *a):
            pass

    with socketserver.TCPServer(("127.0.0.1", 0), Handler) as httpd:
        port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        print(f"serving viewer/ on 127.0.0.1:{port}, launching {Path(chrome).name}")
        proc = subprocess.Popen(
            [chrome, "--headless=new", "--no-sandbox",
             # three-d-stage builds a WebGLRenderer on init, so headless needs a
             # software GL stack. The geometry itself is CPU-side; SwiftShader is
             # only here to let the stage come up.
             "--use-gl=angle", "--use-angle=swiftshader",
             "--enable-unsafe-swiftshader", "--disable-dev-shm-usage",
             f"--user-data-dir={work}", "--virtual-time-budget=120000",
             f"http://127.0.0.1:{port}/__export.html"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        done.wait(args.timeout)
        proc.terminate()
        httpd.shutdown()

    (VIEWER / "__export.html").unlink(missing_ok=True)
    shutil.rmtree(work, ignore_errors=True)

    if status["msg"] != "ok" or "obj" not in captured:
        sys.exit(f"export failed: {status['msg']}")

    out = Path(args.out)
    out.write_bytes(captured["obj"])
    if "mtl" in captured:
        out.with_suffix(".mtl").write_bytes(captured["mtl"])
        print(f"wrote {out.with_suffix('.mtl')}")
    verts = captured["obj"].count(b"\nv ")
    objs = captured["obj"].count(b"\no ")
    print(f"wrote {out}  ({objs} objects, {verts:,} verts, "
          f"{len(captured['obj'])/1e6:.1f} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
