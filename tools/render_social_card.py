#!/usr/bin/env python3
"""Render diagrams/social-card.png from viewer/model.js.

The link-preview card is the first — and for most people the only — picture of
this instrument they will ever see: it is what a shared cell.wei.is renders as
in a timeline. It used to be a hand-taken screenshot, which meant it aged the
moment the model changed and nobody could tell by looking.

Same approach as render_turntable.py and export_model.py: drive headless Chrome
against the real viewer, so the card cannot show something the geometry does
not.

    python3 tools/render_social_card.py
    python3 tools/render_social_card.py --width 1200 --height 630

The framing is a deliberate crop, not the page's own pose. A card competes at
thumbnail size in a feed, so it goes in close: the display and the dish fill
the frame and the body bleeds off every edge. The page's wider studio framing
loses the screen entirely at 400 px wide.
"""

from __future__ import annotations

import argparse
import atexit
import base64
import http.server
import shutil
import signal
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

PAGE = """<!DOCTYPE html>
<html><head><meta charset="utf-8">
<script type="importmap">{"imports":{
"three":"https://unpkg.com/three@0.184.0/build/three.module.js",
"three/addons/controls/OrbitControls.js":"https://unpkg.com/three@0.184.0/examples/jsm/controls/OrbitControls.js",
"three/addons/exporters/OBJExporter.js":"https://unpkg.com/three@0.184.0/examples/jsm/exporters/OBJExporter.js",
"three/addons/exporters/GLTFExporter.js":"https://unpkg.com/three@0.184.0/examples/jsm/exporters/GLTFExporter.js"
}}</script>
<style>
  html,body{margin:0;height:100%%;background:#0c0c0b;overflow:hidden}
  three-d-stage{width:%(w)dpx;height:%(h)dpx;display:block}
</style>
</head><body>
<three-d-stage name="instrument"></three-d-stage>
<script src="./three-d-stage.js"></script>
<script type="module">
const W = %(w)d, H = %(h)d, SS = %(ss)f, GAIN = %(gain)f;
const AZ = %(az)f, EL = %(el)f, FILL = %(fill)f, LOOK = %(look)f;

async function run() {
  const mod = await import('three');
  await import('./model.js');
  const stage = document.querySelector('three-d-stage');
  await stage.ready;
  for (let i = 0; i < 300 && !stage._object; i++) await new Promise(r => setTimeout(r, 50));
  if (!stage._object) throw new Error('model never set an object');

  const renderer = stage._renderer, scene = stage._scene, cam = stage._camera;
  const controls = stage._controls;
  renderer.setAnimationLoop(null);
  controls.autoRotate = false;

  // Supersample in GL and shrink here, for the same reason the turntable does:
  // SwiftShader has no hardware MSAA and the 60 index ticks alias to mush.
  renderer.setPixelRatio(SS);
  renderer.setSize(W, H, false);
  cam.aspect = W / H;
  cam.clearViewOffset();

  // The page paints its backdrop in CSS, which a canvas grab does not capture.
  // Bake it, or the card lands as a near-black object on a transparent
  // background that every crawler composites onto white.
  const bg = new mod.Color(0x0e0e0d);
  scene.background = bg;
  renderer.setClearColor(bg, 1);

  // Left at 1.0 by default. The turntable lifts its studio because a 400 px
  // GIF of a near-black object loses the form; this card is 1200 px and the
  // identity IS the darkness, so lifting it is what makes the shell read as
  // brushed silver instead of graphite.
  if (GAIN !== 1) {
    scene.environmentIntensity *= GAIN;
    scene.traverse(o => { if (o.isDirectionalLight) o.intensity *= GAIN; });
  }

  // Aim at the deck rather than the body centre — the card is about the face.
  const obj = stage._object;
  const box = new mod.Box3().setFromObject(obj);
  const c = box.getCenter(new mod.Vector3());
  const target = new mod.Vector3(c.x, box.max.y, c.z + (box.max.z - c.z) * LOOK);

  const az = (AZ * Math.PI) / 180, el = (EL * Math.PI) / 180;
  const dir = new mod.Vector3(Math.sin(az) * Math.cos(el), Math.sin(el),
                              Math.cos(az) * Math.cos(el));
  // FILL is the fraction of the frame WIDTH the body spans. Above 1 it bleeds
  // off the sides, which is the point.
  const span = box.max.x - box.min.x;
  const hFov = 2 * Math.atan(Math.tan((cam.fov * Math.PI) / 360) * cam.aspect);
  const d = (span / FILL) / (2 * Math.tan(hFov / 2));
  cam.position.copy(target).add(dir.multiplyScalar(d));
  controls.target.copy(target);
  cam.updateProjectionMatrix();
  controls.update();

  renderer.shadowMap.autoUpdate = false;
  renderer.shadowMap.needsUpdate = true;
  renderer.render(scene, cam);

  // Copy out in the same task as render(), before the compositor swaps the
  // drawing buffer. Halve repeatedly rather than shrink once: a single 2.5:1
  // drawImage point-samples and puts the aliasing straight back.
  const gl = renderer.domElement;
  let src = document.createElement('canvas');
  src.width = gl.width; src.height = gl.height;
  src.getContext('2d').drawImage(gl, 0, 0);
  while (src.width > W * 2) {
    const nw = Math.max(W, Math.round(src.width / 2));
    const nh = Math.max(H, Math.round(src.height / 2));
    const step = document.createElement('canvas');
    step.width = nw; step.height = nh;
    const sctx = step.getContext('2d');
    sctx.imageSmoothingEnabled = true;
    sctx.imageSmoothingQuality = 'high';
    sctx.drawImage(src, 0, 0, nw, nh);
    src = step;
  }
  const out = document.createElement('canvas');
  out.width = W; out.height = H;
  const octx = out.getContext('2d');
  octx.imageSmoothingEnabled = true;
  octx.imageSmoothingQuality = 'high';
  octx.drawImage(src, 0, 0, W, H);

  const blob = await new Promise(r => out.toBlob(r, 'image/png'));
  await fetch('/__card', {method: 'POST', body: blob});
  await fetch('/__done', {method: 'POST', body: 'ok'});
}
run().catch(async e => {
  await fetch('/__done', {method: 'POST', body: 'ERROR: ' + (e && e.message || e)});
});
</script>
</body></html>
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=str(ROOT / "diagrams" / "social-card.png"))
    # 1200x630 is what og:image:width / og:image:height declare in
    # tools/build_single_file_viewer.py. Change both together or the card is
    # letterboxed by every consumer that trusts the declaration.
    ap.add_argument("--width", type=int, default=1200)
    ap.add_argument("--height", type=int, default=630)
    ap.add_argument("--az", type=float, default=23.0, help="azimuth, degrees")
    ap.add_argument("--el", type=float, default=33.0, help="elevation, degrees")
    ap.add_argument("--fill", type=float, default=1.12,
                    help="body width as a fraction of the frame; >1 bleeds off "
                         "the sides, which is what makes it read at thumbnail size")
    ap.add_argument("--look", type=float, default=0.10,
                    help="how far forward of centre to aim, as a fraction of "
                         "the half-depth")
    ap.add_argument("--gain", type=float, default=1.0,
                    help="studio lift. The turntable needs 1.22 because a "
                         "400 px GIF of a near-black object loses its form; at "
                         "1200 px the studio already reads, and lifting it "
                         "turns the shell from graphite to silver")
    ap.add_argument("--supersample", type=float, default=2.5)
    ap.add_argument("--timeout", type=int, default=600)
    args = ap.parse_args()

    chrome = next((c for c in CHROME_CANDIDATES
                   if Path(c).exists() or shutil.which(c)), None)
    if not chrome:
        sys.exit("No Chrome or Chromium found.")

    profile = Path(tempfile.mkdtemp(prefix="cell-chrome-"))
    atexit.register(shutil.rmtree, profile, True)
    atexit.register((VIEWER / "__card.html").unlink, True)

    # atexit does not run on SIGTERM, which is how a long render dies when
    # something times it out — the case that leaks a profile directory.
    def _bail(signum, _frame):
        sys.exit(128 + signum)
    for _sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(_sig, _bail)

    (VIEWER / "__card.html").write_text(PAGE % {
        "w": args.width, "h": args.height, "ss": args.supersample,
        "gain": args.gain, "az": args.az, "el": args.el,
        "fill": args.fill, "look": args.look})

    png: dict[str, bytes] = {}
    done = threading.Event()
    status = {"msg": "timed out"}

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=str(VIEWER), **kw)

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            if self.path == "/__card":
                png["data"] = body
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
             "--use-gl=angle", "--use-angle=swiftshader",
             "--enable-unsafe-swiftshader", "--disable-dev-shm-usage",
             f"--user-data-dir={profile}",
             f"--window-size={args.width},{args.height}",
             f"http://127.0.0.1:{port}/__card.html"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        done.wait(args.timeout)
        proc.terminate()
        httpd.shutdown()

    (VIEWER / "__card.html").unlink(missing_ok=True)
    shutil.rmtree(profile, ignore_errors=True)

    if status["msg"] != "ok" or "data" not in png:
        sys.exit(f"render failed: {status['msg']}")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(png["data"])
    print(f"wrote {out}  ({args.width}x{args.height}, "
          f"{len(png['data']) / 1e3:.0f} kB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
