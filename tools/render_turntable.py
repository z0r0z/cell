#!/usr/bin/env python3
"""Render a turntable GIF of the enclosure, straight from viewer/model.js.

    python tools/render_turntable.py                 # diagrams/turntable.gif
    python tools/render_turntable.py --size 600 --frames 48 --fps 20

Same approach as export_model.py: drive headless Chrome against the real
viewer, so the thing in the GIF is the thing in the model. No separate render
scene to fall out of step with the geometry.

Frames come back as PNGs and ffmpeg assembles them with a generated palette —
a single global palette is what keeps a dark, subtly-shaded object from
banding into mud, which is the usual way a product GIF goes wrong.
"""

from __future__ import annotations

import argparse
import base64
import http.server
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
  three-d-stage{width:%(size)dpx;height:%(size)dpx;display:block}
</style>
</head><body>
<three-d-stage name="instrument"></three-d-stage>
<script src="./three-d-stage.js"></script>
<script type="module">
const SIZE = %(size)d, FRAMES = %(frames)d, ELEV = %(elev)f, GAIN = %(gain)f;

async function post(path, body, kind) {
  await fetch(path, {method:'POST', headers: kind ? {'X-Frame': kind} : {}, body});
}

async function run() {
  const mod = await import('three');
  await import('./model.js');
  const stage = document.querySelector('three-d-stage');
  const { THREE } = await stage.ready;
  for (let i = 0; i < 300 && !stage._object; i++) await new Promise(r => setTimeout(r, 50));
  if (!stage._object) throw new Error('model never set an object');

  const renderer = stage._renderer, scene = stage._scene, cam = stage._camera;
  const controls = stage._controls;

  // Stop the stage driving its own loop; we step the camera by hand.
  renderer.setAnimationLoop(null);
  controls.autoRotate = false;
  renderer.setPixelRatio(2);          // supersample, then let ffmpeg downscale
  renderer.setSize(SIZE, SIZE, false);
  cam.aspect = 1; cam.updateProjectionMatrix();

  // Bake an opaque background. The viewer paints its backdrop in CSS, which a
  // canvas grab does not capture — leaving an alpha channel that ffmpeg
  // composites onto white, so a near-black product lands on a white card.
  const bg = new mod.Color(0x0e0e0d);
  scene.background = bg;
  renderer.setClearColor(bg, 1);

  // The shell is near-black by design. Lift the studio just enough that the
  // form and the oxblood read on a phone, without washing out the identity.
  scene.environmentIntensity *= GAIN;
  scene.traverse(o => { if (o.isDirectionalLight) o.intensity *= GAIN; });

  // Turn the OBJECT through fixed studio lighting, rather than flying the
  // camera around it. Two reasons, both visible in the result: the framing is
  // then pixel-stable instead of drifting as a flat slab presents different
  // silhouettes, and the highlights stay put instead of strobing as the body
  // passes through a moving lamp. This is how a product turntable is shot.
  const obj = stage._object;
  const box = new mod.Box3().setFromObject(obj);
  const centre = box.getCenter(new mod.Vector3());
  const sph = box.getBoundingSphere(new mod.Sphere());

  // Pivot about the object's own centre, on the world vertical.
  const pivot = new mod.Group();
  obj.parent.add(pivot);
  pivot.position.copy(centre);
  obj.position.sub(centre);
  pivot.add(obj);

  // Compose once, at the hero three-quarter angle, and leave it alone.
  const el = (ELEV * Math.PI) / 180, az = (27 * Math.PI) / 180;
  const dist = (sph.radius / Math.tan((cam.fov * Math.PI) / 360)) * 1.06;
  cam.position.set(
    centre.x + Math.sin(az) * Math.cos(el) * dist,
    centre.y + Math.sin(el) * dist,
    centre.z + Math.cos(az) * Math.cos(el) * dist);
  cam.lookAt(centre);
  controls.target.copy(centre);
  cam.updateProjectionMatrix();

  for (let i = 0; i < FRAMES; i++) {
    pivot.rotation.y = (i / FRAMES) * Math.PI * 2;
    pivot.updateMatrixWorld(true);
    renderer.render(scene, cam);
    // toDataURL in the same task as render(), before the compositor swaps.
    const url = renderer.domElement.toDataURL('image/png');
    await post('/__frame', url.slice(url.indexOf(',') + 1), String(i).padStart(4,'0'));
  }
  await post('/__done', 'ok');
}
run().catch(async e => { await post('/__done', 'ERROR: ' + (e && e.message || e)); });
</script>
</body></html>
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=str(ROOT / "diagrams" / "turntable.gif"))
    ap.add_argument("--size", type=int, default=600)
    ap.add_argument("--frames", type=int, default=48)
    ap.add_argument("--fps", type=int, default=20)
    ap.add_argument("--elev", type=float, default=26.0, help="camera elevation, degrees")
    ap.add_argument("--gain", type=float, default=1.22,
                help="studio lighting multiplier. The shell is black PETG by "
                     "design; too much here turns it silver and loses the identity.")
    ap.add_argument("--timeout", type=int, default=600)
    args = ap.parse_args()

    if not shutil.which("ffmpeg"):
        sys.exit("ffmpeg not found — needed to assemble the GIF.")
    chrome = next((c for c in CHROME_CANDIDATES
                   if Path(c).exists() or shutil.which(c)), None)
    if not chrome:
        sys.exit("No Chrome or Chromium found.")

    frames_dir = Path(tempfile.mkdtemp())
    profile = Path(tempfile.mkdtemp())
    (VIEWER / "__turntable.html").write_text(
        PAGE % {"size": args.size, "frames": args.frames,
                "elev": args.elev, "gain": args.gain})
    done = threading.Event()
    status = {"msg": "timed out"}
    count = {"n": 0}

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=str(VIEWER), **kw)

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(n)
            if self.path == "/__frame":
                idx = self.headers.get("X-Frame", "0000")
                (frames_dir / f"f{idx}.png").write_bytes(base64.b64decode(body))
                count["n"] += 1
                print(f"\r  frame {count['n']}/{args.frames}", end="", flush=True)
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
        print(f"rendering {args.frames} frames at {args.size}px ...")
        proc = subprocess.Popen(
            [chrome, "--headless=new", "--no-sandbox",
             "--use-gl=angle", "--use-angle=swiftshader",
             "--enable-unsafe-swiftshader", "--disable-dev-shm-usage",
             f"--window-size={args.size},{args.size}",
             f"--user-data-dir={profile}", "--virtual-time-budget=600000",
             f"http://127.0.0.1:{port}/__turntable.html"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        done.wait(args.timeout)
        proc.terminate()
        httpd.shutdown()
    print()

    (VIEWER / "__turntable.html").unlink(missing_ok=True)
    shutil.rmtree(profile, ignore_errors=True)

    if status["msg"] != "ok":
        sys.exit(f"render failed: {status['msg']}")
    if count["n"] < args.frames:
        sys.exit(f"only {count['n']}/{args.frames} frames arrived")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    pal = frames_dir / "palette.png"
    # One global palette over every frame. A per-frame palette makes a dark,
    # softly-shaded body shimmer as the quantiser changes its mind each frame.
    vf = (f"fps={args.fps},scale={args.size}:-1:flags=lanczos,"
          f"format=rgb24")
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error",
                    "-framerate", str(args.fps), "-i", str(frames_dir / "f%04d.png"),
                    "-vf", f"{vf},palettegen=max_colors=256:stats_mode=full",
                    str(pal)], check=True)
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error",
                    "-framerate", str(args.fps), "-i", str(frames_dir / "f%04d.png"),
                    "-i", str(pal), "-lavfi",
                    f"{vf}[x];[x][1:v]paletteuse=dither=sierra2_4a",
                    "-loop", "0", str(out)], check=True)

    # An MP4 alongside it: X re-encodes GIFs anyway, and video posts keep more
    # detail on a dark subject than a 256-colour GIF can.
    mp4 = out.with_suffix(".mp4")
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error",
                    "-framerate", str(args.fps), "-i", str(frames_dir / "f%04d.png"),
                    "-vf", f"fps={args.fps},scale={args.size}:-2:flags=lanczos,"
                           f"format=yuv420p",
                    "-c:v", "libx264", "-crf", "18", "-movflags", "+faststart",
                    str(mp4)], check=True)

    shutil.rmtree(frames_dir, ignore_errors=True)
    print(f"wrote {out}  ({out.stat().st_size/1e6:.2f} MB)")
    print(f"wrote {mp4}  ({mp4.stat().st_size/1e6:.2f} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
