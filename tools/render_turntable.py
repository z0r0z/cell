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
  three-d-stage{width:%(size)dpx;height:%(size)dpx;display:block}
</style>
</head><body>
<three-d-stage name="instrument"></three-d-stage>
<script src="./three-d-stage.js"></script>
<script type="module">
const SIZE = %(size)d, FRAMES = %(frames)d, ELEV = %(elev)f, GAIN = %(gain)f;
const TILT_MAX = %(tilt)f, TILT_MIN = %(tilt_min)f, SS = %(ss)f;
const OUT = %(size)d;

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
  // The stage bakes the shadow map once and holds it, because on the page
  // nothing moves. Here the OBJECT turns, so the shadow has to be re-cast for
  // every frame or all 240 of them carry the pose the model loaded in.
  renderer.shadowMap.autoUpdate = true;
  // Supersample in GL, then downsample HERE rather than in ffmpeg. Rendering
  // at SS x and shrinking is the antialiasing that matters: SwiftShader has no
  // hardware MSAA, so edges and the fine index ticks alias badly at 1:1.
  // Doing the shrink in the browser also keeps the frame files small — a
  // full-resolution PNG per frame is what filled the disk last time.
  renderer.setPixelRatio(SS);
  renderer.setSize(SIZE, SIZE, false);
  // model.js's pose() composes the PAGE off-centre — a 10%% view offset, so the
  // instrument sits left of the caption column. The turntable is square and
  // centred, and this stage is not that page: without clearing the offset
  // every frame is rendered 10%% off-centre and clipped on one side.
  // render_social_card.py does the same thing for the same reason.
  cam.aspect = 1;
  cam.clearViewOffset();
  cam.updateProjectionMatrix();

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
  //
  // The rig is three nested groups, and the nesting is what makes a low camera
  // and a visible screen compatible:
  //
  //   yaw    turned to face the camera, so "toward the viewer" is well defined
  //     tilt   tips the deck up toward the lens by TILT degrees
  //       spin   the turntable itself
  //
  // Because the tilt sits OUTSIDE the spin, the spin axis is what leans
  // forward. The deck therefore holds a constant angle to the camera all the
  // way round, instead of tumbling into and out of view — which is what you
  // get if you tilt inside the spin.
  const obj = stage._object;
  const box0 = new mod.Box3().setFromObject(obj);
  const centre = box0.getCenter(new mod.Vector3());
  const sph = box0.getBoundingSphere(new mod.Sphere());

  const el = (ELEV * Math.PI) / 180, az = (27 * Math.PI) / 180;

  const yaw = new mod.Group();
  yaw.rotation.y = az;                     // local +Z now points at the camera
  const tilt = new mod.Group();            // +X rotation tips +Y toward +Z
  const spin = new mod.Group();

  // The tilt ANIMATES, phased to the spin. The deck carries the screen and the
  // screen only reads upright once per revolution, so the lean peaks exactly
  // there — the object presents its face when the face is worth reading, and
  // relaxes to a low profile through the back half where the silhouette and
  // the cartridge slot are what there is to see. A fixed tilt has to choose
  // between those two and gets neither.
  const tiltAt = (t) => {
    const a = t * Math.PI * 2;             // 0 = screen upright toward camera
    const k = 0.5 + 0.5 * Math.cos(a);     // 1 at the readable position, 0 opposite
    return ((TILT_MIN + (TILT_MAX - TILT_MIN) * k) * Math.PI) / 180;
  };
  obj.parent.add(yaw);
  yaw.position.copy(centre);
  yaw.add(tilt); tilt.add(spin);
  obj.position.sub(centre);
  spin.add(obj);

  const dist = (sph.radius / Math.tan((cam.fov * Math.PI) / 360)) * 1.06;
  cam.position.set(
    centre.x + Math.sin(az) * Math.cos(el) * dist,
    centre.y + Math.sin(el) * dist,
    centre.z + Math.cos(az) * Math.cos(el) * dist);
  cam.lookAt(centre);
  controls.target.copy(centre);
  cam.updateProjectionMatrix();

  // Tilting swings corners below the shadow plane, and the tilt now varies, so
  // the sweep has to cover the actual (spin, tilt) pairs the animation uses.
  // Lift once, by the worst case, so the contact shadow stays put instead of
  // the object pumping up and down against the floor.
  let minY = Infinity;
  for (let i = 0; i < 72; i++) {
    const t = i / 72;
    spin.rotation.y = t * Math.PI * 2;
    tilt.rotation.x = tiltAt(t);
    yaw.updateMatrixWorld(true);
    minY = Math.min(minY, new mod.Box3().setFromObject(obj).min.y);
  }
  yaw.position.y += -minY;
  yaw.updateMatrixWorld(true);

  // Downsample chain. Halving repeatedly beats one big drawImage: a single
  // 3:1 shrink point-samples and reintroduces the aliasing the supersample was
  // meant to remove, which shows up first on the 60 index ticks.
  const grab = document.createElement('canvas');
  const gctx = grab.getContext('2d');
  const step = document.createElement('canvas');
  const sctx = step.getContext('2d');
  for (const c of [gctx, sctx]) { c.imageSmoothingEnabled = true;
                                  c.imageSmoothingQuality = 'high'; }

  for (let i = 0; i < FRAMES; i++) {
    const t = i / FRAMES;
    spin.rotation.y = t * Math.PI * 2;
    tilt.rotation.x = tiltAt(t);
    yaw.updateMatrixWorld(true);
    renderer.render(scene, cam);

    // Copy out synchronously, in the same task as render(), before the
    // compositor swaps the drawing buffer.
    const gl = renderer.domElement;
    grab.width = gl.width; grab.height = gl.height;
    gctx.drawImage(gl, 0, 0);

    let src = grab, w = gl.width;
    while (w > OUT * 2) {
      const h = Math.max(OUT, Math.round(w / 2));
      step.width = h; step.height = h;
      sctx.clearRect(0, 0, h, h);
      sctx.drawImage(src, 0, 0, h, h);
      const keep = document.createElement('canvas');
      keep.width = h; keep.height = h;
      keep.getContext('2d').drawImage(step, 0, 0);
      src = keep; w = h;
    }
    const out = document.createElement('canvas');
    out.width = OUT; out.height = OUT;
    const octx = out.getContext('2d');
    octx.imageSmoothingEnabled = true; octx.imageSmoothingQuality = 'high';
    octx.drawImage(src, 0, 0, OUT, OUT);

    const url = out.toDataURL('image/png');
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
    ap.add_argument("--frames", type=int, default=120,
                help="frames per revolution. With --fps this sets the "
                     "speed: frames/fps seconds per turn.")
    ap.add_argument("--fps", type=int, default=24)
    ap.add_argument("--elev", type=float, default=26.0,
                    help="camera elevation, degrees. High enough to read the "
                         "screen and the ring, which are the two things worth "
                         "seeing.")
    ap.add_argument("--tilt", type=float, default=30.0,
                    help="MAXIMUM lean toward the lens, degrees, reached when "
                         "the screen is upright and facing the camera.")
    ap.add_argument("--tilt-min", type=float, default=4.0,
                    help="minimum lean, reached on the far side of the "
                         "revolution where the silhouette is the subject. "
                         "Set equal to --tilt for a fixed lean.")
    ap.add_argument("--gain", type=float, default=1.22,
                help="studio lighting multiplier. The shell is black PETG by "
                     "design; too much here turns it silver and loses the identity.")
    ap.add_argument("--supersample", type=float, default=2.5,
                    help="render scale before downsampling. 2.0 is crisp but "
                         "doubles render time and on-disk frame size; 1.5 is "
                         "close and much cheaper on a long spin.")
    ap.add_argument("--gif-dither", default="bayer:bayer_scale=5",
                    help="GIF dither. bayer is ordered and reads as texture; "
                         "sierra2_4a scatters pixels and reads as grain on a "
                         "dark subject.")
    ap.add_argument("--gif-fps", type=int, default=None,
                    help="GIF frame rate. Defaults to --fps, i.e. no "
                         "resampling. See the checks in main(): GIF timing is "
                         "quantised to centiseconds, so only some rates are "
                         "even possible and only some decimations are uniform.")
    ap.add_argument("--gif-size", type=int, default=440,
                    help="GIF width. Kept below --size on purpose: a 256-colour "
                         "GIF of a long slow spin gets large fast, and the MP4 "
                         "is the one worth posting anyway.")
    ap.add_argument("--timeout", type=int, default=3600,
                    help="seconds to wait for the render. Software "
                         "rasterisation runs about 5 s/frame at 1440px, so a "
                         "240-frame spin needs ~20 min — the old 600 s default "
                         "killed good renders four fifths of the way through.")
    args = ap.parse_args()

    if args.gif_fps is None:
        args.gif_fps = args.fps

    # Two independent ways a GIF turns janky, both invisible until you watch it:
    #
    # 1. GIF stores per-frame delay in CENTISECONDS. A rate that does not
    #    divide 100 cannot be represented — 15 fps wants 6.67 cs and gets 7,
    #    which is really 14.3 fps and uneven frame to frame.
    #
    # 2. Resampling from the source rate drops frames. That is only smooth if
    #    the ratio is a whole number: 20 -> 10 drops every other frame and
    #    looks fine, while 15 -> 12 drops one in five on an irregular cadence
    #    and visibly stutters.
    if 100 % args.gif_fps:
        print(f"  warning: {args.gif_fps} fps does not divide 100, so GIF frame "
              f"delays cannot be even. Use 10, 20, 25 or 50.")
    if args.fps % args.gif_fps:
        print(f"  warning: {args.fps} -> {args.gif_fps} fps is not a whole-number "
              f"decimation, so frames drop on an uneven cadence and the GIF "
              f"will stutter. Use a divisor of {args.fps}.")

    if not shutil.which("ffmpeg"):
        sys.exit("ffmpeg not found — needed to assemble the GIF.")
    chrome = next((c for c in CHROME_CANDIDATES
                   if Path(c).exists() or shutil.which(c)), None)
    if not chrome:
        sys.exit("No Chrome or Chromium found.")

    # Frames NEVER touch the disk. They stream from the browser straight into
    # ffmpeg's stdin, which writes the MP4 incrementally; the GIF is then made
    # from that MP4. Buffering 240 PNGs first needed ~200 MB of scratch and was
    # the thing that kept failing a long render on a nearly-full volume — and
    # it failed as an opaque "Failed to fetch" in the page, because the frame
    # POST is what actually hits ENOSPC.
    profile = Path(tempfile.mkdtemp(prefix="cell-chrome-"))
    atexit.register(shutil.rmtree, profile, True)
    atexit.register((VIEWER / "__turntable.html").unlink, True)
    # atexit does NOT run on SIGTERM, which is exactly how a long render dies
    # when something times it out — the case that leaks most.
    def _bail(signum, _frame):
        sys.exit(128 + signum)
    for _sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(_sig, _bail)
    (VIEWER / "__turntable.html").write_text(
        PAGE % {"size": args.size, "frames": args.frames, "elev": args.elev,
                "gain": args.gain, "tilt": args.tilt,
                "tilt_min": args.tilt_min, "ss": args.supersample})
    done = threading.Event()
    status = {"msg": "timed out"}
    count = {"n": 0}

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    mp4 = out.with_suffix(".mp4")
    # Encode to a scratch path and move into place only once every frame has
    # arrived. Streaming straight to the destination means a run that dies at
    # frame 154 leaves a truncated clip sitting where the good one was — which
    # is worse than failing, because it looks like output.
    stage_dir = Path(tempfile.mkdtemp(prefix="cell-stage-"))
    atexit.register(shutil.rmtree, stage_dir, True)
    mp4_tmp = stage_dir / "out.mp4"
    # Frames already arrive at output resolution, so no rescale — every extra
    # resample is quality thrown away. crf 16 and preset slow because a
    # near-black subject with soft gradients is what x264 spends bits worst on.
    enc = subprocess.Popen(
        ["ffmpeg", "-y", "-loglevel", "error",
         "-f", "image2pipe", "-framerate", str(args.fps), "-i", "-",
         "-vf", "format=yuv420p", "-c:v", "libx264", "-preset", "slow",
         "-crf", "16", "-pix_fmt", "yuv420p", "-movflags", "+faststart",
         str(mp4_tmp)],
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL)
    atexit.register(lambda: enc.poll() is None and enc.kill())

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=str(VIEWER), **kw)

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(n)
            if self.path == "/__frame":
                # The page awaits each POST, so frames arrive in order and can
                # go straight down the pipe.
                enc.stdin.write(base64.b64decode(body))
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

    try:
        enc.stdin.close()
    except BrokenPipeError:
        pass
    enc.wait(timeout=300)

    if status["msg"] != "ok":
        sys.exit(f"render failed: {status['msg']}")
    if count["n"] < args.frames:
        sys.exit(f"only {count['n']}/{args.frames} frames arrived")
    if enc.returncode != 0:
        sys.exit(f"ffmpeg exited {enc.returncode}")

    # GIF from the finished MP4. One global palette over the whole clip:
    # a per-frame palette makes a dark, softly shaded body shimmer as the
    # quantiser changes its mind each frame.
    pal = stage_dir / "palette.png"
    gif_tmp = stage_dir / "out.gif"
    vf = (f"fps={args.gif_fps},scale={args.gif_size}:-1:flags=lanczos,"
          f"format=rgb24")
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", str(mp4_tmp),
                    "-vf", f"{vf},palettegen=max_colors=256:stats_mode=full",
                    str(pal)], check=True)
    # Ordered bayer dither: error diffusion scatters isolated pixels across
    # smooth gradients, which on a near-black body reads as film grain.
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", str(mp4_tmp),
                    "-i", str(pal), "-lavfi",
                    f"{vf}[x];[x][1:v]paletteuse=dither={args.gif_dither}",
                    "-loop", "0", str(gif_tmp)], check=True)

    # Both are complete: publish together, so the pair can never disagree.
    shutil.move(str(mp4_tmp), str(mp4))
    shutil.move(str(gif_tmp), str(out))

    print(f"wrote {out}  ({out.stat().st_size/1e6:.2f} MB)")
    print(f"wrote {mp4}  ({mp4.stat().st_size/1e6:.2f} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
