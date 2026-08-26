// @ds-adherence-ignore -- omelette starter scaffold (raw elements/hex/px by design)
// Copied omelette starter. Re-running copy_starter_component with this kind overwrites this file with the latest version (page content is unaffected).
/* BEGIN USAGE */
/**
 * <three-d-stage> — 3D object viewer + exporter shell (three.js).
 *
 * The stage owns the whole scene: WebGL renderer, neutral studio lighting
 * with a soft ground shadow, orbit controls (drag to orbit, wheel to zoom,
 * right-drag to pan), a camera auto-framed to the object's bounds, resize
 * handling, and a download toolbar that exports the current object as
 * OBJ + MTL or GLB (binary glTF). FBX cannot be exported in the browser;
 * GLB is the interchange format every modern 3D tool imports.
 *
 * three.js loads through the page's import map. Include this EXACT pinned
 * map in <head>, before any module runs — versions and integrity hashes
 * stay together (same map the "3D object" skill mandates):
 *
 *   <script type="importmap">
 *   {
 *     "imports": {
 *       "three": "https://unpkg.com/three@0.184.0/build/three.module.js",
 *       "three/addons/controls/OrbitControls.js": "https://unpkg.com/three@0.184.0/examples/jsm/controls/OrbitControls.js",
 *       "three/addons/exporters/OBJExporter.js": "https://unpkg.com/three@0.184.0/examples/jsm/exporters/OBJExporter.js",
 *       "three/addons/exporters/GLTFExporter.js": "https://unpkg.com/three@0.184.0/examples/jsm/exporters/GLTFExporter.js"
 *     },
 *     "integrity": {
 *       "https://unpkg.com/three@0.184.0/build/three.module.js": "sha384-8FCZ1eVO6it4+pbec2aDtnTrwjWXZLJRC+MAGCIPDgsYnUrl/E0A2YlF8ioMKI/J",
 *       "https://unpkg.com/three@0.184.0/build/three.core.js": "sha384-dw2ooPewaEIrAgl6oFDBmmBWCE9oW9LxRGcfwZ0hLvEprzo202wXl7vCYHRlSnOT",
 *       "https://unpkg.com/three@0.184.0/examples/jsm/controls/OrbitControls.js": "sha384-4rziNxOBZKQ69i+w+f89KJ55TCYquwchVbByQwmaOeIOXdOU2PLDn3kOfXHwIJC9",
 *       "https://unpkg.com/three@0.184.0/examples/jsm/exporters/OBJExporter.js": "sha384-nbwtoZENJD3Vq+ACK0CuGQdPMuDWHkamC2KJD70EV5nfg6jQjfppKOea07YJN+N3",
 *       "https://unpkg.com/three@0.184.0/examples/jsm/exporters/GLTFExporter.js": "sha384-VofkvpG6HERhFCYbsUOHeNXBCqID2nfqkQqnVzE1jc/oPcz+qJ13ADdXH08hE+cQ"
 *     }
 *   }
 *   </script>
 *
 * Usage:
 *   <style>three-d-stage:not(:defined){visibility:hidden}</style>
 *   <three-d-stage name="rocket"></three-d-stage>
 *   <script src="three-d-stage.js"></script>
 *   <script type="module">
 *     const stage = document.querySelector('three-d-stage');
 *     const { THREE } = await stage.ready;
 *     const model = new THREE.Group();
 *     // …build the model out of named meshes with named materials —
 *     // the names become the o / usemtl entries in the exported OBJ…
 *     stage.setObject(model);
 *   </script>
 *
 * Attributes:
 *   name       — export file basename (default "model")
 *   background — CSS color behind the scene (default a warm paper tone)
 *   autorotate — when present, a slow turntable until the user interacts
 *
 * Theming — set these on the host and every piece of chrome follows:
 *   --stage-bg     CSS background behind the scene
 *   --stage-ink    "r, g, b" triple for note / button / error text
 *   --stage-panel  "r, g, b" triple for the button fill
 * Setting --stage-bg alone on a dark page is what used to leave the hint
 * text dark-on-dark; the two triples exist so that cannot happen.
 *
 * Slot:
 *   <p slot="fallback">…</p>  shown instead of the developer error text when
 *   the canvas cannot start — the case a public page needs to speak to.
 *
 * Rendering is on demand: the stage draws when the controls move and when
 * something calls stage.invalidate(). Move a light or retune its shadow
 * frustum and call stage.invalidateShadow() — the shadow map is baked once
 * and held, because the object does not move.
 *
 * Model in real-world meters, centered on the origin, y-up — exports
 * inherit the scene's units and orientation. The stage fills its own box;
 * size it with ordinary CSS (default 100vw/100vh page hero).
 *
 * Default setup: neutral studio lighting (hemisphere + key + fill), a
 * ground shadow (PCF — shadow.radius and shadow.blurSamples are VSM-only
 * knobs and do nothing here; soften with the ShadowMaterial's opacity), and
 * NO environment map — so high metalness has
 * nothing to reflect and renders near-black. Cap metalness around
 * 0.3–0.4 and carry a metal look with a brighter base color. The copied
 * file is yours: adjust the lights, shadow, or background in _boot()
 * when the object needs a different look.
 */
/* END USAGE */

(() => {
  const stylesheet = `
    /* The three --stage-* custom properties are the whole theming surface.
       They default to the light studio the starter ships with; a dark page
       sets them once and every chrome element follows. Before they existed,
       a page that overrode only --stage-bg got dark-on-dark body text. */
    :host {
      position: relative;
      display: block;
      width: 100%;
      height: 100dvh;
      background: var(--stage-bg, #f0eee6);
      --_ink: var(--stage-ink, 26, 25, 21);
      --_panel: var(--stage-panel, 255, 255, 255);
      overflow: hidden;
    }
    canvas { display: block; outline: none; }
    .toolbar {
      position: absolute;
      right: 16px;
      bottom: 16px;
      display: flex;
      gap: 8px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    .toolbar button {
      appearance: none;
      border: 1px solid rgba(var(--_ink), 0.18);
      border-radius: 8px;
      background: rgba(var(--_panel), 0.92);
      color: rgb(var(--_ink));
      font-family: inherit;
      font-size: 12.5px;
      font-weight: 500;
      line-height: 1;
      padding: 9px 12px;
      cursor: default;
      transition: background 120ms ease, border-color 120ms ease;
    }
    .toolbar button:hover { background: rgba(var(--_panel), 1); }
    .toolbar button:active { transform: translateY(1px); }
    .toolbar button[disabled] { opacity: 0.5; pointer-events: none; }
    /* Bottom-centre, not bottom-left: pages routinely put their own credit or
       repo link in the bottom corners and a heading in the top ones, and this
       used to land straight on top of the credit. The centre column is the
       one strip no other chrome here claims. */
    .note {
      position: absolute;
      left: 50%;
      bottom: 16px;
      transform: translateX(-50%);
      text-align: center;
      max-width: 60%;
      font: 400 12px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      color: rgba(var(--_ink), 0.55);
      user-select: none;
      pointer-events: none;
      transition: opacity 600ms ease;
    }
    .note[hidden] { display: block; opacity: 0; }
    .err {
      position: absolute;
      inset: 0;
      display: none;
      align-items: center;
      justify-content: center;
      padding: 24px;
      font: 500 14px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      color: rgba(var(--_ink), 0.75);
      text-align: center;
      white-space: pre-line;
    }
    /* Narrow viewports: the two export buttons and a page's own bottom-left
       credit cannot share one 390px row. Give the toolbar the full width and
       lift it clear. */
    @media (max-width: 560px) {
      .toolbar { left: 16px; right: 16px; bottom: 52px; }
      .toolbar button { flex: 1; padding: 11px 8px; }
      .note { bottom: 104px; max-width: calc(100% - 32px); }
    }
  `;

  function download(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 4000);
  }

  /** Tell the host an export attempt settled — telemetry only. The host
   *  (HTMLViewer) verifies the source and re-reads these fields defensively
   *  before counting; nothing else crosses the frame boundary. Guarded so
   *  telemetry can never break the download path. */
  function notifyExport(format, ok) {
    try {
      window.parent.postMessage(
        { type: 'omelette:notify-3d-export', format: format, ok: ok === true },
        '*'
      );
    } catch (e) {}
  }

  class ThreeDStage extends HTMLElement {
    constructor() {
      super();
      const root = this.attachShadow({ mode: 'open' });
      const style = document.createElement('style');
      style.textContent = stylesheet;
      root.appendChild(style);
      this._err = document.createElement('div');
      this._err.className = 'err';
      // A page can supply visitor-facing copy for the dead-canvas case:
      //   <three-d-stage><p slot="fallback">…</p></three-d-stage>
      // Without one the element falls back to the developer text below, which
      // is the right message on a dev page and the wrong one on a public URL.
      this._fallback = document.createElement('slot');
      this._fallback.name = 'fallback';
      this._err.appendChild(this._fallback);
      root.appendChild(this._err);
      this._note = document.createElement('div');
      this._note.className = 'note';
      // Name the gestures this device actually has. "scroll to zoom,
      // right-drag to pan" is instructions for a mouse nobody is holding.
      const touch = matchMedia('(hover: none) and (pointer: coarse)').matches;
      this._note.textContent = touch
        ? 'Drag to orbit · pinch to zoom · two-finger drag to pan'
        : 'Drag to orbit · scroll to zoom · right-drag to pan';
      root.appendChild(this._note);
      this._toolbar = document.createElement('div');
      this._toolbar.className = 'toolbar';
      this._objBtn = document.createElement('button');
      this._objBtn.type = 'button';
      this._objBtn.textContent = 'Download OBJ + MTL';
      this._objBtn.addEventListener('click', () => this._runExport('obj'));
      this._glbBtn = document.createElement('button');
      this._glbBtn.type = 'button';
      this._glbBtn.textContent = 'Download GLB';
      this._glbBtn.addEventListener('click', () => this._runExport('glb'));
      this._toolbar.appendChild(this._objBtn);
      this._toolbar.appendChild(this._glbBtn);
      root.appendChild(this._toolbar);
      this._setButtonsEnabled(false);
      /** Resolves with { THREE } once the scene is live — build the model
       *  in `await stage.ready` so nothing races the library load. */
      this.ready = new Promise((resolve, reject) => {
        this._readyResolve = resolve;
        this._readyReject = reject;
      });
    }

    connectedCallback() {
      if (this._booted) {
        // Re-attached after a removal — resume what disconnected stopped.
        if (this._renderer) {
          this._renderer.setAnimationLoop(this._loop);
          this._ro && this._ro.observe(this);
        }
        return;
      }
      this._booted = true;
      this._boot().catch((err) => {
        this._showFailure(err);
        this._readyReject(err);
      });
    }

    /** Dead canvas. Two very different causes, and only one of them is the
     *  developer's fault, so say which. A page that provided slotted fallback
     *  copy gets that instead of either message. */
    _showFailure(err) {
      this._err.style.display = 'flex';
      this._setButtonsEnabled(false);
      this._note.hidden = true;
      if (this._fallback.assignedNodes().length) return;
      const msg = String((err && err.message) || err);
      const noGL = /webgl|context/i.test(msg);
      const body = document.createElement('div');
      body.textContent = noGL
        ? 'This page draws a 3D object, and this browser could not open a ' +
          'WebGL canvas.\n\nHardware acceleration may be off, or the browser ' +
          'may be in a hardened mode that blocks it.'
        : 'three.js failed to load.\n' +
          'Check that the pinned <script type="importmap"> from the usage ' +
          'notes is in <head> before any module script.\n\n' + msg;
      this._err.appendChild(body);
    }

    async _boot() {
      const bg = this.getAttribute('background');
      if (bg) this.style.setProperty('--stage-bg', bg);
      const [THREE, controlsMod] = await Promise.all([
        import('three'),
        import('three/addons/controls/OrbitControls.js'),
      ]);
      this._THREE = THREE;
      // preserveDrawingBuffer keeps the last frame readable after
      // compositing (toDataURL / drawImage) — it's what lets the
      // screenshot tools capture the scene instead of a blank canvas.
      const renderer = new THREE.WebGLRenderer({
        antialias: true,
        alpha: true,
        preserveDrawingBuffer: true,
      });
      renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
      renderer.shadowMap.enabled = true;
      // PCFSoftShadowMap is deprecated in r184: three warns and falls back to
      // PCF anyway, so asking for PCF is honest about what you get. It also
      // means shadow.radius / blurSamples do NOTHING — those are VSM knobs.
      // Soften the contact shadow with the ShadowMaterial's opacity instead.
      renderer.shadowMap.type = THREE.PCFShadowMap;
      // The scene is static: baking the shadow map once and holding it is the
      // single biggest saving here. A 4096 map over 100k triangles re-rendered
      // at 60fps is most of the GPU cost of a page where nothing moves.
      renderer.shadowMap.autoUpdate = false;
      renderer.shadowMap.needsUpdate = true;
      renderer.toneMapping = THREE.ACESFilmicToneMapping;
      renderer.toneMappingExposure = 0.95;
      this._renderer = renderer;
      this.shadowRoot.insertBefore(renderer.domElement, this._err);

      const scene = new THREE.Scene();
      this._scene = scene;

      const camera = new THREE.PerspectiveCamera(45, 1, 0.01, 500);
      camera.position.set(3, 2.2, 4);
      this._camera = camera;

      const controls = new controlsMod.OrbitControls(camera, renderer.domElement);
      controls.enableDamping = true;
      controls.dampingFactor = 0.08;
      this._controls = controls;

      // Dark studio: a baked environment stands in for softbox + rim
      // panels (RectAreaLight needs an addon outside the pinned map), plus
      // a shadow-casting key and a low cool fill.
      const env = new THREE.Scene();
      const panel = (w, h, color, pos, look) => {
        const m = new THREE.Mesh(
          new THREE.PlaneGeometry(w, h),
          new THREE.MeshBasicMaterial({ color: color, side: THREE.DoubleSide })
        );
        m.position.set(pos[0], pos[1], pos[2]);
        m.lookAt(look[0], look[1], look[2]);
        env.add(m);
      };
      const shell = new THREE.Mesh(
        new THREE.SphereGeometry(40, 24, 16),
        new THREE.MeshBasicMaterial({ color: 0x0a0a0a, side: THREE.BackSide })
      );
      env.add(shell);
      panel(16, 10, 0xfff4e6, [-9, 12, 7], [0, 0, 0]);   // softbox, upper-left
      panel(7, 7, 0xfffaf2, [-4, 15, 2], [0, 0, 0]);      // hotter core
      panel(30, 1.2, 0xffffff, [5, 5.5, -13], [0, 0, 0]);  // rim strip, behind-right
      panel(6, 24, 0xffffff, [-4, 9, -13], [0, 0, 0]);   // strip the display reflects
      panel(10, 7, 0x8ea6ba, [-11, 0.5, 12], [0, 0, 0]); // cool fill, front-left
      panel(30, 30, 0x0d0d0c, [0, -14, 0], [0, 0, 0]);   // floor bounce
      const pmrem = new THREE.PMREMGenerator(renderer);
      pmrem.compileEquirectangularShader();
      scene.environment = pmrem.fromScene(env, 0.02).texture;
      scene.environmentIntensity = 0.62;

      const key = new THREE.DirectionalLight(0xfff6ec, 5.4);
      key.position.set(-5, 5.6, 4.4);
      key.castShadow = true;
      key.shadow.mapSize.set(2048, 2048);
      key.shadow.bias = -0.0004;
      this._key = key;
      scene.add(key);
      const rim = new THREE.DirectionalLight(0xfff8ef, 15.0);
      rim.position.set(5.2, 0.42, -8);
      scene.add(rim);
      const fill = new THREE.DirectionalLight(0xc9d8e6, 0.35);
      fill.position.set(-4, 1.2, 5);
      scene.add(fill);

      const ground = new THREE.Mesh(
        new THREE.PlaneGeometry(200, 200),
        new THREE.ShadowMaterial({ opacity: 0.5 })
      );
      ground.rotation.x = -Math.PI / 2;
      ground.receiveShadow = true;
      this._ground = ground;
      scene.add(ground);

      this._autorotate = this.hasAttribute('autorotate');
      controls.autoRotate = this._autorotate;
      controls.autoRotateSpeed = 1.2;
      controls.addEventListener('start', () => {
        controls.autoRotate = false;
        this._note.hidden = true;      // it has done its job
      });

      const fit = () => {
        const w = this.clientWidth || 1;
        const h = this.clientHeight || 1;
        renderer.setSize(w, h);
        camera.aspect = w / h;
        camera.updateProjectionMatrix();
        this.invalidate();
      };
      fit();
      this._ro = new ResizeObserver(fit);
      // Draw only when something changed. controls.update() reports whether it
      // moved the camera, which covers the drag itself and the damping tail;
      // everything else asks for a frame through invalidate(). The rAF keeps
      // ticking either way — it is the render that is expensive, not the
      // callback — so resize and damping stay as simple as they were.
      this._loop = () => {
        const moved = controls.update();
        if (moved || this._dirty) {
          this._dirty = false;
          renderer.render(scene, camera);
        }
      };
      // Detached while three.js was fetching? Stay idle — the
      // connectedCallback resume starts the loop and observer on
      // reattach.
      if (this.isConnected) {
        this._ro.observe(this);
        renderer.setAnimationLoop(this._loop);
      }

      this._readyResolve({ THREE });
    }

    /** Ask for one more frame. Call after changing anything the renderer can
     *  see from outside the loop — camera, materials, visibility. */
    invalidate() {
      this._dirty = true;
    }

    /** Re-bake the (otherwise frozen) shadow map. Call after moving a light,
     *  retuning its frustum, or changing what casts. */
    invalidateShadow() {
      if (this._renderer) this._renderer.shadowMap.needsUpdate = true;
      this._dirty = true;
    }

    disconnectedCallback() {
      // Stop rendering and observing while detached; connectedCallback
      // resumes both. (The renderer itself is kept — a move within the
      // document must not rebuild the scene.)
      if (this._renderer) this._renderer.setAnimationLoop(null);
      if (this._ro) this._ro.disconnect();
    }

    /** Show (and own) the object. Replaces any previous object, enables
     *  shadows on every mesh, rests it on the ground plane, and frames
     *  the camera to its bounds. */
    setObject(object) {
      const THREE = this._THREE;
      if (!THREE) throw new Error('three-d-stage: not ready — await stage.ready first');
      if (this._object) this._scene.remove(this._object);
      this._object = object;
      object.traverse((o) => {
        if (o.isMesh) {
          o.castShadow = true;
          o.receiveShadow = true;
        }
      });
      const box = new THREE.Box3().setFromObject(object);
      if (!box.isEmpty()) {
        // Rest the object on the ground without moving its origin.
        this._ground.position.y = box.min.y;
        const sphere = box.getBoundingSphere(new THREE.Sphere());
        const dist =
          (sphere.radius / Math.tan((this._camera.fov * Math.PI) / 360)) * 1.35;
        const dir = new THREE.Vector3(1, 0.55, 1.25).normalize();
        this._camera.position
          .copy(sphere.center)
          .add(dir.multiplyScalar(dist));
        this._camera.near = Math.max(dist / 100, 0.01);
        this._camera.far = dist * 100;
        this._camera.updateProjectionMatrix();
        this._controls.target.copy(sphere.center);
        this._controls.update();
        const span = sphere.radius * 3;
        this._key.shadow.camera.left = -span;
        this._key.shadow.camera.right = span;
        this._key.shadow.camera.top = span;
        this._key.shadow.camera.bottom = -span;
        this._key.shadow.camera.updateProjectionMatrix();
      }
      this._scene.add(object);
      this._setButtonsEnabled(true);
      this.invalidateShadow();
    }

    get _basename() {
      return (this.getAttribute('name') || 'model').replace(/[^\w.-]+/g, '_');
    }

    _setButtonsEnabled(on) {
      this._objBtn.disabled = !on;
      this._glbBtn.disabled = !on;
    }

    /** Every mesh and material needs a unique name for o/usemtl lines —
     *  fill in stable fallbacks, and return the unique material list. */
    _nameParts() {
      const mats = [];
      const seen = new Set();
      let meshI = 0;
      let matI = 0;
      this._object.traverse((o) => {
        if (!o.isMesh) return;
        if (!o.name) o.name = 'part_' + meshI;
        meshI += 1;
        const list = Array.isArray(o.material) ? o.material : [o.material];
        for (const m of list) {
          if (!m || mats.includes(m)) continue;
          if (!m.name) {
            m.name = 'mat_' + matI;
            matI += 1;
          }
          while (seen.has(m.name)) {
            m.name = m.name + '_' + matI;
            matI += 1;
          }
          seen.add(m.name);
          mats.push(m);
        }
      });
      return mats;
    }

    /** One export attempt, reported to the host however it settles.
     *  Rethrows so a failure stays visible on the guest console exactly as
     *  before. The no-object early return is not an attempt (the toolbar is
     *  disabled until the model loads) and reports nothing. */
    async _runExport(format) {
      if (!this._object) return;
      try {
        await (format === 'obj' ? this._exportObj() : this._exportGlb());
        notifyExport(format, true);
      } catch (err) {
        notifyExport(format, false);
        throw err;
      }
    }

    async _exportObj() {
      if (!this._object) return;
      const mod = await import('three/addons/exporters/OBJExporter.js');
      const mats = this._nameParts();
      const base = this._basename;
      const obj =
        'mtllib ' + base + '.mtl\n' + new mod.OBJExporter().parse(this._object);
      let mtl = '# Exported by three-d-stage\n';
      for (const m of mats) {
        const c = m.color || { r: 0.8, g: 0.8, b: 0.8 };
        const rough = typeof m.roughness === 'number' ? m.roughness : 0.5;
        const opacity = typeof m.opacity === 'number' ? m.opacity : 1;
        mtl += 'newmtl ' + m.name + '\n';
        mtl +=
          'Kd ' + c.r.toFixed(4) + ' ' + c.g.toFixed(4) + ' ' + c.b.toFixed(4) + '\n';
        mtl += 'Ks 0.2000 0.2000 0.2000\n';
        mtl += 'Ns ' + Math.round((1 - rough) * 200) + '\n';
        mtl += 'd ' + opacity.toFixed(4) + '\n\n';
      }
      download(new Blob([obj], { type: 'text/plain' }), base + '.obj');
      download(new Blob([mtl], { type: 'text/plain' }), base + '.mtl');
    }

    async _exportGlb() {
      if (!this._object) return;
      const mod = await import('three/addons/exporters/GLTFExporter.js');
      this._nameParts();
      const base = this._basename;
      const buf = await new mod.GLTFExporter().parseAsync(this._object, {
        binary: true,
      });
      download(
        new Blob([buf], { type: 'model/gltf-binary' }),
        base + '.glb'
      );
    }
  }

  customElements.define('three-d-stage', ThreeDStage);
})();
