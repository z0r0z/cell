import * as THREE from 'three';

const stage = document.querySelector('three-d-stage');
await stage.ready;

/* ---------- procedural maps ---------- */

function noiseRoughness(size = 512) {
  const c = document.createElement('canvas');
  c.width = c.height = size;
  const ctx = c.getContext('2d');
  const img = ctx.createImageData(size, size);
  // coarse value-noise lattice, bilinearly sampled -> fine but not per-pixel harsh
  const N = 64, lat = new Float32Array(N * N);
  for (let i = 0; i < lat.length; i++) lat[i] = Math.random();
  const at = (x, y) => lat[(y % N) * N + (x % N)];
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const fx = (x / size) * N, fy = (y / size) * N;
      const x0 = Math.floor(fx), y0 = Math.floor(fy);
      const tx = fx - x0, ty = fy - y0;
      const a = at(x0, y0), b = at(x0 + 1, y0), cc = at(x0, y0 + 1), d = at(x0 + 1, y0 + 1);
      const v = a * (1 - tx) * (1 - ty) + b * tx * (1 - ty) + cc * (1 - tx) * ty + d * tx * ty;
      const fine = Math.random() * 0.25 + 0.75;
      // map to 0.79..1.00 so roughness 0.70 * map lands in 0.55..0.70
      const g = Math.round(255 * (0.88 + 0.12 * (v * 0.8 + fine * 0.2)));
      const o = (y * size + x) * 4;
      img.data[o] = img.data[o + 1] = img.data[o + 2] = g;
      img.data[o + 3] = 255;
    }
  }
  ctx.putImageData(img, 0, 0);
  const t = new THREE.CanvasTexture(c);
  t.wrapS = t.wrapT = THREE.RepeatWrapping;
  // ExtrudeGeometry UVs are in model units (mm) — one tile per ~60mm
  t.repeat.set(1 / 42, 1 / 42);
  t.anisotropy = 8;
  return t;
}

/** Height canvas -> tangent-space normal map. */
function normalFromHeight(height, strength) {
  const size = height.width;
  const hctx = height.getContext('2d');
  const src = hctx.getImageData(0, 0, size, size).data;
  const h = (x, y) => {
    const xx = Math.min(size - 1, Math.max(0, x));
    const yy = Math.min(size - 1, Math.max(0, y));
    return src[(yy * size + xx) * 4] / 255;
  };
  const out = document.createElement('canvas');
  out.width = out.height = size;
  const octx = out.getContext('2d');
  const img = octx.createImageData(size, size);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const dx = (h(x + 1, y) - h(x - 1, y)) * strength;
      const dy = (h(x, y + 1) - h(x, y - 1)) * strength;
      let nx = -dx, ny = dy, nz = 1;
      const l = Math.hypot(nx, ny, nz);
      nx /= l; ny /= l; nz /= l;
      const o = (y * size + x) * 4;
      img.data[o] = Math.round((nx * 0.5 + 0.5) * 255);
      img.data[o + 1] = Math.round((ny * 0.5 + 0.5) * 255);
      img.data[o + 2] = Math.round((nz * 0.5 + 0.5) * 255);
      img.data[o + 3] = 255;
    }
  }
  octx.putImageData(img, 0, 0);
  const t = new THREE.CanvasTexture(out);
  t.colorSpace = THREE.NoColorSpace;
  return t;
}

/** Fourfold porphyrin ring, as a soft height field. */
function porphyrinNormal() {
  const size = 512, c = document.createElement('canvas');
  c.width = c.height = size;
  const ctx = c.getContext('2d');
  ctx.fillStyle = '#000';
  ctx.fillRect(0, 0, size, size);
  ctx.translate(size / 2, size / 2);
  ctx.strokeStyle = '#fff';
  ctx.lineJoin = 'round';
  ctx.lineCap = 'round';
  const R = size * 0.24;
  // macrocycle: four pyrrole rings at the cardinal points, bridged
  for (let k = 0; k < 4; k++) {
    ctx.save();
    ctx.rotate((k * Math.PI) / 2);
    ctx.lineWidth = size * 0.014;
    // pyrrole pentagon
    ctx.beginPath();
    const pr = size * 0.078;
    for (let i = 0; i < 5; i++) {
      const a = -Math.PI / 2 + (i * 2 * Math.PI) / 5;
      const px = Math.cos(a) * pr, py = -R + Math.sin(a) * pr;
      i ? ctx.lineTo(px, py) : ctx.moveTo(px, py);
    }
    ctx.closePath();
    ctx.stroke();
    // methine bridge to the next ring
    ctx.beginPath();
    ctx.moveTo(pr * 0.95, -R + pr * 0.6);
    ctx.quadraticCurveTo(R * 0.78, -R * 0.78, R - pr * 0.6, -pr * 0.95);
    ctx.stroke();
    // outward vinyl / methyl stub
    ctx.beginPath();
    ctx.moveTo(0, -R - pr);
    ctx.lineTo(0, -R - pr - size * 0.045);
    ctx.stroke();
    ctx.restore();
  }
  // central metal site
  ctx.lineWidth = size * 0.016;
  ctx.beginPath();
  ctx.arc(0, 0, size * 0.026, 0, Math.PI * 2);
  ctx.stroke();
  for (let k = 0; k < 4; k++) {
    ctx.save();
    ctx.rotate((k * Math.PI) / 2);
    ctx.lineWidth = size * 0.009;
    ctx.beginPath();
    ctx.moveTo(0, -size * 0.032);
    ctx.lineTo(0, -R + size * 0.062);
    ctx.stroke();
    ctx.restore();
  }
  // soften: the etch is a change in sheen, not an engraved line
  ctx.setTransform(1, 0, 0, 1, 0, 0);
  ctx.filter = 'blur(3.6px)';
  ctx.drawImage(c, 0, 0);
  ctx.filter = 'none';
  return normalFromHeight(c, 1.1);
}

/* ---------- materials ---------- */

const rough = noiseRoughness();

const shellMat = new THREE.MeshPhysicalMaterial({
  name: 'shell', color: 0x1a1917, roughness: 0.70, metalness: 0.0,
  roughnessMap: rough, clearcoat: 0.14, clearcoatRoughness: 0.42,
  envMapIntensity: 1.0,
});
const trimMat = new THREE.MeshPhysicalMaterial({
  name: 'trim_oxblood', color: 0x5f151d, roughness: 0.22, metalness: 0.95,
  envMapIntensity: 1.1,
});
const steelMat = new THREE.MeshPhysicalMaterial({
  name: 'steel', color: 0x8d8880, roughness: 0.34, metalness: 0.95,
  envMapIntensity: 0.55,
});
const oxbloodMat = new THREE.MeshPhysicalMaterial({
  name: 'oxblood', color: 0x55161d, roughness: 0.38, metalness: 0.92,
  envMapIntensity: 0.4, side: THREE.DoubleSide,
});
/** Demo signing screen — a reflective panel graphic, not an emissive display. */
function screenTexture() {
  const w = 1000, h = 760, c = document.createElement('canvas');
  c.width = w; c.height = h;
  const g = c.getContext('2d');
  g.fillStyle = '#07080a';
  g.fillRect(0, 0, w, h);
  const M = 52;
  g.fillStyle = '#8b98a2';
  g.font = '500 36px ui-monospace, SFMono-Regular, Menlo, monospace';
  g.fillText('SIGN TRANSACTION', M, M + 36);
  g.font = '400 32px ui-monospace, SFMono-Regular, Menlo, monospace';
  const step = '2 / 3';
  const stepW = g.measureText(step).width;
  g.fillStyle = '#565f65';
  g.fillText(step, w - M - stepW, M + 36);
  const tier = 'BLOOD';                       // 'TOUCH' renders in header grey
  const tierW = g.measureText(tier).width;
  g.fillStyle = tier === 'BLOOD' ? '#8c2434' : '#565f65';
  g.fillText(tier, w - M - stepW - 46 - tierW, M + 36);
  g.fillStyle = '#2e3337';
  g.fillRect(M, M + 66, w - 2 * M, 3);

  g.fillStyle = '#dbe3e8';
  g.font = '600 96px ui-monospace, SFMono-Regular, Menlo, monospace';
  g.fillText('0.41800', M, 246);
  g.fillStyle = '#8b98a2';
  g.font = '500 44px ui-monospace, SFMono-Regular, Menlo, monospace';
  g.fillText('BTC', M + 418, 246);

  // full 42-character destination, grouped in fours — this screen is the whole defence
  g.fillStyle = '#4d5559';
  g.font = '500 30px ui-monospace, SFMono-Regular, Menlo, monospace';
  g.fillText('TO', M, 316);
  g.font = '500 42px ui-monospace, SFMono-Regular, Menlo, monospace';
  const gap = g.measureText('0').width * 0.5;
  const drawGroups = (groups, y) => {
    let x = M;
    for (const grp of groups) {
      g.fillStyle = '#c3ced5';
      g.fillText(grp, x, y);
      x += g.measureText(grp).width + gap;
    }
  };
  drawGroups(['bc1q', '4m8z', '9xkt', '7fk3', 'p2vq', '8dl4'], 372);
  drawGroups(['r6nw', 'e5ta', '9c0h', 'juxs', 'qz'], 424);

  g.fillStyle = '#4d5559';
  g.font = '500 30px ui-monospace, SFMono-Regular, Menlo, monospace';
  g.fillText('CHANGE', M, 486);
  g.fillStyle = '#9fb0a6';
  g.font = '500 32px ui-monospace, SFMono-Regular, Menlo, monospace';
  g.fillText('OWNED  bc1q…8nq2', M + 150, 486);
  g.fillStyle = '#4d5559';
  g.font = '500 30px ui-monospace, SFMono-Regular, Menlo, monospace';
  g.fillText('FEE', M, 540);
  g.fillStyle = '#9aa6ae';
  g.font = '500 32px ui-monospace, SFMono-Regular, Menlo, monospace';
  g.fillText('0.00012  ·  8 sat/vB', M + 150, 540);

  g.fillStyle = '#8c2434';
  g.fillRect(M, 606, 236, 6);
  g.fillStyle = '#23272b';
  g.fillRect(M + 236, 606, w - 2 * M - 236, 6);
  g.fillStyle = '#7b878f';
  g.font = '500 40px ui-monospace, SFMono-Regular, Menlo, monospace';
  g.fillText('HOLD CONFIRM', M, 686);

  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  t.anisotropy = 8;
  return t;
}

const screenMat = new THREE.MeshPhysicalMaterial({
  name: 'screen', map: screenTexture(), roughness: 0.62, metalness: 0.0,
  envMapIntensity: 0.3,
});

const glassMat = new THREE.MeshPhysicalMaterial({
  name: 'glass', color: 0x08090b, roughness: 0.06, metalness: 0.0,
  clearcoat: 1.0, clearcoatRoughness: 0.03, envMapIntensity: 3.2,
  ior: 1.52, reflectivity: 0.9, specularIntensity: 1.0,
  transparent: true, opacity: 0.34,
});
const etchMat = new THREE.MeshPhysicalMaterial({
  name: 'etch_floor', color: 0x1a1917, roughness: 0.66, metalness: 0.0,
  roughnessMap: rough, normalMap: porphyrinNormal(),
  normalScale: new THREE.Vector2(0.06, 0.06), envMapIntensity: 1.0,
});
const cavityMat = new THREE.MeshPhysicalMaterial({
  name: 'cavity', color: 0x050505, roughness: 0.95, metalness: 0.0,
  envMapIntensity: 0.06,
});
const printMat = new THREE.MeshPhysicalMaterial({
  name: 'silkscreen', color: 0x24221f, roughness: 0.96, metalness: 0.0,
  envMapIntensity: 0.3,
});
const padMat = new THREE.MeshPhysicalMaterial({
  name: 'pad', color: 0x15140f, roughness: 0.88, metalness: 0.0,
  roughnessMap: rough, envMapIntensity: 0.5,
});

/* ---------- geometry ----------
 * COORDINATE CONVENTION: all dimensions in millimetres, LEFT-EDGE ORIGIN.
 * X runs 0→115 across the body, Y runs 0→72 from the FRONT face.
 * X()/Y() convert to the centre-origin model space three.js renders in
 * (±57.5, ±36). Drawings quoting ±58.1 half-widths are centre-origin —
 * never mix the two without converting.
 * Shape space is (X, Y, Z-up); the whole plate is rotated -90° about X at
 * the end, so shape +Z becomes world +Y and the front face lands at +Z.
 */

const X = (x) => x - 57.5;
const Y = (y) => y - 36;

function roundedPath(Ctor, w, h, r, cx = 0, cy = 0) {
  const s = new Ctor();
  const x0 = cx - w / 2, y0 = cy - h / 2, x1 = cx + w / 2, y1 = cy + h / 2;
  s.moveTo(x0 + r, y0);
  s.lineTo(x1 - r, y0);
  s.absarc(x1 - r, y0 + r, r, -Math.PI / 2, 0, false);
  s.lineTo(x1, y1 - r);
  s.absarc(x1 - r, y1 - r, r, 0, Math.PI / 2, false);
  s.lineTo(x0 + r, y1);
  s.absarc(x0 + r, y1 - r, r, Math.PI / 2, Math.PI, false);
  s.lineTo(x0, y0 + r);
  s.absarc(x0 + r, y0 + r, r, Math.PI, Math.PI * 1.5, false);
  return s;
}

function circleHole(r, cx, cy) {
  const p = new THREE.Path();
  p.absarc(cx, cy, r, 0, Math.PI * 2, true);
  return p;
}

function slab(shape, z0, z1, bevel, mat, name) {
  const bt = bevel;
  const geo = new THREE.ExtrudeGeometry(shape, {
    depth: Math.max(z1 - z0 - 2 * bt, 0.02),
    bevelEnabled: bevel > 0,
    bevelThickness: bt, bevelSize: bt, bevelSegments: 4,
    curveSegments: 64,
  });
  geo.translate(0, 0, z0 + bt);
  const m = new THREE.Mesh(geo, mat);
  m.name = name;
  return m;
}

function box(dx, dy, dz, cx, cy, cz, mat, name) {
  const m = new THREE.Mesh(new THREE.BoxGeometry(dx, dy, dz), mat);
  m.position.set(cx, cy, cz);
  m.name = name;
  return m;
}

const plate = new THREE.Group();
plate.name = 'instrument';

// lower shell, parting seam, upper shell
plate.add(slab(roundedPath(THREE.Shape, 115, 72, 3), 0, 11.0, 0.6, shellMat, 'shell_lower'));
plate.add(slab(roundedPath(THREE.Shape, 114.4, 71.4, 2.7), 11.0, 11.4, 0, oxbloodMat, 'parting_seam'));
plate.add(slab(roundedPath(THREE.Shape, 115, 72, 3), 11.4, 25.5, 0, shellMat, 'shell_upper'));

// deck: 25.5 -> 27.5 carries the Ø48 recess; the 0.5 skin carries the shallow pockets
// dish centre: X 86, Y 31 (device-centre Z = +5, cartridge travel 41mm → 45mm cartridge)
const RCX = X(86), RCY = Y(31);
const deck = roundedPath(THREE.Shape, 115, 72, 3);
deck.holes.push(circleHole(24, RCX, RCY));
plate.add(slab(deck, 25.5, 27.5, 0, shellMat, 'shell_deck'));

const skin = roundedPath(THREE.Shape, 115, 72, 3);
skin.holes.push(circleHole(24, RCX, RCY));
skin.holes.push(roundedPath(THREE.Path, 50, 38, 1.2, X(32), Y(43)));   // display pocket 7→57, 24→62
const btns = [[13, 5.8], [24, 5.8], [35, 5.8], [52, 8.6]];
for (const [bx, d] of btns) skin.holes.push(circleHole(d / 2 + 0.25, X(bx), Y(13)));
plate.add(slab(skin, 27.5, 28.0, 0.4, shellMat, 'shell_skin'));

// recess floor + etched porphyrin
const floor = new THREE.Mesh(new THREE.CircleGeometry(23.6, 96), etchMat);
floor.position.set(RCX, RCY, 25.502);
floor.name = 'recess_floor_etch';
plate.add(floor);

// raised annulus at the recess centre
const ringPts = [
  new THREE.Vector2(4.9, 0), new THREE.Vector2(4.9, 1.2),
  new THREE.Vector2(5.2, 1.5), new THREE.Vector2(6.9, 1.5),
  new THREE.Vector2(7.2, 1.2), new THREE.Vector2(7.2, 0),
];
const ring = new THREE.Mesh(new THREE.LatheGeometry(ringPts, 96), oxbloodMat);
ring.rotation.x = Math.PI / 2;
ring.position.set(RCX, RCY, 25.5);
ring.name = 'ring';
plate.add(ring);

// display: reflective signing panel under a thin cover glass
const screen = new THREE.Mesh(new THREE.PlaneGeometry(49.4, 37.4), screenMat);
screen.position.set(X(32), Y(43), 27.62);
screen.name = 'screen';
plate.add(screen);
plate.add(box(49.7, 37.7, 0.24, X(32), Y(43), 27.78, glassMat, 'display_glass'));
// the fingerprint site is printed flat, not recessed — no open pocket beside the port
const padPrint = new THREE.Mesh(new THREE.PlaneGeometry(24, 12), printMat);
padPrint.position.set(X(86), Y(62.5), 28.006);
padPrint.name = 'pad_print';
plate.add(padPrint);
for (const [bx, d] of btns) {
  const r = d / 2;
  const prof = [
    new THREE.Vector2(0, 0), new THREE.Vector2(r, 0),
    new THREE.Vector2(r, 1.3), new THREE.Vector2(r - 0.35, 1.6),
    new THREE.Vector2(0, 1.6),
  ];
  const b = new THREE.Mesh(new THREE.LatheGeometry(prof, 64), padMat);
  b.rotation.x = Math.PI / 2;
  b.position.set(X(bx), Y(13), 26.6);
  b.name = 'button_' + bx;
  plate.add(b);
}

// CONFIRM sits apart from the row of three and carries a trim collar
const collar = new THREE.Shape();
collar.absarc(X(52), Y(13), 5.9, 0, Math.PI * 2, false);
const collarHole = new THREE.Path();
collarHole.absarc(X(52), Y(13), 4.6, 0, Math.PI * 2, true);
collar.holes.push(collarHole);
plate.add(slab(collar, 27.5, 28.03, 0.12, trimMat, 'confirm_collar'));

// diamond-cut edge break around the top perimeter — the hairline the rim light catches
const breakBand = roundedPath(THREE.Shape, 115, 72, 3);
breakBand.holes.push(roundedPath(THREE.Path, 113.1, 70.1, 2.05));
plate.add(slab(breakBand, 27.52, 28.03, 0.12, trimMat, 'edge_break'));

// display bezel
const bezel = roundedPath(THREE.Shape, 52.4, 40.4, 1.9, X(32), Y(43));
bezel.holes.push(roundedPath(THREE.Path, 50.05, 38.05, 1.2, X(32), Y(43)));
plate.add(slab(bezel, 27.88, 28.04, 0.05, trimMat, 'display_bezel'));

// index ring engraved around the circular recess
for (let i = 0; i < 60; i++) {
  const a = (i / 60) * Math.PI * 2;
  const long = i % 5 === 0;
  const len = long ? 2.3 : 1.2;
  const t = new THREE.Mesh(
    new THREE.BoxGeometry(0.28, len, 0.13),
    long ? steelMat : trimMat
  );
  const rr = 21.9 - len / 2;
  t.position.set(RCX + Math.cos(a) * rr, RCY + Math.sin(a) * rr, 25.56);
  t.rotation.z = a - Math.PI / 2;
  t.name = 'index_' + i;
  plate.add(t);
}

// smooth bezel — no knurling: the ring is a marker for the measurement spot, not a knob
// vent grille, front face, left of the sample slot
for (let i = 0; i < 15; i++) {
  plate.add(box(0.6, 3.0, 2.6, X(34 + i * 1.6), -(36 - 1.48), 14.9, cavityMat, 'vent_' + i));
}

// recessed fasteners, front face
for (const fx of [12, 110]) {
  const s = new THREE.Mesh(new THREE.CylinderGeometry(2, 2, 1.2, 32), steelMat);
  s.position.set(X(fx), -35.55, 5.6);
  s.name = 'fastener_' + fx;
  plate.add(s);
  const slot = new THREE.Mesh(new THREE.BoxGeometry(2.6, 1.4, 0.5), cavityMat);
  slot.position.set(X(fx), -35.9, 5.6);
  slot.name = 'fastener_slot_' + fx;
  plate.add(slot);
}

// apertures: sample slot (centred under the dish), rear bay, USB-C
plate.add(box(34, 4.2, 3, X(86), -(36 + 0.05 - 2.1), 14.9, cavityMat, 'front_slot'));
plate.add(box(72, 3.2, 16, 0, 36 - 1.55, 14, cavityMat, 'rear_bay'));
const usb = new THREE.Mesh(new THREE.CapsuleGeometry(1.6, 5.8, 8, 24), cavityMat);
usb.position.set(55.9, 0, 14);
usb.name = 'usb_c';
plate.add(usb);

plate.rotation.x = -Math.PI / 2;
const model = new THREE.Group();
model.name = 'instrument_root';
model.add(plate);
stage.setObject(model);
// thin surface parts must not cast — they only produce shadow acne
for (const n of ['display_glass', 'screen', 'display_bezel', 'edge_break']) {
  const o = plate.getObjectByName(n);
  if (o) o.castShadow = false;
}
plate.traverse((o) => {
  if (o.isMesh && /^(index_|knurl_|vent_|fastener)/.test(o.name)) o.castShadow = false;
});

/* ---------- pose: 25° azimuth, 28° elevation, object left of frame ---------- */

const cam = stage._camera;
const controls = stage._controls;
cam.fov = 39;
cam.near = 1;
cam.far = 5000;

function pose() {
  const aspect = cam.aspect || 1.6;
  const apparentW = 115 * Math.cos(0.4712) + 72 * Math.sin(0.4712);
  const frameW = apparentW / 0.62;
  const frameH = frameW / aspect;
  const d = frameH / (2 * Math.tan((39 * Math.PI) / 360));
  const az = (27 * Math.PI) / 180, el = (30 * Math.PI) / 180;
  const center = new THREE.Vector3(0, 15, 0);
  const dir = new THREE.Vector3(
    Math.sin(az) * Math.cos(el), Math.sin(el), Math.cos(az) * Math.cos(el)
  );
  const right = new THREE.Vector3().crossVectors(new THREE.Vector3(0, 1, 0), dir).normalize();
  const shift = right.multiplyScalar(frameW * 0.11);
  cam.position.copy(center).add(dir.multiplyScalar(d)).add(shift);
  controls.target.copy(center).add(shift);
  cam.updateProjectionMatrix();
  controls.update();
}
pose();
window.addEventListener('resize', () => setTimeout(pose, 60));

// key light shadow frustum, tightened for a crisp contact shadow
const k = stage._key;
k.position.set(-150, 300, 135);
k.shadow.camera.left = -140;
k.shadow.camera.right = 140;
k.shadow.camera.top = 140;
k.shadow.camera.bottom = -140;
k.shadow.camera.near = 10;
k.shadow.camera.far = 700;
k.shadow.radius = 4;
k.shadow.bias = -0.0008;
k.shadow.normalBias = 0.6;
k.shadow.blurSamples = 24;
k.shadow.mapSize.set(4096, 4096);
if (k.shadow.map) { k.shadow.map.dispose(); k.shadow.map = null; }
k.shadow.camera.updateProjectionMatrix();
