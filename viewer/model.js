import * as THREE from 'three';

const stage = document.querySelector('three-d-stage');
await stage.ready;

/* ---------- procedural maps ---------- */

function noiseRoughness(size = 512) {
  const c = document.createElement('canvas');
  c.width = c.height = size;
  const ctx = c.getContext('2d', { willReadFrequently: true });
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
  const hctx = height.getContext('2d', { willReadFrequently: true });
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

/** Height canvas -> roughness map. The etch is a change in SHEEN, so the
 *  lines have to differ from the floor in gloss, not only in normal: at the
 *  grazing angles this scene lights the dish from, a pure normal map of a
 *  0.05 mm etch returns nothing. `dip` is how far the lines pull roughness
 *  below the surrounding floor (the map multiplies material.roughness). */
function roughnessFromHeight(height, dip, grain) {
  const size = height.width;
  const src = height.getContext('2d', { willReadFrequently: true })
    .getImageData(0, 0, size, size).data;
  const out = document.createElement('canvas');
  out.width = out.height = size;
  const octx = out.getContext('2d');
  const img = octx.createImageData(size, size);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const o = (y * size + x) * 4;
      const h = src[o] / 255;
      // Fine tooth on the moulded floor, so the etch reads against a surface
      // that is itself not perfectly uniform. The dish is one UV tile across,
      // which is why the shell's own tiled noise map cannot do this job here.
      const n = 1 - grain * Math.random();
      const g = Math.round(255 * Math.max(0, Math.min(1, (1 - dip * h) * n)));
      img.data[o] = img.data[o + 1] = img.data[o + 2] = g;
      img.data[o + 3] = 255;
    }
  }
  octx.putImageData(img, 0, 0);
  const t = new THREE.CanvasTexture(out);
  t.colorSpace = THREE.NoColorSpace;
  t.anisotropy = 8;
  return t;
}

/** Fourfold porphyrin ring, as a soft height field.
 *  Returns both maps built from the same field, so they cannot drift. */
function porphyrinMaps() {
  const size = 512, c = document.createElement('canvas');
  c.width = c.height = size;
  const ctx = c.getContext('2d', { willReadFrequently: true });
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
  return { normal: normalFromHeight(c, 1.1),
           roughness: roughnessFromHeight(c, 0.42, 0.10) };
}

/* ---------- materials ---------- */

const rough = noiseRoughness();

const shellMat = new THREE.MeshPhysicalMaterial({
  name: 'shell', color: 0x1a1917, roughness: 0.70, metalness: 0.0,
  roughnessMap: rough, clearcoat: 0.14, clearcoatRoughness: 0.42,
  envMapIntensity: 1.0,
});
// FINISHES — the accent, and the only part of this instrument anyone is meant
// to choose. Two materials carry it: `ring` is the parting seam and the raised
// annulus around the sensor port; `trim` is the CONFIRM collar, the edge
// break, the display bezel and the 60 index ticks. Everything else — shell,
// steel, glass, the etched dish — is the same in every finish.
//
// On a printed device the accent is a second filament or a paint fill
// (BUILD.md section 10), so these are buyable colours, not screen-only themes.
// PRINTING.md carries the same table with the filament each one wants.
//
// `metalness` is doing as much work here as the colour. Oxblood at 0.92 takes
// a hard specular on a ring that surrounds a black bore; the softer finishes
// drop it deliberately so the ring reads as a machined bezel rather than a
// lit aperture.
const FINISHES = {
  oxblood: { ring: 0x55161d, trim: 0x5f151d, ringRough: 0.38, trimRough: 0.22,
             ringMetal: 0.92, trimMetal: 0.95 },
  deep:    { ring: 0x2e1013, trim: 0x3a141a, ringRough: 0.46, trimRough: 0.42,
             ringMetal: 0.55, trimMetal: 0.60 },
  bone:    { ring: 0x8e877a, trim: 0x9a9284, ringRough: 0.42, trimRough: 0.40,
             ringMetal: 0.35, trimMetal: 0.40 },
  brass:   { ring: 0x6b5220, trim: 0x7a5f2a, ringRough: 0.34, trimRough: 0.30,
             ringMetal: 0.90, trimMetal: 0.92 },
  nickel:  { ring: 0x6f6a63, trim: 0x7d776f, ringRough: 0.26, trimRough: 0.24,
             ringMetal: 0.95, trimMetal: 0.95 },
};
// Oxblood is the default and stays the default: it is what the drawing, the
// social card and every committed render show. `?finish=bone` and the others
// are for looking, and change nothing that is exported.
const DEFAULT_FINISH = 'oxblood';
const FINISH = (() => {
  try {
    const q = new URLSearchParams(location.search).get('finish');
    return (q && Object.hasOwn(FINISHES, q)) ? q : DEFAULT_FINISH;
  } catch { return DEFAULT_FINISH; }
})();
const ACCENT = FINISHES[FINISH];

// The collar, the bezel and the edge break all finish flush with the deck, so
// their top faces are exactly coplanar with the skin's. Depth-offset them, or
// the two surfaces stipple against each other wherever they meet.
const trimMat = new THREE.MeshPhysicalMaterial({
  name: 'trim_oxblood', color: ACCENT.trim, roughness: ACCENT.trimRough,
  metalness: ACCENT.trimMetal,
  envMapIntensity: 1.1,
  polygonOffset: true, polygonOffsetFactor: -2, polygonOffsetUnits: -2,
});
const steelMat = new THREE.MeshPhysicalMaterial({
  name: 'steel', color: 0x8d8880, roughness: 0.34, metalness: 0.95,
  envMapIntensity: 0.55,
});
const oxbloodMat = new THREE.MeshPhysicalMaterial({
  name: 'oxblood', color: ACCENT.ring, roughness: ACCENT.ringRough,
  metalness: ACCENT.ringMetal,
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

/** The reserved fingerprint footprint: a printed outline, not a pocket.
 *  BUILD.md 10 note 2 — an unpopulated recess on the deck is somewhere for
 *  blood to sit, so the site is marked and left flat. */
function padTexture() {
  const w = 480, h = 240, c = document.createElement('canvas');
  c.width = w; c.height = h;
  const g = c.getContext('2d');
  g.clearRect(0, 0, w, h);
  // The footprint is a reserved outline: it should be findable, not loud. It
  // was reading as the brightest thing on the deck, louder than the wordmark.
  g.strokeStyle = 'rgba(196,190,178,0.5)';
  g.lineWidth = 4;
  g.setLineDash([15, 12]);
  const m = 22, r = 26;
  g.beginPath();
  g.moveTo(m + r, m);
  g.arcTo(w - m, m, w - m, h - m, r);
  g.arcTo(w - m, h - m, m, h - m, r);
  g.arcTo(m, h - m, m, m, r);
  g.arcTo(m, m, w - m, m, r);
  g.closePath();
  g.stroke();
  g.setLineDash([]);
  // A whorl: tall nested loops that all but close, broken only where the
  // finger leaves the frame. Shallow nested domes over a shared centre are
  // the signal-strength icon, which is what a 120-degree arc draws.
  // Sized to a fingertip — about 6 x 8 mm at this texture's 20 px/mm — rather
  // than the 4 mm token it was, which left the footprint reading as an empty
  // box with a speck in it.
  g.strokeStyle = 'rgba(196,190,178,0.72)';
  g.lineWidth = 4.5;
  const cx = w / 2, cy = h / 2 - 1;
  for (let i = 0; i < 4; i++) {
    g.beginPath();
    g.ellipse(cx, cy, 16 + i * 15, 20 + i * 19, 0,
              Math.PI * 0.66, Math.PI * 2.34);
    g.stroke();
  }
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  t.anisotropy = 8;
  return t;
}

/** Wordmark, silkscreened on the rear-left deck. */
function markTexture() {
  const w = 512, h = 128, c = document.createElement('canvas');
  c.width = w; c.height = h;
  const g = c.getContext('2d');
  g.clearRect(0, 0, w, h);
  g.fillStyle = 'rgba(203,197,185,0.95)';
  g.font = '600 62px ui-sans-serif, system-ui, -apple-system, Helvetica, sans-serif';
  g.textBaseline = 'middle';
  let x = 10;
  for (const ch of 'CELL') {              // letterspaced by hand; canvas has no tracking
    g.fillText(ch, x, h / 2 + 2);
    x += g.measureText(ch).width + 21;
  }
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
// The dish is a single UV tile across, so the shell's noise map — tiled at
// one per 42 mm — sampled to very nearly a constant here and did nothing.
// The porphyrin's own maps carry both the relief and the floor's grain.
const porphyrin = porphyrinMaps();
const etchMat = new THREE.MeshPhysicalMaterial({
  name: 'etch_floor', color: 0x1a1917, roughness: 0.66, metalness: 0.0,
  roughnessMap: porphyrin.roughness, normalMap: porphyrin.normal,
  normalScale: new THREE.Vector2(0.22, 0.22),
  clearcoat: 0.10, clearcoatRoughness: 0.5, envMapIntensity: 1.0,
});
const cavityMat = new THREE.MeshPhysicalMaterial({
  name: 'cavity', color: 0x050505, roughness: 0.95, metalness: 0.0,
  envMapIntensity: 0.06,
  // Biased HARDER than steelMat's -2. Most cavities protrude and never need
  // this, but the fastener slot is coplanar with both the shell face and the
  // screw head it is cut into, and it has to win against both.
  polygonOffset: true, polygonOffsetFactor: -4, polygonOffsetUnits: -4,
});
// The port bore is the one cavity surface seen from INSIDE, so it needs the
// back faces of its open cylinder. Its own material rather than a side flag
// on cavityMat: that one is shared with the slot, the bay, the vents and the
// USB cutout, and flipping it there renders the far wall of every one of them.
const boreMat = new THREE.MeshPhysicalMaterial({
  name: 'cavity_bore', color: 0x050505, roughness: 0.95, metalness: 0.0,
  envMapIntensity: 0.06, side: THREE.BackSide,
});
// Was 0x24221f flat on a 0x1a1917 shell — three values apart, and invisible.
// Real silkscreen on black plastic is a light, dead-matte ink; the artwork
// rides in the map's alpha so only the marking prints, not its panel.
const printMat = new THREE.MeshPhysicalMaterial({
  name: 'silkscreen', color: 0x8f897e, roughness: 0.99, metalness: 0.0,
  map: padTexture(), transparent: true, envMapIntensity: 0.22,
});
const markMat = new THREE.MeshPhysicalMaterial({
  name: 'silkscreen_mark', color: 0xa8a296, roughness: 0.99, metalness: 0.0,
  map: markTexture(), transparent: true, envMapIntensity: 0.22,
});
// Ink sits ON the deck, exactly coplanar with it. Depth-offset rather than
// floated: lifting it even a hundredth would raise the model's envelope,
// which gen_enclosure.py cross-checks against the printed shells.
for (const m of [printMat, markMat, steelMat]) {
  m.polygonOffset = true;
  m.polygonOffsetFactor = -2;
  m.polygonOffsetUnits = -2;
}
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

// deck: 25.5 -> 27.5 carries the Ø48 recess; the 0.5 skin carries the shallow pockets
// dish centre: X 86, Y 31 (device-centre Z = +5, cartridge travel 41mm → 45mm cartridge)
const RCX = X(86), RCY = Y(31);

// Sensor port, straight down the dish centreline to the optical chamber. The
// numbers are gen_enclosure.py's, which owns the inside: PORT_D 9.8 (the ring
// ID), and a Ø10.2 x 0.6 rebate the Ø10 x 0.5 ring window drops into flush.
// The window is on the BOM and in BUILD.md 8; until now the model had nothing
// there and the read spot rendered as painted-on floor.
const PORT_R = 9.8 / 2, GLASS_R = 10.2 / 2, GLASS_REBATE = 0.6, GLASS_T = 0.5;
// The dish is 2.0 deep, because gen_enclosure.py's DISH_DEPTH is 2.0 and that
// number is load-bearing: check_stack() derives the optical skirt and the
// chamber ceiling from it. This constant used to be 25.502 -- the top of the
// shell_upper slab plus a z-fight offset, i.e. wherever the slab stack
// happened to end -- which made the RENDERED dish 2.818 deep and the PRINTED
// one 2.0. Two models of one instrument, 0.82 mm apart, with nothing
// comparing them; gen_enclosure.check_viewer_envelope now does.
const DECK_TOP_Z = 28.32;               // restated as DECK_TOP below
const DISH_DEPTH = 2.0;
const DISH_FLOOR = DECK_TOP_Z - DISH_DEPTH, PART_LINE = 11.4;
const REBATE_FLOOR = DISH_FLOOR - GLASS_REBATE;

// lower shell, parting seam, upper shell
plate.add(slab(roundedPath(THREE.Shape, 115, 72, 3), 0, 11.0, 0.6, shellMat, 'shell_lower'));
plate.add(slab(roundedPath(THREE.Shape, 114.4, 71.4, 2.7), 11.0, 11.4, 0, oxbloodMat, 'parting_seam'));
const upper = roundedPath(THREE.Shape, 115, 72, 3);
upper.holes.push(circleHole(PORT_R + 0.05, RCX, RCY));   // sleeved below, so slightly clear
plate.add(slab(upper, PART_LINE, 25.5, 0, shellMat, 'shell_upper'));
// Two slabs, because the dish has a FLOOR. The deck is solid across its whole
// footprint up to DISH_FLOOR -- only the sensor port passes through -- and is
// holed for the dish above that. One slab holed all the way through is what
// left the recess bottoming out on shell_upper.
const deck = roundedPath(THREE.Shape, 115, 72, 3);
deck.holes.push(circleHole(PORT_R + 0.05, RCX, RCY));
plate.add(slab(deck, 25.5, DISH_FLOOR, 0, shellMat, 'shell_deck'));
const deckDish = roundedPath(THREE.Shape, 115, 72, 3);
deckDish.holes.push(circleHole(24, RCX, RCY));
plate.add(slab(deckDish, DISH_FLOOR, 27.5, 0, shellMat, 'shell_deck_dish'));

// The skin's 0.4 bevel is thicker than half its own 0.5 slab, so ExtrudeGeometry
// clamps the depth and the chamfer adds its full thickness on top: the deck's
// real top face is 28.32, not the 28.0 this slab asks for. gen_enclosure.py's
// ENV_Z is pinned to that 28.32, so the number stays — but everything that
// sits ON the deck has to be placed against it. Four things were not, and had
// been quietly buried inside the shell ever since.
const DECK_TOP = DECK_TOP_Z;
const skin = roundedPath(THREE.Shape, 115, 72, 3);
skin.holes.push(circleHole(24, RCX, RCY));
skin.holes.push(roundedPath(THREE.Path, 50, 38, 1.2, X(32), Y(43)));   // display pocket 7→57, 24→62
const btns = [[13, 5.8], [24, 5.8], [35, 5.8], [52, 8.6]];
for (const [bx, d] of btns) skin.holes.push(circleHole(d / 2 + 0.25, X(bx), Y(13)));
plate.add(slab(skin, 27.5, 28.0, 0.4, shellMat, 'shell_skin'));

// recess floor + etched porphyrin, now an annulus around the port. The
// macrocycle's own iron site falls inside the bore, which is where the
// measurement happens — the drawing frames the read spot rather than
// covering it.
const floor = new THREE.Mesh(new THREE.RingGeometry(GLASS_R, 23.6, 96, 1), etchMat);
floor.position.set(RCX, RCY, DISH_FLOOR);
floor.name = 'recess_floor_etch';
plate.add(floor);

// port sleeve + its blind cap: matte black, so the read spot returns nothing
const sleeveH = REBATE_FLOOR - PART_LINE;
const sleeve = new THREE.Mesh(
  new THREE.CylinderGeometry(PORT_R, PORT_R, sleeveH, 64, 1, true), boreMat);
sleeve.rotation.x = Math.PI / 2;
sleeve.position.set(RCX, RCY, PART_LINE + sleeveH / 2);
sleeve.name = 'port_sleeve';
plate.add(sleeve);
const portFloor = new THREE.Mesh(new THREE.CircleGeometry(PORT_R, 64), cavityMat);
portFloor.position.set(RCX, RCY, PART_LINE);
portFloor.name = 'port_floor';
plate.add(portFloor);

// the ring window, seated in its rebate under the ring's inner lip
const windowDisc = new THREE.Mesh(
  new THREE.CylinderGeometry(GLASS_R, GLASS_R, GLASS_T, 96), glassMat);
windowDisc.rotation.x = Math.PI / 2;
windowDisc.position.set(RCX, RCY, REBATE_FLOOR + GLASS_T / 2);
windowDisc.name = 'ring_window';
plate.add(windowDisc);

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
padPrint.position.set(X(86), Y(62.5), DECK_TOP);
padPrint.name = 'pad_print';
plate.add(padPrint);

// wordmark, rear-left deck: the strip behind the display, clear of the pad
const mark = new THREE.Mesh(new THREE.PlaneGeometry(22, 5.5), markMat);
mark.position.set(X(19), Y(67), DECK_TOP);
mark.name = 'wordmark';
plate.add(mark);
for (const [bx, d] of btns) {
  const r = d / 2;
  // A flat top on a near-black cap returns nothing and reads as an open hole.
  // A shallow crown gives the key light somewhere to land, which is the whole
  // difference between a button and a bore. The APEX stays at 1.6 — the crown
  // is cut into the cap, not added on top of it: 26.6 + 1.6 is 28.2, and
  // anything over 28.32 would raise the envelope gen_enclosure.py pins.
  const prof = [
    new THREE.Vector2(0, 0), new THREE.Vector2(r, 0),
    new THREE.Vector2(r, 1.3), new THREE.Vector2(r - 0.35, 1.44),
    new THREE.Vector2(r * 0.62, 1.56), new THREE.Vector2(0, 1.6),
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
plate.add(slab(collar, DECK_TOP - 0.53, DECK_TOP, 0.12, trimMat, 'confirm_collar'));

// diamond-cut edge break around the top perimeter — the hairline the rim light
// catches. Sized to the deck's TOP face (115 less the skin's 0.4 chamfer on
// each side), not to the body outline: run out to 115 at this height and the
// band overhangs the chamfer with nothing under it.
const breakBand = roundedPath(THREE.Shape, 114.2, 71.2, 2.6);
breakBand.holes.push(roundedPath(THREE.Path, 113.1, 70.1, 2.05));
plate.add(slab(breakBand, DECK_TOP - 0.51, DECK_TOP, 0.12, trimMat, 'edge_break'));

// display bezel
const bezel = roundedPath(THREE.Shape, 52.4, 40.4, 1.9, X(32), Y(43));
bezel.holes.push(roundedPath(THREE.Path, 50.05, 38.05, 1.2, X(32), Y(43)));
plate.add(slab(bezel, DECK_TOP - 0.16, DECK_TOP, 0.05, trimMat, 'display_bezel'));

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
  // Front face COPLANAR with the shell's, not 0.45 mm behind it. The head is
  // 1.2 deep and the face is at -36.6, so the centre is -36.0; at -35.55 the
  // whole head sat inside solid shell and only its slot ever rendered -- two
  // black slots on a blank face, with no screw. Coplanar and depth-offset
  // rather than floated, because protruding would push the model's envelope
  // past the 73.2 that gen_enclosure.py checks against the printed shells.
  s.position.set(X(fx), -36.0, 5.6);
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
// 55.95, so the capsule's +X extreme is 57.55 against a right face at 57.5.
// At 55.9 it reached exactly 57.5 and was tangent to the wall: the aperture
// was entirely inside solid shell, the end face rendered blank, and the
// mechanical drawing dimensioned a USB-C opening that the render did not
// have. The 0.05 protrusion is what front_slot and rear_bay already use, and
// it stays inside the +/-58.1 envelope.
usb.position.set(55.95, 0, 14);
usb.name = 'usb_c';
plate.add(usb);

plate.rotation.x = -Math.PI / 2;
const model = new THREE.Group();
model.name = 'instrument_root';
model.add(plate);
stage.setObject(model);
// thin surface parts must not cast — they only produce shadow acne
for (const n of ['display_glass', 'screen', 'display_bezel', 'edge_break',
                 'pad_print', 'wordmark', 'ring_window', 'recess_floor_etch']) {
  const o = plate.getObjectByName(n);
  if (o) o.castShadow = false;
}
plate.traverse((o) => {
  if (o.isMesh && /^(index_|knurl_|vent_|fastener)/.test(o.name)) o.castShadow = false;
});

/* ---------- pose: 27° azimuth, 30° elevation, object left of frame ----------
 * Fit is measured, not assumed. The old version fixed the frame from the
 * body's apparent WIDTH and derived its height as frameW / aspect, which is
 * only a fit in landscape: at a phone's 0.46 it pushed the camera three and a
 * half times further out and left the instrument a chip in a field of black.
 * Here the eight bounding-box corners are projected onto the camera's own
 * right/up axes, and the distance is whichever of the two constraints binds.
 */

const cam = stage._camera;
const controls = stage._controls;
cam.fov = 39;
cam.near = 1;
cam.far = 5000;

const AZ = (27 * Math.PI) / 180, EL = (30 * Math.PI) / 180;
const BOX = new THREE.Box3().setFromObject(model);
const CENTRE = BOX.getCenter(new THREE.Vector3());
const CORNERS = [];
for (const x of [BOX.min.x, BOX.max.x])
  for (const y of [BOX.min.y, BOX.max.y])
    for (const z of [BOX.min.z, BOX.max.z])
      CORNERS.push(new THREE.Vector3(x, y, z).sub(CENTRE));

function pose() {
  const aspect = cam.aspect || 1.6;
  const dir = new THREE.Vector3(
    Math.sin(AZ) * Math.cos(EL), Math.sin(EL), Math.cos(AZ) * Math.cos(EL)
  );
  const right = new THREE.Vector3()
    .crossVectors(new THREE.Vector3(0, 1, 0), dir).normalize();
  const up = new THREE.Vector3().crossVectors(dir, right).normalize();

  // half-extents of the silhouette, in the camera's own frame
  let hw = 0, hh = 0;
  for (const c of CORNERS) {
    hw = Math.max(hw, Math.abs(c.dot(right)));
    hh = Math.max(hh, Math.abs(c.dot(up)));
  }

  const vFov = (cam.fov * Math.PI) / 180;
  const hFov = 2 * Math.atan(Math.tan(vFov / 2) * aspect);
  // Portrait gives the object the width and spends the surplus height on air;
  // landscape holds the wider margins the studio framing was composed for.
  const portrait = aspect < 1;
  const fillW = portrait ? 0.94 : 0.68;
  const fillH = portrait ? 0.46 : 0.70;
  const d = Math.max(hw / fillW / Math.tan(hFov / 2),
                     hh / fillH / Math.tan(vFov / 2));

  cam.position.copy(CENTRE).add(dir.multiplyScalar(d));
  controls.target.copy(CENTRE);

  // Compose off-centre with the projection rather than by moving the orbit
  // target. Shifting the target is what used to put the turntable's axis a
  // couple of centimetres beside the object, so it swung instead of spun.
  const w = stage.clientWidth || 1, h = stage.clientHeight || 1;
  const offset = portrait ? 0 : Math.round(w * 0.10);
  if (offset) cam.setViewOffset(w, h, offset, 0, w, h);
  else cam.clearViewOffset();

  cam.updateProjectionMatrix();
  controls.update();
  stage.invalidate();
}
pose();
window.addEventListener('resize', () => setTimeout(pose, 60));

// A drift, not a carousel. The turntable is here to say "this is a thing you
// can turn", and the composed pose above is worth staying near while someone
// reads the first line — so a revolution takes about two minutes, and the
// first interaction stops it for good.
controls.autoRotateSpeed = 0.5;

// The studio's fill is the starter's 0.35, against a key of 5.4 and a floor
// bounce panel that is almost black. On a body this dark that leaves every
// VERTICAL face at nothing: the deck lights up, the sides fall to the
// background, and the instrument reads as a lit plate floating on a void
// rather than a solid 28 mm box. Raise the fill and bring it round to rake
// the front and left walls — the object has to hold its form from every
// angle the orbit allows, not just the composed three-quarter one.
const fillLight = stage._scene.children.find(
  (o) => o.isDirectionalLight && o !== stage._key && o.intensity < 1);
if (fillLight) {
  fillLight.intensity = 1.15;
  fillLight.position.set(-70, 26, 120);
}

// Key light shadow frustum. The stage is on VSM, which is the only type where
// radius and blurSamples reach the filter — and the object needs them: it is a
// slab lit from high and to one side, so the cast shadow is a long hard wedge
// running off across a floor the page never draws. A wide penumbra is what
// keeps it reading as a shadow rather than as a second object.
const k = stage._key;
k.position.set(-150, 300, 135);
k.shadow.camera.left = -140;
k.shadow.camera.right = 140;
k.shadow.camera.top = 140;
k.shadow.camera.bottom = -140;
k.shadow.camera.near = 10;
k.shadow.camera.far = 700;
// VSM wants a depth-space bias, not the polygon offset PCF needs; the large
// negative value PCF used detaches the shadow from the object under VSM.
k.shadow.bias = -0.0006;
k.shadow.normalBias = 0.0;
// VSM's blur is measured in TEXELS, so the world-space penumbra depends on the
// map's resolution as much as on the radius: at 4096 over this frustum a texel
// is 0.07 mm, and even a radius of 7 is a penumbra you need to zoom in to
// find. 1024 puts a texel at 0.27 mm, and radius 18 gives about 5 mm of
// falloff — enough that the cast edge reads as a shadow instead of as a
// second object lying on a floor the page never draws.
//
// The blur is expensive and completely free here: the map is baked once and
// held, because nothing in the scene moves.
k.shadow.radius = 18;
k.shadow.blurSamples = 24;
k.shadow.mapSize.set(1024, 1024);
if (k.shadow.map) { k.shadow.map.dispose(); k.shadow.map = null; }
k.shadow.camera.updateProjectionMatrix();
stage._ground.material.opacity = 0.36;
// The map is baked once and held, so it has to be re-baked after that retune.
stage.invalidateShadow();

/* ---------- pick a part, read what it is ----------
 * The README has to carry a caption under the turntable explaining that the
 * ring is a bezel and nothing rotates, because a picture cannot say so. Here
 * the model can: click a part and it names itself.
 *
 * Every dimension below is measured off the geometry that is already on the
 * page — the same constants the shapes were built from — rather than
 * transcribed from BUILD.md. A caption that repeats a number is a caption that
 * can disagree with it.
 */

const callout = document.querySelector('.callout');
if (callout) {
  const D = (n) => n.toFixed(1);
  const OD = (n) => 'Ø' + n.toFixed(1);
  const bigBtn = btns[btns.length - 1][1], smallBtn = btns[0][1];
  const nSmall = btns.filter(([, d]) => d === smallBtn).length;

  // name -> [title, dimension, note]. Tested longest-prefix first, so
  // 'button_52' beats 'button_'.
  const FEATURES = [
    ['ring_window', ['Ring window', OD(GLASS_R * 2) + ' × ' + D(GLASS_T),
      'Clear acrylic or glass, seated in its rebate under the ring lip. It seals the optical chamber and gives the fingertip a defined surface to land on.']],
    ['ring', ['Sensor port', OD(PORT_R * 2) + ' bore, ring ' + OD(14.4) + ' OD',
      'A fingertip on the ring for the touch tier; a cartridge under it for blood. The ring is a bezel, not a control — nothing rotates.']],
    ['port_', ['Sensor port', OD(PORT_R * 2) + ' through the dish',
      'The optical path down to the chamber. Matte black, so the read spot returns nothing of its own.']],
    ['recess_floor_etch', ['Sample dish',
      OD(23.6 * 2) + ', ' + D(DECK_TOP - DISH_FLOOR) + ' deep',
      'The etched macrocycle is a porphyrin. Haemoglobin carries an iron atom at the centre of one, and the 415 nm Soret band that ring produces is what the chemistry gate looks for.']],
    ['index_', ['Index ring', '60 ticks, every fifth in steel',
      'Decorative. The dish is a reader, not a dial.']],
    ['screen', ['Display', null,
      'The whole transaction, in full: the complete destination address, the amount, the change and the fee. This screen is the defence — everything else assumes you read it.']],
    ['display_', ['Display', null, 'Flush cover glass in an oxblood bezel.']],
    ['confirm_collar', ['CONFIRM', OD(bigBtn),
      'Set apart from the row of three, and collared, so it cannot be found by accident.']],
    ['button_' + btns[btns.length - 1][0], ['CONFIRM', OD(bigBtn),
      'Set apart from the row of three, and collared, so it cannot be found by accident.']],
    ['button_', ['Navigation', nSmall + ' × ' + OD(smallBtn), 'Move through the transaction and the menus.']],
    ['pad_print', ['Reserved', null,
      'A printed footprint for the optional fingerprint sensor, which the base build does not fit — the PIN does identity. Printed flat rather than recessed: an empty pocket on the deck is somewhere for blood to sit.']],
    ['front_slot', ['Cartridge slot', null,
      'On the dish centreline. The cartridge travels in until it sits under the read spot, and what is left proud of the slot is the grip.']],
    ['vent_', ['Vents', null,
      'Blind pockets, not through-holes. A through-hole would let ambient light into the optical chamber and the 415 nm gate would stop working.']],
    ['rear_bay', ['Compute bay', null, 'The Pi slides in from the rear, like a cartridge.']],
    ['usb_c', ['USB-C', null,
      'Power only. There is no USB data path, no wifi and no bluetooth — transactions arrive and leave as QR codes.']],
    ['parting_seam', ['Part line', D(PART_LINE) + ' from the base',
      'Where the two printed shells meet, picked out in oxblood.']],
    ['fastener', ['Fasteners', '2 × ' + OD(4.0) + ' slotted', 'Front face, into the lower shell.']],
    ['wordmark', ['CELL', null, 'Silkscreen on the deck.']],
    ['', ['Enclosure', null,
      'Two PETG shells, printed. Black for the body, a second filament or a paint fill for the oxblood seam, ring, bezel and ticks.']],
  ];

  const lookup = (name) => {
    let best = null;
    for (const [prefix, entry] of FEATURES) {
      if (name.startsWith(prefix) && (!best || prefix.length > best[0].length)) {
        best = [prefix, entry];
      }
    }
    return best && best[1];
  };

  // Marker lives in the SCENE, not in the model: the exporters serialise
  // stage._object, and a pin the visitor happened to drop must not end up in
  // their OBJ.
  const pinMat = new THREE.MeshBasicMaterial({
    color: 0xd0455a, transparent: true, opacity: 0.95, depthTest: false,
  });
  const pin = new THREE.Mesh(new THREE.RingGeometry(1.7, 2.5, 40), pinMat);
  pin.renderOrder = 999;
  pin.visible = false;
  pin.castShadow = pin.receiveShadow = false;
  stage._scene.add(pin);

  const title = callout.querySelector('.callout-title');
  const dim = callout.querySelector('.callout-dim');
  const note = callout.querySelector('.callout-note');
  const ray = new THREE.Raycaster();
  const ndc = new THREE.Vector2();
  const el = stage;

  // Meshes a click passes straight through to whatever is behind them.
  const PICK_THROUGH = new Set(['display_glass']);

  const hit = (ev) => {
    const r = el.getBoundingClientRect();
    ndc.set(((ev.clientX - r.left) / r.width) * 2 - 1,
            -((ev.clientY - r.top) / r.height) * 2 + 1);
    ray.setFromCamera(ndc, cam);
    // The 0.24 mm cover glass sits in front of the panel and is larger than
    // it in both axes, so every ray reaching the display from outside hit the
    // glass first and resolved to the 'display_' entry. That made 'screen' —
    // "this screen is the defence, everything else assumes you read it", the
    // one caption this whole module exists to deliver — unreachable.
    const hits = ray.intersectObject(model, true);
    return hits.find((h) => !PICK_THROUGH.has(h.object.name)) || hits[0] || null;
  };

  const clear = () => {
    pin.visible = false;
    callout.hidden = true;
    stage.invalidate();
  };

  const pinNormal = new THREE.Vector3(0, 1, 0);
  const select = (h) => {
    const f = lookup(h.object.name || '');
    if (!f) return clear();
    title.textContent = f[0];
    dim.textContent = f[1] || '';
    dim.hidden = !f[1];
    note.textContent = f[2];
    callout.hidden = false;
    pin.position.copy(h.point);
    // Lie the marker on the surface it was dropped on, lifted a hair so it
    // does not fight the face it is annotating.
    pinNormal.copy(h.face
      ? h.face.normal.clone().transformDirection(h.object.matrixWorld)
      : new THREE.Vector3(0, 1, 0));
    pin.lookAt(h.point.clone().add(pinNormal));
    pin.position.addScaledVector(pinNormal, 0.35);
    pin.visible = true;
    stage.invalidate();
    pressCap(h.object.name || '');
  };

  /* ---------- the buttons travel ----------
   * Naming a part is information. Pressing one is the other half: these are
   * switches, and a switch that does not move under the pointer reads as a
   * picture of a switch. The travel is the real thing — 0.7 mm, which is what
   * a 12 mm tactile switch gives you — so the animation is not decoration, it
   * is the same number the enclosure was built around.
   *
   * CONFIRM is deliberately slower. The device asks the owner to HOLD it, and
   * a cap that snaps back in 200 ms would say the opposite.
   */
  const TRAVEL = 0.7;
  const CONFIRM_NAME = 'button_' + btns[btns.length - 1][0];
  const caps = new Map();          // mesh -> its resting z
  for (const [bx] of btns) {
    const m = model.getObjectByName('button_' + bx);
    if (m) caps.set(m, m.position.z);
  }

  let animating = null;            // { mesh, t0, hold } or null

  // Put every cap back where the geometry says it sits. Called before an
  // export, and before any new press, so two clicks in quick succession
  // cannot leave one stuck down.
  const settleCaps = () => {
    animating = null;
    let moved = false;
    for (const [m, z] of caps) {
      if (m.position.z !== z) { m.position.z = z; moved = true; }
    }
    if (moved) stage.invalidate();
  };
  stage.addEventListener('beforeexport', settleCaps);
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) settleCaps();
  });

  const easeOut = (u) => 1 - (1 - u) * (1 - u);

  const step = () => {
    if (!animating) return;
    const { mesh, t0, hold } = animating;
    const rest = caps.get(mesh);
    const DOWN = 70, UP = 170;
    const t = performance.now() - t0;
    let d;                                  // 0 at rest, 1 fully depressed
    if (t < DOWN) d = easeOut(t / DOWN);
    else if (t < DOWN + hold) d = 1;
    else d = 1 - easeOut(Math.min(1, (t - DOWN - hold) / UP));
    mesh.position.z = rest - TRAVEL * d;
    stage.invalidate();
    if (t < DOWN + hold + UP) requestAnimationFrame(step);
    else { mesh.position.z = rest; animating = null; stage.invalidate(); }
  };

  // The cap under a hit, or null. Clicking the CONFIRM collar presses the cap
  // it surrounds: the collar is shell, and nobody aiming at it means the trim.
  const capFor = (name) => {
    if (name === 'confirm_collar') return model.getObjectByName(CONFIRM_NAME);
    return name.startsWith('button_') ? model.getObjectByName(name) : null;
  };

  const pressCap = (name) => {
    const mesh = capFor(name || '');
    if (!mesh || !caps.has(mesh)) return;
    settleCaps();
    animating = { mesh, t0: performance.now(),
                  hold: mesh.name === CONFIRM_NAME ? 420 : 45 };
    requestAnimationFrame(step);
  };

  // OrbitControls owns the drag. Only a press that barely moved, did not
  // linger, and was the only finger down is a click — otherwise every orbit
  // would pick something, and every pinch would pick twice.
  let downAt = null, downT = 0, fingers = 0;
  el.addEventListener('pointerdown', (ev) => {
    fingers += 1;
    downAt = fingers > 1 ? null : { x: ev.clientX, y: ev.clientY };
    downT = performance.now();
  });
  const endPointer = () => { fingers = Math.max(0, fingers - 1); };
  el.addEventListener('pointercancel', () => { downAt = null; endPointer(); });
  el.addEventListener('pointerup', (ev) => {
    const start = downAt;
    downAt = null;
    const multi = fingers > 1;
    endPointer();
    if (!start || multi) return;
    if (Math.hypot(ev.clientX - start.x, ev.clientY - start.y) > 5) return;
    if (performance.now() - downT > 500) return;
    const h = hit(ev);
    h ? select(h) : clear();
  });

  // Hover only sets a cursor, and a raycast against 300k triangles is far too
  // expensive to run on every pointermove. Throttle it, and skip it entirely
  // on touch, where there is no cursor and no hover.
  let hoverAt = 0;
  if (!matchMedia('(hover: none)').matches) {
    el.addEventListener('pointermove', (ev) => {
      if (downAt || fingers) return;           // mid-drag: leave the cursor alone
      const now = performance.now();
      if (now - hoverAt < 120) return;
      hoverAt = now;
      el.style.cursor = hit(ev) ? 'pointer' : '';
    });
  }
  el.addEventListener('pointerleave', () => { el.style.cursor = ''; });
  window.addEventListener('keydown', (ev) => { if (ev.key === 'Escape') clear(); });
  callout.querySelector('.callout-close').addEventListener('click', clear);

  // The marker is in world space and the label is in the page, so the label
  // has to be re-placed whenever the camera moves. Rendering is on demand, so
  // this rides the same signal: it runs on the frames that are actually drawn.
  const project = new THREE.Vector3();
  const toCam = new THREE.Vector3();
  const place = () => {
    if (!pin.visible) return;
    project.copy(pin.position).project(cam);
    const r = el.getBoundingClientRect();
    const x = (project.x * 0.5 + 0.5) * r.width;
    const y = (-project.y * 0.5 + 0.5) * r.height;
    callout.style.left = x + 'px';
    callout.style.top = y + 'px';
    // Sit on whichever side of the marker has room. Without this, anything
    // picked on the right-hand half of the object labels itself off-frame.
    callout.classList.toggle('flip', x + 18 + callout.offsetWidth > r.width - 8);
    // Hide rather than leave a label pointing at nothing: behind the camera,
    // or on a face that has since turned away from it.
    toCam.subVectors(cam.position, pin.position);
    callout.classList.toggle(
      'behind', project.z > 1 || toCam.dot(pinNormal) <= 0);
  };
  // Wrap the stage's own loop rather than the animation callback, so a
  // detach/reattach — which restores stage._loop — keeps the label alive.
  const inner = stage._loop;
  stage._loop = () => { inner(); place(); };
  stage._renderer.setAnimationLoop(stage._loop);
}
