# Enclosure model

`instrument.obj` — 131 named objects with materials, 116.2 × 73.2 × 28.3 mm.
~53 MB, tracked with Git LFS (see `.gitattributes`).

## The chain is one-way

```
viewer/model.js  ──export──▶  instrument.obj  ──generate──▶  diagrams/mechanical.svg
```

`viewer/model.js` is the **parametric source**. It builds the geometry in
three.js; `instrument.obj` is an export from that viewer, and the drawing is
generated from the export by `tools/gen_mechanical.py`, which reads every
dimension out of the mesh at generation time so the drawing cannot drift from
the model. CI fails if it does.

After any model change, re-export and then:

```bash
python tools/gen_mechanical.py
```

**Do not hand-edit the OBJ.** It is 53 MB of triangles, and nothing downstream
of a hand edit can be reconciled with a parametric change.

`instrument.mtl` is referenced by the OBJ but was never supplied. Material
names also ride on the objects themselves (`shell`, `oxblood`, `trim_oxblood`,
`glass`, `pad`, `etch_floor`, `steel`, `cavity`), so the separation survives
without it — assign your own.

## Coordinate convention: centre-origin

| Axis | Range | Meaning |
|---|---|---|
| X | −58.10 … +58.10 | length, right positive |
| Y | 0 … 28.32 | height from the base |
| Z | −36.60 … +36.60 | depth, **+Z toward the front face** |

Some tooling works left-edge-origin (0 … 116.2). Crossing the two frames is a
silent 58 mm error that will not look wrong on screen.

---

## BLOCKING OPEN ITEM — the cartridge cannot reach the read spot

**A cartridge inserted through the front slot cannot arrive under the optical
head. The slot and the read spot are misaligned in both axes.** Measured from
the mesh, not estimated:

| | X centre | Z |
|---|---|---|
| `front_slot` mouth | **−0.50** (spans −17.5 … +16.5) | +36.05 |
| `ring` / read spot | **+28.50** (spans +21.3 … +35.7) | −9.00 |
| Front face | — | +36.60 |

Two independent faults:

**1. Lateral — the harder one.** The slot is centred at X = −0.5 and its far
edge is X = +16.5. The ring spans X = +21.3 … +35.7. **They do not overlap.**
A cartridge pushed straight in travels along the slot's centreline and misses
the read spot by 12 mm at the nearest edge; 29 mm centre to centre. No
insertion depth fixes this.

**2. Depth.** The read spot is 45.6 mm back from the front face. The cartridge
is 32 mm (`BUILD.md` §8). Even if the axes lined up, the cartridge would be
swallowed 13.6 mm inside the shell with nothing left to grip — and the 8 × 14
mm grip tab exists precisely so fingers stay off the optics.

### Resolution — pick one, then re-export and regenerate

| Option | Change | Cost |
|---|---|---|
| **A. Move the dish** (preferred) | Set dish/ring centre to X ≈ −0.5, Z ≈ +5. Insertion becomes ~31.6 mm, so the 32 mm cartridge sits with a few mm proud | Re-lays the deck: display, buttons and index ticks all reference the dish |
| **B. Move the slot** | Re-cut `front_slot` to X centre +28.5, and lengthen the cartridge to ~64 mm so it still protrudes | Cheapest model edit, but a 64 mm cartridge doubles consumable print time and PETG use |
| **C. Side-load** | Move the slot to the right face and keep the dish where it is | Frees the front face, but collides with the USB-C cutout at X = +58 |

Option A is the right answer for a device where the dish is the visual centre
of the product. Option B is the fastest to prove Phase 2 with.

**This does not block Phase 1.** Phase 1 is a bare optical chamber on a
breadboard with no enclosure — the shell is Phase 2 work. Resolve it before
printing shells, not before proving the sensing.
