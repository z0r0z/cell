# Enclosure model

`instrument.obj`: 104 named objects with materials, 116.2 × 73.2 × 28.3 mm.
~54 MB, tracked with Git LFS (see `.gitattributes`).

The object and vertex counts are printed in the corner of
`diagrams/mechanical.svg`, which is generated from this file. Trust that copy
if this line ever drifts again.

## The chain is one-way

```
viewer/model.js  ──export──▶  instrument.obj  ──generate──▶  diagrams/mechanical.svg
```

`viewer/model.js` is the **parametric source**. It builds the geometry in
three.js. `instrument.obj` is an export from that viewer. The drawing is
generated from the export by `tools/gen_mechanical.py`, which reads every
dimension out of the mesh at generation time, so the drawing cannot drift from
the model. CI fails if it does.

After any model change, re-export and then:

```bash
python tools/gen_mechanical.py
```

**Do not hand-edit the OBJ.** It is 54 MB of triangles, and nothing downstream
of a hand edit can be reconciled with a parametric change.

`instrument.mtl` is written by `tools/export_model.py` in the same pass as the
OBJ, from the viewer's own materials, so the two stay in step. Material names
also ride on the objects themselves (`shell`, `oxblood`, `trim_oxblood`,
`glass`, `pad`, `etch_floor`, `steel`, `cavity`, `cavity_bore`, `screen`,
`silkscreen`, `silkscreen_mark`), so the separation survives if you drop the
MTL and assign your own. Twelve, not eleven: `cavity_bore` is the inward-facing
material on `port_sleeve`, and it is the one the OBJ cannot carry faithfully,
because a back-faced material is a thing the format has no way to say.

The two accent materials, `oxblood` and `trim_oxblood`, are the only ones a
builder is meant to choose. `model.js`'s `FINISHES` table names five, and
`PRINTING.md` section 2b carries the same set as filament colours. Oxblood is
the default, and the export is byte-identical in every finish that does not
change it: the OBJ carries no colour at all, and the MTL is written from
whichever finish is loaded, which for every committed artefact is the default.
Nothing here needs regenerating when a finish is added.

## Coordinate convention: centre-origin

| Axis | Range | Meaning |
|---|---|---|
| X | −58.10 … +58.10 | length, right positive |
| Y | 0 … 28.32 | height from the base |
| Z | −36.60 … +36.60 | depth, **+Z toward the front face** |

Some tooling works left-edge-origin (0 … 116.2). Crossing the two frames is a
silent 58 mm error that will not look wrong on screen.

---

## The printed parts

`models/print/` holds the parts that are *not* enclosure: the cartridge, the
pre-flight REFERENCE and NULL bodies, the aperture tube, the optical head, the
slot baffle, the display bezel, the rear bay blank, the window jig, and both
enclosure shells.
`python3 tools/gen_printables.py` builds all eleven, validates each one, and
regenerates `models/print/MANIFEST.md` from the same constants. The manifest
cannot describe a part the STLs no longer are.

The shells are the one place the one-way chain above does not tell the whole
story. `model.js` owns the outside and is an appearance model: its shells are
solid, and its openings are dark boxes with no volume removed. The inside
(wall, part line, bosses, rails, optical chamber) comes from
`tools/gen_enclosure.py`. Two parametric sources is exactly the drift this file
warns about, so the seam is checked on every run: the assembled shells must
match the documented envelope, and the assembly checks must pass. See
`models/print/MANIFEST.md`.

## Regenerating

`tools/export_model.py` drives headless Chrome against the real viewer, so the
mesh comes out of the same three.js code path a person gets when they open the
page. No reimplementation to drift.

```bash
python tools/export_model.py        # model.js  -> instrument.obj + .mtl
python tools/gen_mechanical.py      # instrument.obj -> diagrams/mechanical.svg
```

Run both after any model change, in the same commit. CI checks both links: the
`model-export` job re-exports and diffs the OBJ, and `drawings` regenerates the
SVG from it.

Three more things are rendered from this same model and are stale the moment it
changes. None is checked by CI, because each needs a browser:

```bash
python3 tools/render_turntable.py       # -> diagrams/turntable.gif + .mp4
python3 tools/render_social_card.py     # -> diagrams/social-card.png
python3 tools/build_single_file_viewer.py   # -> viewer/instrument-standalone.html
```

The last one is what `cell.wei.is` serves, so it is the one that matters
outside the repository. Building it is not deploying it. CI's `viewer` job
checks the bundle in the tree carries this tree's viewer. Nothing can check
what the host is serving.

## Geometry check

The cartridge enters the front slot and must land under the optical head, so
the slot and the ring share a centreline:

| | X centre | Z |
|---|---|---|
| `front_slot` | +28.50 (spans +11.5 … +45.5) | +36.05 |
| `ring` / read spot | +28.50 | +5.00 |
| Front face | — | +36.60 |

Cartridge travel front face to read spot is **31.6 mm**, which sets the 51 mm
cartridge length in `BUILD.md` §8. The WELL has to reach the read spot and sits
10.5 mm back from the tip, so 42.1 mm goes in and 8.9 mm stands proud to grip.
If you move the dish, re-derive the cartridge length from this number.

## The sensor port

The dish floor is an annulus. `PORT_D` 9.8 opens through it to the optical
chamber, and the Ø10 × 0.5 ring window that `BOM.csv` buys sits in a
Ø10.2 × 0.6 rebate under the ring's inner lip, flush with the floor. Four
objects carry it: `recess_floor_etch` (the annulus), `ring_window`,
`port_sleeve` and `port_floor`. The numbers come from `tools/gen_enclosure.py`,
which owns the inside. This file's job is only to look like it.

## The deck's top face is 28.32

Not 28.0. `shell_skin` extrudes 27.5 → 28.0 with a 0.4 bevel, which is thicker
than half the slab, so `ExtrudeGeometry` clamps the depth and the chamfer adds
its full thickness on top. The deck finishes at 28.32. That is where the
envelope's 28.32 comes from, and what `gen_enclosure.py` pins `ENV_Z` to.

Anything that sits ON the deck has to be placed against 28.32. Four things were
placed against 28.0 instead and spent a long time invisible inside the shell:
the pad marking, the display bezel, the CONFIRM collar and the edge break. They
are coplanar with the deck now, and depth-offset instead of floated, because
lifting them even a hundredth would raise the envelope that
`gen_enclosure.check_viewer_envelope()` compares against the printed shells.
