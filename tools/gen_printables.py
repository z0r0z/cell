#!/usr/bin/env python3
"""Generate every printable part CELL needs, as STL, from the BUILD.md numbers.

    python3 tools/gen_printables.py           # -> models/print/*.stl + MANIFEST.md

This file covers the parts that live inside the instrument or get consumed by
it, and calls `tools/gen_enclosure.py` for the two shells, so one command
produces everything printable:

    cartridge            BUILD.md section 8
    cartridge_reference  section 8 / BOM (pre-flight REFERENCE)
    cartridge_null       section 8 / BOM (pre-flight NULL)
    aperture_tube        section 9
    optical_head         section 9  -- DERIVED, see MANIFEST
    slot_baffle          section 9
    window_jig           section 8 (cutting aid, not part of the instrument)
    shell_lower/upper    section 10, via tools/gen_enclosure.py

Every dimension that BUILD.md states appears below as a named constant. Every
dimension it does not state is marked DERIVED in the manifest.
"""

import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import stl

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "models", "print")

# --- BUILD.md section 8, the cartridge -------------------------------------
CART_L, CART_W, CART_T = 51.0, 14.0, 2.4      # 51 x 14 x 2.4 mm
WELL_D, WELL_DEPTH = 4.0, 0.55                # 4.0 dia, 0.55 deep, ~7 uL
MOAT_D, MOAT_DEPTH = 7.0, 0.40                # 7.0 annulus, 0.4 deep
PATCH = 4.0                                   # white reference patch, 4 x 4
PATCH_FROM_TIP = 3.0                          # patch centre, ahead of the moat
DETENT_PROUD = 0.35                           # first-stop bump, rides over on a push
DETENT_L = 1.2                                # along the cartridge
WINDOW_L, WINDOW_W = 12.0, 10.0               # PET window blank
TRAVEL = 31.6                                 # front face to read spot

# --- BUILD.md section 9, the optical head ----------------------------------
APERTURE_BORE, APERTURE_LEN = 3.0, 6.0        # 3 dia x 6 long
SENSOR_STANDOFF = 9.0                         # AS7341 above the sample
LED_ANGLE, LED_RADIUS = 45.0, 12.0            # 45 deg, 12 mm from spot centre
LASER_ANGLE = 30.0                            # 30 deg off normal
CAMERA_STANDOFF = 20.0                        # lensless, ~20 mm from spot
SLOT_W, SLOT_H = 34.0, 3.0                    # front slot, 34.0 x 3.0
BAFFLE_OFFSET = 6.0                           # baffle 6 mm behind the flap

# --- DERIVED: nothing in BUILD.md fixes these ------------------------------
# The well sits far enough back that a 4 x 4 patch fits AHEAD of the moat.
# That ordering is what makes the two-stop read possible: features nearer the
# tip cross the read spot first, so the patch is read before the sample rather
# than after it. At 6.0 the moat outer wall was 2.5 mm from the tip and there
# was nowhere to put the patch — which is why nothing could read it.
WELL_FROM_TIP = 10.5       # well centre; moat spans 7.0-14.0 from the tip
GRIP_T = 3.6               # > SLOT_H, so the shoulder is the insertion stop
LED_BORE = 5.4             # 5 mm LED slip fit
LASER_BORE = 6.4           # 6 mm laser module slip fit
CAMERA_BORE = 8.0          # lensless CSI module clear aperture
HEAD_DIA = 46.0            # fits the 47.2 sample dish
WALL = 2.4                 # 6 perimeters at 0.4, per the print table

# Two stops. Push to the first, the patch is under the aperture and the device
# reads white and dark; push past the detent to the second and the well is
# under the aperture for the sample and the 600 s speckle series.
INSERT_WHITE = PATCH_FROM_TIP + TRAVEL         # 34.6 mm — stop 1, the patch
INSERT_DEPTH = WELL_FROM_TIP + TRAVEL          # 42.1 mm — stop 2, the well
GRIP_PROUD = CART_L - INSERT_DEPTH             # 8.9 mm at the specified length


def _cartridge_body(with_pocket=True):
    """Slab, plus the raised grip that stops insertion at the read spot.

    The grip is a separate overlapping solid. Slicers union coincident solids;
    keeping it separate means the pocket mesh stays a single clean shell.
    """
    pocket = None
    if with_pocket:
        pocket = dict(cx=WELL_FROM_TIP, cy=CART_W / 2,
                      r_well=WELL_D / 2, d_well=WELL_DEPTH,
                      r_moat=MOAT_D / 2, d_moat=MOAT_DEPTH)
    tris = stl.slab_with_pocket(0, 0, CART_L, CART_W, CART_T, pocket)
    # Stop rib: its leading face at INSERT_DEPTH lands the well on the read
    # spot. Inset from every edge and sunk 1 mm into the slab, so the two
    # solids overlap in volume without sharing a face -- coincident faces are
    # what makes a slicer guess.
    tris += stl.box(INSERT_DEPTH, 1.0, 1.0, CART_L - 2.0, CART_W - 1.0, GRIP_T)
    # First-stop detent: a low ridge that meets the slot lip when the patch is
    # under the aperture. It is proud by less than the slot clearance, so a
    # deliberate push rides over it to the second stop; it is a tactile stop,
    # not a lock. Sunk into the slab so the two solids overlap in volume rather
    # than sharing a face.
    tris += stl.box(INSERT_WHITE - DETENT_L / 2, 3.0, CART_T - 0.4,
                    INSERT_WHITE + DETENT_L / 2, CART_W - 3.0,
                    CART_T + DETENT_PROUD)
    return tris


def cartridge():
    return _cartridge_body(with_pocket=True)


def cartridge_null():
    """Pre-flight NULL: no well. Must fail gate 1 on the bright side."""
    return _cartridge_body(with_pocket=False)


def aperture_tube():
    """3 mm bore, 6 mm long, with a seating flange. Paint the bore matte black."""
    return stl.tube(0, 0, 0, APERTURE_LEN, APERTURE_BORE / 2 + 1.5,
                    APERTURE_BORE / 2, flange_r=APERTURE_BORE / 2 + 3.5,
                    flange_h=1.0)


def slot_baffle():
    """Light trap behind the cartridge flap: a slot offset from the outer one,
    so no straight optical path reaches the chamber."""
    w, h, t = SLOT_W + 8.0, SLOT_H + 10.0, 2.0
    tris = stl.box(-w / 2, -t / 2, 0, w / 2, t / 2, h)
    # the pass-through, dropped below the outer slot centreline by BAFFLE_OFFSET
    def f(p):
        solid = stl.sd_box(p, (0, 0, h / 2), (w / 2, t / 2, h / 2))
        cut = stl.sd_box(p, (0, 0, h / 2 - BAFFLE_OFFSET / 2),
                         (SLOT_W / 2, t, SLOT_H / 2))
        return max(solid, -cut)
    return stl.sdf_mesh(f, ((-w / 2 - 1, -t / 2 - 1, -1),
                            (w / 2 + 1, t / 2 + 1, h + 1)), 0.3)


def window_jig():
    """Cutting jig for the 12 x 10 mm PET windows. Not part of the instrument."""
    t, wall = 3.0, 3.0
    w, l = WINDOW_W + 2 * wall, WINDOW_L + 2 * wall

    def f(p):
        solid = stl.sd_box(p, (0, 0, t / 2), (l / 2, w / 2, t / 2))
        slot = stl.sd_box(p, (0, 0, t / 2), (WINDOW_L / 2, WINDOW_W / 2, t))
        return max(solid, -slot)
    return stl.sdf_mesh(f, ((-l, -w, -1), (l, w, t + 1)), 0.25)


def optical_head():
    """Bracket carrying the aperture tube, two 45 deg white LEDs, the 940 nm
    LED co-sited with LED #1, the 650 nm laser at 30 deg, and the lensless
    camera. Origin at the sample spot, +Z up toward the sensor.

    DERIVED. BUILD.md fixes the angles, standoffs and radii below; the block
    that carries them is this file's invention. Check it against your own
    breakout footprints before printing.
    """
    top = SENSOR_STANDOFF + 3.0
    R = HEAD_DIA / 2

    def bore_from(angle_deg, azimuth_deg, radius, dia, length=60.0):
        """A bore aimed at the sample spot, arriving `angle_deg` off vertical.

        `radius` is documentation only -- the component's stated distance from
        the spot. The bore itself runs the full block, so the part sits at
        whatever standoff its own footprint allows.
        """
        a = math.radians(angle_deg)
        az = math.radians(azimuth_deg)
        d = (math.sin(a) * math.cos(az), math.sin(a) * math.sin(az), math.cos(a))
        entry = (d[0] * length, d[1] * length, d[2] * length)
        return lambda p: stl.sd_capsule_axis(p, (0, 0, 0), entry, dia / 2)

    aperture = lambda p: stl.sd_cyl_axis(p, (0, 0, -1), (0, 0, top + 1),
                                         APERTURE_BORE / 2 + 1.5)
    led_a = bore_from(LED_ANGLE, 0, LED_RADIUS, LED_BORE)
    led_b = bore_from(LED_ANGLE, 180, LED_RADIUS, LED_BORE)
    ir = bore_from(LED_ANGLE, 22, LED_RADIUS, LED_BORE)     # co-sited with #1
    laser = bore_from(LASER_ANGLE, 90, LED_RADIUS, LASER_BORE)
    camera = bore_from(20.0, 250, CAMERA_STANDOFF, CAMERA_BORE)

    def f(p):
        x, y, z = p
        r = math.hypot(x, y)
        body = max(r - R, abs(z - top / 2) - top / 2)
        # hollow the chamber, leaving WALL all round and a floor open to the dish
        cavity = max(r - (R - WALL), abs(z - (top - WALL) / 2) - (top - WALL) / 2)
        d = max(body, -cavity)
        for cut in (aperture, led_a, led_b, ir, laser, camera):
            d = max(d, -cut(p))
        return d

    return stl.sdf_mesh(f, ((-R - 2, -R - 2, -2), (R + 2, R + 2, top + 2)), 0.35)


PARTS = [
    ("cartridge", cartridge, "PETG white, 0.15 mm, 3 perim, 100%, ironing ON"),
    ("cartridge_reference", cartridge, "as cartridge; seal a known target in the well"),
    ("cartridge_null", cartridge_null, "as cartridge; no well, leave bare"),
    ("aperture_tube", aperture_tube, "PETG black, 0.12 mm, 4 perim, 100%, bore matte black"),
    ("optical_head", optical_head, "PETG black, 0.12 mm, 6 perim, 40%, interior matte black"),
    ("slot_baffle", slot_baffle, "PETG black, 0.16 mm, 4 perim, 40%"),
    ("window_jig", window_jig, "any filament; not a device part"),
]


def validate(name, tris):
    """Every shell closed, consistently wound, and positive in volume.

    Checked per connected component, because a part may legitimately be more
    than one shell -- the cartridge is a slab plus a stop rib that overlap in
    volume, which a slicer unions. What is never legitimate is an open shell
    or an inverted one: the slicer will print it anyway and quietly invent
    whatever surface it thinks is missing.
    """
    import collections
    parent = {}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    for i, tri in enumerate(tris):
        parent.setdefault(i, i)
        for v in tri:
            parent.setdefault(v, v)
            union(i, v)

    shells = collections.defaultdict(list)
    for i, tri in enumerate(tris):
        shells[find(i)].append(tri)

    total = 0.0
    for shell in shells.values():
        edges = collections.Counter()
        vol = 0.0
        for a, b, c in shell:
            for u, v in ((a, b), (b, c), (c, a)):
                edges[(u, v) if u < v else (v, u)] += 1
            vol += (a[0] * (b[1] * c[2] - b[2] * c[1])
                    - a[1] * (b[0] * c[2] - b[2] * c[0])
                    + a[2] * (b[0] * c[1] - b[1] * c[0])) / 6.0
        bad = sum(1 for n in edges.values() if n != 2)
        if bad:
            raise SystemExit("%s: shell with %d non-manifold edges" % (name, bad))
        if vol <= 0:
            raise SystemExit("%s: shell volume %.1f -- normals inverted"
                             % (name, vol))
        total += vol
    return total


def check_cartridge_geometry():
    """The two-stop read is a set of distances that must all hold at once.

    Every one of these was violated by the 45 mm single-stop cartridge, which
    is how it shipped with a white patch that no optical path could reach. They
    are checked here so the same thing cannot happen quietly again.
    """
    fails = []
    if PATCH_FROM_TIP + PATCH / 2 >= WELL_FROM_TIP - MOAT_D / 2:
        fails.append("the patch overlaps the moat — no clean white surface")
    if PATCH_FROM_TIP - PATCH / 2 <= 0.5:
        fails.append("the patch runs off the tip")
    if INSERT_WHITE >= INSERT_DEPTH:
        fails.append("stop 1 is not ahead of stop 2 — the patch is never read first")
    if DETENT_PROUD >= SLOT_H - CART_T:
        fails.append("the detent is taller than the slot clearance — it will jam")
    if INSERT_WHITE - DETENT_L / 2 <= WELL_FROM_TIP + WINDOW_L / 2:
        fails.append("the detent sits under the PET window")
    if GRIP_PROUD < 6.0:
        fails.append(f"only {GRIP_PROUD:.1f} mm of cartridge left to hold")
    if fails:
        raise SystemExit("cartridge geometry:\n  " + "\n  ".join(fails))
    return (f"cartridge: patch at {PATCH_FROM_TIP:.1f}, well at "
            f"{WELL_FROM_TIP:.1f}, stops at {INSERT_WHITE:.1f} and "
            f"{INSERT_DEPTH:.1f} mm, {GRIP_PROUD:.1f} mm grip")


def main():
    os.makedirs(OUT, exist_ok=True)
    rows = []
    for name, fn, note in PARTS:
        tris = fn()
        vol = validate(name, tris)
        path = os.path.join(OUT, name + ".stl")
        stl.write_stl(path, tris, header=("cell " + name).encode())
        rows.append((name, len(tris), vol, note))
        print("%-20s %7d tris  %9.1f mm3  %8.1f kB"
              % (name, len(tris), vol, os.path.getsize(path) / 1024))
    import gen_enclosure
    rows += gen_enclosure.generate()
    print(check_cartridge_geometry())
    _manifest(rows)


def _manifest(rows):
    p = os.path.join(OUT, "MANIFEST.md")
    with open(p, "w") as fh:
        fh.write("# Printed parts\n\n")
        fh.write("Generated by `tools/gen_printables.py`, which builds the "
                 "internal and consumable parts itself and calls "
                 "`tools/gen_enclosure.py` for the two shells. Do not "
                 "hand-edit the STLs -- regenerate.\n\n")
        fh.write("| Part | Triangles | Shell volume | Print settings |\n|---|---|---|---|\n")
        for name, n, vol, note in rows:
            fh.write("| `%s.stl` | %d | %.1f mm3 | %s |\n" % (name, n, vol, note))
        fh.write("""
## Two sources, one instrument

`viewer/model.js` owns the instrument's OUTSIDE: it is what the turntable
renders and what `gen_mechanical.py` measures. It is an appearance model --
solid extrusions, with the openings drawn as dark boxes rather than cut out of
anything. Slicing it gives you a brick.

`tools/gen_enclosure.py` owns the INSIDE: wall, part line, tongue and groove,
real openings, insert bosses, the rails the Pi slides in on, and the
light-tight skirt around the optical chamber.

Two parametric sources is the drift `models/README.md` warns about, so the
seam between them is checked rather than trusted. `check_envelope()` fails the
build if the assembled shells stop matching the documented envelope, and
`check_fit()` fails it if the inside stops being assemblable -- see below.

## What the fit checks cover

Watertight is not the same as buildable. Every generation run probes the five
ways this enclosure can be wrong without looking wrong:

* the cartridge path, across the full width and thickness of the cartridge,
  from the front face to the read spot;
* every vent, which must still have material behind it;
* the Pi bay, sampled at 1 mm through the corridor a 65 x 30 board sweeps
  plus its headroom;
* the sensor port, across the 3 mm spot the aperture tube defines;
* the part line, where no point may be solid in both shells at once.

Each check is tested against a deliberate break, so it is known to bite. Three
real conflicts were found this way and are fixed in the geometry: two insert
bosses standing inside the Pi's footprint, a dish recess as deep as the
ceiling it was cut into (so the dish opened straight through to the interior),
and vent pockets deeper than the wall is thick.

## Mesh accuracy

`cartridge`, `cartridge_null` and `aperture_tube` are analytic: circles are
192- and 96-gon approximations, everything else is exact.

`optical_head`, `slot_baffle` and `window_jig` are isosurfaced at a 0.35, 0.3
and 0.25 mm grid respectively, because their bores enter walls at an angle and
that needs real CSG. Expect edges rounded by roughly half the grid pitch. That
is under the print's own tolerance for a clearance bore, but do not take a
critical dimension off those three meshes -- take it from the constants at the
top of `tools/gen_printables.py`.

Every part is checked before it is written: each shell closed, consistently
wound, positive in volume. The generator exits non-zero rather than emit a
mesh that fails. Shell volumes in the table above are summed per shell, so the
cartridge's figure double-counts where the stop rib is sunk into the slab.

## Orientation

Cartridge: well-side up, on the bed, no supports. The well floor and the white
patch must both be top surfaces or ironing does nothing for them.

Aperture tube: flange down. The flange seats on top of the optical head and
the barrel drops through the 6 mm bore, so the tube hangs at the standoff
rather than being glued at it.

Optical head: open face down on the bed, no supports. Every bore is 30 deg or
more off horizontal and self-supports.

## Dimensions taken from BUILD.md

Cartridge 45 x 14 x 2.4; well 4.0 dia x 0.55; moat 7.0 dia x 0.4; patch 4 x 4;
window 12 x 10 x 0.1 PET; travel 31.6; aperture 3.0 dia x 6.0; sensor standoff
9.0; LEDs 45 deg at 12 mm; laser 30 deg; camera 20 mm lensless; slot 34.0 x
3.0; baffle offset 6.0.

## Derived here, not in BUILD.md -- review before printing

* **Well position, 6.0 mm from the tip.** See the length note below.
* **Grip shoulder 3.6 mm thick** at 37.6 mm from the tip, stepping over the
  3.0 mm slot so the shoulder is the insertion stop.
* **Bore diameters** 5.4 (5 mm LED), 6.4 (6 mm laser), 8.0 (camera).
* **Optical head block** 46 mm dia x 12 mm, 2.4 wall. Fits the 47.2 dish. The
  angles and standoffs are BUILD.md's; the block carrying them is not.

## Derived for the enclosure -- review before printing

BUILD.md section 10 dimensions the outside. Everything structural is this
generator's invention, and all of it is a constant at the top of
`tools/gen_enclosure.py`:

* **2.4 wall, 2.0 floor and ceiling**; a 1.2 x 2.0 tongue on the lower shell
  into a groove in the upper, 0.15 clearance.
* **Six M2.5 insert bosses**, Ø6 outer, Ø3.6 x 6 insert hole, with Ø2.8
  clearance and a Ø4.8 head counterbore in the upper shell. Six plus the two
  front fasteners is the eight the BOM buys.
* **Pi rails at 7.0**, a 1.8 slot 30 mm deep, entered through the rear bay.
  The board cannot sit on the cartridge plane at 14.9 -- that is inside the
  optical chamber -- so it lives under the skirt with 4.8 mm of headroom.
* **Optical chamber skirt**, Ø50 x 2.4 wall, hanging 12 mm off the deck
  underside, slotted where the cartridge crosses it.
* **Vents cut 1.6 deep, not 3.0.** Section 10's figure was safe in a solid
  body and is 0.6 mm past the inside face of a 2.4 mm wall. Blind is the
  point: one through-hole and the 415 nm gate stops working.
* **Display ledge and four posts**, Ø4 with a Ø1.8 pilot. The window follows
  the model at 49.7 x 37.7, which is larger than a 1.3 in module -- fit a
  bezel or shrink the window to suit the screen you actually buy.

## Filament

About 55 cm3 of black PETG for the two shells and 8 cm3 for the optical parts
-- near enough 80 g, against the 90 g the BOM budgets. A cartridge is 1.6 cm3,
so the 30 g white spool is roughly fifteen of them.

## Length note -- a real conflict in section 8

Section 8 asks for three things that cannot all hold at 45 mm: the well over
the read spot at 31.6 mm depth, 13.4 mm of grip proud of the slot, and 45 mm
overall. The well needs its own clearance ahead of it -- 6.0 mm to the moat
outer wall -- so insertion depth is 37.6 mm and only **7.4 mm** stands proud.

These parts are generated at the specified 45 mm, giving 7.4 mm of grip. To
get the 13.4 mm section 8 intends, set `CART_L = 51.0` and regenerate; nothing
else changes. Decide before you print a batch, because the two are not
interchangeable in the slot.
""")


if __name__ == "__main__":
    main()
