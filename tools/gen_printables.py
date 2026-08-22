#!/usr/bin/env python3
"""Generate every printable part CELL needs, as STL, from the BUILD.md numbers.

    python3 tools/gen_printables.py           # -> models/print/*.stl + MANIFEST.md

The enclosure shells are NOT generated here -- they come out of the parametric
viewer (`tools/export_model.py`), which stays the single source for anything
with an outside surface. This file covers the parts that live inside the
instrument or get consumed by it, and whose dimensions BUILD.md fixes:

    cartridge            BUILD.md section 8
    cartridge_reference  section 8 / BOM (pre-flight REFERENCE)
    cartridge_null       section 8 / BOM (pre-flight NULL)
    aperture_tube        section 9
    optical_head         section 9  -- DERIVED, see MANIFEST
    slot_baffle          section 9
    window_jig           section 8 (cutting aid, not part of the instrument)

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
CART_L, CART_W, CART_T = 45.0, 14.0, 2.4      # 45 x 14 x 2.4 mm
WELL_D, WELL_DEPTH = 4.0, 0.55                # 4.0 dia, 0.55 deep, ~7 uL
MOAT_D, MOAT_DEPTH = 7.0, 0.40                # 7.0 annulus, 0.4 deep
PATCH = 4.0                                   # white reference patch, 4 x 4
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
WELL_FROM_TIP = 6.0        # tip clearance ahead of the moat outer wall
GRIP_T = 3.6               # > SLOT_H, so the shoulder is the insertion stop
LED_BORE = 5.4             # 5 mm LED slip fit
LASER_BORE = 6.4           # 6 mm laser module slip fit
CAMERA_BORE = 8.0          # lensless CSI module clear aperture
HEAD_DIA = 46.0            # fits the 47.2 sample dish
WALL = 2.4                 # 6 perimeters at 0.4, per the print table

INSERT_DEPTH = WELL_FROM_TIP + TRAVEL          # 37.6 mm
GRIP_PROUD = CART_L - INSERT_DEPTH             # 7.4 mm at the specified length


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
    tris += stl.box(INSERT_DEPTH - 2.0, 0, 0, CART_L, CART_W, GRIP_T)
    return tris


def cartridge():
    return _cartridge_body(with_pocket=True)


def cartridge_null():
    """Pre-flight NULL: no well. Must fail gate 1 on the bright side."""
    return _cartridge_body(with_pocket=False)


def aperture_tube():
    """3 mm bore, 6 mm long, with a seating flange. Paint the bore matte black."""
    tris = stl.tube(0, 0, 0, APERTURE_LEN, APERTURE_BORE / 2 + 1.5,
                    APERTURE_BORE / 2)
    tris += stl.tube(0, 0, 0, 1.0, APERTURE_BORE / 2 + 3.5,
                     APERTURE_BORE / 2 + 1.5)
    return tris


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
                            (w / 2 + 1, t / 2 + 1, h + 1)), 0.4)


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
        """A bore aimed at the origin, arriving `angle_deg` off vertical."""
        a = math.radians(angle_deg)
        az = math.radians(azimuth_deg)
        d = (math.sin(a) * math.cos(az), math.sin(a) * math.sin(az), math.cos(a))
        start = [d[i] * radius / max(math.sin(a), 1e-6) if i < 2 else 0
                 for i in range(3)]
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

    return stl.sdf_mesh(f, ((-R - 1, -R - 1, -1), (R + 1, R + 1, top + 1)), 0.5)


PARTS = [
    ("cartridge", cartridge, "PETG white, 0.15 mm, 3 perim, 100%, ironing ON"),
    ("cartridge_reference", cartridge, "as cartridge; seal a known target in the well"),
    ("cartridge_null", cartridge_null, "as cartridge; no well, leave bare"),
    ("aperture_tube", aperture_tube, "PETG black, 0.12 mm, 4 perim, 100%, bore matte black"),
    ("optical_head", optical_head, "PETG black, 0.12 mm, 6 perim, 40%, interior matte black"),
    ("slot_baffle", slot_baffle, "PETG black, 0.16 mm, 4 perim, 40%"),
    ("window_jig", window_jig, "any filament; not a device part"),
]


def main():
    os.makedirs(OUT, exist_ok=True)
    rows = []
    for name, fn, note in PARTS:
        tris = fn()
        path = os.path.join(OUT, name + ".stl")
        stl.write_stl(path, tris, header=("cell " + name).encode())
        rows.append((name, len(tris), os.path.getsize(path), note))
        print("%-20s %7d tris  %8.1f kB" % (name, len(tris),
                                            os.path.getsize(path) / 1024))
    _manifest(rows)


def _manifest(rows):
    p = os.path.join(OUT, "MANIFEST.md")
    with open(p, "w") as fh:
        fh.write("# Printed parts\n\n")
        fh.write("Generated by `tools/gen_printables.py`. Do not hand-edit the "
                 "STLs -- regenerate.\n\nThe enclosure shells are not here: "
                 "they come from `tools/export_model.py`, which stays the "
                 "single source for anything with an outside surface.\n\n")
        fh.write("| Part | Triangles | Print settings |\n|---|---|---|\n")
        for name, n, _sz, note in rows:
            fh.write("| `%s.stl` | %d | %s |\n" % (name, n, note))
        fh.write("""
## Orientation

Cartridge: well-side up, on the bed, no supports. The well floor and the white
patch must both be top surfaces or ironing does nothing for them.

Aperture tube and optical head: bore axis vertical, no supports. The 45 deg
and 30 deg bores self-support at those angles; the camera bore at 20 deg off
vertical does not need support either.

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
