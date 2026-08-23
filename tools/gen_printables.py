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
# gen_enclosure imports `validate` from this module lazily, inside generate(),
# so importing it here is not circular. The bezel has to know the window and
# post positions it is filling, and those are that file's constants.
import gen_enclosure as enc

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
BAY_W, BAY_H = 72.0, 16.0                     # compute bay, rear face
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

# --- DERIVED: the display bezel --------------------------------------------
# The enclosure window is 49.7 x 37.7 (BUILD.md section 10, carried from the
# viewer model). No 1.3 in module is that big, so the window is masked by a
# printed frame rather than left as a hole with a small screen behind it.
#
# MEASURE THE MODULE YOU ACTUALLY BOUGHT. These defaults are for a 1.3 in
# 240x240 ST7789 breakout of the Adafruit 4313 class; boards from other
# vendors put the active area in a different place on the PCB, and the four
# posts in the shell are on a 25.0 x 30.0 grid that not every board matches.
# All three numbers below are constants for exactly that reason.
SCREEN_W, SCREEN_H = 23.4, 23.4    # active area of a 1.3 in 240x240 panel
SCREEN_OFFSET_Y = 0.0              # active-area centre vs. window centre, +Y front
BEZEL_CLEAR = 0.3                  # plate vs. window opening, total
BEZEL_CB_D, BEZEL_CB_DEPTH = 5.0, 1.4   # clears the module's mounting screw heads

# --- consumable planning ----------------------------------------------------
PETG_DENSITY = 1.27e-3     # g/mm3
CART_BATCH = 20            # BUILD.md section 15, milestone 3: print 20, measure them
PREFLIGHT_CARTS = 2        # REFERENCE + NULL

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


def bay_blank():
    """Closes the rear compute bay after provisioning.

    The bay is how the Pi and its microSD are reached during a build. Left
    open it is also how an attacker reaches them without disturbing the
    optical chamber, which is the one thing the chamber binding cannot
    survive -- pull the card, alter the firmware, put it back, and the
    diffuser never moved. See BUILD.md section 16.

    A plate and a lip, not a lid: it is meant to be bonded or sealed over,
    and taken off only by someone who accepts that re-enrolment follows.
    Sized from BAY_W/BAY_H so it cannot drift from the opening it closes.
    """
    clear = 0.3                       # total, so it drops in rather than presses
    w, h, t = BAY_W - clear, BAY_H - clear, 2.0
    lip = 1.6                         # sits proud of the wall, gives a bond area
    tris = stl.box(-w / 2, 0.0, -h / 2, w / 2, t, h / 2)
    tris += stl.box(-(w / 2 + lip), t, -(h / 2 + lip),
                    w / 2 + lip, t + 1.2, h / 2 + lip)
    return tris


def display_bezel():
    """Frame that fills the 49.7 x 37.7 window down to the module's active area.

    DERIVED, and the one part you should check against your own hardware
    before printing -- see the constants above. It drops into the window from
    outside and sits flush with the deck: the opening is CEIL deep and the
    plate is CEIL thick, resting on the ledge `gen_enclosure` puts under it.
    The module hangs below on the four posts, screwed down into their pilots
    from above, so the plate is counterbored over those screw heads.
    """
    t = enc.CEIL
    w = enc.DISPLAY_W - BEZEL_CLEAR
    h = enc.DISPLAY_H - BEZEL_CLEAR
    # Post positions are absolute in the enclosure frame; the plate is built
    # about its own centre, which is the window centre.
    posts = [(px - enc.DISPLAY_X, py - enc.DISPLAY_Y) for px, py in enc.DISPLAY_POST]

    def f(p_):
        x, y, z = p_
        d = stl.sd_box(p_, (0, 0, t / 2), (w / 2, h / 2, t / 2))
        aperture = stl.sd_box(p_, (0, SCREEN_OFFSET_Y, t / 2),
                              (SCREEN_W / 2, SCREEN_H / 2, t))
        d = max(d, -aperture)
        for px, py in posts:
            cb = stl.sd_cyl_axis(p_, (px, py, -1.0), (px, py, BEZEL_CB_DEPTH),
                                 BEZEL_CB_D / 2)
            d = max(d, -cb)
        return d

    return stl.sdf_mesh(f, ((-w / 2 - 1, -h / 2 - 1, -1),
                            (w / 2 + 1, h / 2 + 1, t + 1)), 0.3)


PARTS = [
    ("cartridge", cartridge, "PETG white, 0.15 mm, 3 perim, 100%, ironing ON"),
    ("cartridge_reference", cartridge, "as cartridge; seal a known target in the well"),
    ("cartridge_null", cartridge_null, "as cartridge; no well, leave bare"),
    ("aperture_tube", aperture_tube, "PETG black, 0.12 mm, 4 perim, 100%, bore matte black"),
    ("optical_head", optical_head, "PETG black, 0.12 mm, 6 perim, 40%, interior matte black"),
    ("slot_baffle", slot_baffle, "PETG black, 0.16 mm, 4 perim, 40%"),
    ("display_bezel", display_bezel,
     "PETG black, 0.12 mm, 4 perim, 100%; masks the window to your screen"),
    ("bay_blank", bay_blank,
     "PETG black, 0.16 mm, 4 perim, 40%; fit AFTER provisioning, then seal"),
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
    # Recomputed from the primitives rather than read off the module-level
    # constants, so a test can break one input and see the check bite -- and
    # so the two can never disagree without this saying so.
    insert_white = PATCH_FROM_TIP + TRAVEL
    insert_depth = WELL_FROM_TIP + TRAVEL
    grip_proud = CART_L - insert_depth

    fails = []
    if PATCH_FROM_TIP + PATCH / 2 >= WELL_FROM_TIP - MOAT_D / 2:
        fails.append("the patch overlaps the moat — no clean white surface")
    if PATCH_FROM_TIP - PATCH / 2 <= 0.5:
        fails.append("the patch runs off the tip")
    if insert_white >= insert_depth:
        fails.append("stop 1 is not ahead of stop 2 — the patch is never read first")
    if DETENT_PROUD >= SLOT_H - CART_T:
        fails.append("the detent is taller than the slot clearance — it will jam")
    if insert_white - DETENT_L / 2 <= WELL_FROM_TIP + WINDOW_L / 2:
        fails.append("the detent sits under the PET window")
    if grip_proud < 6.0:
        fails.append(f"only {grip_proud:.1f} mm of cartridge left to hold")
    if fails:
        raise SystemExit("cartridge geometry:\n  " + "\n  ".join(fails))
    return (f"cartridge: patch at {PATCH_FROM_TIP:.1f}, well at "
            f"{WELL_FROM_TIP:.1f}, stops at {insert_white:.1f} and "
            f"{insert_depth:.1f} mm, {grip_proud:.1f} mm grip")


def check_bezel_geometry():
    """The bezel is the only part fitted to a component nobody has specified.

    BUILD.md buys "ST7789 1.3in 240x240" and the window follows the viewer
    model at 49.7 x 37.7. Those two do not determine each other, so every way
    the frame can be wrong is checked here rather than discovered on the bed.
    """
    fails = []
    w = enc.DISPLAY_W - BEZEL_CLEAR
    h = enc.DISPLAY_H - BEZEL_CLEAR
    posts = [(px - enc.DISPLAY_X, py - enc.DISPLAY_Y) for px, py in enc.DISPLAY_POST]
    if SCREEN_W >= w or SCREEN_H >= h:
        fails.append("the active area is bigger than the window -- no frame left")
    for px, py in posts:
        if abs(px) + BEZEL_CB_D / 2 > w / 2 or abs(py) + BEZEL_CB_D / 2 > h / 2:
            fails.append(f"the counterbore at ({px:.1f}, {py:.1f}) runs off the plate")
        if (abs(px) - BEZEL_CB_D / 2 < SCREEN_W / 2
                and abs(py - SCREEN_OFFSET_Y) - BEZEL_CB_D / 2 < SCREEN_H / 2):
            fails.append(f"the counterbore at ({px:.1f}, {py:.1f}) breaks into the aperture")
    if BEZEL_CB_DEPTH >= enc.CEIL:
        fails.append("the counterbore is as deep as the plate is thick")
    frame = min((w - SCREEN_W) / 2, (h - SCREEN_H) / 2)
    if frame < 2.0:
        fails.append(f"only {frame:.1f} mm of frame -- too thin to print flat")
    if fails:
        raise SystemExit("display bezel:\n  " + "\n  ".join(fails))
    return (f"bezel: {w:.1f} x {h:.1f} plate, {SCREEN_W:.1f} x {SCREEN_H:.1f} "
            f"aperture, {frame:.1f} mm narrowest frame")


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
    print(check_bezel_geometry())
    print(check_filament_budget(rows))
    _manifest(rows)

def _bom_filament():
    """Grams of each filament BOM.csv buys, keyed black/white."""
    import csv
    import re
    budget = {}
    with open(os.path.join(ROOT, "BOM.csv"), encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            m = re.match(r"PETG (black|white) ~(\d+)\s*g", row["Part / Spec"])
            if m:
                budget[m.group(1)] = float(m.group(2))
    if set(budget) != {"black", "white"}:
        raise SystemExit("BOM.csv: cannot find both PETG filament rows")
    return budget


def check_filament_budget(rows):
    """The BOM has to buy enough filament to print what BUILD.md asks for.

    Milestone 3 of the build order is a batch of CART_BATCH cartridges measured
    against each other, plus the sealed REFERENCE and NULL pair. That is a real
    quantity of white PETG, and it is set by geometry that moves -- the 51 mm
    cartridge is a third heavier than the 45 mm one it replaced. So the spool
    sizes in BOM.csv are checked against the meshes rather than remembered.
    """
    vols = {name: vol for name, _, vol, _ in rows}
    budget = _bom_filament()

    black = sum(vols[k] for k in
                ("shell_lower", "shell_upper", "optical_head", "aperture_tube",
                 "slot_baffle", "display_bezel")) * PETG_DENSITY
    white = vols["cartridge"] * (CART_BATCH + PREFLIGHT_CARTS) * PETG_DENSITY

    fails = []
    for kind, need, have in (("black", black, budget["black"]),
                             ("white", white, budget["white"])):
        if need > have:
            fails.append(f"{kind}: {need:.0f} g of parts against {have:.0f} g "
                         f"bought in BOM.csv")
    if fails:
        raise SystemExit("filament budget:\n  " + "\n  ".join(fails))
    return (f"filament: {black:.0f} g black of {budget['black']:.0f} bought, "
            f"{white:.0f} g white of {budget['white']:.0f} for "
            f"{CART_BATCH + PREFLIGHT_CARTS} cartridges")


def _rewrap(text, width=78):
    """Re-flow prose to `width` after interpolation.

    The manifest body is written as a wrapped f-string, and substituting a
    number for a placeholder leaves the wrapping wrong -- short lines where a
    long expression was, long ones where a short value landed. Headings,
    tables and code stay untouched; paragraphs and list items are re-flowed.
    """
    import textwrap
    # Never split a hyphenated token or a long identifier: `pre-flight` and
    # `tools/gen_printables.py` have to survive the wrap intact.
    opts = dict(break_on_hyphens=False, break_long_words=False)
    out, para, bullet = [], [], None

    def flush():
        if not para:
            return
        joined = " ".join(" ".join(para).split())
        if bullet is None:
            out.extend(textwrap.wrap(joined, width, **opts) or [""])
        else:
            out.extend(textwrap.wrap(joined, width, initial_indent=bullet,
                                     subsequent_indent=" " * len(bullet),
                                     **opts))
        para.clear()

    for line in text.split("\n"):
        stripped = line.strip()
        if (not stripped or stripped.startswith(("#", "|", "```", "    "))):
            flush()
            bullet = None
            out.append(line)
            continue
        if stripped.startswith("* "):
            flush()
            bullet = "* "
            para.append(stripped[2:])
            continue
        para.append(stripped)
    flush()
    return "\n".join(out)


def _manifest(rows):
    """Write MANIFEST.md.

    Every number below is interpolated from the constants this file and
    `gen_enclosure` actually generated from, or measured off the meshes just
    written. Nothing here is typed twice: a prose manifest that restates the
    dimensions goes stale the first time a constant moves, which is exactly
    how this file came to describe a 45 mm cartridge that no longer existed.
    """
    vols = {name: vol for name, _, vol, _ in rows}
    PETG = PETG_DENSITY
    budget = _bom_filament()
    black = sum(vols[k] for k in
                ("shell_lower", "shell_upper", "optical_head", "aperture_tube",
                 "slot_baffle", "display_bezel"))
    shells = vols["shell_lower"] + vols["shell_upper"]
    cart = vols["cartridge"]
    bezel_w = enc.DISPLAY_W - BEZEL_CLEAR
    bezel_h = enc.DISPLAY_H - BEZEL_CLEAR
    frame = min((bezel_w - SCREEN_W) / 2, (bezel_h - SCREEN_H) / 2)
    moat_from_tip = WELL_FROM_TIP - MOAT_D / 2

    p = os.path.join(OUT, "MANIFEST.md")
    with open(p, "w") as fh:
        fh.write("# Printed parts\n\n")
        fh.write("Generated by `tools/gen_printables.py`, which builds the "
                 "internal and consumable parts itself and calls "
                 "`tools/gen_enclosure.py` for the two shells. Every number "
                 "in this file is interpolated from the constants the STLs "
                 "were generated from. Do not hand-edit either -- "
                 "regenerate.\n\n")
        fh.write("| Part | Triangles | Shell volume | Print settings |\n|---|---|---|---|\n")
        for name, n, vol, note in rows:
            fh.write("| `%s.stl` | %d | %.1f mm3 | %s |\n" % (name, n, vol, note))

        fh.write(_rewrap(f"""
## How many of each

One of everything, except:

* **cartridges -- print a plate of them.** They are consumed one per reading
  and they are biohazard afterwards. BUILD.md's build order asks for 20 up
  front, measured against each other, before you trust any of them.
* **`cartridge_reference` and `cartridge_null` -- one each, then seal them.**
  These are the pre-flight pair. REFERENCE takes a known target in the well
  and must pass the spectral gates while failing the liveness gate, because it
  cannot move; NULL has no well at all and must fail gate 1 on the bright
  side. Print them from the same spool, in the same session, as the batch they
  are the reference for.
* **`window_jig` -- one, and it is not part of the instrument.** It is the
  cutting template for the {WINDOW_L:.0f} x {WINDOW_W:.0f} mm PET windows.

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

Watertight is not the same as buildable. Every generation run probes the ways
this instrument can be wrong without looking wrong.

The enclosure, in `gen_enclosure.check_fit()`:

* the cartridge path, across the full width and thickness of the cartridge,
  from the front face to the read spot;
* every vent, which must still have material behind it;
* the Pi bay, sampled at 1 mm through the corridor a {enc.PI_W:.0f} x 30 board
  sweeps plus its headroom;
* the sensor port, across the {APERTURE_BORE:.0f} mm spot the aperture tube
  defines;
* the part line, where no point may be solid in both shells at once.

The cartridge, in `check_cartridge_geometry()` -- the six distances the
two-stop read needs to hold at once: patch clear of the moat, patch on the
part, stop 1 ahead of stop 2, detent shorter than the slot clearance, detent
clear of the PET window, and enough grip left to pull the thing out.

The bezel, in `check_bezel_geometry()`: aperture inside the window, screw
counterbores on the plate and out of the aperture, counterbore shallower than
the plate, and frame wide enough to print flat.

A check that has never failed is a check nobody knows works, so
`tools/test_printables.py` drives the cartridge, bezel and filament guards
past their own limits and requires each one to raise; CI runs it. The
enclosure's `check_fit()` samples a distance field over the whole body and is
too slow to break repeatedly, so it runs on every generation instead. Real
conflicts found this way and fixed in the geometry: two insert bosses standing
inside the Pi's footprint, a dish recess as deep as the ceiling it was cut into
(so the dish opened straight through to the interior), vent pockets deeper than
the wall is thick, and a white patch with no optical path to it.

## Mesh accuracy

`cartridge`, `cartridge_null` and `aperture_tube` are analytic: circles are
192- and 96-gon approximations, everything else is exact.

`optical_head`, `slot_baffle`, `display_bezel` and `window_jig` are isosurfaced
at a 0.35, 0.3, 0.3 and 0.25 mm grid respectively, because their bores enter
walls at an angle and that needs real CSG. Expect edges rounded by roughly half
the grid pitch. That is under the print's own tolerance for a clearance bore,
but do not take a critical dimension off those meshes -- take it from the
constants at the top of `tools/gen_printables.py`.

Every part is checked before it is written: each shell closed, consistently
wound, positive in volume. The generator exits non-zero rather than emit a
mesh that fails. Shell volumes in the table above are summed per shell, so the
cartridge's figure double-counts where the stop rib is sunk into the slab.

## Orientation

Cartridge: well-side up, on the bed, no supports. The well floor and the white
patch must both be top surfaces or ironing does nothing for them.

Aperture tube: flange down. The flange seats on top of the optical head and
the barrel drops through the {APERTURE_BORE + 3.0:.0f} mm bore, so the tube
hangs at the standoff rather than being glued at it.

Optical head: open face down on the bed, no supports. Every bore is
{min(LED_ANGLE, LASER_ANGLE, 90 - LED_ANGLE):.0f} deg or more off horizontal
and self-supports.

Display bezel: front face down, no supports. The counterbores open upward and
the aperture is a through-cut, so nothing overhangs.

Shells: part line down -- the tongue on the lower shell and the groove in the
upper both print as top features that way, and neither needs support.

## Dimensions taken from BUILD.md

Cartridge {CART_L:.0f} x {CART_W:.0f} x {CART_T}; well {WELL_D} dia x
{WELL_DEPTH}; moat {MOAT_D} dia x {MOAT_DEPTH}; patch {PATCH:.0f} x {PATCH:.0f};
window {WINDOW_L:.0f} x {WINDOW_W:.0f} x 0.1 PET; travel {TRAVEL}; aperture
{APERTURE_BORE} dia x {APERTURE_LEN}; sensor standoff {SENSOR_STANDOFF};
LEDs {LED_ANGLE:.0f} deg at {LED_RADIUS} mm; laser {LASER_ANGLE:.0f} deg;
camera {CAMERA_STANDOFF:.0f} mm lensless; slot {SLOT_W} x {SLOT_H}; baffle
offset {BAFFLE_OFFSET}.

## Derived here, not in BUILD.md -- review before printing

* **Well centre {WELL_FROM_TIP} mm from the tip**, moat outer wall at
  {moat_from_tip:.1f}, so a {PATCH:.0f} mm patch centred at {PATCH_FROM_TIP}
  fits ahead of it. Features nearer the tip cross the read spot first, which is
  what makes the patch readable before the sample rather than after it.
* **Two stops, {INSERT_WHITE:.1f} and {INSERT_DEPTH:.1f} mm of insertion.**
  Stop 1 puts the patch under the aperture, stop 2 puts the well there. The
  first is a detent ridge {DETENT_PROUD} proud and {DETENT_L} along, into
  {SLOT_H - CART_T:.1f} mm of slot clearance -- a tactile stop that a
  deliberate push rides over, not a lock. The second is the grip shoulder,
  {GRIP_T} thick against the {SLOT_H} slot.
* **{GRIP_PROUD:.1f} mm of cartridge proud of the slot** at stop 2, which is
  what you have to pull a blood-contact part back out with.
* **Bore diameters** {LED_BORE} ({LED_BORE - 0.4:.0f} mm LED), {LASER_BORE}
  ({LASER_BORE - 0.4:.0f} mm laser), {CAMERA_BORE} (camera).
* **Optical head block** {HEAD_DIA:.0f} mm dia x {SENSOR_STANDOFF + 3.0:.0f}
  mm, {WALL} wall. Fits the {enc.DISH_R * 2:.1f} dish. The angles and standoffs
  are BUILD.md's; the block carrying them is not.
* **Display bezel {bezel_w:.1f} x {bezel_h:.1f} x {enc.CEIL}**, aperture
  {SCREEN_W} x {SCREEN_H}, {frame:.1f} mm narrowest frame, with
  {BEZEL_CB_D} x {BEZEL_CB_DEPTH} counterbores over the module's screw heads.
  **This is the part fitted to hardware nobody specified** -- see below.

## The bezel is fitted to your screen, not to a standard

BUILD.md buys an "ST7789 1.3in 240x240" and the enclosure window follows the
viewer model at {enc.DISPLAY_W} x {enc.DISPLAY_H}. No 1.3 in module is that
big, so the window is masked by this frame rather than left as a hole with a
small screen rattling behind it.

The defaults are for an Adafruit 4313-class breakout. Boards from other
vendors put the active area somewhere else on the PCB, and the four posts in
the shell are on a {abs(enc.DISPLAY_POST[1][0] - enc.DISPLAY_POST[0][0]):.0f} x
{abs(enc.DISPLAY_POST[2][1] - enc.DISPLAY_POST[0][1]):.0f} mm grid that not
every board matches. **Measure the module in your hand**, set `SCREEN_W`,
`SCREEN_H` and `SCREEN_OFFSET_Y` at the top of `tools/gen_printables.py`, and
regenerate. `check_bezel_geometry()` will refuse anything that cannot be
printed or cannot fit. If your board's mounting holes do not land on the post
grid, move `DISPLAY_POST` in `tools/gen_enclosure.py` and regenerate both --
the posts are derived, not specified.

Print the bezel last, once the screen is in front of you.

## Derived for the enclosure -- review before printing

BUILD.md section 10 dimensions the outside. Everything structural is
`tools/gen_enclosure.py`'s invention, and all of it is a constant at the top of
that file:

* **{enc.WALL} wall, {enc.FLOOR} floor and {enc.CEIL} ceiling**; a
  {enc.LIP_W} x {enc.LIP_H} tongue on the lower shell into a groove in the
  upper, 0.15 clearance.
* **{len(enc.BOSSES)} M2.5 insert bosses**, Ø{enc.BOSS_OD:.0f} outer,
  Ø{enc.INSERT_D} x {enc.INSERT_DEPTH:.0f} insert hole, with Ø{enc.SCREW_CLEAR}
  clearance and a Ø{enc.SCREW_HEAD} head counterbore in the upper shell.
  {len(enc.BOSSES)} plus the {len(enc.FASTENER_X)} front fasteners is the
  {len(enc.BOSSES) + len(enc.FASTENER_X)} the BOM buys.
* **Pi rails at {enc.PI_RAIL_Z}**, a {enc.PI_SLOT} slot {enc.PI_DEPTH:.0f} mm
  deep, entered through the rear bay. The board cannot sit on the cartridge
  plane at {enc.SLOT_Z} -- that is inside the optical chamber -- so it lives
  under the skirt with {enc.PI_HEADROOM} mm of headroom.
* **Optical chamber skirt**, Ø{enc.CHAMBER_R * 2:.0f} x {enc.WALL} wall,
  hanging {enc.CHAMBER_DROP:.0f} mm off the deck underside, slotted where the
  cartridge crosses it.
* **Vents cut {enc.VENT_DEPTH} deep, not 3.0.** Section 10's figure was safe in
  a solid body and is {3.0 - enc.WALL:.1f} mm past the inside face of a
  {enc.WALL} mm wall. Blind is the point: one through-hole and the 415 nm gate
  stops working.
* **Display ledge and four posts**, Ø4 with a Ø1.8 pilot, masked by the bezel
  above.

## Filament

About {shells / 1000:.0f} cm3 of black PETG for the two shells and
{(black - shells) / 1000:.0f} cm3 for the optical parts and bezel -- near
enough {black * PETG:.0f} g, against the {budget['black']:.0f} g the BOM
budgets. A cartridge is {cart / 1000:.1f} cm3, or {cart * PETG:.1f} g, so the
{CART_BATCH} of them the build order wants plus the {PREFLIGHT_CARTS}
pre-flight bodies is {cart * PETG * (CART_BATCH + PREFLIGHT_CARTS):.0f} g of
the {budget['white']:.0f} g white spool.

`check_filament_budget()` compares both figures against `BOM.csv` on every
run, so a heavier part cannot quietly outgrow the spool the BOM buys.

Those are solid volumes. Real filament use runs under them wherever infill is
below 100% -- the shells are the bulk of it and print at 25% -- so treat the
figure as the ceiling, not the estimate.
"""))


if __name__ == "__main__":
    main()
