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
# A detent has to INTERFERE to be felt. At 0.35 into 0.6 mm of slot clearance
# the ridge cleared the slot lip by 0.25 and touched nothing, so there was no
# first stop at all -- and the guard below asked for exactly that, testing
# that the ridge stayed UNDER the clearance rather than over it.
DETENT_PROUD = 0.80                           # first-stop bump, rides over on a push
DETENT_L = 1.2                                # along the cartridge
WINDOW_L, WINDOW_W = 12.0, 10.0               # PET window blank
# The window covers the well and its moat, and it is 12 long against a moat
# that is 7. Centred on the well its leading edge fell at 4.5, half a
# millimetre over the white patch -- film and adhesive across the corner of
# the one surface every gate is normalised against. Nothing checked it.
WINDOW_FROM_TIP = 11.5                        # window centre, clear of the patch
TRAVEL = 31.6                                 # front face to read spot

# --- BUILD.md section 9, the optical head ----------------------------------
APERTURE_BORE, APERTURE_LEN = 3.0, 6.0        # 3 dia x 6 long
SENSOR_STANDOFF = 9.0                         # AS7341 above the sample
LED_ANGLE, LED_RADIUS = 45.0, 12.0            # 45 deg, 12 mm from spot centre
LASER_ANGLE = 30.0                            # 30 deg off normal
CAMERA_STANDOFF = 20.0                        # lensless, ~20 mm from spot
# The camera's angle and the IR LED's azimuth are the two numbers here that
# nothing outside this file fixes. Every bore is aimed at the same sample
# spot, so near the spot they all merge -- which is fine, below the roof the
# head is one painted cavity. What is not fine is a pair that merges at the
# bottom of the roof and separates at the top: the wall between them then runs
# out to a knife edge, which is unprintable, and is also a surface the
# isosurfacer cannot close, so it surfaces as non-manifold edges rather than
# as anything a slicer would refuse. At 20 deg the camera did that against
# LED B, and at 22 deg the IR bore did it against the laser.
#
# check_head_geometry() requires every pair to be cleanly apart or cleanly
# merged across the whole roof, with BORE_MARGIN to spare on a grid of
# HEAD_PITCH. Moving an angle without re-running it will not produce a mesh.
CAMERA_ANGLE, CAMERA_AZIMUTH = 52.0, 250.0    # off vertical, and about Z
# 315, and not the 22 it was. "Co-sited with LED #1" is a description of a
# second emitter on the same 45 deg ring, not of a second bore sharing the
# first one's hole: at 22 deg the two openings overlapped by a quarter of a
# millimetre, which is a crease, not a bore. 315 puts it clear of LED #1, of
# the laser at 90 and of the camera at 250.
IR_AZIMUTH = 315.0                            # on the same ring as LED #1
BORE_MARGIN = 0.4                             # apart or merged, never tangent
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
APERTURE_TUBE_OD = APERTURE_BORE + 2.0        # 5.0 -- the tube's outside
APERTURE_FIT = 0.4         # bore over tube OD: the slip fit the LEDs already use
# The head lives INSIDE the optical chamber's skirt, so what it has to pass is
# the skirt's bore -- not the cosmetic Ø47.2 recess in the top face, which is
# where 46.0 came from. It was 0.8 mm too wide for a Ø45.2 bore and 3.5 mm
# taller than the chamber's own ceiling. Both numbers are taken from
# gen_enclosure now instead of being typed here.
HEAD_CLEAR = 0.8           # per side, head to skirt bore
HEAD_PITCH = 0.35          # isosurface grid; BORE_MARGIN is set against it
# 1.8, not the 2.4 the rest of the file uses. The head is a light shield, not
# a structural part, and the chamber leaves it only 8.22 mm of height: at 2.4
# the roof starts low enough that the 45 deg LED bores are still tangent to
# the aperture bore where they cross it. 1.8 is 4 perimeters at 0.45.
HEAD_WALL = 2.4
# What passes through the roof is the BEAM, not the module. At these angles a
# component 12 to 20 mm from the sample spot sits above an 8.2 mm block, so
# its body mounts on the head's top face and only its light has to get
# through. Boring the roof to the module's own diameter instead made every
# opening large enough to run into its neighbours, and the walls between them
# tapered to knife edges the isosurfacer could not close.
LED_BEAM = 3.4             # 5 mm LED's emitting window
# 4.9 so that the laser channel MERGES with the aperture bore across the
# whole roof instead of parting from it inside it. At 30 deg off vertical the
# two are 0.9 mm apart at the bottom of the roof and 0.3 mm apart at the top:
# a wall that feathers to nothing, which prints as a whisker. Merged, they are
# one opening, which is what they already were below the roof.
LASER_BEAM = 4.9           # 650 nm module's beam, merged with the aperture
CAMERA_BEAM = 5.0          # lensless sensor's view through a 2.4 mm roof
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
SCREEN_CLEAR = 0.4                 # aperture over the active area, total
# Two different minimums. FRAME is full-thickness material between the
# aperture and the plate edge. WEB is the material beside a counterbore, which
# still has BEZEL_CB_DEPTH of plate under it, so it can be thinner.
BEZEL_FRAME_MIN = 2.0
BEZEL_WEB_MIN = 0.8                # 2 extrusion widths at 0.4
# 4.4, not 5.0. A Ø5 counterbore centred 15.0 from the window centre leaves
# 0.60 mm of web between itself and a 23.8 mm aperture -- one and a half
# extrusion widths. 4.4 still clears an M2 pan head (3.8) by 0.3 a side.
BEZEL_CB_D, BEZEL_CB_DEPTH = 4.4, 1.4   # clears the module's mounting screw heads

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

# The cartridge's section is needed on both sides of the seam: gen_enclosure
# has to cut a slot the part fits through, and carries its own copy so that
# importing it here is not circular. This is where the two are held together.
assert (enc.CART_W, enc.CART_T) == (CART_W, CART_T), (
    "cartridge section disagrees: gen_printables %r, gen_enclosure %r"
    % ((CART_W, CART_T), (enc.CART_W, enc.CART_T)))

# --- DERIVED: the space the optical head actually has ----------------------
_STACK = enc.check_stack()
SAMPLE_PLANE = _STACK["sample_plane"]          # top face of a seated cartridge
HEAD_DIA = _STACK["chamber_bore"] - 2 * HEAD_CLEAR
HEAD_H = _STACK["chamber_ceiling"] - SAMPLE_PLANE - 0.3
# What is left between the top of the block and SENSOR_STANDOFF is the sensor
# breakout's own board: the block's top face is the mounting face, and the
# standoff is made up by the PCB the AS7341 already sits on. Checked rather
# than assumed, because HEAD_H is derived from the enclosure while the
# standoff is BUILD.md's, and nothing else stops the two drifting apart.
SENSOR_PCB = SENSOR_STANDOFF - HEAD_H


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
    return stl.tube(0, 0, 0, APERTURE_LEN, APERTURE_TUBE_OD / 2,
                    APERTURE_BORE / 2, flange_r=APERTURE_TUBE_OD / 2 + 2.0,
                    flange_h=1.0)


def slot_baffle():
    """Light trap behind the cartridge flap: a slot offset from the outer
    one, so no straight optical path reaches the chamber.

    The offset is LATERAL. A rigid 51 mm cartridge travels 31.6 mm through
    this part, so offsetting the opening across the cartridge's own 2.4 mm
    THICKNESS closes the path the cartridge needs. Dropped BAFFLE_OFFSET/2
    below the outer slot -- itself half the offset the constant, BUILD.md
    and the manifest all state -- the two openings had no overlap at all,
    and the baffle stood as a 2.0 mm wall across the slot. Offset across
    the WIDTH instead: the cartridge is 14 wide in a 34 wide slot, so the
    opening can move sideways and still pass the part, while a ray
    entering the outer slot at the far side lands on material here.
    """
    w, h, t = SLOT_W + 8.0, SLOT_H + 10.0, 2.0
    tris = stl.box(-w / 2, -t / 2, 0, w / 2, t / 2, h)
    ow = CART_W + 1.0            # passes the cartridge, not the whole slot
    def f(p):
        solid = stl.sd_box(p, (0, 0, h / 2), (w / 2, t / 2, h / 2))
        cut = stl.sd_box(p, (BAFFLE_OFFSET, 0, h / 2),
                         (ow / 2, t, SLOT_H / 2))
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
    top = HEAD_H
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
                                         (APERTURE_TUBE_OD + APERTURE_FIT) / 2)
    led_a = bore_from(LED_ANGLE, 0, LED_RADIUS, LED_BEAM)
    led_b = bore_from(LED_ANGLE, 180, LED_RADIUS, LED_BEAM)
    ir = bore_from(LED_ANGLE, IR_AZIMUTH, LED_RADIUS, LED_BEAM)     # co-sited with #1
    laser = bore_from(LASER_ANGLE, 90, LED_RADIUS, LASER_BEAM)
    camera = bore_from(CAMERA_ANGLE, CAMERA_AZIMUTH, CAMERA_STANDOFF, CAMERA_BEAM)

    def f(p):
        x, y, z = p
        r = math.hypot(x, y)
        body = max(r - R, abs(z - top / 2) - top / 2)
        # hollow the chamber, leaving WALL all round and a floor open to the dish
        cavity = max(r - (R - HEAD_WALL),
                     abs(z - (top - HEAD_WALL) / 2) - (top - HEAD_WALL) / 2)
        d = max(body, -cavity)
        for cut in (aperture, led_a, led_b, ir, laser, camera):
            d = max(d, -cut(p))
        return d

    return stl.sdf_mesh(f, ((-R - 2, -R - 2, -2), (R + 2, R + 2, top + 2)),
                        HEAD_PITCH)


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
    # The two solids OVERLAP by 0.8 rather than meeting at one coincident
    # face, which is the case _cartridge_body goes out of its way to avoid:
    # the slicer has to decide what a zero-thickness contact means, and
    # slicers decide differently. It is the PLATE that grows into the lip's
    # band, not the lip into the plate's -- the lip has the larger footprint,
    # so extending it downward would have wrapped a 0.8 mm ring of new
    # material all the way round and changed the part, not just how it is
    # built.
    tris = stl.box(-w / 2, 0.0, -h / 2, w / 2, t + 0.8, h / 2)
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
    # The window is a ROUNDED rectangle. A square-cornered plate 0.15 mm
    # smaller on every side still stands 0.285 mm proud of it at all four
    # corners, which is a bezel that does not go in. The plate is the
    # window's own profile offset inward, corner radius included.
    plate = enc.inset(enc.DISPLAY_W, enc.DISPLAY_H, enc.DISPLAY_R, BEZEL_CLEAR / 2)
    ap_w, ap_h = SCREEN_W + SCREEN_CLEAR, SCREEN_H + SCREEN_CLEAR
    # Post positions are absolute in the enclosure frame; the plate is built
    # about its own centre, which is the window centre.
    posts = [(px - enc.DISPLAY_X, py - enc.DISPLAY_Y) for px, py in enc.DISPLAY_POST]

    def f(p_):
        x, y, z = p_
        d = max(plate(x, y), abs(z - t / 2) - t / 2)
        aperture = stl.sd_box(p_, (0, SCREEN_OFFSET_Y, t / 2),
                              (ap_w / 2, ap_h / 2, t))
        d = max(d, -aperture)
        for px, py in posts:
            cb = stl.sd_cyl_axis(p_, (px, py, -1.0), (px, py, BEZEL_CB_DEPTH),
                                 BEZEL_CB_D / 2)
            d = max(d, -cb)
        return d

    return stl.sdf_mesh(f, ((-w / 2 - 1, -h / 2 - 1, -1),
                            (w / 2 + 1, h / 2 + 1, t + 1)), 0.3)


# name, builder, print note, and how many overlapping shells the part is
# ENTITLED to. That last column is not bookkeeping -- see validate().
PARTS = [
    ("cartridge", cartridge, "PETG white, 0.15 mm, 3 perim, 100%, ironing ON", 3),
    ("cartridge_reference", cartridge, "as cartridge; seal a known target in the well", 3),
    ("cartridge_null", cartridge_null, "as cartridge; no well, leave bare", 3),
    ("aperture_tube", aperture_tube, "PETG black, 0.12 mm, 4 perim, 100%, bore matte black", 1),
    ("optical_head", optical_head, "PETG black, 0.12 mm, 6 perim, 40%, interior matte black", 1),
    ("slot_baffle", slot_baffle, "PETG black, 0.16 mm, 4 perim, 40%", 1),
    ("display_bezel", display_bezel,
     "PETG black, 0.12 mm, 4 perim, 100%; masks the window to your screen", 1),
    ("bay_blank", bay_blank,
     "PETG black, 0.16 mm, 4 perim, 40%; fit AFTER provisioning, then seal", 2),
    ("window_jig", window_jig, "any filament; not a device part", 1),
]


def validate(name, tris, shells=1):
    """Every shell closed, consistently wound, and positive in volume.

    Checked per connected component, because a part may legitimately be more
    than one shell -- the cartridge is a slab plus a stop rib that overlap in
    volume, which a slicer unions. What is never legitimate is an open shell
    or an inverted one: the slicer will print it anyway and quietly invent
    whatever surface it thinks is missing.

    `shells` is how many components the part is ENTITLED to. A component that
    turns up undeclared is a piece of the part that touches nothing else, and
    it prints as a loose object on the bed. The upper shell shipped with four:
    the display posts hung inside the window opening with the ceiling cut away
    above them and a ledge that stopped 1.85 mm short, so they came out as
    four detached pins.

    Winding is counted on DIRECTED edges. Counting undirected ones -- which is
    what this did -- proves only that the mesh is closed: flip one triangle
    and all three of its undirected counts stay at 2. An inverted patch passed
    a function whose docstring promised to catch exactly that.
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

    parts = collections.defaultdict(list)
    for i, tri in enumerate(tris):
        parts[find(i)].append(tri)

    if len(parts) != shells:
        raise SystemExit(
            "%s: %d separate shells, expected %d -- an undeclared shell is a "
            "piece of the part that touches nothing and prints loose"
            % (name, len(parts), shells))

    total = 0.0
    boxes = []
    for shell in parts.values():
        undirected = collections.Counter()
        directed = collections.Counter()
        vol = 0.0
        for a, b, c in shell:
            for u, v in ((a, b), (b, c), (c, a)):
                undirected[(u, v) if u < v else (v, u)] += 1
                directed[(u, v)] += 1
            vol += (a[0] * (b[1] * c[2] - b[2] * c[1])
                    - a[1] * (b[0] * c[2] - b[2] * c[0])
                    + a[2] * (b[0] * c[1] - b[1] * c[0])) / 6.0
        bad = sum(1 for n in undirected.values() if n != 2)
        if bad:
            raise SystemExit("%s: shell with %d non-manifold edges" % (name, bad))
        flipped = sum(1 for n in directed.values() if n != 1)
        if flipped:
            raise SystemExit("%s: %d edges traversed twice the same way -- a "
                             "patch of this shell is wound inside out"
                             % (name, flipped))
        if vol <= 0:
            raise SystemExit("%s: shell volume %.1f -- normals inverted"
                             % (name, vol))
        total += vol
        lo = [min(v[k] for t in shell for v in t) for k in range(3)]
        hi = [max(v[k] for t in shell for v in t) for k in range(3)]
        boxes.append((vol, lo, hi))
    return total - _union_correction(boxes)


def _union_correction(boxes):
    """How much the per-shell sum double-counts where shells interpenetrate.

    A part is allowed to be several overlapping solids -- the cartridge is a
    slab with a grip rib and a detent sunk into it, and a slicer unions them.
    Summing their volumes counts the sunk part twice, which inflated the
    cartridge by 6.7% and the bay blank by 22%, and both figures feed the
    filament the BOM has to buy. The overlaps here are all axis-aligned boxes,
    so their intersection is exact.
    """
    corr = 0.0
    for i in range(len(boxes)):
        for j in range(i + 1, len(boxes)):
            (_, alo, ahi), (_, blo, bhi) = boxes[i], boxes[j]
            v = 1.0
            for k in range(3):
                v *= max(0.0, min(ahi[k], bhi[k]) - max(alo[k], blo[k]))
            corr += v
    return corr


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
    # A detent that clears the slot lip is not a detent. This asked for the
    # ridge to stay UNDER the clearance, which is the condition for it never
    # being felt -- so stop 1, the reading every gate is normalised against,
    # had no tactile marker at all. It has to interfere, and then not by so
    # much that a deliberate push cannot ride over it.
    slot_clear = SLOT_H - CART_T
    if DETENT_PROUD <= slot_clear:
        fails.append(f"the detent stands {DETENT_PROUD:.2f} into "
                     f"{slot_clear:.2f} mm of clearance — it never reaches the "
                     f"slot lip, so there is no first stop")
    if DETENT_PROUD >= slot_clear + 0.6:
        fails.append("the detent is too proud to ride over — it is a lock")
    if insert_white - DETENT_L / 2 <= WINDOW_FROM_TIP + WINDOW_L / 2:
        fails.append("the detent sits under the PET window")
    # The window is taped over the well and the patch sits ahead of it.
    # Nothing checked that the two did not overlap, and they did, by 0.5 mm:
    # film and adhesive across the corner of the white reference.
    if PATCH_FROM_TIP + PATCH / 2 >= WINDOW_FROM_TIP - WINDOW_L / 2:
        fails.append("the PET window overlaps the white patch")
    if (WINDOW_FROM_TIP - WINDOW_L / 2 > WELL_FROM_TIP - MOAT_D / 2
            or WINDOW_FROM_TIP + WINDOW_L / 2 < WELL_FROM_TIP + MOAT_D / 2):
        fails.append("the PET window does not cover the moat")
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
    ap_w, ap_h = SCREEN_W + SCREEN_CLEAR, SCREEN_H + SCREEN_CLEAR
    plate = enc.inset(enc.DISPLAY_W, enc.DISPLAY_H, enc.DISPLAY_R,
                      BEZEL_CLEAR / 2)
    if SCREEN_CLEAR <= 0:
        fails.append("the aperture is cut to the active area with no allowance")
    if ap_w >= w or ap_h >= h:
        fails.append("the active area is bigger than the window -- no frame left")
    for px, py in posts:
        if abs(px) + BEZEL_CB_D / 2 > w / 2 or abs(py) + BEZEL_CB_D / 2 > h / 2:
            fails.append(f"the counterbore at ({px:.1f}, {py:.1f}) runs off the plate")
        if (abs(px) - BEZEL_CB_D / 2 < ap_w / 2
                and abs(py - SCREEN_OFFSET_Y) - BEZEL_CB_D / 2 < ap_h / 2):
            fails.append(f"the counterbore at ({px:.1f}, {py:.1f}) breaks into the aperture")
    if BEZEL_CB_DEPTH >= enc.CEIL:
        fails.append("the counterbore is as deep as the plate is thick")

    # The plate has to fit the window's CORNERS, which have a radius. A square
    # plate 0.15 mm smaller on every side still stood 0.285 mm inside the
    # ceiling at all four of them, passed every check above, and could not be
    # pressed in. Swept over the plate's footprint rather than along rays from
    # its centre -- a ray sweep steps past a corner between samples, and a
    # corner is the only place this goes wrong -- and swept WIDER than the
    # window, because a sweep bounded by the window only looks where the plate
    # is bound to be innocent.
    window = enc.rrect(enc.DISPLAY_W, enc.DISPLAY_H, enc.DISPLAY_R)
    worst, worst_at = -1e9, (0.0, 0.0)
    ext_w, ext_h = enc.DISPLAY_W + 8.0, enc.DISPLAY_H + 8.0
    nx, ny = int(ext_w / 0.1) + 1, int(ext_h / 0.1) + 1
    for i in range(nx + 1):
        px = -ext_w / 2 + i * ext_w / nx
        for j in range(ny + 1):
            py = -ext_h / 2 + j * ext_h / ny
            if plate(px, py) > 0:
                continue                    # no plate material here
            v = window(px, py)
            if v > worst:
                worst, worst_at = v, (px, py)
    if worst > -BEZEL_CLEAR / 4:
        fails.append(
            f"the plate at ({worst_at[0]:+.2f}, {worst_at[1]:+.2f}) is "
            f"{worst:+.3f} mm into the ceiling, against {BEZEL_CLEAR / 2:.3f} "
            f"mm of designed clearance. A square plate does not fit a hole "
            f"with {enc.DISPLAY_R} mm corners -- follow the window's own "
            f"profile")

    # The narrowest web is not (plate - aperture)/2. Four Ø5 counterbores sit
    # inside that frame, and the real minimum runs between a counterbore and
    # the aperture, or between a counterbore and the plate edge: 0.90 mm,
    # where this reported 7.0 and called it comfortable.
    frame = min((w - ap_w) / 2, (h - ap_h) / 2)
    if frame < BEZEL_FRAME_MIN:
        fails.append(f"only {frame:.2f} mm of frame -- too thin to print flat")
    web = frame
    for px, py in posts:
        to_aperture = max(abs(px) - ap_w / 2,
                          abs(py - SCREEN_OFFSET_Y) - ap_h / 2)
        to_edge = min(w / 2 - abs(px), h / 2 - abs(py))
        web = min(web, to_aperture - BEZEL_CB_D / 2, to_edge - BEZEL_CB_D / 2)
    if web < BEZEL_WEB_MIN:
        fails.append(f"only {web:.2f} mm of web beside a counterbore -- under "
                     f"{BEZEL_WEB_MIN} it is too thin to print")

    # And it has to land on something. The ledge is gen_enclosure's and the
    # plate is this file's, so the bearing between them is checked here.
    bearing = (w - (enc.DISPLAY_W - 2 * enc.DISPLAY_LEDGE_W)) / 2
    if bearing < 1.0:
        fails.append(f"the bezel has {bearing:.2f} mm of ledge to rest on -- "
                     f"it drops through the window into the case")
    if fails:
        raise SystemExit("display bezel:\n  " + "\n  ".join(fails))
    return (f"bezel: {w:.1f} x {h:.1f} plate, {ap_w:.1f} x {ap_h:.1f} "
            f"aperture, {frame:.1f} mm frame, {web:.2f} mm web, "
            f"{bearing:.1f} mm bearing")


def _head_bores():
    """(name, angle off vertical, azimuth, radius) for every bore in the head."""
    return [("aperture", 0.0, 0.0, (APERTURE_TUBE_OD + APERTURE_FIT) / 2),
            ("led A", LED_ANGLE, 0.0, LED_BEAM / 2),
            ("led B", LED_ANGLE, 180.0, LED_BEAM / 2),
            ("ir", LED_ANGLE, IR_AZIMUTH, LED_BEAM / 2),
            ("laser", LASER_ANGLE, 90.0, LASER_BEAM / 2),
            ("camera", CAMERA_ANGLE, CAMERA_AZIMUTH, CAMERA_BEAM / 2)]


def _bore_dir(b):
    a, az = math.radians(b[1]), math.radians(b[2])
    return (math.sin(a) * math.cos(az), math.sin(a) * math.sin(az), math.cos(a))


def _bore_depth(b, x, y, z):
    """Signed distance from (x, y, z) to the bore's surface. Negative inside.

    The distance to a TILTED cylinder is not the distance to where its axis
    crosses this height. Treating it that way -- which is the obvious thing,
    and what the first version of this check did -- models a slanted bore as a
    circle when its cross-section at constant z is an ellipse, semi-major
    r/cos(angle). At 52 degrees that understates the camera bore's footprint
    by 62%, so the check reported walls that were not there.
    """
    d = _bore_dir(b)
    k = x * d[0] + y * d[1] + z * d[2]
    return math.hypot(x - k * d[0], y - k * d[1], z - k * d[2]) - b[3]


def _bore_rim(b, z, n=48):
    """n points around the bore's true cross-section at height z."""
    d = _bore_dir(b)
    cx, cy = z * d[0] / d[2], z * d[1] / d[2]
    pts = []
    for i in range(n):
        th = 2 * math.pi * i / n
        ux, uy = math.cos(th), math.sin(th)
        lo, hi = 0.0, 60.0
        for _ in range(40):
            mid = (lo + hi) / 2
            if _bore_depth(b, cx + ux * mid, cy + uy * mid, z) < 0:
                lo = mid
            else:
                hi = mid
        pts.append((cx + ux * lo, cy + uy * lo))
    return pts


def _flange_seat(bores):
    """Fraction of the aperture tube's flange annulus that lands on material."""
    r_in = (APERTURE_TUBE_OD + APERTURE_FIT) / 2
    r_out = APERTURE_TUBE_OD / 2 + 2.0
    z, ok, tot = HEAD_H, 0, 0
    for i in range(360):
        th = 2 * math.pi * i / 360
        for k in range(12):
            r = r_in + (r_out - r_in) * (k + 0.5) / 12
            x, y = r * math.cos(th), r * math.sin(th)
            tot += 1
            for b in bores:
                if b[0] == "aperture":
                    continue
                if _bore_depth(b, x, y, z) < 0:
                    break
            else:
                ok += 1
    return ok / tot


def check_head_geometry():
    """The head has to fit the chamber, and its bores have to behave.

    Nothing checked either. The block was sized to the Ø47.2 cosmetic recess
    in the top face rather than to the Ø45.2 bore it actually passes through,
    and it stood 3.5 mm taller than the chamber ceiling.
    """
    fails = []
    bore = _STACK["chamber_bore"]
    if HEAD_DIA >= bore:
        fails.append(f"the head is {HEAD_DIA:.1f} across and the chamber bore "
                     f"is {bore:.1f} -- it will not go in")
    if HEAD_H <= 0 or HEAD_H + SAMPLE_PLANE > _STACK["chamber_ceiling"]:
        fails.append(f"the head stands {HEAD_H:.2f} above the sample plane at "
                     f"{SAMPLE_PLANE:.2f}, through a ceiling at "
                     f"{_STACK['chamber_ceiling']:.2f}")
    if not 0.6 <= SENSOR_PCB <= 2.0:
        fails.append(f"the block tops out {SENSOR_PCB:.2f} mm under the "
                     f"{SENSOR_STANDOFF:.1f} mm sensor standoff -- no breakout "
                     f"board makes up that gap")
    if HEAD_DIA - 2 * HEAD_WALL <= APERTURE_TUBE_OD + APERTURE_FIT:
        fails.append("the head has no cavity left around the aperture tube")

    # Across the ROOF -- the only part of the block with material between
    # bores -- every pair has to be unambiguously apart or unambiguously
    # merged. Below the roof they all converge on the sample spot and share
    # one painted cavity, which is the design. A pair that CHANGES state
    # inside the roof is the problem: the wall between them tapers to nothing,
    # which is unprintable, and is also a surface the isosurfacer cannot
    # close, so it surfaces as non-manifold edges instead of as a refusal.
    bores = _head_bores()
    z0, z1 = HEAD_H - HEAD_WALL, HEAD_H
    for i in range(len(bores)):
        for j in range(i + 1, len(bores)):
            a, b = bores[i], bores[j]
            states = set()
            for k in range(21):
                z = z0 + (z1 - z0) * k / 20.0
                gap = min(_bore_depth(b, x, y, z) for x, y in _bore_rim(a, z))
                states.add("apart" if gap > BORE_MARGIN else
                           "merged" if gap < -BORE_MARGIN else "tangent")
            if len(states) > 1 or "tangent" in states:
                fails.append("the %s and %s bores are tangent across the roof "
                             "(%s) -- the wall between them runs out to an edge"
                             % (a[0], b[0], "/".join(sorted(states))))

    # The aperture tube seats on the roof's top face. The laser arrives 30 deg
    # off vertical, which in a block this short keeps its bore alongside the
    # aperture's whatever else moves, so the seat is an arc and not a full
    # annulus. Measure it rather than assume it.
    seat = _flange_seat(bores)
    if seat < 0.70:
        fails.append(f"only {seat * 100:.0f}% of the aperture tube's flange "
                     f"seat is solid -- the tube tips in its bore")

    if fails:
        raise SystemExit("optical head:\n  " + "\n  ".join(fails))
    return (f"head: {HEAD_DIA:.1f} dia x {HEAD_H:.2f} in a {bore:.1f} bore, "
            f"{SENSOR_PCB:.2f} mm of board to the sensor plane, "
            f"{seat * 100:.0f}% of the flange seat solid")


def main():
    os.makedirs(OUT, exist_ok=True)
    rows = []
    for name, fn, note, shells in PARTS:
        tris = fn()
        vol = validate(name, tris, shells)
        path = os.path.join(OUT, name + ".stl")
        stl.write_stl(path, tris, header=("cell " + name).encode())
        rows.append((name, len(tris), vol, note))
        print("%-20s %7d tris  %9.1f mm3  %8.1f kB"
              % (name, len(tris), vol, os.path.getsize(path) / 1024))
    import gen_enclosure
    rows += gen_enclosure.generate()
    print(check_cartridge_geometry())
    print(check_head_geometry())
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

    # Derived from the spec column, not from a list kept by hand beside it.
    # The hand-kept list is how bay_blank -- 5 g of black PETG, spec'd "PETG
    # black" in the table above -- stayed out of the printed figure entirely.
    black = sum(vol for name, _, vol, note in rows
                if note.startswith("PETG black")) * PETG_DENSITY
    white = vols["cartridge"] * (CART_BATCH + PREFLIGHT_CARTS) * PETG_DENSITY
    if not black:
        raise SystemExit("filament budget: no part is spec'd PETG black")

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
    black = sum(vol for name, _, vol, note in rows
                if note.startswith("PETG black"))
    shells = vols["shell_lower"] + vols["shell_upper"]
    cart = vols["cartridge"]
    bezel_w = enc.DISPLAY_W - BEZEL_CLEAR
    bezel_h = enc.DISPLAY_H - BEZEL_CLEAR
    ap_w, ap_h = SCREEN_W + SCREEN_CLEAR, SCREEN_H + SCREEN_CLEAR
    frame = min((bezel_w - ap_w) / 2, (bezel_h - ap_h) / 2)
    web = frame
    for _px, _py in ((px - enc.DISPLAY_X, py - enc.DISPLAY_Y)
                     for px, py in enc.DISPLAY_POST):
        web = min(web,
                  max(abs(_px) - ap_w / 2,
                      abs(_py - SCREEN_OFFSET_Y) - ap_h / 2) - BEZEL_CB_D / 2,
                  min(bezel_w / 2 - abs(_px), bezel_h / 2 - abs(_py))
                  - BEZEL_CB_D / 2)
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
        fh.write("| Part | Triangles | Solid volume | Print settings |\n|---|---|---|---|\n")
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
at a {HEAD_PITCH}, 0.3, 0.3 and 0.25 mm grid respectively, because their bores
enter walls at an angle and that needs real CSG. Expect edges rounded by
roughly half the grid pitch. That is under the print's own tolerance for a
clearance bore, but do not take a critical dimension off those meshes -- take
it from the constants at the top of `tools/gen_printables.py`.

**Both shells are surface-netted at {enc.PITCH} mm**, the coarsest grid in the
set, on the two parts that carry the part line, the tongue and groove and the
insert bosses. No fit feature finer than that survives into the mesh, which is
worth knowing before you judge a {enc.PART_CLEAR} mm clearance by eye.

Every part is checked before it is written: each shell closed, consistently
wound the same way, positive in volume, and in no more separate pieces than it
is entitled to. Winding is counted on directed edges, which is what makes it a
real test -- an undirected count proves only closure, and passes a mesh with a
patch turned inside out. The generator exits non-zero rather than emit a mesh
that fails any of it. Volumes in the table above are SOLID volumes: where a
part is several overlapping shells the sum is corrected for what they share,
so the cartridge's figure no longer double-counts the stop rib sunk into its
slab, and the bay blank's no longer double-counts its lip.

## Orientation

Cartridge: well-side up, on the bed, no supports. The well floor and the white
patch must both be top surfaces or ironing does nothing for them.

Aperture tube: flange down. The flange seats on the optical head's roof and
the barrel drops through the {APERTURE_TUBE_OD + APERTURE_FIT:.1f} mm bore, so
the tube hangs at the standoff rather than being glued at it. The seat is an
arc, not a full ring -- the laser arrives close enough to vertical to cut into
it -- so bond the flange as well as seating it.

Optical head: open face UP on the bed, no supports. Face down, the chamber
roof is a {HEAD_DIA - 2 * HEAD_WALL:.0f} mm unsupported span printed in mid-air,
and it is the surface that carries the aperture tube and sets the sensor
standoff. Face up it is the first layer instead: a solid disc, which is also
far better adhesion than a {HEAD_WALL} mm ring. Every bore is
{90 - max(LED_ANGLE, LASER_ANGLE, CAMERA_ANGLE):.0f} deg or more off horizontal
and self-supports either way.

Slot baffle: flat on its largest face, no supports. On edge it is a
{SLOT_W + 8.0:.0f} x {SLOT_H + 10.0:.0f} wall {2.0} mm thick and wants a brim.

Display bezel: front face down, no supports. The counterbores open upward and
the aperture is a through-cut, so nothing overhangs.

Bay blank: lip down. The lip is {1.6} mm larger than the plate on all four
sides, so plate-down it is an unsupported ledge appearing in mid-air.

Window jig: either face down. It is a flat plate with a through slot.

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
* **Beam channels through the roof**, not module bores: {LED_BEAM} for each
  LED, {LASER_BEAM} for the laser, {CAMERA_BEAM} for the camera. At these
  angles a part {LED_RADIUS:.0f} to {CAMERA_STANDOFF:.0f} mm from the sample
  spot sits above a {HEAD_H:.1f} mm block, so its body mounts on the top face
  and only its light goes through. Bored to the modules' own
  {LED_BORE}/{LASER_BORE}/{CAMERA_BORE} the openings ran into each other and
  the walls between them feathered away to nothing.
* **The angled channels converge**, so below the roof they are one painted
  cavity -- that is the design. Across the roof each pair is held either
  clearly apart or clearly merged, never tangent, with {BORE_MARGIN} mm to
  spare. `check_head_geometry()` measures it on the true elliptical section a
  tilted bore actually cuts, which is what a slanted cylinder leaves at
  constant height, and not on the circle it is tempting to assume.
* **Optical head block** {HEAD_DIA:.1f} mm dia x {HEAD_H:.2f}
  mm, {HEAD_WALL} wall. It has to pass the optical chamber's
  Ø{_STACK['chamber_bore']:.1f} skirt bore and fit under a ceiling
  {_STACK['chamber_ceiling'] - SAMPLE_PLANE:.2f} mm above a seated cartridge --
  NOT the Ø{enc.DISH_R * 2:.1f} cosmetic recess in the top face, which is where
  the old 46 mm came from and is 0.8 mm too wide for the hole it has to enter.
  The angles and standoffs are BUILD.md's; the block carrying them is not.
* **Display bezel {bezel_w:.1f} x {bezel_h:.1f} x {enc.CEIL}**, aperture
  {ap_w} x {ap_h}, {frame:.1f} mm of frame and {web:.2f} mm of web beside a
  counterbore, with
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
  upper, {enc.PART_CLEAR} clearance on the sides as well as over the top, with
  a {enc.LIP_LEAD} lead-in so the joint starts itself.
* **{len(enc.BOSSES)} M2.5 fasteners, entering from the BASE.** The insert
  lives in the UPPER shell -- a Ø{enc.INSERT_D} x {enc.INSERT_DEPTH:.0f} hole
  in a pillar hanging from the deck underside to the part line -- and the
  screw passes through a Ø{enc.BOSS_OD:.0f} column in the lower shell on a
  Ø{enc.SCREW_CLEAR} clearance, its head sunk {enc.SCREW_CB_DEPTH} into the
  base. That is the only direction that works: the insert has to be in the
  half the screw does not pass through, and a screw entering the deck would
  span the whole interior and put {len(enc.BOSSES)} heads on the display face.
  M2.5 x {enc.SCREW_LEN:.0f}, and `check_fit()` proves the length reaches.
  The {len(enc.FASTENER_X)} front-face features are blind Ø{enc.FASTENER_D:.0f}
  x {enc.FASTENER_DEPTH} pockets and take no fastener: the pocket and anything
  that could be threaded behind it are both in the lower shell, so there is
  nothing there for a screw to clamp.
* **Pi rails at {enc.PI_RAIL_Z}**, a {enc.PI_SLOT} slot {enc.PI_DEPTH:.0f} mm
  deep, entered through the rear bay. The board cannot sit on the cartridge
  plane at {enc.SLOT_Z} -- that is inside the optical chamber -- so it lives
  under the skirt with {enc.PI_HEADROOM} mm of headroom above the board's top
  face. The groove is narrower than the rail and biased outboard, so the lip
  reaches {enc.PI_ENGAGE} mm over the board's edge; cut the full width of the
  rail, it reached nothing and the board fell out.
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
