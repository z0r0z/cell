#!/usr/bin/env python3
"""Generate the two printable enclosure shells.

    python3 tools/gen_enclosure.py      # -> models/print/shell_lower.stl, shell_upper.stl

WHY THIS IS NOT THE VIEWER
--------------------------
`viewer/model.js` is the source for the instrument's *outside*: the turntable
renders it and `tools/gen_mechanical.py` measures it. It is an appearance
model. Its shells are solid extrusions with no interior, and its openings --
`front_slot`, `rear_bay`, the vents, the USB port -- are separate boxes drawn
in a dark material rather than volume removed from the body. Slice it and you
get a 116 x 73 x 28 mm brick.

This file is the source for the *inside*: wall, part line, real openings,
board mounts, insert bosses, the light-tight optical chamber. The two frames
meet at the envelope and the feature positions, and `check_envelope()` below
fails if they drift.

FRAME
-----
X length, 0 at centre, right positive      -58.10 .. +58.10
Y depth,  0 at centre, +Y toward the FRONT  -36.60 .. +36.60
Z height, 0 at the base                       0.00 .. 28.32

models/README.md uses the same axes with height on Y and depth on Z, because
that is what three.js renders. Height is Z here so that the isosurfacer's
innermost loop runs up the extrusion axis, which is what makes a part this
size tractable in pure Python. `_TO_VIEWER` converts.

Positions carried over from viewer/model.js, whose comments use a left-edge
origin (x 0..115 across, y 0..72 back from the front face):

    X = x - 57.5        Y = 36 - y
"""

import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import stl

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "models", "print")

# --- envelope and part line, BUILD.md section 10 ---------------------------
ENV_X, ENV_Y, ENV_Z = 116.2, 73.2, 28.32
CORNER_R = 3.6
PART_LINE = 11.4                     # two shells parted at 11.4 from the base

# --- features, BUILD.md section 10, positions from viewer/model.js ---------
DISH_X, DISH_Y, DISH_R, DISH_DEPTH = 28.5, 5.0, 23.6, 2.0
PORT_D = 9.8                         # ring ID: the sensor port through the dish
RING_OD = 14.4
DISPLAY_X, DISPLAY_Y = -25.5, -7.0
DISPLAY_W, DISPLAY_H = 49.7, 37.7
BUTTON_Y = 23.0
BUTTONS = [(-44.5, 5.8), (-33.5, 5.8), (-22.5, 5.8), (-5.5, 8.6)]
SLOT_X, SLOT_W, SLOT_H = 28.5, 34.0, 3.0
SLOT_Z = 14.9                        # slot centre height
SLOT_DEPTH = 4.2
BAY_W, BAY_H, BAY_Z = 72.0, 16.0, 14.0
USB_W, USB_H, USB_Z = 9.0, 3.2, 14.0
VENT_N, VENT_W, VENT_H = 15, 0.6, 2.6
VENT_X0, VENT_PITCH, VENT_Z = -23.5, 1.6, 14.9
FASTENER_X, FASTENER_Z, FASTENER_D = (-45.5, 52.5), 5.6, 4.0

# --- DERIVED: the inside, which BUILD.md does not dimension ----------------
WALL = 2.4                  # 6 perimeters at 0.4
VENT_DEPTH = 1.6            # blind: shallower than the wall, see shell_upper
FLOOR = 2.0
CEIL = 2.0
LIP_W = 1.2                 # tongue on the lower shell, groove in the upper
LIP_H = 2.0
BOSS_OD, INSERT_D, INSERT_DEPTH = 6.0, 3.6, 6.0     # M2.5 heat-set insert
SCREW_CLEAR, SCREW_HEAD = 2.8, 4.8
# Six insert bosses, not eight. The two that would sit mid-span at the rear
# stood inside the Pi's 65 x 30 footprint -- the fit check catches it if they
# come back. The corner pair at the rear clears the board because the board is
# narrower than the body. Six here plus the two front fasteners is the eight
# the BOM buys.
BOSSES = [(-50, 30), (-20, 30), (20, 30), (50, 30), (-50, -30), (50, -30)]
CHAMBER_R = 25.0            # light-tight skirt around the dish
CHAMBER_DROP = 12.0
PI_W, PI_SLOT, PI_RAIL_Z = 65.0, 1.8, 7.0           # Pi Zero 2 W slides in
PI_DEPTH = 30.0
GLASS_D, GLASS_REBATE = 10.2, 0.6                   # the 10 mm ring window
PI_HEADROOM = 4.8           # tallest part on a Pi Zero, under the skirt at 12.3
DISPLAY_POST = [(-38, -22), (-13, -22), (-38, 8), (-13, 8)]
PITCH = 0.5

_TO_VIEWER = "X -> X, Y(depth) -> Z, Z(height) -> Y"


# --------------------------------------------------------------------------
# 2-D profiles. Every feature is a profile plus a height range, which is what
# lets one column of samples share its expensive part.
# --------------------------------------------------------------------------

def rrect(w, h, r, cx=0.0, cy=0.0):
    hw, hh = w / 2 - r, h / 2 - r
    def f(x, y):
        dx, dy = abs(x - cx) - hw, abs(y - cy) - hh
        return (math.hypot(max(dx, 0.0), max(dy, 0.0))
                + min(max(dx, dy), 0.0) - r)
    return f


def rect(w, h, cx=0.0, cy=0.0):
    return rrect(w, h, 0.0, cx, cy)


def circ(d, cx=0.0, cy=0.0):
    r = d / 2
    return lambda x, y: math.hypot(x - cx, y - cy) - r


def ring(d_out, d_in, cx=0.0, cy=0.0):
    o, i = circ(d_out, cx, cy), circ(d_in, cx, cy)
    return lambda x, y: max(o(x, y), -i(x, y))


def inset(w, h, r, d):
    """The envelope profile shrunk by d -- the inside of a wall d thick."""
    return rrect(w - 2 * d, h - 2 * d, max(r - d, 0.05), 0, 0)


OUTER = rrect(ENV_X, ENV_Y, CORNER_R)
INNER = inset(ENV_X, ENV_Y, CORNER_R, WALL)
LIP = inset(ENV_X, ENV_Y, CORNER_R, WALL - LIP_W)


# --------------------------------------------------------------------------
# assembling a shell from prisms
# --------------------------------------------------------------------------

class Shell:
    """An ORDERED list of prism operations, applied in sequence.

    Order is the whole point. An unordered union-then-subtract erases every
    internal feature the moment the cavity is cut, because a boss standing on
    the floor is inside the cavity by definition. So the cavity is subtracted
    first, and the bosses, rails, skirt and posts are added into the space it
    left.

    Evaluated column by column: for a given (x, y) most features are far
    enough away that they cannot change the sign anywhere in that column, and
    are dropped before the height loop runs. That is what makes a
    116 x 73 x 28 part mesh in seconds in pure Python.
    """

    NEAR = 3.0

    def __init__(self):
        self.ops = []
        self._key = None
        self._live = []

    def solid(self, prof, z0, z1):
        self.ops.append((True, prof, z0, z1))
        return self

    def hole(self, prof, z0, z1):
        self.ops.append((False, prof, z0, z1))
        return self

    def __call__(self, p):
        x, y, z = p
        if self._key != (x, y):
            self._key = (x, y)
            self._live = [(a, d, (z0 + z1) / 2, (z1 - z0) / 2)
                          for a, d, z0, z1 in
                          ((a, pr(x, y), z0, z1) for a, pr, z0, z1 in self.ops)
                          if d < self.NEAR]
        d = 1e9
        for add, d2, zc, zh in self._live:
            v = max(d2, abs(z - zc) - zh)
            d = min(d, v) if add else max(d, -v)
        return d


# --------------------------------------------------------------------------
# the two shells
# --------------------------------------------------------------------------

def shell_lower():
    """Base, wall, tongue, insert bosses. Takes the lower half of the rear
    bay and both front fasteners."""
    s = Shell()
    s.solid(OUTER, 0.0, PART_LINE)
    s.hole(INNER, FLOOR, PART_LINE + 1.0)                 # open at the top
    s.solid(lambda x, y: max(LIP(x, y), -INNER(x, y)),    # tongue
            PART_LINE, PART_LINE + LIP_H)

    for bx, by in BOSSES:
        s.solid(circ(BOSS_OD, bx, by), FLOOR - 0.6, PART_LINE - 0.6)
        s.hole(circ(INSERT_D, bx, by),
               PART_LINE - 0.6 - INSERT_DEPTH, PART_LINE + 1.0)

    # rear bay, lower half: the Pi enters here and the opening spans the part line
    s.hole(rect(BAY_W, WALL * 4, 0, -(ENV_Y / 2 - WALL)),
           BAY_Z - BAY_H / 2, PART_LINE + LIP_H + 1.0)   # clears the tongue too
    # Rails: the Pi enters from the rear like a cartridge. It lives in the
    # LOWER shell at 7.0, not on the cartridge plane -- the optical chamber
    # hangs to 12.3 and the cartridge reads at 14.9, so a board at that height
    # would be inside the chamber. 30 mm of depth and 5 mm of headroom under
    # the skirt is what the two constraints leave.
    for sx in (-PI_W / 2 - 1.2, PI_W / 2 + 1.2):
        s.solid(rect(2.4, PI_DEPTH, sx, -(ENV_Y / 2 - WALL - PI_DEPTH / 2)),
                PI_RAIL_Z - 2.4, PI_RAIL_Z + 2.4)
        s.hole(rect(3.0, PI_DEPTH + 2, sx + (1.2 if sx < 0 else -1.2),
                    -(ENV_Y / 2 - WALL - PI_DEPTH / 2)),
               PI_RAIL_Z - PI_SLOT / 2, PI_RAIL_Z + PI_SLOT / 2)

    for fx in FASTENER_X:                                  # front fasteners
        s.hole(circ(FASTENER_D, fx, ENV_Y / 2 - WALL / 2), FASTENER_Z - 3, FASTENER_Z + 3)
    return s, ((-ENV_X / 2 - 1, -ENV_Y / 2 - 1, -1),
               (ENV_X / 2 + 1, ENV_Y / 2 + 1, PART_LINE + LIP_H + 1))


def shell_upper():
    """Deck, dish, display, buttons, cartridge slot, vents, the optical
    chamber skirt and the rails the Pi slides in on."""
    s = Shell()
    top = ENV_Z
    s.solid(OUTER, PART_LINE, top)
    s.hole(INNER, PART_LINE - 1.0, top - CEIL)             # hollow
    s.hole(LIP, PART_LINE - 1.0, PART_LINE + LIP_H + 0.15)  # groove for the tongue

    # The dish needs a floor of its own. A 2.0 recess in a 2.0 ceiling leaves
    # nothing between the dish and the interior -- the recess IS the cavity
    # ceiling -- so the deck is thickened locally to carry the port, the glass
    # rebate, and the top of the optical chamber.
    s.solid(circ(DISH_R * 2 + 2 * WALL, DISH_X, DISH_Y),
            top - DISH_DEPTH - CEIL, top - DISH_DEPTH)

    # sample dish, its sensor port, and the rebate the ring window drops into
    s.hole(circ(DISH_R * 2, DISH_X, DISH_Y), top - DISH_DEPTH, top + 1.0)
    s.hole(circ(PORT_D, DISH_X, DISH_Y), top - DISH_DEPTH - CEIL - 1.0, top + 1.0)
    s.hole(circ(GLASS_D, DISH_X, DISH_Y),
           top - DISH_DEPTH - GLASS_REBATE, top - DISH_DEPTH + 0.01)

    # display window, with a ledge inside for the module to seat against
    s.hole(rrect(DISPLAY_W, DISPLAY_H, 1.2, DISPLAY_X, DISPLAY_Y), top - CEIL - 1.0, top + 1.0)
    s.solid(lambda x, y: max(rrect(DISPLAY_W + 4, DISPLAY_H + 4, 1.2, DISPLAY_X, DISPLAY_Y)(x, y),
                             -rrect(DISPLAY_W, DISPLAY_H, 1.2, DISPLAY_X, DISPLAY_Y)(x, y)),
            top - CEIL - 1.2, top - CEIL)
    for px, py in DISPLAY_POST:
        s.solid(circ(4.0, px, py), top - CEIL - 6.0, top - CEIL)
        s.hole(circ(1.8, px, py), top - CEIL - 6.2, top - CEIL + 0.01)

    for bx, d in BUTTONS:                                   # buttons
        s.hole(circ(d + 0.5, bx, BUTTON_Y), top - CEIL - 1.0, top + 1.0)

    # cartridge slot, front face, on the dish centreline
    s.hole(rect(SLOT_W, SLOT_DEPTH * 2, SLOT_X, ENV_Y / 2 - SLOT_DEPTH / 2 + 0.1),
           SLOT_Z - SLOT_H / 2, SLOT_Z + SLOT_H / 2)

    # rear bay, upper half; USB-C on the right face
    s.hole(rect(BAY_W, WALL * 4, 0, -(ENV_Y / 2 - WALL)), PART_LINE - 1.0, BAY_Z + BAY_H / 2)
    s.hole(rect(WALL * 4, USB_W, ENV_X / 2 - WALL, 0.0), USB_Z - USB_H / 2, USB_Z + USB_H / 2)

    # Vents: blind pockets, and blind is the whole point -- one through-hole
    # puts ambient light on the optical chamber and the 415 nm gate stops
    # working. Section 10 says 3.0 deep, which was safe in a solid body and is
    # 0.6 mm PAST the inside face of a 2.4 mm wall. They are cut 1.6 here,
    # leaving 0.8 of material. Do not deepen them.
    for i in range(VENT_N):
        vx = VENT_X0 + i * VENT_PITCH
        s.hole(rect(VENT_W, VENT_DEPTH * 2, vx, ENV_Y / 2),
               VENT_Z - VENT_H / 2, VENT_Z + VENT_H / 2)

    # screw clearance and head counterbore, over the lower shell's bosses
    for bx, by in BOSSES:
        s.hole(circ(SCREW_CLEAR, bx, by), PART_LINE - 1.0, top + 1.0)
        s.hole(circ(SCREW_HEAD, bx, by), PART_LINE - 1.0, PART_LINE + 2.4)

    # optical chamber: a skirt from the deck underside down past the cartridge
    # plane, so the only light that reaches the head comes through the port
    skirt_top = top - DISH_DEPTH - CEIL
    s.solid(ring(CHAMBER_R * 2, CHAMBER_R * 2 - 2 * WALL, DISH_X, DISH_Y),
            skirt_top - CHAMBER_DROP, skirt_top)
    # The cartridge crosses the skirt on its way to the read spot, so the slot
    # is cut through the skirt as well as through the outer wall -- from the
    # face at +36.6 back past the skirt's front arc at +30.0.
    s.hole(rect(SLOT_W, 12.0, SLOT_X, ENV_Y / 2 - 4.0),
           SLOT_Z - SLOT_H / 2 - 0.3, SLOT_Z + SLOT_H / 2 + 0.3)

    return s, ((-ENV_X / 2 - 1, -ENV_Y / 2 - 1, PART_LINE - 1),
               (ENV_X / 2 + 1, ENV_Y / 2 + 1, ENV_Z + 1))


# --------------------------------------------------------------------------
# the check that keeps the two sources reconciled
# --------------------------------------------------------------------------

def check_envelope(meshes):
    """The printed shells and the viewer model describe one instrument. This
    is the seam between the two parametric sources, so it is checked rather
    than trusted: the assembled bounding box must be the documented envelope.
    """
    lo = [1e9] * 3
    hi = [-1e9] * 3
    for tris in meshes:
        for tri in tris:
            for v in tri:
                for k in range(3):
                    lo[k] = min(lo[k], v[k])
                    hi[k] = max(hi[k], v[k])
    got = [hi[k] - lo[k] for k in range(3)]
    want = [ENV_X, ENV_Y, ENV_Z]
    for k, (g, w) in enumerate(zip(got, want)):
        if abs(g - w) > PITCH:
            raise SystemExit(
                "envelope drift on axis %d: shells give %.2f, BUILD.md says %.2f"
                % (k, g, w))
    return got


def check_fit(lower, upper):
    """Clearance checks, run every time the shells are generated.

    A mesh can be perfectly watertight and still describe a device that cannot
    be assembled. These are the four ways this enclosure can be wrong without
    looking wrong: a blocked cartridge path, a vent that went through, a board
    bay fouled by the optical chamber, and two shells that occupy the same
    space at the part line.
    """
    def solid(f, p):
        return f(p) < 0

    fails = []

    # The cartridge runs from the front face to the read spot. Probed across
    # its full 14 mm width and 2.4 mm thickness, not down its centreline -- a
    # centreline probe slips through a slot a hundredth of a millimetre wide.
    for cx in (SLOT_X - 6.5, SLOT_X, SLOT_X + 6.5):
        for cz in (SLOT_Z - 1.0, SLOT_Z, SLOT_Z + 1.0):
            for t in range(0, 65):
                y = ENV_Y / 2 - t * 0.5
                if y < DISH_Y:
                    break
                if solid(upper, (cx, y, cz)):
                    fails.append("cartridge path blocked at (%+.1f, %+.1f, %.1f)"
                                 % (cx, y, cz))
                    break

    # every vent must still have material behind it
    for i in range(VENT_N):
        vx = VENT_X0 + i * VENT_PITCH
        if not solid(upper, (vx, ENV_Y / 2 - WALL + 0.4, VENT_Z)):
            fails.append("vent %d is a through-hole" % i)

    # The Pi bay: the corridor a 65 x 30 board sweeps through on its way in,
    # plus the headroom its tallest parts need. Sampled at 1 mm, because the
    # thing most likely to be in the way is the 2.4 mm skirt wall, and a
    # coarser sweep steps straight over it.
    bay = []
    for xi in range(-32, 33, 4):
        for t in range(0, 31):
            y = -(ENV_Y / 2 - WALL) + t
            for dz in (1.0, PI_HEADROOM):
                for f, nm in ((lower, "lower"), (upper, "upper")):
                    if solid(f, (float(xi), y, PI_RAIL_Z + dz)):
                        bay.append("%s shell at (%d, %+.0f, %.1f)"
                                   % (nm, xi, y, PI_RAIL_Z + dz))
    if bay:
        fails.append("Pi bay fouled: " + bay[0]
                     + (" and %d more" % (len(bay) - 1) if len(bay) > 1 else ""))

    # The sensor port has to see daylight through the dish, across the 3 mm
    # spot the aperture tube defines rather than at a single point.
    for k in range(4):
        a = math.pi / 2 * k
        px = DISH_X + 1.5 * math.cos(a)
        py = DISH_Y + 1.5 * math.sin(a)
        for t in range(0, 12):
            z = ENV_Z - t * 0.4
            if z < ENV_Z - DISH_DEPTH - CEIL:
                break
            if solid(upper, (px, py, z)):
                fails.append("sensor port blocked at z=%.1f" % z)
                break

    # tongue and groove: no point may be solid in both shells at once
    clash = 0
    for i in range(72):
        a = TAU_STEP * i
        x = (ENV_X / 2 - WALL / 2) * math.cos(a)
        y = (ENV_Y / 2 - WALL / 2) * math.sin(a)
        for t in range(0, 9):
            z = PART_LINE + t * 0.25
            if solid(lower, (x, y, z)) and solid(upper, (x, y, z)):
                clash += 1
    if clash:
        fails.append("shells interfere at the part line in %d places" % clash)

    if fails:
        raise SystemExit("fit check failed:\n  " + "\n  ".join(fails))
    return True


TAU_STEP = 2 * math.pi / 72


SETTINGS = "PETG black, 0.16 mm, 4 perim, 25%, seam at a corner"


def generate(verbose=True):
    """Write both shells and run every check. Returns manifest rows."""
    from gen_printables import validate
    os.makedirs(OUT, exist_ok=True)
    meshes, fields, rows = [], {}, []
    for name, fn in (("shell_lower", shell_lower), ("shell_upper", shell_upper)):
        field, bounds = fn()
        fields[name] = field
        tris = stl.sdf_mesh(field, bounds, PITCH)
        vol = validate(name, tris)
        path = os.path.join(OUT, name + ".stl")
        stl.write_stl(path, tris, header=("cell " + name).encode())
        meshes.append(tris)
        rows.append((name, len(tris), vol, SETTINGS))
        if verbose:
            print("%-20s %7d tris  %9.1f mm3  %8.1f kB"
                  % (name, len(tris), vol, os.path.getsize(path) / 1024))
    check_fit(fields["shell_lower"], fields["shell_upper"])
    env = check_envelope(meshes)
    if verbose:
        print("fit checks pass: cartridge path, blind vents, Pi bay, sensor "
              "port, part line")
        print("envelope %.2f x %.2f x %.2f mm -- matches BUILD.md section 10"
              % tuple(env))
    return rows


def main():
    generate()


if __name__ == "__main__":
    main()
