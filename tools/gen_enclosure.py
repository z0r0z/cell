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
DISPLAY_R = 1.2                      # window corner radius; the bezel matches it
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
FASTENER_DEPTH = 1.2                 # blind: viewer/model.js draws it 1.2 deep

# --- DERIVED: the inside, which BUILD.md does not dimension ----------------
WALL = 2.4                  # 6 perimeters at 0.4
VENT_DEPTH = 1.6            # blind: shallower than the wall, see shell_upper
FLOOR = 2.0
CEIL = 2.0
LIP_W = 1.2                 # tongue on the lower shell, groove in the upper
LIP_H = 2.0
LIP_LEAD = 0.4              # chamfer on the tongue's top edge, to start the joint
PART_CLEAR = 0.15           # tongue to groove, on the SIDES as well as over the top
BOSS_OD, INSERT_D, INSERT_DEPTH = 6.0, 3.6, 6.0     # M2.5 heat-set insert
SCREW_CLEAR, SCREW_HEAD = 2.8, 4.8
SCREW_CB_DEPTH = 2.4        # head sunk into the base, so the case still sits flat
SCREW_RELIEF = 2.0          # past the insert, so a long screw cannot bottom out
# The screw enters from the BASE and threads up into an insert in the UPPER
# shell. That is the only direction that works. The insert has to be in the
# half the screw does not pass through, and a screw entering the deck would
# have to span the whole 17.5 mm interior and would put six heads on the
# display face. Length follows from the stack, and check_fit() proves it.
SCREW_LEN = 16.0            # M2.5 x 16
# Six insert bosses, not eight. The two that would sit mid-span at the rear
# stood inside the Pi's 65 x 30 footprint -- the fit check catches it if they
# come back. The corner pair at the rear clears the board because the board is
# narrower than the body. Six here plus the two front fasteners is the eight
# the BOM buys.
#
# Every boss now carries a pillar in the UPPER shell as well, so a boss is no
# longer a stub on the floor -- it is a column through the whole interior, and
# it has to miss everything on the way. The front-middle one was at (20, 30),
# inside the 11.5 .. 45.5 that the cartridge slot sweeps, and its pillar cut
# straight through the cartridge's path.
BOSSES = [(-50, 30), (-20, 30), (5, 30), (50, 30), (-50, -30), (50, -30)]
CHAMBER_R = 25.0            # light-tight skirt around the dish
# 11.2, not 12.0. At 12.0 the skirt hung to 12.32 and the tallest part on the
# board reached 12.7, so the two overlapped by 0.38 mm. The check that should
# have caught it measured headroom from the middle of the board instead of its
# top face. The skirt still hangs past the cartridge plane at 13.4, which is
# what closes the chamber.
CHAMBER_DROP = 11.2
# 7.1, not 7.0: the board enters through the rear bay, whose floor is at 6.0,
# so the underside of the board has to start above that. check_stack() proves
# the whole column -- bay floor, board, headroom, skirt -- still fits.
PI_W, PI_SLOT, PI_RAIL_Z = 65.0, 1.8, 7.1           # Pi Zero 2 W slides in
PI_DEPTH = 30.0
PI_CLEAR = 0.2              # per side, board edge to the back of the groove
PI_ENGAGE = 1.2             # how far the rail lip reaches over the board
GLASS_D, GLASS_REBATE = 10.2, 0.6                   # the 10 mm ring window
PI_HEADROOM = 4.8           # tallest part on a Pi Zero, under the skirt at 12.3
DISPLAY_POST = [(-38, -22), (-13, -22), (-38, 8), (-13, 8)]
# How far the ledge reaches IN past the window edge. It does two jobs: it is
# what the printed bezel lands on, and it is what the four display posts hang
# from. Running it OUTWARD from the window edge, which is what it used to do,
# put every millimetre of it behind solid deck -- so the bezel had nothing to
# rest on and dropped through, and the posts touched nothing and came out of
# the slicer as four loose pins standing in the window.
DISPLAY_LEDGE_W = 4.5
PITCH = 0.5

# The cartridge is gen_printables.py's part, but the shells have to let it
# through, so its section is needed here too. gen_printables asserts these
# against its own constants on import: the two cannot drift apart in silence.
CART_W, CART_T = 14.0, 2.4

# How far back the cartridge slot has to be cut through the optical-chamber
# skirt. Derived, not guessed: the skirt's inner arc comes nearest the front at
# the cartridge's EDGES, not on its centreline, and a cut sized for the
# centreline left a 0.11 mm sliver of skirt standing in the path of both edges
# for the full height of the slot.
SKIRT_CUT_BACK = (DISH_Y
                  + math.sqrt((CHAMBER_R - WALL) ** 2 - (CART_W / 2) ** 2)
                  - 0.5)

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


def _span(x0, x1, dy, cy):
    """A rectangle from x0 to x1 in either order, dy deep, centred cy."""
    lo, hi = (x0, x1) if x0 < x1 else (x1, x0)
    return rect(hi - lo, dy, (lo + hi) / 2, cy)


def _bore_y(x, z, y0, y1, r):
    """A cylindrical bore along Y (depth) -- the axis circ() cannot express."""
    lo, hi = (y0, y1) if y0 < y1 else (y1, y0)

    def f(p):
        px, py, pz = p
        return max(math.hypot(px - x, pz - z) - r, py - hi, lo - py)
    return f


def inset(w, h, r, d):
    """The envelope profile shrunk by d -- the inside of a wall d thick."""
    return rrect(w - 2 * d, h - 2 * d, max(r - d, 0.05), 0, 0)


OUTER = rrect(ENV_X, ENV_Y, CORNER_R)
INNER = inset(ENV_X, ENV_Y, CORNER_R, WALL)
LIP = inset(ENV_X, ENV_Y, CORNER_R, WALL - LIP_W)
# The groove is cut on LIP and the tongue PART_CLEAR narrower. Cutting both
# from the same profile is what left the joint 0.15 mm of clearance over the
# top of the tongue and 0.000 mm on either side of it -- an interference fit
# around a 358 mm perimeter, which is a shell that will not close.
TONGUE = inset(ENV_X, ENV_Y, CORNER_R, WALL - LIP_W + PART_CLEAR)
TONGUE_LEAD = inset(ENV_X, ENV_Y, CORNER_R, WALL - LIP_W + PART_CLEAR + LIP_LEAD)


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
        self.ops.append((True, prof, z0, z1, None))
        return self

    def hole(self, prof, z0, z1):
        self.ops.append((False, prof, z0, z1, None))
        return self

    def hole3(self, field):
        """Subtract a full 3-D field, for a feature whose axis is not Z.

        Every prism op above extrudes a 2-D profile along Z, which is right
        for the vents, the slot, the bay and the USB cutout. It is wrong for
        anything bored into a vertical face: circ() extruded along Z is a
        VERTICAL bore, and using it for the front-face fasteners cut two Ø4
        slots clean through the front wall of the lower shell.
        """
        self.ops.append((False, None, None, None, field))
        return self

    def __call__(self, p):
        x, y, z = p
        if self._key != (x, y):
            self._key = (x, y)
            live = []
            for a, pr, z0, z1, fld in self.ops:
                if fld is not None:
                    live.append((a, None, None, None, fld))
                    continue
                d = pr(x, y)
                if d < self.NEAR:
                    live.append((a, d, (z0 + z1) / 2, (z1 - z0) / 2, None))
            self._live = live
        d = 1e9
        for add, d2, zc, zh, fld in self._live:
            v = fld(p) if fld is not None else max(d2, abs(z - zc) - zh)
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
    s.solid(lambda x, y: max(TONGUE(x, y), -INNER(x, y)),   # tongue
            PART_LINE, PART_LINE + LIP_H)
    # Lead-in: the top LIP_LEAD of the tongue is stepped in again, so the
    # joint starts itself instead of having to be aligned to a tenth before
    # it will begin to close.
    s.hole(lambda x, y: -TONGUE_LEAD(x, y),
           PART_LINE + LIP_H - LIP_LEAD, PART_LINE + LIP_H + 1.0)

    # Screw columns. The head sinks into the BASE and the screw passes clean
    # through this shell into an insert in the upper one -- see SCREW_LEN.
    for bx, by in BOSSES:
        s.solid(circ(BOSS_OD, bx, by), FLOOR - 0.6, PART_LINE - 0.6)
        s.hole(circ(SCREW_CLEAR, bx, by), -1.0, PART_LINE + 1.0)
        s.hole(circ(SCREW_HEAD, bx, by), -1.0, SCREW_CB_DEPTH)

    # rear bay, lower half: the Pi enters here and the opening spans the part line
    s.hole(rect(BAY_W, WALL * 4, 0, -(ENV_Y / 2 - WALL)),
           BAY_Z - BAY_H / 2, PART_LINE + LIP_H + 1.0)   # clears the tongue too
    # Rails: the Pi enters from the rear like a cartridge. It lives in the
    # LOWER shell at 7.0, not on the cartridge plane -- the optical chamber
    # hangs to 12.3 and the cartridge reads at 14.9, so a board at that height
    # would be inside the chamber. 30 mm of depth and 5 mm of headroom under
    # the skirt is what the two constraints leave.
    # The groove has to be NARROWER than the rail and biased outboard, or the
    # lip that retains the board never reaches over it. Cut 3.0 wide out of a
    # 2.4 rail, the groove floor and the lip both landed on the same 32.5 as
    # the board's own edge: 0.005 mm of engagement, and no lateral position in
    # which both edges are captured at once. The board fell out of its rails.
    rail_y = -(ENV_Y / 2 - WALL - PI_DEPTH / 2)
    groove_out = PI_W / 2 + PI_CLEAR            # board edge reaches here
    lip_in = groove_out - PI_ENGAGE             # lip reaches this far inboard
    rail_out = groove_out + 2.2
    for sgn in (-1.0, 1.0):
        s.solid(_span(sgn * lip_in, sgn * rail_out, PI_DEPTH, rail_y),
                PI_RAIL_Z - 2.4, PI_RAIL_Z + 2.4)
        s.hole(_span(sgn * (lip_in - 2.0), sgn * groove_out,
                     PI_DEPTH + 2, rail_y),
               PI_RAIL_Z - PI_SLOT / 2, PI_RAIL_Z + PI_SLOT / 2)

    # Front-face fasteners: BLIND pockets, Ø4.0 x 1.2 deep, which is exactly
    # what viewer/model.js draws. They are cosmetic, and the geometry says so
    # -- the pocket and anything that could be threaded behind it are both in
    # THIS shell, so there is nothing here for a screw to clamp. Cut as a
    # vertical circ() they came out as two Ø4 slots straight through the front
    # wall: a clear path for ambient light into the body, in the one
    # instrument where that breaks a gate.
    for fx in FASTENER_X:
        s.hole3(_bore_y(fx, FASTENER_Z, ENV_Y / 2 - FASTENER_DEPTH,
                        ENV_Y / 2 + 1.0, FASTENER_D / 2))
    return s, ((-ENV_X / 2 - 1, -ENV_Y / 2 - 1, -1),
               (ENV_X / 2 + 1, ENV_Y / 2 + 1, PART_LINE + LIP_H + 1))


def shell_upper():
    """Deck, dish, display, buttons, cartridge slot, vents, the optical
    chamber skirt and the rails the Pi slides in on."""
    s = Shell()
    top = ENV_Z
    s.solid(OUTER, PART_LINE, top)
    s.hole(INNER, PART_LINE - 1.0, top - CEIL)             # hollow
    # Groove for the tongue, cut on LIP while the tongue is cut PART_CLEAR
    # narrower, so the joint has clearance on the sides and not only over the top.
    s.hole(LIP, PART_LINE - 1.0, PART_LINE + LIP_H + PART_CLEAR)

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
    s.hole(rrect(DISPLAY_W, DISPLAY_H, DISPLAY_R, DISPLAY_X, DISPLAY_Y),
           top - CEIL - 1.0, top + 1.0)
    # The ledge has to reach INWARD of the window edge or the bezel has
    # nothing to land on. Running it from the window edge outward -- which is
    # what an annulus from DISPLAY_W to DISPLAY_W + 4 does -- puts all of it
    # behind solid deck: the bezel drops through the window into the case, and
    # the four posts below hang off nothing.
    s.solid(lambda x, y: max(
        rrect(DISPLAY_W + 4, DISPLAY_H + 4, DISPLAY_R, DISPLAY_X, DISPLAY_Y)(x, y),
        -rrect(DISPLAY_W - 2 * DISPLAY_LEDGE_W, DISPLAY_H - 2 * DISPLAY_LEDGE_W,
               DISPLAY_R, DISPLAY_X, DISPLAY_Y)(x, y)),
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

    # Insert pillars, hanging from the deck underside down to the part line.
    # Without these the upper shell had NO material at any of the six screw
    # positions: the Ø4.8 head counterbore was cut in open cavity, the Ø2.8
    # clearance came out as six through-holes in the display face, and a screw
    # would have had to span 17.5 mm of air to reach an insert it could not
    # engage anyway. The insert lives here; the screw comes up from the base.
    for bx, by in BOSSES:
        s.solid(circ(BOSS_OD, bx, by), PART_LINE, top - CEIL)
        s.hole(circ(INSERT_D, bx, by), PART_LINE - 1.0, PART_LINE + INSERT_DEPTH)
        s.hole(circ(SCREW_CLEAR, bx, by), PART_LINE + INSERT_DEPTH,
               PART_LINE + INSERT_DEPTH + SCREW_RELIEF)

    # optical chamber: a skirt from the deck underside down past the cartridge
    # plane, so the only light that reaches the head comes through the port
    skirt_top = top - DISH_DEPTH - CEIL
    s.solid(ring(CHAMBER_R * 2, CHAMBER_R * 2 - 2 * WALL, DISH_X, DISH_Y),
            skirt_top - CHAMBER_DROP, skirt_top)
    # The cartridge crosses the skirt on its way to the read spot, so the slot
    # is cut through the skirt as well as through the outer wall -- from the
    # face at +36.6 back past the skirt's front arc at +30.0.
    s.hole(_span(SLOT_X - SLOT_W / 2, SLOT_X + SLOT_W / 2,
                 (ENV_Y / 2 + 1.0) - SKIRT_CUT_BACK,
                 (SKIRT_CUT_BACK + ENV_Y / 2 + 1.0) / 2),
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


def check_viewer_envelope():
    """The printed shells and the RENDERED model must be one instrument.

    check_envelope() above proves the meshes match the constants at the top of
    this file. That is only half the seam: those constants were copied from
    viewer/model.js by hand, and nothing until now noticed if the viewer
    moved. Someone printing these STLs expects the thing in the turntable, so
    the exported model is measured rather than trusted.

    models/instrument.obj is the viewer's own export (tools/export_model.py),
    in three.js axes: X across, Y up, Z back. This file puts height on Z, so
    the mapping is the one _TO_VIEWER states, read backwards.

    Absent is not a failure -- a checkout that has not run export_model.py yet
    is a normal state, and this check simply has nothing to compare against.
    """
    obj = os.path.join(ROOT, "models", "instrument.obj")
    if not os.path.exists(obj):
        return None
    lo = [float("inf")] * 3
    hi = [float("-inf")] * 3
    # The dish floor, tracked separately. A bounding box cannot see it, which
    # is how the RENDERED dish came to be 2.818 deep while the PRINTED one is
    # DISH_DEPTH -- two models of one instrument, 0.82 mm apart, each
    # internally consistent, with every job green.
    dish_top = float("-inf")
    obj_name = None
    with open(obj) as fh:
        for line in fh:
            if line.startswith("o "):
                obj_name = line.split(None, 1)[1].strip()
            elif line.startswith("v "):
                p = [float(v) for v in line.split()[1:4]]
                for k in range(3):
                    lo[k] = min(lo[k], p[k])
                    hi[k] = max(hi[k], p[k])
                if obj_name == "recess_floor_etch":
                    dish_top = max(dish_top, p[1])
    if lo[0] > hi[0]:
        return None                       # no vertices; not an OBJ we can read
    # viewer (x, y=height, z=depth) -> this file's (X, Y=depth, Z=height)
    got = (hi[0] - lo[0], hi[2] - lo[2], hi[1] - lo[1])
    want = (ENV_X, ENV_Y, ENV_Z)
    names = ("length", "depth", "height")
    bad = [(names[k], got[k], want[k])
           for k in range(3) if abs(got[k] - want[k]) > PITCH]
    if bad:
        raise SystemExit(
            "the printed shells and viewer/model.js describe different "
            "instruments:\n  "
            + "\n  ".join("%s: instrument.obj %.2f mm, gen_enclosure %.2f mm"
                          % b for b in bad)
            + "\n  Change the parametric source, re-run tools/export_model.py, "
              "and bring ENV_X/ENV_Y/ENV_Z here into step.")
    if dish_top > float("-inf"):
        depth = hi[1] - dish_top          # outer surface down to the dish floor
        if abs(depth - DISH_DEPTH) > PITCH:
            raise SystemExit(
                "the rendered dish and the printed dish are different depths:\n"
                "  instrument.obj %.3f mm, gen_enclosure DISH_DEPTH %.3f mm\n"
                "  The recess is where the sample sits and where the ring "
                "window seats, so this is not cosmetic. Move model.js's "
                "DISH_FLOOR or this DISH_DEPTH, re-run tools/export_model.py, "
                "and make them one number." % (depth, DISH_DEPTH))
    return got


def check_stack():
    """The vertical column, which several constants have to agree on at once.

    Nothing here is measured off a mesh; it is arithmetic between constants,
    and it is checked because the arithmetic was wrong in two places at the
    same time. The board sat 0.38 mm inside the optical chamber's skirt, and
    the optical head was specified 3.5 mm taller than the chamber it lives in.
    Both were invisible: no check compared these numbers to each other.
    """
    fails = []
    bay_floor = BAY_Z - BAY_H / 2
    board_lo = PI_RAIL_Z - PI_SLOT / 2
    board_hi = PI_RAIL_Z + PI_SLOT / 2
    skirt_under = ENV_Z - DISH_DEPTH - CEIL - CHAMBER_DROP
    if board_lo < bay_floor + 0.1:
        fails.append("the board sits at %.2f but enters through a bay whose "
                     "floor is at %.2f" % (board_lo, bay_floor))
    if board_hi + PI_HEADROOM > skirt_under - 0.1:
        fails.append("board top %.2f plus %.1f of headroom reaches %.2f, into "
                     "the chamber skirt at %.2f"
                     % (board_hi, PI_HEADROOM, board_hi + PI_HEADROOM, skirt_under))
    if skirt_under > SLOT_Z - SLOT_H / 2:
        fails.append("the skirt stops at %.2f, above the cartridge plane at "
                     "%.2f -- the chamber is not closed"
                     % (skirt_under, SLOT_Z - SLOT_H / 2))
    if fails:
        raise SystemExit("stack check failed:\n  " + "\n  ".join(fails))
    return dict(sample_plane=SLOT_Z - SLOT_H / 2 + CART_T,
                chamber_ceiling=ENV_Z - DISH_DEPTH - CEIL,
                chamber_bore=2 * (CHAMBER_R - WALL),
                skirt_under=skirt_under)


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
    # The SECTION and the STEP both fell short of what that sentence claims:
    # +-6.5 by +-1.0 is 13.0 x 2.0, so the probe ran 0.5 mm inside the part's
    # own edges, and a 0.5 mm step walks over anything thinner than itself.
    # The skirt's inner arc dips 0.11 mm into the path at both cartridge
    # edges, which is invisible to either.
    for cx in (SLOT_X - CART_W / 2, SLOT_X - CART_W / 4, SLOT_X,
               SLOT_X + CART_W / 4, SLOT_X + CART_W / 2):
        for cz in (SLOT_Z - CART_T / 2, SLOT_Z, SLOT_Z + CART_T / 2):
            for t in range(0, 641):
                y = ENV_Y / 2 - t * 0.05
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
    # The x sweep said 1 mm and stepped 4, and stopped 0.5 mm short of the
    # board's own +-32.5 edges. Headroom is measured from the board's TOP
    # face: taken from the rail centreline it loses PI_SLOT/2 and hid a
    # 0.38 mm overlap with the skirt. The slab and the component headroom are
    # two corridors, not one -- the rail lips are SUPPOSED to overhang the
    # board's edges, and that overhang is the whole retention.
    bay = []
    board_hw, comp_hw = PI_W / 2, PI_W / 2 - PI_ENGAGE
    slab = (-PI_SLOT / 2 + 0.1, 0.0, PI_SLOT / 2 - 0.1)
    head = (PI_SLOT / 2 + 0.1, PI_SLOT / 2 + PI_HEADROOM)
    for xi in [x_ / 2.0 for x_ in range(-2 * int(board_hw), 2 * int(board_hw) + 1)]:
        for t in range(0, 31):
            y = -(ENV_Y / 2 - WALL) + t
            for dz in (slab if abs(xi) > comp_hw else slab + head):
                for f, nm in ((lower, "lower"), (upper, "upper")):
                    if solid(f, (float(xi), y, PI_RAIL_Z + dz)):
                        bay.append("%s shell at (%.1f, %+.0f, %.1f)"
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

    # Tongue and groove. Two things were wrong here, and between them they
    # made the check unable to fire at all.
    #
    # It walked an ELLIPSE inscribed in a rounded rectangle. That is not the
    # wall: 68 of its 72 samples sat in open cavity, the 45 degree one 11.6 mm
    # inside the outer surface, and all four CORNERS -- where a tongue offset
    # around a corner radius is likeliest to bind -- were never visited. At
    # the four points where it did meet the wall the field was exactly
    # -0.000, which is not < 0. So march each ray out to the tongue's own
    # profile instead.
    #
    # And "solid in both shells" is not how this joint fails. Coincident faces
    # are never solid in both, so a ZERO-clearance fit passes -- which is what
    # the tongue and the groove had, both cut from the same LIP profile onto
    # the identical coordinate. Measure the gap, and require one.
    clash, tight = 0, []
    for x, y in _seam_points(180):
        for t in range(0, 9):
            z = PART_LINE + t * 0.25
            if solid(lower, (x, y, z)) and solid(upper, (x, y, z)):
                clash += 1
        gap = _lateral_gap(lower, upper, x, y, PART_LINE + LIP_H / 2)
        if gap is not None and gap < PART_CLEAR - 0.03:
            tight.append((x, y, gap))
    if clash:
        fails.append("shells interfere at the part line in %d places" % clash)
    if tight:
        x, y, g = min(tight, key=lambda t: t[2])
        fails.append("part line has %.3f mm of side clearance at (%+.1f, %+.1f)"
                     ", want %.2f -- %d of 180 samples tight"
                     % (g, x, y, PART_CLEAR, len(tight)))

    # Every front-face fastener pocket must stay blind. Cut on the wrong axis
    # these were Ø4 slots straight through the wall, and one clear path for
    # ambient light into the body is the whole 415 nm gate.
    for fx in FASTENER_X:
        if not solid(lower, (fx, ENV_Y / 2 - WALL + 0.2, FASTENER_Z)):
            fails.append("front fastener at x=%+.1f went through the wall" % fx)

    # The screw has to reach its insert, and the insert has to be in the half
    # the screw does not pass through. Six screws were being cut into an upper
    # shell with no material at any of the six positions: the head counterbore
    # sat in open cavity, and the clearance came out as six through-holes in
    # the display face.
    off = BOSS_OD / 2 - 0.4
    for bx, by in BOSSES:
        if not solid(lower, (bx + off, by, FLOOR + 1.0)):
            fails.append("no screw column in the lower shell at (%+.0f, %+.0f)"
                         % (bx, by))
        if not solid(upper, (bx + off, by, PART_LINE + INSERT_DEPTH / 2)):
            fails.append("no insert pillar in the upper shell at (%+.0f, %+.0f)"
                         % (bx, by))
        if not solid(upper, (bx, by, ENV_Z - 0.2)):
            fails.append("the screw at (%+.0f, %+.0f) breaks through the deck"
                         % (bx, by))
    reach = PART_LINE + INSERT_DEPTH - SCREW_CB_DEPTH
    if SCREW_LEN < reach:
        fails.append("M2.5 x %.0f cannot reach the insert: %.1f mm of stack "
                     "above the head" % (SCREW_LEN, reach))

    if fails:
        raise SystemExit("fit check failed:\n  " + "\n  ".join(fails))
    return True


def _seam_points(n):
    """n points on the tongue's own profile, corners included."""
    pts = []
    for i in range(n):
        a = TAU * i / n
        dx, dy = math.cos(a), math.sin(a)
        lo, hi = 0.0, ENV_X
        for _ in range(60):                    # bisect out to the isocontour
            mid = (lo + hi) / 2
            if TONGUE(dx * mid, dy * mid) < 0:
                lo = mid
            else:
                hi = mid
        pts.append((dx * lo, dy * lo))
    return pts


def _lateral_gap(lower, upper, x, y, z):
    """Outward gap from the tongue's face to the groove wall at (x, y)."""
    r = math.hypot(x, y)
    if r < 1e-9:
        return None
    ux, uy = x / r, y / r
    out_at = None
    for k in range(401):                       # sweep outward across the seam
        d = -1.0 + k * 0.01
        px, py = x + ux * d, y + uy * d
        if out_at is None and lower((px, py, z)) >= 0:
            out_at = d
        if out_at is not None and upper((px, py, z)) < 0:
            return d - out_at
    return None


TAU = 2 * math.pi
TAU_STEP = TAU / 72


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
    check_stack()
    check_fit(fields["shell_lower"], fields["shell_upper"])
    env = check_envelope(meshes)
    viewer_env = check_viewer_envelope()
    if verbose:
        print("fit checks pass: cartridge path, blind vents, Pi bay, sensor "
              "port, part line")
        print("envelope %.2f x %.2f x %.2f mm -- matches BUILD.md section 10"
              % tuple(env))
        print("viewer model agrees: %s"
              % ("%.2f x %.2f x %.2f mm from models/instrument.obj" % viewer_env
                 if viewer_env else
                 "models/instrument.obj absent -- run tools/export_model.py"))
    return rows


def main():
    generate()


if __name__ == "__main__":
    main()
