#!/usr/bin/env python3
"""Break each geometry check on purpose and require it to bite.

    python3 tools/test_printables.py

A check that has never failed is a check nobody knows works. These are the
guards standing between a constant somebody edits and a plate of parts that
cannot be assembled, so each one is driven past its own limit here and
required to raise.

The enclosure's `check_fit()` is not exercised here: it samples a signed
distance field over the whole body, and re-running that per deliberate break
costs minutes rather than milliseconds. It runs on every generation instead.
"""

import contextlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gen_printables as gp


@contextlib.contextmanager
def constants(**kw):
    """Temporarily set module constants, restoring them afterwards."""
    old = {k: getattr(gp, k) for k in kw}
    for k, v in kw.items():
        setattr(gp, k, v)
    try:
        yield
    finally:
        for k, v in old.items():
            setattr(gp, k, v)


def expect_fail(name, fn, **broken):
    with constants(**broken):
        try:
            fn()
        except SystemExit as e:
            print("  %-42s bites: %s" % (name, str(e).split("\n")[1].strip()))
            return
    raise SystemExit("FAIL: %s did not fail the check" % name)


def expect_pass(name, fn):
    result = fn()
    print("  %-42s passes: %s" % (name, result))


# The cartridge's two-stop read is a set of distances that must hold at once.
CARTRIDGE_BREAKS = [
    ("patch overlapping the moat", dict(PATCH_FROM_TIP=6.0)),
    ("patch running off the tip", dict(PATCH_FROM_TIP=0.4)),
    # A patch behind the well puts the stops in the wrong order, and trips the
    # moat rule on the way past. The ordering guard stays in the check as
    # belt-and-braces: it is what would catch the same mistake if the moat
    # ever moved out from under it.
    ("patch behind the well", dict(PATCH_FROM_TIP=12.0, WELL_FROM_TIP=12.0)),
    ("detent taller than the slot clearance", dict(DETENT_PROUD=0.9)),
    ("detent under the PET window", dict(WELL_FROM_TIP=30.0)),
    ("nothing left to grip", dict(CART_L=45.0)),
]

# The bezel is the one part fitted to a component BUILD.md does not pin down.
BEZEL_BREAKS = [
    ("active area larger than the window", dict(SCREEN_W=60.0)),
    ("frame too thin to print", dict(SCREEN_W=46.0)),
    ("counterbore breaking into the aperture", dict(SCREEN_W=32.0, SCREEN_H=32.0)),
    ("counterbore deeper than the plate", dict(BEZEL_CB_DEPTH=3.0)),
]


def main():
    print("cartridge geometry")
    expect_pass("as generated", gp.check_cartridge_geometry)
    for name, broken in CARTRIDGE_BREAKS:
        expect_fail(name, gp.check_cartridge_geometry, **broken)

    print("display bezel")
    expect_pass("as generated", gp.check_bezel_geometry)
    for name, broken in BEZEL_BREAKS:
        expect_fail(name, gp.check_bezel_geometry, **broken)

    print("filament budget")
    # Volumes are what the meshes actually are, so the budget check is driven
    # with the real numbers rather than invented ones.
    rows = [(name, len(tris), gp.validate(name, tris), note)
            for name, fn, note in gp.PARTS for tris in (fn(),)]
    import gen_enclosure
    for name in ("shell_lower", "shell_upper"):
        path = os.path.join(gp.OUT, name + ".stl")
        if not os.path.exists(path):
            raise SystemExit("run tools/gen_printables.py first -- %s missing" % path)
        rows.append((name, 0, _stl_volume(path), gen_enclosure.SETTINGS))

    expect_pass("as generated", lambda: gp.check_filament_budget(rows))
    expect_fail("a cartridge batch bigger than the spool",
                lambda: gp.check_filament_budget(rows), CART_BATCH=200)
    expect_fail("shells heavier than the spool",
                lambda: gp.check_filament_budget(rows), PETG_DENSITY=1.27e-1)

    print("\nall geometry checks bite")


def _stl_volume(path):
    """Signed volume of a binary STL, so the shells need not be re-meshed."""
    import struct
    with open(path, "rb") as fh:
        data = fh.read()
    n = struct.unpack("<I", data[80:84])[0]
    vol = 0.0
    for i in range(n):
        o = 84 + i * 50 + 12
        a, b, c = (struct.unpack("<3f", data[o + v * 12:o + v * 12 + 12])
                   for v in range(3))
        vol += (a[0] * (b[1] * c[2] - b[2] * c[1])
                - a[1] * (b[0] * c[2] - b[2] * c[0])
                + a[2] * (b[0] * c[1] - b[1] * c[0])) / 6.0
    return vol


if __name__ == "__main__":
    main()
