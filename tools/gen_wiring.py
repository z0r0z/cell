#!/usr/bin/env python3
"""Generate diagrams/wiring.svg from the pin table in BUILD.md section 11.

    python3 tools/gen_wiring.py

Phase 1 only. The reader is what someone builds first -- a breadboard, a
spectrometer, three LEDs, a laser and a lensless camera -- and it is where a
first-time builder stalls, because everything up to now has been a pin table
in prose. The wallet half is Phase 2 and gets its own sheet when someone has
built one.

The connections are PARSED out of BUILD.md rather than restated here, for the
same reason the mechanical drawing is read out of the mesh: two descriptions
of one wiring loom will disagree eventually, and the one people solder from
should not be the copy. Change the table, re-run this, commit both.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "BUILD.md"
OUT = ROOT / "diagrams" / "wiring.svg"

INK, DIM, RED, MUT, STEEL = "#D8D2C8", "#8A8B8F", "#B23A48", "#6F7178", "#9FA3A8"
GREEN, AMBER = "#4E7A5B", "#8A7440"

# Which rows of the section 11 table belong to the reader. The wallet half --
# display, buttons, secure element -- is Phase 2 and is deliberately absent, so
# nobody wires a screen before the sensing works.
PHASE1 = ("GPIO2/3", "GPIO12", "GPIO6", "GPIO23", "GPIO22", "CSI")


def pin_table() -> list[tuple[str, str]]:
    text = BUILD.read_text()
    sec = text[text.index("## 11. Wiring"):text.index("### Radio removal")]
    rows = []
    for line in sec.splitlines():
        m = re.match(r"^\|\s*(.+?)\s*\|\s*(.+?)\s*\|$", line)
        if not m or m.group(1) in ("Pin", "---"):
            continue
        pin = re.sub(r"\*\*|`", "", m.group(1)).strip()
        fn = re.sub(r"\*\*|`", "", m.group(2)).strip()
        rows.append((pin, fn))
    if not rows:
        sys.exit("no pin rows parsed from BUILD.md section 11 -- did the table change?")
    return rows


def main() -> int:
    rows = pin_table()
    phase1 = [(p, f) for p, f in rows if p in PHASE1]
    missing = [p for p in PHASE1 if p not in {r[0] for r in rows}]
    if missing:
        sys.exit(f"BUILD.md section 11 no longer has rows for {', '.join(missing)}. "
                 f"Update PHASE1 in this file, or the table.")

    W = 1180
    o = ["", ""]                      # header and background, filled in at the end
    A = o.append

    A(f'<text x="46" y="50" font-size="21" font-weight="200" letter-spacing="9" '
      f'fill="{INK}">CELL — PHASE 1 WIRING</text>')
    A(f'<rect x="47" y="61" width="26" height="2" fill="{RED}"/>')
    A(f'<text x="46" y="82" font-size="10" letter-spacing="2" fill="{MUT}">'
      f'The reader only. Read from the pin table in BUILD.md section 11 at generation '
      f'time. BCM numbering. No display, no buttons, no secure element — those are Phase 2.</text>')

    # ---- the Pi ---------------------------------------------------------
    PX, PY, PW, PH = 60, 130, 250, 430
    A(f'<rect x="{PX}" y="{PY}" width="{PW}" height="{PH}" rx="6" fill="#121211" '
      f'stroke="{DIM}" stroke-width="1.2"/>')
    A(f'<text x="{PX+16}" y="{PY+28}" font-size="13" fill="{INK}">Raspberry Pi Zero 2 W</text>')
    A(f'<text x="{PX+16}" y="{PY+46}" font-size="9.5" fill="{MUT}">'
      f'radios disabled, antenna trace cut</text>')

    # Peripherals, in the order the pins appear.
    dest = {
        "GPIO2/3": ("AS7341 spectrometer", "0x39 on I²C1, 100 kHz",
                    "8 colour channels + Clear + NIR.\nDrives white LED #1 on its LDR pin.", GREEN),
        "GPIO12":  ("White LED #2", "2N7002 low-side, 68 Ω to +5 V",
                    "45° opposed to LED #1, so droplet\nasymmetry cancels.", AMBER),
        "GPIO23":  ("940 nm IR LED", "2N7002 low-side, 47 Ω to +3V3",
                    "Co-sited with LED #1. Gives touch\nmode its infrared channel.", AMBER),
        "GPIO6":   ("650 nm laser, ≤5 mW", "2N7002, interlocked",
                    "COHERENT SOURCE IS MANDATORY.\nAn LED produces no speckle.", RED),
        "GPIO22":  ("Cartridge microswitch", "pull-up, LOW when seated",
                    "Gates the laser. Wire the interlock\neven though the chamber is sealed.", STEEL),
        "CSI":     ("Pi Camera, LENS REMOVED", "mini-CSI ribbon",
                    "Fixed exposure ≤2 ms, fixed gain,\nAWB and denoise off.", RED),
    }

    # Start below the board's own caption, or the first pin label lands on top
    # of it.
    y = PY + 56
    step = (PH - 76) / len(phase1)
    for pin, _fn in phase1:
        name, bus, note, col = dest[pin]
        py = y + step / 2
        A(f'<text x="{PX+16}" y="{py+4:.0f}" font-size="10.5" fill="{STEEL}">{pin}</text>')
        A(f'<line x1="{PX+PW}" y1="{py:.0f}" x2="{PX+PW+90}" y2="{py:.0f}" '
          f'stroke="{col}" stroke-width="1.4"/>')
        A(f'<circle cx="{PX+PW}" cy="{py:.0f}" r="2.6" fill="{col}"/>')
        bx = PX + PW + 90
        A(f'<rect x="{bx}" y="{py-26:.0f}" width="600" height="{step-14:.0f}" rx="4" '
          f'fill="#141312" stroke="{col}" stroke-width="1"/>')
        A(f'<text x="{bx+14}" y="{py-8:.0f}" font-size="12" fill="{INK}">{name}</text>')
        A(f'<text x="{bx+14}" y="{py+8:.0f}" font-size="9" fill="{MUT}">{bus}</text>')
        for i, ln in enumerate(note.split("\n")):
            A(f'<text x="{bx+300}" y="{py-8+i*13:.0f}" font-size="9" fill="{MUT}">{ln}</text>')
        y += step

    # ---- the two failures that eat a first build ------------------------
    ny = PY + PH + 46
    A(f'<line x1="46" y1="{ny-20}" x2="{W-46}" y2="{ny-20}" stroke="#22242A" stroke-width="1"/>')
    A(f'<text x="46" y="{ny}" font-size="10" letter-spacing="3" fill="{MUT}">'
      f'WHAT EATS A FIRST BUILD</text>')
    notes = [
        ("Both I²C breakouts ship with pull-ups fitted.",
         "Remove one 2.2 kΩ pair. With both fitted the bus may not enumerate, and it "
         "presents as a dead sensor rather than as a wiring fault. This is the most common "
         "first-build failure."),
        ("The optical chamber must be light-tight before any reading means anything.",
         "Black PETG, ≥4 perimeters, interior painted matte black. Test: cartridge in, "
         "room at 10,000 lux, all LEDs off, Clear channel under 0.5% of its LEDs-on value. "
         "Thin PETG passes more light than you would expect, and a leak quietly ruins the "
         "415 nm gate rather than failing loudly."),
        ("The camera lens comes off, and the exposure is fixed.",
         "Lensless speckle grain is about 4 px on an IMX219 at 20 mm, which is well sampled; "
         "with the lens fitted it is ~1.6 px and undersampled. Any auto-exposure or "
         "auto-white-balance between frames destroys the correlation measurement outright."),
    ]
    yy = ny + 24
    for head, body in notes:
        A(f'<text x="46" y="{yy}" font-size="11" fill="{INK}">{head}</text>')
        line, out = "", []
        for word in body.split():
            if len(line) + len(word) > 150:
                out.append(line); line = ""
            line += word + " "
        out.append(line)
        for i, ln in enumerate(out):
            A(f'<text x="46" y="{yy+16+i*14}" font-size="9.5" fill="{MUT}">{ln.strip()}</text>')
        yy += 16 + len(out) * 14 + 16

    H = int(yy + 20)
    o[0] = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" '
            f'width="{W}" height="{H}" '
            f'font-family="Helvetica Neue, Helvetica, Arial, sans-serif">')
    o[1] = f'<rect width="{W}" height="{H}" fill="#0C0C0B"/>'
    A("</svg>")
    OUT.write_text("\n".join(o))
    print(f"wrote {OUT}  ({len(phase1)} Phase 1 connections, from BUILD.md section 11)")
    for pin, fn in phase1:
        print(f"  {pin:<10} {fn[:64]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
