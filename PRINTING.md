# Printing CELL

Everything printable comes out of one command. This file is the order to print
in, what to check before moving on, and the post-processing the device does not
work without. Dimensions live in
[`models/print/MANIFEST.md`](models/print/MANIFEST.md), generated from the same
constants as the STLs. If this file and the manifest disagree about a number,
the manifest is right.

## 0. Generate the parts

```bash
python3 tools/gen_printables.py     # -> models/print/*.stl + MANIFEST.md
```

The STLs are committed, so you can slice them straight from a clone and skip
this. Run it if you have changed anything, and always after editing a constant.
The generator validates every mesh, runs the fit checks, and exits non-zero
instead of handing your slicer something it would have to guess at. CI runs the
same command and fails if the committed STLs are not what it produces.

Eleven parts. Nothing needs supports.

## 1. What you need

| | |
|---|---|
| Printer | Anything with a 130 × 90 mm bed that can hold PETG temperatures |
| Temperatures | 240 °C nozzle, 80 °C bed. Fix on one pair and hold it for the whole cartridge batch |
| Black PETG | ~90 g. Shells, optics, bezel, bay blank |
| White PETG | ~60 g. Cartridges. A *different spool*, not "light grey" |
| Matte black paint | Acrylic or model paint, for the optical bores |
| M2.5 heat-set inserts | 6, Ø3.5 knurled OD, plus a soldering iron with an insert tip |
| M2.5 × 16 screws | 6. They enter from the base and thread into the inserts in the upper shell |

**PETG, not PLA.** PLA creeps under screw preload and softens in a hot car. The
bosses lose their grip and the optical chamber stops being light-tight.

**Dry the white spool before the batch.** Four hours at 65 °C. PETG is
hygroscopic, and wet PETG's signature failure is a hazy, stringy top surface —
which is the surface every reading in this device is normalised against. A
builder who fails the Stage 1 check below and goes hunting through flow and
temperature will not find it there.

**The white spool is a measuring instrument.** Every cartridge carries the white
reference patch that every reading is normalised against. Print the whole batch
from one spool in one session. Switching filament mid-batch walks your
thresholds without telling you.

## 2. Print order

Each stage tells you something about the next one, and the first stage is cheap.

### Stage 1: one cartridge

Print a single `cartridge.stl` before anything else. It is the smallest part and
the most demanding. The white patch and the well floor must both come out as
clean ironed top surfaces.

**Check before continuing:** the patch is smooth and matte, with no gaps between
ironed lines. Hold it to the light at an angle. If it is ridged, or
glossy-then-dull in patches, fix your ironing now: flow, speed, and top-layer
temperature. Every gate in the device is normalised against this surface.

### Stage 2: the cartridge batch

Plate them, plus one `cartridge_reference.stl` and one
`cartridge_null.stl`. Twenty-two at 51 × 14 mm is three plates on a
130 × 90 bed, so run the plates back to back on the one spool. That is [BUILD.md §15](BUILD.md) milestone 3. It is a
measurement and not a stockpile: read the white patch on all 20 and require
**under 3% spread after normalisation**. Cartridges that do not agree with each
other will not agree with themselves next month. Fix the printer here.

The REFERENCE and NULL bodies must come off the same spool in the same session
as the batch they are the reference for.

### Stage 3: the optics

`optical_head.stl`, `aperture_tube.stl`, `slot_baffle.stl`. Black PETG, fine
layers, and the orientations in the manifest: open face down for the head,
flange down for the tube.

These three are the light-tight chamber. They are also the parts where "looks
fine" and "works" are different things. See post-processing below.

### Stage 4: the shells

`shell_lower.stl` and `shell_upper.stl`, part line down, seam at a corner. These
two are most of the filament and most of the hours. Babysit the first layer,
and on smooth PEI or glass put a glue-stick layer down first — PETG bonds to a
bare sheet hard enough to take a piece of it away with the part. Keep part
cooling low: the shells carry the screw preload PETG was chosen for, and fan
speed is what costs you layer adhesion.

**Check before continuing:** the tongue on the lower shell enters the groove in
the upper without forcing, and the two close with no visible gap at the part
line. There is 0.15 mm of clearance designed in, on the sides as well as over
the top, with a 0.4 mm lead-in on the tongue so the joint starts itself. If it is tight, your printer is
running wide and the cartridge slot will be tight too.

### Stage 5: the bezel, last

`display_bezel.stl`, once the display module is physically in your hand.

**This is the only part fitted to hardware the specification does not pin
down.** BUILD.md buys "an ST7789 1.3 in 240×240". Those boards differ between
vendors in where the active area sits on the PCB and where the mounting holes
are. Measure yours, set `SCREEN_W`, `SCREEN_H` and `SCREEN_OFFSET_Y` at the top
of `tools/gen_printables.py`, and regenerate. If the mounting holes miss the
four posts, move `DISPLAY_POST` in `tools/gen_enclosure.py` and regenerate both.
The posts are derived, not specified.

`check_bezel_geometry()` refuses anything that cannot fit or cannot print, so a
wrong number is a failed run instead of a wasted print.

### Also: the window jig

`window_jig.stl`, any filament, whenever. It is a cutting template for the PET
windows and no part of the instrument.

### And last of all: the bay blank

`bay_blank.stl`, black PETG, lip down so the 1.6 mm lip is not a ledge printed
into mid-air. It closes the rear compute bay, and it goes on **after
provisioning** — the bay is how you reach the Pi and its microSD during a
build. Fit it, then seal it.

## 3. Post-processing

Four steps. The first two are load-bearing.

**Paint every optical bore matte black.** The inside of the aperture tube and
the whole interior of the optical head. Black PETG is not optically black. It
reflects enough at grazing incidence to put stray light on the sensor, and stray
light is indistinguishable from a bright sample. Thin acrylic paint, two coats,
kept out of the bore's clear path.

**Fit the six heat-set inserts.** Ø3.6 × 6 holes in the **upper** shell, M2.5
inserts, soldering iron at ~230 °C, pressed in square and flush. Skewed inserts
are the usual reason an enclosure will not close. The screws come up from the
base through the lower shell and thread into these, so the heads finish
underneath and the display face stays unbroken.

**Cut and tape the PET windows.** Use the jig: 12 × 10 mm rectangles from 0.1 mm
film, one per cartridge. Tape one long edge to the cartridge body with 3M 300LSE
so it flips up to load and down to close. **The tape is the hinge.** Handle the
film by its edges. A fingerprint on the window is a calibration error.

**Seal the pre-flight pair.** Put a known target in the REFERENCE well and close
it permanently. Leave NULL bare. Record their baselines. REFERENCE must pass the
spectral gates and fail the liveness gate, since it cannot move. NULL must fail
gate 1 on the bright side.

## 4. Before you call it printed

* [ ] 20 cartridges agree with each other within 3% after normalisation
* [ ] All optical bores are matte black inside
* [ ] Six inserts in the upper shell, square and flush, and six M2.5 × 16
  screws reaching them from the base
* [ ] Shells close on the tongue and groove with no gap at the part line
* [ ] A cartridge slides to the first detent, then past it, without forcing
* [ ] Chamber light-tight: clear channel under 0.5% of LEDs-on at 10,000 lux
* [ ] REFERENCE and NULL sealed, baselines recorded

The light-tightness test is the one people skip. Every vent in the shell is a
**blind pocket** for this reason. One vent that broke through to the interior
puts ambient light on the optical chamber and the 415 nm gate stops working.
Test it. Do not eyeball it.

## 5. Used cartridges are biohazard

A cartridge that has held blood goes in the sharps container with the lancet.
Never in household waste, never back in the slot. Read
[`SAFETY.md`](SAFETY.md) before you print the batch.
