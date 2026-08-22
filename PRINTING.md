# Printing CELL

Everything printable comes out of one command. This file is the order to print
in, what to check before moving on, and the post-processing that is not
optional. Dimensions live in [`models/print/MANIFEST.md`](models/print/MANIFEST.md),
which is generated from the same constants as the STLs — when this file and
the manifest disagree about a number, the manifest is right.

## 0. Generate the parts

```bash
python3 tools/gen_printables.py     # -> models/print/*.stl + MANIFEST.md
```

The STLs are committed, so you can slice them straight from a clone and skip
this. Run it anyway if you have changed anything, and always after editing a
constant: the generator validates every mesh, runs the fit checks, and exits
non-zero rather than hand your slicer something it would have to guess at. CI
runs the same command and fails if the committed STLs are not what it
produces.

Ten parts. Nothing needs supports.

## 1. What you need

| | |
|---|---|
| Printer | Anything with a 120 × 80 mm bed that can hold PETG temperatures |
| Black PETG | ~90 g — shells, optics, bezel |
| White PETG | ~60 g — cartridges. A *different spool*, not "light grey" |
| Matte black paint | Acrylic or model paint, for the optical bores |
| M2.5 heat-set inserts | 6, plus a soldering iron with an insert tip |

**PETG, not PLA.** PLA creeps under screw preload and softens in a hot car.
This is not a preference.

**The white spool is a measuring instrument.** Every cartridge carries the
white reference patch that every reading is normalised against, so print the
whole batch from one spool in one session. Switching filament mid-batch walks
your thresholds without telling you.

## 2. Print order

Print in this order. Each stage tells you something about the next one, and
the first stage is cheap.

### Stage 1 — one cartridge

Print a single `cartridge.stl` before anything else. It is the smallest part
and the most demanding one: the white patch and the well floor must both come
out as clean ironed top surfaces.

**Check before continuing:** the patch is smooth and matte, with no gaps
between ironed lines. Hold it to the light at an angle. If it is ridged or
glossy-then-dull in patches, fix your ironing (flow, speed, and top-layer
temperature) now — every gate in the device is normalised against this
surface.

### Stage 2 — the cartridge batch

Plate 20 of them, plus one `cartridge_reference.stl` and one
`cartridge_null.stl`. That is [BUILD.md §15](BUILD.md) milestone 3, and it is
a measurement, not a stockpile: read the white patch on all 20 and require
**under 3% spread after normalisation**. If they do not agree with each other,
they will not agree with themselves next month either — fix the printer here.

The REFERENCE and NULL bodies must come off the same spool in the same
session as the batch they are the reference for.

### Stage 3 — the optics

`optical_head.stl`, `aperture_tube.stl`, `slot_baffle.stl`. Black PETG, fine
layers, and the orientations in the manifest — open face down for the head,
flange down for the tube.

These three are the light-tight chamber. They are also the parts where
"looks fine" and "works" are different things: see post-processing below.

### Stage 4 — the shells

`shell_lower.stl` and `shell_upper.stl`, part line down, seam at a corner.
These two are most of the filament and most of the hours — the print worth
babysitting the first layer of.

**Check before continuing:** the tongue on the lower shell enters the groove
in the upper without forcing, and the two close with no visible gap at the
part line. There is 0.15 mm of clearance designed in — if it is tight, your
printer is running wide and the cartridge slot will be tight too.

### Stage 5 — the bezel, last

`display_bezel.stl`, once the display module is physically in your hand.

**This is the only part fitted to hardware the specification does not pin
down.** BUILD.md buys "an ST7789 1.3 in 240×240"; those boards differ between
vendors in where the active area sits on the PCB and where the mounting holes
are. Measure yours, set `SCREEN_W`, `SCREEN_H` and `SCREEN_OFFSET_Y` at the
top of `tools/gen_printables.py`, and regenerate. If the mounting holes miss
the four posts, move `DISPLAY_POST` in `tools/gen_enclosure.py` and regenerate
both — the posts are derived, not specified.

`check_bezel_geometry()` refuses anything that cannot fit or cannot print, so
a wrong number is a failed run rather than a wasted print.

### Also: the window jig

`window_jig.stl`, any filament, whenever. It is a cutting template for the PET
windows, not part of the instrument.

## 3. Post-processing

Four steps. The first two are load-bearing — the device does not work without
them.

**Paint every optical bore matte black.** The inside of the aperture tube and
the whole interior of the optical head. Black PETG is not optically black: it
reflects enough at grazing incidence to put stray light on the sensor, and
stray light is indistinguishable from a bright sample. Thin acrylic paint, two
coats, and keep it out of the bore's clear path.

**Fit the six heat-set inserts.** Ø3.6 × 6 holes in the lower shell, M2.5
inserts, soldering iron at ~230 °C, pressed in square and flush. Skewed
inserts are the usual reason an enclosure will not close.

**Cut and tape the PET windows.** Use the jig: 12 × 10 mm rectangles from
0.1 mm film, one per cartridge. Tape one long edge to the cartridge body with
3M 300LSE so it flips up to load and down to close — **the tape is the hinge**.
Handle the film by its edges; a fingerprint on the window is a calibration
error.

**Seal the pre-flight pair.** Put a known target in the REFERENCE well and
close it permanently; leave NULL bare. Record their baselines. REFERENCE must
pass the spectral gates and fail the liveness gate — it cannot move. NULL must
fail gate 1 on the bright side.

## 4. Before you call it printed

* [ ] 20 cartridges agree with each other within 3% after normalisation
* [ ] All optical bores are matte black inside
* [ ] Six inserts in, square and flush
* [ ] Shells close on the tongue and groove with no gap at the part line
* [ ] A cartridge slides to the first detent, then past it, without forcing
* [ ] Chamber light-tight: clear channel under 0.5% of LEDs-on at 10,000 lux
* [ ] REFERENCE and NULL sealed, baselines recorded

The light-tightness test is the one people skip. Every vent in the shell is a
**blind pocket** for exactly this reason — one vent that broke through to the
interior puts ambient light on the optical chamber and the 415 nm gate stops
working. Test it, do not eyeball it.

## 5. Used cartridges are biohazard

A cartridge that has held blood goes in the sharps container with the lancet,
not in household waste and not back in the slot. Read [`SAFETY.md`](SAFETY.md)
before you print the batch, not after.
