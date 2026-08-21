# Changelog

## Rev 0.6 — first public release

The design is unchanged in intent. This revision fixes defects found in review
of Rev 0.5, closes the calibration loop, and states the validation status
honestly enough to publish.

**Nothing here has been validated on hardware. See `VALIDATION.md`.**

### Fixed — would have failed on a real build

- **Touch mode could not reach its own sample rate.** `read_ppg` used the
  chemistry integration time, 281 ms per channel, against a 20 ms budget for
  two channels at 50 Hz. The capture ran ~6× slow and was analysed at the
  nominal rate, so a healthy 68 bpm read as ~11 bpm and failed T3 for every
  genuine user. Touch mode now switches to a short integration time, measures
  the rate it actually achieved, and analyses at that rate. New gate **T0**
  refuses a capture too slow to analyse, reported as a hardware fault rather
  than a failed pulse.
- **Gates 1–4 were never evaluated early.** The chemistry was read at t = 5 s
  as documented, but nothing looked at it until the full 600 s capture
  finished, so an obvious spoof still took ten minutes. `acquire()` now
  evaluates and aborts at the early read.
- **Gate 1 could not reject a bright sample.** It was a floor, so an empty
  white well (~0.97 of the white patch) and the NULL pre-flight cartridge (a
  bright red swatch, ~0.58) both passed it — contradicting the §5 pre-flight
  procedure, which says NULL must fail Gate 1. Gate 1 is now a window.
- **Gate 2 measured LED drive current, not cellular scatter.** Clear is read
  under the white LED and NIR under the 940 nm LED, and the raw ratio was the
  only gate with no white-patch normalisation — so it drifted with LED aging,
  the exact effect the printed patch exists to cancel. Both channels are now
  normalised before the ratio.
- **Gate 4 had almost no dynamic range.** SAM over all eight channels of
  clamped absorbance put every blood-like spectrum above 0.99: deoxygenated
  blood scored 0.991 against a 0.985 threshold and was **accepted**. The
  clamped channels carry no shape information by construction. SAM now runs
  over the unclamped channels only — genuine 0.99999, deoxyHb 0.98821 — and
  the threshold moved to 0.995.
- **Speckle decorrelation measured the beam, not the sample.** Frames were
  correlated raw, so the static illumination envelope dominated and could hold
  the correlation above 0.5 with the speckle fully boiling, failing G5 on
  genuine blood. Frames are now spatially high-passed individually, and
  contrast is measured locally.
- **`thresholds.json` was written but never read.** A calibration run produced
  a file nothing consulted, leaving the device on shipped defaults while every
  report said "calibrated". `Thresholds.load()` and `TouchThresholds.load()`
  now read it, with `provenance()` for the About screen.
- **`blood_above = 0` meant the opposite of how it reads.** It disabled
  amount-based escalation — touch for everything — while scanning as "blood
  above zero". Someone hardening their device would have set it. `None` is now
  the off switch; `0` means blood for any positive amount.
- **A malformed attestation crashed the verifier.** An unknown tier byte raised
  out of `unpack`. Added `verify_blob()`, which turns any malformed record into
  a `Verdict`, and self-tests for truncated, empty, wrong-magic, wrong-version,
  unknown-tier and all-zero input.
- **`tools/gen_mechanical.py` had a hardcoded absolute path** from the machine
  it was written on and could not run.

### Calibration

- `roc` now sets **every** threshold in `Thresholds`, not just two, driven off
  a single `TUNABLE` table. Thresholds are set from the genuine distribution
  rather than from a gap to the spoofs, because each gate owns its own physics
  — then the false-accept rate is measured through the conjunction.
- Quantiles land on observed samples rather than interpolating, and thresholds
  round outward. Both bugs independently produced 100% FRR on perfectly
  consistent data.
- Reported FRR is now labelled in-sample, because it is.
- Captures are `.npz`, not `pickle` — a spoof panel is only useful if it can be
  shared, and unpickling a file someone sent you executes it.

### Testing

- `firmware/run_tests.py` runs every suite, including a full
  capture → sweep → load → re-verify calibration round trip.
- Both panels now fail if any gate stops being exercised by at least one class.
- Added panel classes: `deoxygenated` (the G4 negative), `null_cartridge` and
  `reference` (the two sealed pre-flight cartridges), `slow_capture` (T0).
- Synthetic sample shapes are set by what each material physically does in a
  0.55 mm semi-infinite well rather than by what made the test pass.
- CI on 3.10 and 3.12, plus a check that the mechanical drawing has been
  regenerated from the model.

### Documentation

- `VALIDATION.md`, `SAFETY.md`, `CONTRIBUTING.md` added.
- Repository reorganised into the layout the README already described:
  `firmware/`, `models/`, `diagrams/`, `tools/`, `viewer/`.
- `viewer/model.js` is named as the parametric source of the enclosure;
  `instrument.obj` is its export, not the master.

## Rev 0.5

Initial design.
