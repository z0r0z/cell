# Contributing

The design is public domain (CC0). The most valuable thing you can contribute
is **not code**.

## What this project actually needs

In order:

### 1. Spoof panel data from real hardware

Nobody has run the panel. Every threshold in `firmware/blood_gate.py` is
reasoned from physics and unmeasured. One person completing `BUILD.md` §13
Phase 1 and publishing their captures is worth more than every other
contribution combined.

Phase 1 is ~US$60 and one weekend. It has no security requirements because it
signs nothing. It answers the only question that determines whether the rest of
the project is worth building: **does the gate separate real blood from every
fake?**

To contribute a run:

```bash
python firmware/calibrate.py capture --label genuine     # x30+
python firmware/calibrate.py capture --label edta        # x30+  ... etc
python firmware/calibrate.py roc
```

Then open an issue with `thresholds.json`, the per-class table, and your
hardware notes — printer, filament, LED part numbers, camera. Captures are
`.npz` (plain arrays, no pickle) specifically so they can be shared and
replayed safely.

**Negative results are the most useful result.** If a red dye passes, or if
genuine blood fails G5, say so. A design that does not work should be found out
cheaply and publicly rather than expensively and privately.

### 2. Independent review of the physics

Particularly:

- **The speckle gate.** Is a lensless Pi Camera at 20 mm actually sampling
  speckle at 3–5 px? Does the spatial high-pass in `speckle_metrics` remove
  enough of the illumination envelope?
- **Gate 2.** Is a white-patch-normalised NIR/Clear ratio a real measure of
  cellular scatter, or is it dominated by something else?
- **Native clotting on PETG over 600 s.** The 35-minute figure this is derived
  from used glass microchannels, which are strong contact activators.

### 3. Security review

Nobody has audited this. The threat model is in `README.md` and
`BUILD.md` §16. The parts most worth attacking:

- The unlock chain in `BUILD.md` §12 — the seed touches RAM
- Nonce generation — `blood_noise_residual` feeds BIP-340 `aux_rand` only, and
  must never do more than that
- The policy floor, which is the entire two-tier argument
- What an attestation is worth given no secure boot on a Pi Zero 2 W

### 4. The wallet layer

`BUILD.md` §12 specifies forking [SeedSigner](https://github.com/SeedSigner/seedsigner)
and inserting the gate before `sign()`. That fork does not exist here. If you
write it, **do not write your own PSBT parser** — that is how people lose money
to change-address bugs.

## What this project does not need

- Rewrites in another language
- A score, a model, or a learned classifier in place of the named thresholds.
  The design rule is that a reviewer who is not the author can read
  `blood_gate.py` and see why a sample passed. A trained model destroys that
  and cannot be audited by the person whose keys depend on it.
- Features. The closed operation set in `BUILD.md` §5 is a deliberate scope
  decision, not an oversight.

## Ground rules

**Claim what you measured.** `calibrate.py` computes the rule-of-three bound
and refuses to print "FAR = 0" for a reason. A spec sheet that overstates its
validation is worse than none, and this is a device people would keep keys on.

**Read `SAFETY.md` before any build involving blood.** Do not share a device.
Do not reuse a lancet. Do not skip the sharps container.

**Keep the drawings generated.** `diagrams/mechanical.svg` comes from
`tools/gen_mechanical.py`; CI fails if they drift. If you change the model,
re-run the generator in the same commit.

## Running the tests

```bash
pip install -r firmware/requirements.txt
python firmware/run_tests.py
```

No hardware needed. This proves the logic is self-consistent and proves nothing
about any threshold — see `VALIDATION.md`.
