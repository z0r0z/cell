# Contributing

The design is public domain (CC0). Build it, fork it, sell it. No permission
needed, no attribution required.

Measurements are worth more here than patches, because the design is written
and the physics is not confirmed. In rough order of usefulness:

### 1. Spoof panel data from real hardware

**A panel run is a partial claim on the build bounty. See `BOUNTY.md`.**

The reader kit is $62 of hardware plus $31 of consumables, and it produces the
number this whole design turns on: how cleanly the gate separates real blood
from every fake. Every threshold in `firmware/blood_gate.py` is derived from
published physics. Panel data turns those into measured values with a stated
confidence bound.

Different optics, different printers, different bodies. Each independent run is
another condition the threshold set has to survive.

```bash
python firmware/calibrate.py capture --label genuine     # x30+
python firmware/calibrate.py capture --label edta        # x30+  ... etc
python firmware/calibrate.py roc
```

Then open an issue with `thresholds.json`, the per-class table, and your
hardware notes: printer, filament, LED part numbers, camera. Captures are `.npz`
(plain arrays, no pickle) specifically so they can be shared and replayed
safely.

Surprises are the most valuable thing you can post. If a dye clears a gate, or
genuine blood trips G5 on your optics, that is a finding. It says something no
amount of passing runs will.

`calibrate.py` prints the rule-of-three bound next to your results and will not
print `FAR = 0`, so the claim you publish is already the claim your sample size
supports.

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

The threat model is in `BUILD.md` §16. The cryptography is standard construction
verified against published test vectors. The parts most worth attacking:

- The unlock chain in `BUILD.md` §12, where the seed touches RAM
- Nonce generation. `blood_noise_residual` feeds BIP-340 `aux_rand` only, and
  must never do more than that
- The policy floor, which is the entire two-tier argument
- What an attestation is worth given no secure boot on a Pi Zero 2 W

### 4. The wallet layer

The unlock chain, the closed operation set and the renderer are written and
tested in `firmware/signer.py`. `Signer` takes four collaborators by injection:

```python
Signer(se, policy, fw_hash,
       confirm,      # (lines) -> bool      CONFIRM on GPIO26
       run_gate,     # (Tier)  -> (ok, att) touch_gate / blood_gate
       unwrap_seed,  # (key)   -> bytearray AES-GCM open of the stored seed
       sign_digest)  # (seed, sighash) -> bytes
```

Those are supplied now: `firmware/wallet.py` for the seed and the signing,
`firmware/app.py` for the loop, and the modules under it for PSBT, BIP-32 and
the screen. `BUILD.md` §12 explains why they were written here instead of taken
from [SeedSigner](https://github.com/SeedSigner/seedsigner), which is still the
reference worth reading for the parts this repo does not solve.

What is left is review. A hand-rolled PSBT parser is how change-address bugs
happen, which is why this one is checked against published vectors, against two
independent implementations, and against a real node in `tools/regtest_e2e.py`.
Another pair of eyes on it is the most useful thing you can bring.

## Scope

Three things get turned down often enough to be worth saying in advance. Each
one would cost a property the design is built on.

**New operations to sign.** The closed set in `BUILD.md` §5 is what lets the
device render everything it signs as a sentence a human can check. Every
addition spends some of that, so the bar is high. It is a discussion and not a
wall: open an issue before writing the code.

**A score, a model, or a learned classifier in place of the named thresholds.**
Someone who is not the author has to be able to read `blood_gate.py` and see why
a sample passed. A trained model cannot be audited by the person whose keys
depend on it.

**Rewrites in another language.** Nothing against the language. There is one
build and one set of eyes on it.

## Practicalities

Anything involving blood: `SAFETY.md` first. One device per person, one lancet
per use, sharps container.

The drawings are generated. `diagrams/mechanical.svg` comes from
`tools/gen_mechanical.py` and CI fails if they drift. If you change the model,
re-run the generator in the same commit.

```bash
pip install -r firmware/requirements.txt
python firmware/run_tests.py
```

No hardware needed. 44 suites covering the signing stack, the gates, the tier
policy, the attestation format and the calibration round trip. `VALIDATION.md`
is the engineering status record.

Prose in the reference documents is linted:

```bash
python3 tools/prose_lint.py
```

It keeps BUILD, VALIDATION, PRINTING and SAFETY flat. The budgets are a
ratchet. Lowering one is a contribution.
