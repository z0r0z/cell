# Validation status

What is established, what is assumed, and what nobody has checked. Read this
before deciding what to trust and before repeating any claim from `README.md`
elsewhere.

**Summary: no part of this device's sensing has been validated on hardware.
The logic self-tests; the physics does not. Do not put money on it.**

---

## The three levels of claim

| Level | Meaning | How much of CELL is here |
|---|---|---|
| **Proven** | Tested, reproducibly, against the thing itself | The cryptography, and nothing else |
| **Self-consistent** | The code does what the code says | All gate logic, policy, attestation |
| **Reasoned** | Derived from published physics, never measured here | Every sensing threshold |

Most of this project is at level 3. That is a legitimate place for a design to
start. It is not a place to keep keys.

---

## Proven

Run `python firmware/run_tests.py`.

- **BIP-340 Schnorr.** `attest.py` is checked against the published BIP-340
  test vectors, not merely against itself. A round trip with your own
  implementation proves nothing; matching the vector proves interoperability.
- **Attestation record format.** Packs, unpacks, round-trips at 174 bytes.
  Rejects wrong-transaction, replayed-counter, unknown-firmware, wrong-signer,
  forged-signature, truncated, and malformed-tier records without raising.
- **Quorum semantics.** A missing attestation fails; a touch-tier attestation
  fails where blood is required.
- **Tier policy.** Escalation permitted, de-escalation refused, the five
  permanently blood-locked classes enforced, `blood_above` sentinel behaviour.

These are real results because the thing being tested is entirely in software.

## Self-consistent

- **Six blood gates and seven touch gates** behave as designed against
  synthetic sample classes, and every gate is exercised by at least one class
  (the self-test fails if that stops being true).
- **The calibration loop closes**: capture → sweep → `thresholds.json` →
  `Thresholds.load()` → the device uses them.

**The synthetic sample classes are not data.** They are hand-written shapes
chosen to exercise the pipeline. They cannot validate a threshold, and a
passing self-test is not evidence that real ketchup is rejected. `calibrate.py`
prints this every time it runs, deliberately.

## Reasoned but unmeasured

Every number below is a first-principles starting point. Each has a physical
argument behind it and none has been compared to a sample.

| Threshold | Basis | Risk if wrong |
|---|---|---|
| `soret_index_min` 0.75 | Haem Soret band at 415 nm is ~10× any other visible feature | Too low: a dark red non-porphyrin passes. Too high: genuine rejected |
| `return_min` / `return_max` | Whole blood in a semi-infinite well is dark but not black | Ceiling untested against real cartridge whites |
| `nir_scatter_min` 2.2 | Intact cells scatter in NIR; dye solutions do not | **Least anchored of the chemistry gates** — see below |
| `sam_cos_min` 0.995 | Restricted to unclamped channels; deoxyHb measured at 0.988 against a synthetic reference | The reference spectrum itself is reasoned, not enrolled |
| `d_liquid_min` 0.60, `d_clot_max` 0.25 | Speckle from a liquid suspension decorrelates fully; a clot is static | **Least validated part of the design** — see below |
| `duration_s` 600 | Native clotting on PETG, with margin over published glass-microchannel work at 35 min | Too short: genuine samples rejected as never-clotting |
| All touch thresholds | Standard PPG physiology (perfusion index, RSA, ratio-of-ratios) | The optical path is unusual — a phosphor white LED as the red source |

### The two weakest links, stated plainly

**1. The speckle gate.** The physics is established and the signal is large,
but this specific implementation — plastic well, lensless camera, 600 s window
— has never been run. The known failure mode is that the static illumination
envelope dominates the frame-to-frame correlation and `D` reports the beam
rather than the sample. `speckle_metrics` spatially high-passes each frame to
remove it, and the autocorrelation check in `hardware.py` verifies the speckle
is sampled at 3–5 px. **Neither has been confirmed on real hardware.** If the
grain is undersampled, `D` reads low regardless of what the sample does and
genuine blood fails G5.

**2. Gate 2, cellular scatter.** Clear is read under the white LED and NIR
under the 940 nm LED. Both are normalised against the cartridge's white patch
so the ratio is a property of the sample rather than of the two drive currents
— but the resulting value has been reasoned, never measured. Expect this to be
the first threshold that needs moving.

## Not addressed at all

- **Dormancy.** Nobody has built this, left it in a drawer for two years and
  taken it out. The sealed REFERENCE and NULL cartridges exist because that is
  the risk; they are a mitigation, not evidence.
- **Cartridge manufacturing repeatability** beyond one printer.
- **Inter-person variation.** Clotting time moves with hydration, temperature
  and medication. The false-reject rate across a population is unknown.
- **The wallet layer.** Not written. `BUILD.md` §12 specifies forking
  SeedSigner; that fork does not exist in this repository.
- **Security review.** Nobody has audited this. It is a design grounded in
  correct physics and standard cryptographic construction, not a product.

## What a validation run would have to show

`BUILD.md` §13 is the procedure. The finish line is Milestone 7:

- ≥30 captures per class across the full spoof panel, ≥100 for a meaningful bound
- Zero acceptances in every non-genuine class
- FRR ≤ 5% measured on captures taken **after** the thresholds were set, not
  the ones they were fitted to
- The rule-of-three bound stated honestly: 0 acceptances in *n* trials means
  FAR ≤ 3/*n* at 95% confidence, and nothing better

`calibrate.py` computes and prints that bound, and refuses to let you write
"FAR = 0".

## Reporting

If you build one and the panel behaves differently — in either direction —
that is the single most valuable contribution this project can receive. See
`CONTRIBUTING.md`.
