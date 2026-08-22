# Verification status

What has been verified, by what method, and what is scheduled for first build.
This is the engineering status record — `README.md` is the product description
and `BUILD.md` is the specification.

Instruments are calibrated to their hardware before use. CELL is no different:
the thresholds ship as physics-derived defaults, and `calibrate.py` replaces
them with values measured on your own optics, your own printer and your own
samples. That step is part of the build, not a caveat about it.

---

## Verified in CI, every commit

`python firmware/run_tests.py` — seven suites, no hardware required.

| Component | Method | Result |
|---|---|---|
| BIP-340 Schnorr | Published BIP-340 test vectors | Byte-exact match on pubkey and signature |
| Attestation record | Pack/unpack round trip | 206 bytes, exact |
| Attestation rejection | 7 negative cases | Wrong transaction, replayed counter, unknown firmware, unregistered calibration, wrong signer, forged signature, wrong tier — all refused |
| Malformed input | 6 hostile inputs | Truncated, empty, bad magic, bad version, unknown tier, all-zero — all return a verdict, none raise |
| Quorum | 3-signer roster | Missing attestation fails; touch-tier attestation fails where blood is required |
| Tier policy | 12 cases | Escalation permitted, de-escalation refused, five locked classes enforced |
| Unlock chain | 41 checks | Step order asserted against `EXPECTED_ORDER`; render before all, confirm before PIN, gate before unwrap |
| Key binding | Differential | Changing the gate measurements or the transaction changes the wrapping key |
| Operation set | 5 hostile payloads | Unknown type, bare hash, unknown field, missing field, non-object — all refused |
| Display safety | Width and height limits | Destinations shown in full; anything that does not fit is refused, never truncated |
| Secure element | 12 checks | Attempt debited before compare, wipe at 10, KDF context-bound and per-device |
| Blood gates | 17 sample classes | Each rejected at the physically correct gate; all 6 gates exercised |
| Touch gates | 9 sample classes | Each rejected at the correct gate; all 7 gates exercised |
| Calibration loop | Capture → sweep → load → re-verify | Thresholds written, loaded, and still separate the panel |
| Enrolment invariant | Reference emitted by `enroll-reference` | Reproduces the G4 clamp mask; 415 nm stays excluded |
| Hostile captures | 9 malformed captures | Zeros, NaNs, negative counts, short speckle — each rejected at a named gate, none raise |
| Mechanical drawing | Regenerated from the mesh | Byte-identical, enforced in CI |

Interoperability against the BIP-340 vectors is the meaningful result there —
a round trip against your own implementation proves nothing.

## Calibrated at first build

These are set by `calibrate.py roc` from your captures. Defaults are derived
from published physics and are starting points by design, the way any
instrument ships with a nominal calibration.

| Threshold | Physical basis |
|---|---|
| `soret_index_min` | Haem Soret band at 415 nm, ~10× stronger than any other visible feature |
| `return_min` / `return_max` | Whole blood in an optically semi-infinite well is dark, but not black |
| `nir_scatter_min` | Intact cells scatter in NIR where haemoglobin barely absorbs; solutions do not |
| `sam_cos_min` | Spectral angle over the unclamped channels. Genuine 0.99999, deoxyHb 0.98821 |
| `d_liquid_min`, `d_clot_max` | Speckle from a liquid suspension decorrelates fully; a clot is static |
| `duration_s` | Native clotting on PETG, with margin over published glass-microchannel work at 35 min |
| Touch thresholds | Perfusion index, respiratory sinus arrhythmia, ratio-of-ratios |

`calibrate.py` sets every one of them from your own genuine captures, measures
the false-accept rate through the conjunction of all six gates, and states the
rule-of-three bound your sample size supports. It will not print "FAR = 0",
because no achievable garage sample size supports that claim.

Target: zero acceptances across the panel, FRR ≤ 5% on captures taken after
calibration.

## Scheduled for first build

Two measurements gate the design, and Phase 1 makes both for about $60:

**Speckle sampling.** Lensless grain is ~λz/D ≈ 4 µm at 20 mm, about 4 px on an
IMX219. `hardware.py` includes the check: autocorrelate one frame, confirm the
central peak spans 3–5 px. Frames are spatially high-passed before correlation
so the static beam envelope cannot masquerade as a frozen speckle field.

**Gate 2 separation.** Clear reads under the white LED and NIR under the 940 nm
LED, both normalised against the cartridge's printed white patch so the ratio is
a property of the sample rather than of the two drive currents. The separation
between a cellular suspension and a dye solution is the number to confirm.

Milestone 5 in `BUILD.md` §15 — spectrum of dye against your own blood — is the
"it works" moment, and it is reachable in a weekend.

## Not yet built

- **Chain encoding and the UI.** `firmware/signer.py` is the unlock chain and
  the closed operation set, with the secure element, the gate, the policy and
  the attestation wired together and tested. What remains is PSBT
  serialisation, BIP32 derivation, the ST7789 screen and QR transport —
  `BUILD.md` §12 specifies forking SeedSigner for exactly that, and `Signer`
  takes them as injected collaborators so the fork plugs in without touching
  the chain.
- **Long dormancy.** The sealed REFERENCE and NULL cartridges exist to catch
  optics drift over a year in a drawer; they are checked at every pre-flight.
- **Population-scale false-reject rate.** Clotting time moves with hydration,
  temperature and medication.
- **Recalcified citrate.** Not a gap in the measurement, a stated limit of the
  method: citrate anticoagulation is reversed by adding calcium, so a citrated
  sample recalcified before loading starts liquid, arrests, and passes G5 and
  G6. EDTA is not practically reversible and stays rejected. `BUILD.md` §16
  carries the reasoning and the scope this leaves the blood tier.

## Contributing a measurement

Panel data from real hardware is the most valuable contribution to this
project. Captures are `.npz` — plain arrays, safe to share and replay. See
`CONTRIBUTING.md`.
