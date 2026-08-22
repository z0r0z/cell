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

`python firmware/run_tests.py` — nineteen suites, no hardware required.

### The signing stack

Every row here is checked against vectors published by someone else. A round
trip against our own implementation proves nothing, so none of these are that.

| Component | Method | Result |
|---|---|---|
| RIPEMD-160 | ISO reference vectors, incl. the 1 MB case | Byte-exact; also cross-checked against OpenSSL where available |
| Keccak-256 | Published vectors, plus rate-boundary lengths | Byte-exact; asserted to differ from SHA3-256, which is the mistake that silently produces wrong Ethereum addresses |
| ECDSA nonces | RFC 6979 secp256k1/SHA-256 vector | Byte-exact on both r and s |
| ECDSA signatures | OpenSSL verification of our output | Accepted; low-S and low-R enforced across 24 signatures |
| BIP-340 Schnorr | Published BIP-340 test vectors | Byte-exact match on pubkey and signature |
| BIP-341 tweaks | Private and public tweak agreement | Same output key by both routes; key-path signature verifies |
| BIP-39 | Official Trezor vectors, 12 and 24 words | Mnemonic and seed byte-exact at every length; wordlist SHA-256 verified on load |
| BIP-32 | Official vectors 1, 2 and 5 | xprv and xpub byte-exact; invalid keys refused; hardened derivation impossible from an xpub |
| bech32 / bech32m | BIP-173 and BIP-350, valid and invalid | All decode; wrong-variant checksums refused, which is the failure that burns taproot funds |
| EIP-55 | Vectors from the EIP | Byte-exact; a single flipped case is rejected |
| BIP-143 sighash | Published P2WPKH and P2SH-P2WPKH vectors | Byte-exact |
| BIP-341 sighash | Differential against an independent implementation | Byte-exact; asserted to commit to every input's amount |
| Transaction parsing | The block-170 mainnet transaction | Round trips byte for byte; txid matches the known value |
| RLP | Yellow-paper vectors | Byte-exact; negative, boolean and float inputs refused |
| EIP-1559 | Field-by-field differential | The digest changes if any of the seven signed fields changes |
| Cross-implementation | `embit` and `eth-account`, during development | Signatures byte-identical across four Bitcoin script types and six EVM chains. Neither package is a dependency |
| Two Schnorr copies | `attest.py` vs `secp256k1.py` | Pinned to agree on 8 keys, so the standalone copy in `attest.py` cannot drift |
| Attestation record | Pack/unpack round trip | 238 bytes, exact |
| Independent-verifier vectors | `firmware/vectors/attest-v1.json` packed by `attest.py`, re-verified in CI | Blob unpacks and `verify()` accepts; file is stale if it disagrees with a live `export_vectors()` |
| Attestation rejection | 8 negative cases | Wrong transaction, replayed counter, unknown firmware, unregistered calibration, swapped gate measurements, wrong signer, forged signature, wrong tier — all refused |
| Malformed input | 6 hostile inputs | Truncated, empty, bad magic, bad version, unknown tier, all-zero — all return a verdict, none raise |
| Quorum | 3-signer roster | Missing attestation fails; touch-tier attestation fails where blood is required |
| Tier policy | 12 cases | Escalation permitted, de-escalation refused, five locked classes enforced |
| Unlock chain | 41 checks | Step order asserted against `EXPECTED_ORDER`; render before all, confirm before PIN, gate before unwrap |
| Key binding | Differential | Wrapping key is stable across captures and transactions, so the seed stays recoverable; changing the PIN or the device secret changes it |
| Liveness in the record | Differential | The attestation commits to the gate measurements; a different capture attests a different hash |
| Operation set | 5 hostile payloads | Unknown type, bare hash, unknown field, missing field, non-object — all refused |
| Display safety | Width and height limits | Destinations shown in full; anything that does not fit is refused, never truncated |
| Secure element | 12 checks | Attempt debited before compare, wipe at 10, KDF context-bound and per-device |
| Blood gates | 18 sample classes | Each rejected at the physically correct gate; all 6 gates exercised |
| Touch gates | 9 sample classes | Each rejected at the correct gate; all 7 gates exercised |
| Calibration loop | Capture → sweep → load → re-verify | Thresholds written, loaded, and still separate the panel |
| Touch calibration loop | Same, for the touch tier | Every touch threshold set from captured sessions; calibrated set still separates the panel |
| Enrolment invariant | Reference emitted by `enroll-reference` | Reproduces the G4 clamp mask; 415 nm stays excluded |
| Hostile captures | 9 malformed captures | Zeros, NaNs, negative counts, short speckle — each rejected at a named gate, none raise |
| Mechanical drawing | Regenerated from the mesh | Byte-identical, enforced in CI |

### The wallet, end to end and under attack

`firmware/test_wallet.py`. The first group proves it works; the rest are the
ways hardware wallets have actually lost money, each written as a hostile
input whose pass condition is a refusal.

| Case | Result |
|---|---|
| Full unlock chain, 4 script types | p2wpkh, p2sh-p2wpkh, p2pkh, p2tr — signature verifies against the sighash; change recognised; attestation rides in the PSBT |
| Fee inflation | A witness UTXO alone is refused for segwit v0; one that disagrees with the parent is refused; a parent with the wrong txid is refused |
| Taproot exception | A witness UTXO alone IS accepted for p2tr, because BIP-341 covers every amount |
| Change substitution | Change we cannot derive is shown as a WARNING with the address in full, never as "your wallet" |
| Path lying | A real key quoted at a path that does not derive it is not treated as change; the correctly quoted version still is |
| Sighash downgrade | NONE, SINGLE, ANYONECANPAY\|ALL, ANYONECANPAY\|NONE all refused; an explicit ALL accepted |
| Unrenderable transactions | A batched payment and an OP_RETURN output both refused |
| Nothing to sign | A PSBT holding none of our keys is refused rather than silently returning unchanged |
| Malformed encodings | Truncated, trailing bytes, bad magic, duplicate map key, pre-signed unsigned transaction — all refused |
| The seed at rest | A wrong PIN, a tampered blob and a foreign chip all fail closed, with one message for all three |
| Ethereum | Recovers to the displayed sender; chain id, nonce and worst-case fee displayed; calldata and unnamed chains refused; the chain id changes the digest |
| Coordinator challenge | Nonce shown in full; attestation binds `SHA256(CELL/challenge/v1\|purpose\|nonce)`; spend-key Schnorr verifies; unknown purpose refused; Touch-default |
| The gate still governs | A spend above the floor demands blood; a failed gate signs nothing; cancelling at the prompt signs nothing |

Interoperability against published vectors is the meaningful result in both
tables — a round trip against your own implementation proves nothing.

## Written but unverified

| Component | Why | How to verify |
|---|---|---|
| `firmware/se_atecc.py` | Needs the chip. The interface conformance runs in CI; nothing that touches I2C does | `python3 firmware/se_atecc.py --probe` on a built device |
| `firmware/hardware.py` | Needs the sensor head | The bring-up checklist in that file |
| `firmware/qr.py` on real optics | The framing and reassembly are tested; scanning a real 240×240 screen with a real webcam is not | Scan a signed PSBT into a coordinator and back |
| Attestation key custody | The ATECC608B signs NIST P-256 only, so the secp256k1 attestation scalar is derived from a chip secret and exists in RAM while signing, rather than never leaving the chip | Stated in `se_atecc.py`; switch `attest.py` to P-256 if you need the stronger property |

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

Two measurements gate the design, and the reader kit makes both:

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
