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

`python firmware/run_tests.py` — twenty-nine suites, no hardware required.

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
| Drift invariance | LED aging, gain drift, ambient leak, beam envelope | Gate scores do not move: the white patch divides the first two out, the dark read subtracts the third, the spatial high-pass removes the fourth |
| Drift margins | 7 disturbance axes, bisected | Tightest budget reported and ranked; a finite tolerance on an invariance axis fails the suite |
| Mechanical drawing | Regenerated from the mesh | Byte-identical, enforced in CI |

### Multisig, and the registry it depends on

| Case | Result |
|---|---|
| 2-of-3 p2wsh, full unlock chain | Partial signature present and verifying against the BIP-143 sighash; only our key signed for |
| 2-of-3 p2sh-p2wsh | Signs; both BIP-48 script types covered |
| Quorum on the confirmation screen | "MULTISIG 2 of 3" and "signature 1 of 2", rebuilt from the registered co-signers rather than read off the host's script |
| Unregistered quorum | Refused before the gate — a device that signs a quorum it cannot describe cannot tell yours from someone else's |
| **A co-signer swapped in a change output** | Not treated as change; shown as a WARNING with the address in full. This is the attack registration exists to stop |
| A co-signer quoted at a different index | Not change |
| BIP-67 ordering flipped | Not change |
| Witness script absent, or not a bare m-of-n | Not change; a non-multisig witness script is refused at the input |
| Registering a quorum we are not in | Refused |
| Registering one that quotes a foreign xpub under our fingerprint | Refused |
| 4-of-3, or a duplicate label | Refused |

### PSBT version 2 (BIP-370)

| Case | Result |
|---|---|
| v2 rebuilt into a transaction | Byte-identical to the v0 form of the same PSBT |
| v2 signed | Same signature as v0, returned as v2 rather than silently downgraded |
| v2 under attack | Two destinations and a lying witness UTXO refused exactly as in v0 |
| Malformed v2 | Missing input count, previous txid, output index; short version or txid — all refused |
| Locktimes | A required height locktime overrides the fallback; requiring both a height and a time locktime is refused as unsatisfiable |
| An unknown PSBT version | Refused by name, not guessed at |

### The application loop

`firmware/test_app.py`. The device driven end to end with fake display, buttons
and camera — the seams between parts that are individually correct.

| Case | Result |
|---|---|
| A scanned PSBT, start to finish | Signed; emitted frames reassemble into a PSBT carrying both the signature and the attestation |
| Ordering | The transaction is displayed before the PIN is asked for, the PIN before the gate runs |
| Declining | At the confirmation, at the PIN, and at the gate — nothing signed, nothing emitted, and the owner told so |
| A wrong PIN | Refused, gate never reached, attempts remaining shown |
| Hostile input | A PSBT with none of our keys, a truncated one, a two-destination one, a QR that is not a transaction, foreign JSON, an Ethereum request with an unknown or missing field — every one refused as a readable screen, never a traceback |
| An incomplete scan | Reported in words rather than hung on |
| Ethereum | Signed; chain, chain id, nonce and worst-case fee all on screen; raw transaction emitted as a typed envelope |
| Multisig | A registered quorum signs and shows its threshold; an unregistered one is refused before the gate |
| Tier policy | A spend above the floor demands blood and says what that costs; a small one runs at touch |
| Read-only screens | The receiving address matches what the seed derives, with nothing unlocked to show it |
| Every screen, everywhere | None overflowed 40 columns or 20 rows |
| **The seam to the sensing half** | `app.gate_result` adapted against the gates' REAL outputs, not a mock: a genuine blood capture and a genuine touch capture pass, ketchup and a pumped silicone finger fail with a message naming the gate. The two tiers report measurements under different keys — blood `gate_scores`, touch `features` — and `liveness_digest` reads both, so two captures at either tier attest to different measurements |

### The secure element driver

`firmware/test_se_atecc.py`, against a fake chip. This is logic coverage, not
evidence about silicon — the fake holds slot secrets in memory, which is the
one thing the real part does not do.

| Case | Result |
|---|---|
| An unlocked chip | Refused outright, with a message saying how to fix it |
| The attempt counter | Spent before the comparison; the cost survives a power cut |
| A correct PIN | Restores the budget by moving the on-chip baseline, never by winding the counter back |
| A baseline ahead of the counter | Treated as tampering and refused |
| The wipe | Overwrites the wrapping slot; the correct PIN cannot revive the device, across a power cut |
| The KDF | Refuses without a spent attempt, and is single use |
| The attestation key | Stable, per-chip, verifies against its own pubkey, and is not the wrapping key |

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
| The gate still governs | A spend above the floor demands blood; a failed gate signs nothing; cancelling at the prompt signs nothing |

Interoperability against published vectors is the meaningful result in both
tables — a round trip against your own implementation proves nothing.

### Verified without the hardware

These close part of what used to be listed below as unverifiable. None of them
say anything about the parts themselves; they say the code addresses those
parts correctly, which is a different failure mode and the one that fails
silently.

| Component | Method | Result |
|---|---|---|
| cryptoauthlib calls | Signatures introspected from the installed package and compared to ours | All eight match. **Found two real defects**: `atcab_checkmac` was called with six arguments where the binding takes five, and the data zone was read using the lock-zone constant, which names a different region. Both imported cleanly and would have reached a bench |
| The PIN mechanism | Read against what CheckMac actually does | **Redesigned.** CheckMac compares a MAC the *host* computed, so the host must know the slot secret — which here it must not. Replaced with a verifier the chip computes under a slot key that never leaves it |
| Zone constants | Cross-checked against the binding's own docstrings | `LOCK_ZONE_*` and `ATCA_ZONE_*` are different namespaces with different values; both now restated with the values the docstrings quote |
| ST7789, gpiozero, OpenCV, Pillow, qrcode | Every argument, constant and return shape we use, introspected | All present and correctly used; the 320-row default is overridden |
| Script execution | `python-bitcoinlib`'s interpreter, under P2SH/DERSIG/STRICTENC/NULLDUMMY/CLEANSTACK/MINIMALDATA | p2pkh and bare 2-of-3 multisig **execute and succeed**; mangled, lifted, wrong-key, wrong-sighash-byte, out-of-order, short-quorum and non-empty-dummy variants all fail. Witness execution is not covered — that library predates segwit |
| `app.load_device` | Built from a real provisioned directory and driven to its idle screen | Assembles; exercises `provision.load`, the account records and the display path |

## Written but unverified

| Component | Why | How to verify |
|---|---|---|
| `firmware/se_atecc.py` | Needs the chip. The logic around it is now covered against a fake transport; nothing that touches I2C is | `python3 firmware/se_atecc.py --probe` on a built device |
| `firmware/display.py` | Needs the panel. Layout limits and library calls are covered; the SPI timing, the font metrics and the Y offset many 240x240 panels need are not | Any screen on a built device |
| `firmware/buttons.py` | Needs the switches. Consent and debounce logic and the library calls are covered; whether 30 ms actually settles YOUR switches is not | Press each button on a built device |
| `firmware/camera.py` | Needs the webcam. Collection, framing and the OpenCV calls are covered; whether a cheap lens focuses on a 240x240 panel is not | Scan a signed PSBT into a coordinator and back |
| Segwit and taproot on a node | No interpreter available here supports witness execution | Broadcast one testnet transaction |
| The ATECC608B config zone | The LimitedUse binding between slot 0 and Counter0 is what makes the attempt counter real, and no software can confirm it from outside | `se_atecc.py --probe`, then try eleven wrong PINs on a device you can afford to wipe |
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
