# CELL

A hardware wallet that needs a live pulse, or a drop of fresh blood, to authorise a transaction.

Airgapped signer for Bitcoin and Ethereum. Raspberry Pi, 3D-printed enclosure, $97.45 of hardware. Public domain.

<img src="diagrams/turntable.gif" alt="CELL enclosure, 116 x 73 x 28 mm" width="100%">

<sup>The ring is the sensor port. A fingertip on it, or a cartridge under it. It is a bezel, not a control; nothing rotates.</sup>

## What it is

Transactions arrive as a QR code read by the camera and leave as a QR code on the display, in either of the two framings the airgap ecosystem uses. There is no wifi, no bluetooth and no USB data path.

`BUILD.md` §11 describes an optional USB-C data variant, for a device that signs often from one machine. It costs two properties §16 sets out, and it is not the default.

To authorise a signature you enter an eight-digit PIN and pass one of two liveness proofs.

| | Touch | Blood |
|---|---|---|
| Action | Fingertip on the ring | A drop in a disposable cartridge |
| Duration | 15 seconds | 10 minutes |
| Consumable | None | Cartridge and lancet |
| Proves | A living body is present | A living body bled, just now |

Touch is the everyday default. Blood is a mode you enter deliberately.

A button press costs nothing, so malware, an automated script and a deliberate human decision all produce an identical signal. An act your body rate-limits separates them: one drop of blood is one signature, and no budget compresses that.

<img src="diagrams/how-it-works.svg" alt="How the two liveness tiers gate the signing key" width="100%">

## Status

**Firmware: complete.** 51 suites run on every commit, covering the signing stack against the vectors published in the BIPs, RFC 6979 and the EIPs, both liveness gates, the whole device loop, and the documented build sequence driven end to end. Bitcoin Core funds an address this firmware derives, and accepts and mines the spend it signs.

**Enclosure: complete.** Eleven parts are printed, all generated from the same constants the specification quotes, all mesh-checked and fit-checked before they are written.

**Sensors and secure element: written, not yet run on hardware.** The sensor head, the display, the buttons and the ATECC608B driver are code without a bench behind them. `VALIDATION.md` lists every claim in this repository and how it was checked, including the ones that are still open.

**Thresholds: calibrated on your build.** Sensing thresholds ship as physics-derived defaults. `calibrate.py` runs the spoof panel for both tiers against your own samples and writes the file the device loads. `BUILD.md` §13 is the procedure.

### Someone built one

**[Austin Griffith built a prototype and signed a transaction with fresh blood.](https://x.com/austingriffith/status/2097231722094191031)** Video, September 2026.

<a href="https://x.com/austingriffith/status/2097231722094191031"><img src="diagrams/first-build.png" alt="The blood gate running on the first prototype: laser warm-up, then gates G1 to G4" width="360"></a>

<sup>A frame from the video: the blood gate mid-run on the prototype's display, showing this design's chemistry sequence in the builder's own wording: G1 return signal, G2 cellular scatter, G3 Soret, G4 shape.</sup>

The first build outside this repository: assembled hardware, a sample in the chamber, and a signature that happened because the blood gate passed. That build did not send back any measurements, so `VALIDATION.md` is unchanged. Everything it lists as needing hardware still needs it.

**There is a [bounty](https://poidh.xyz/mainnet/bounty/24) for building one and signing with it.** `BOUNTY.md` says what a claim looks like. A reader-only build counts.

## Try it without hardware

The gate logic, the signing stack and the whole device loop run on any machine.

```bash
pip install -r firmware/requirements.txt
python firmware/run_tests.py           # all 51 suites
```

Or one piece at a time:

```bash
cd firmware
python calibrate.py selftest --n 8     # blood tier, 6 gates, 18 sample classes
python touch_gate.py                   # touch tier, 7 gates
python test_app.py                     # the whole loop, driven with fakes
python test_wallet.py                  # end to end, then every footgun
```

Each spoof class fails at the physically correct gate, and the self-test fails if any gate stops being exercised by at least one class.

You can also spin the enclosure. It is a parametric three.js model, not a static render, and you can export OBJ or glTF straight from the viewer:

```bash
python3 -m http.server -d viewer 8000     # then open localhost:8000/instrument.html
```

## Building one

Read `SAFETY.md` first. It is short, and it covers blood handling.

The build splits into two kits, bought separately. **Order the reader kit first.** It answers the question that decides whether the rest is worth building, it has no security requirements because it signs nothing, and it costs a third of the total.

### 1. The reader kit: $63 of hardware plus $31 of consumables

A Pi, a spectrometer, a laser, a lensless camera, LEDs, a printed optical chamber, and the lancets, film and cartridges to run them. One weekend.

Build it, then run the spoof panel in `BUILD.md` §13. If the gate does not separate real blood from every fake on your hardware, you stop here and you have spent $94.

### 2. The wallet kit: a further $34.70

The signing half: display, buttons, QR webcam, ATECC608B secure element, USB-C power, the printed shells and the ring window. Then provision a seed and do the airgap hardening: radios disabled, antenna trace cut, read-only rootfs.

### The documents

| | |
|---|---|
| `BUILD.md` | The specification. Parts, wiring, optics, cartridge, firmware, calibration, threat model |
| `BOM.csv` | Every part, with a `Kit` column saying which kit it belongs to and what to insist on |
| `PRINTING.md` | The print runbook: plate order, what to check at each stage, the post-processing that is not optional |
| `SAFETY.md` | Blood handling. Read it before the first build |

Eleven parts are printed, all from `python3 tools/gen_printables.py`, all checked before they are written. `models/print/MANIFEST.md` is generated in the same pass and carries every dimension, quantity and print setting.

**Running costs.** A touch signature costs nothing. A blood signature spends a lancet, an alcohol pad, a PET window and a printed cartridge: about twenty cents, restocked from any pharmacy. Nothing in the device is consumed by either, and nothing on the bill of materials has a shelf life.

## How the gates work

### Blood: six gates, all must pass

**Chemistry.** Haemoglobin absorbs strongly at 415 nm, the Soret band of the iron-bearing porphyrin ring at the centre of the molecule. The absorption is roughly an order of magnitude stronger than anything else in the visible spectrum, and no common red substance produces it. Ketchup, food dye, beet juice and theatrical blood all fail immediately. Three further gates confirm that the sample returns light at all, that it scatters in the near infrared the way a suspension of cells does rather than a dye solution, and that the full eight-channel spectrum matches oxygenated whole blood.

**Motion.** Colour cannot tell fresh blood from a stored sample, so the device measures movement instead. Under laser illumination a liquid suspension of red cells produces a speckle pattern that boils as the cells move; as fibrin forms it locks them in place and the pattern freezes. A camera watches for ten minutes and measures the frame-to-frame correlation.

Fresh blood is the only sample that starts decorrelated and becomes correlated. Anticoagulated blood never arrests. Clotted blood, corn syrup and gels never moved in the first place. Dye produces no speckle at all.

This works because of an asymmetry in how blood can be kept: blood you can store has been anticoagulated and will not clot in the chamber, and blood that was not anticoagulated has already clotted and cannot be poured into a well. `BUILD.md` §16 gives the one exception and how far it reaches.

Implementation in `firmware/blood_gate.py`, with every threshold in a single dataclass.

### Touch: seven gates, all must pass

Photoplethysmography through the same ring bore the cartridge sits under. Arterial blood volume in the fingertip changes with each heartbeat, so the light coming back carries a small pulsatile signal on a large steady one. The white LED gives a red channel and the 940 nm LED gives infrared, both sampled at 50 Hz by the spectrometer that is already there. No extra parts.

The gates check that the capture rate was high enough to analyse, that a finger is in contact, that the signal is pulsatile at a physiological depth, that the rate falls between 40 and 180 bpm, that the cardiac band dominates, that beat-to-beat variability is present, and that the red-to-infrared ratio matches haemoglobin.

The last two carry most of the anti-spoof weight. A silicone finger with dye pumped through it can produce a convincing pulse, but dye does not share haemoglobin's absorption ratio across the two wavelengths; and respiratory sinus arrhythmia puts a resting adult's beat-to-beat variability in the tens of milliseconds, where a mechanical pulsator produces single digits.

Implementation in `firmware/touch_gate.py`.

### Tier policy

You may always escalate to a higher tier than policy requires. You may never proceed at a lower one.

Policy sets a floor, and changing that floor is blood-locked in both directions. Loosening must cost blood, or a thief lowers the bar and uses their own finger. Tightening must cost blood too, or someone locks you out by raising your floor while you are travelling without cartridges.

Escalation applies to one operation and does not persist. Five operations are blood-locked at provisioning and cannot be unlocked: policy changes, key export, device wipe, reprovisioning, and changes to the recipient allowlist.

Implementation in `firmware/policy.py`.

## What else it does

### Attestation

A signature says nothing about what gated the key, so the tier is claimed separately. Each device holds an attestation key generated at provisioning and signs a 238-byte record binding the tier to a specific sighash, a monotonic counter, a firmware hash, the calibration in force and the gate measurements behind the claim.

Co-signers register each other's attestation keys once, alongside the firmware and calibration hashes they accept. Verifying that every member of a quorum signed at blood tier is then a mechanical check, and a missing attestation counts as a failure and never an abstention.

The record travels beside the PSBT in a BIP-174 proprietary field and is stripped before broadcast, so it does not appear on chain. Publishing it says "this address is a CELL device, and this spend was authorised with blood", which is a leak for a treasury, and the whole point for an allowlist, so it is an option and not a default.

A contract can check the record itself. `contracts/src/CellAttestation.sol` verifies the signature; `CellRegistry.sol` holds what the record cannot carry: whose key it is, the highest counter seen from it, and which firmware and calibration you accept. The BIP-340 Schnorr signature has no EVM precompile, so it is rearranged into one `ecrecover` plus a `modexp` to lift the point: about 41k gas to verify, 81k for a full `redeem`. The digest commits to the chain, the contract and the claimant, so a record cannot be replayed on a fork, against another deployment, or by someone else.

What that buys is a signature nobody can farm. A script produces a million; a body produces about two a day, each costing a lancet and ten minutes. Implementation in `firmware/attest.py`.

### One of these devices bled, and you cannot tell which

For an allowlist, a mint or a quorum vote, the claim worth publishing is "a human bled", not "device 7 bled".

`firmware/ring.py` signs as one member of a registered set, using LSAG over the same secp256k1 everything else here signs on. A key image `I = d · H(event ‖ P)` links two claims from one device in one event, so nobody votes twice, and leaves claims in different events unlinkable, so nobody accumulates a voting history.

The firmware and calibration hashes are deliberately left out. They are what makes the ordinary record auditable, and they are exactly what would narrow a ring of forty to a ring of three. The ring replaces them: a verifier admits a set of keys and checked their firmware when it registered them.

A ring of n costs about 2n scalar multiplications on each side, which is slow in pure Python and does not matter, because the ring computes while the sample clots. Use it off chain or in a coordinator-maintained allowlist; it is too expensive to verify on chain.

### Proof of life

Dead-man switches key off signing activity, which answers the wrong question. A stolen key resets the clock, and an owner who simply does not spend for a year looks dead. The touch gate measures a body, so CELL can tell them apart.

A beacon is the attestation with no transaction under it: fifteen seconds, no consumable, nothing signed with the seed. `CellRegistry.heartbeat` records when a living human was last proven present, and an inheritance path, a recovery quorum or a multisig can read it.

**The date on the screen is the security control.** The device has no clock. The period comes from the companion and is displayed as a date range, so the owner is the clock, and `heartbeat` accepts a beacon only while its period is current. A harvested record cannot be spent early or late.

`CellDormancy.sol` reads it in two phases on purpose: a claim releases nothing, it opens a challenge window, and one beacon during that window cancels it. Six months in a drawer is the ordinary case, and fifteen seconds of a fingertip undoes it.

## The signing stack

Both chains sign on secp256k1, so one key and one signing core serve both. The wallet half is implemented here rather than delegated because the gate reaches inside it: the tier decision, the confirmation screen and the attestation all depend on what the transaction actually says. Pure Python, with `cryptography` as the only dependency, used for AES-GCM.

| | |
|---|---|
| `secp256k1.py` | ECDSA with RFC 6979 nonces, low-S, low-R grinding, BIP-340 Schnorr, BIP-341 tweaks |
| `bip39.py` / `bip32.py` | Mnemonic and HD derivation, with the wordlist's SHA-256 checked on load |
| `psbt.py` / `tx.py` | BIP-174 and BIP-370 parsing, and all three sighash algorithms |
| `addresses.py` | bech32 and bech32m, every script type, EIP-55 |
| `eth.py` | RLP and EIP-1559, built on the device from fields it displays |
| `names.py` | WNS, GNS and ENS names the owner registered — routing, per-chain addresses, and the reverse the screen draws |
| `eip712.py` | EIP-712 typed data for smart accounts, the timelock the screen states, and the EIP-7702 delegation |
| `beacon.py` | The beacon digest, and the period the owner reads |
| `qr.py` | The airgap: `pNofM` frames, and reassembly that refuses substitution |
| `ur.py` | UR 2.0 with fountain codes, and EIP-4527, against the published vectors |
| `link.py` | The USB-C data variant's wire. Opt-in, and it costs two properties |
| `app.py` | The loop: scan, show, confirm, PIN, gate, sign, emit |

The device signs a closed set of operations it can render as readable text, and refuses everything else, including arbitrary EVM calldata. Two consequences look like missing features and are not: a PSBT paying several recipients is refused, because the owner can check one destination character by character and cannot check a total; and every Ethereum field (chain id, nonce, and `gas_limit × max_fee_per_gas`) is on the confirmation screen, with unrecognised chain ids refused.

**Handing over your accounts.** The device prints its extended public keys on screen, and will also emit them as one `ur:crypto-account` so a coordinator scans all four Bitcoin script types instead of somebody retyping an xpub. It signs nothing and needs no PIN. It sits behind a warning, because an account xpub reveals every address that wallet will ever use, forever, to whoever reads it.

**Both QR framings, and a browser.** Transfers arrive and leave as either `pNofM` frames (the Specter convention) or UR 2.0 (what Sparrow and the Keystone-compatible coordinators reach for), and the device replies in whichever it was asked in. UR is rateless, so a frame the camera never manages to read is recovered from a mixture of others instead of stalling the transfer — which matters on a $8 webcam. UR also carries EIP-4527, so MetaMask's and Rabby's QR-account flows work: the request arrives as `ur:eth-sign-request` and the answer goes back as `ur:eth-signature`. There the transaction arrives encoded rather than as fields, so the device rebuilds it, re-encodes it, and refuses if the two differ by a byte.

One operation carries calldata, and the way it does is the point. An **ERC-20 transfer** is signed for tokens the owner registered, and the device is never handed those 68 bytes — it is handed a token, a recipient and an amount, and it writes `transfer(address,uint256)` itself. Both addresses go on the screen in full, because an ERC-20 transfer is addressed to the *contract* and carries the *recipient* in its calldata, and one address on a screen is the wrong one. `decimals` comes from the registration and never from the request: it is where the decimal point goes, and a request that could supply it could render a millionth of a token as one whole token. `approve` is not implemented, and neither is any other selector.

**Names, on both chains.** A payee's `.wei`, `.gwei` or `.eth` name can sit above their address on the confirmation screen — WNS first, then GNS, then ENS, since this project co-developed WNS. The device never resolves one: it has no network, and a name that arrived with a transaction would be a label an attacker picked for an address you are about to approve. So names are registered like chains, tokens and quorums are — `tools/ethnames.py` resolves and forward-verifies on the host, you check the address against the name's own page, and `provision.py name` records the pair. The address stays on the screen in full, and it is still what the signature commits to.

All three systems are rooted on Ethereum mainnet and read through the same SLIP-44 coin types, so one name covers more than one chain: its default address is drawn on every EVM chain, a per-chain address (ENSIP-11) overrides it on the chain that published one, and a Bitcoin address (coin type 0) makes the same name a payee on a Bitcoin spend. Where a name publishes an override, the device refuses to draw that name over the default address on that chain — the same twenty bytes on two chains can be two different owners.

One exception earns its place. A smart account's timelock is not in the signed message, so the same signature means "send now" or "send in two days" depending on chain state the device cannot read — the delay is registered out of band and stated on the screen, along with whether every owner signing together can skip it. And `cancelQueued` is the one self-call the device will sign, at touch tier, because a device that can start a delay but not stop one has given its owner a countdown and no button.

Multisig and smart accounts must be registered before they can be signed, and this device has to be a member of what it registers — a Bitcoin quorum it holds no key in, or an EVM account it is not an owner of, is refused rather than signed for and rejected afterwards. Without the co-signers on file, "is this output mine?" collapses to "does it contain a key of mine?", and a hostile coordinator can build a script holding one key of yours and the rest theirs; it hashes correctly, the wallet calls it change, and the money moves somewhere you cannot spend alone. With the quorum registered the device rebuilds the exact script your co-signers produce and compares it byte for byte. `tools/provision.py multisig` does the registering.

## Keys and backup

The device holds a standard BIP39 seed, encrypted at rest and unwrapped only after the gate passes. The unwrapping key comes from your PIN and the secure element's own secret, so the encrypted seed is inert on any other machine and recoverable on this one. Back it up on paper or steel as with any hardware wallet. If the device fails, restore to a Ledger, a Trezor or a replacement build.

The seed itself is drawn from three sources XORed together: the kernel CSPRNG, the ATECC608B's hardware RNG, and the difference between disjoint pairs of speckle frames from the chamber, where the static field cancels and photon shot noise does not. `provision.py` prints the min-entropy it measured on the sample it actually drew. A chamber that is dark, blocked or absent contributes zeros and says so, and zeros XOR into nothing.

## Limits

Worth reading before you trust it with anything. `BUILD.md` §16 carries the full threat model.

**The PIN is what proves who.** The gate only proves that someone alive is present. The PIN is eight digits. PIN-v2 derives each candidate through a random secret in the secure element, consuming a chip-counter use before comparison. A public PIN hash no longer suffices for raw verification commands. Firmware wipes after ten wrong entries; the separate hardware bound is the remaining Counter0 capacity, at most 2,097,151 uses shared with wrapping operations. The new provisioning policy rejects the old configuration. Physical validation remains required before release; see `VALIDATION.md`.

**The attestation rests on firmware and the tamper seal.** It states that a device holding this key ran the gate; it does not prove the gate passed. This is the same assumption as a TPM quote or a Secure Enclave receipt. Someone who opens the case and extracts the key can sign records without bleeding, so treat it as raising the cost of faking a human. Co-signers register firmware hashes alongside keys, and `verify()` refuses builds it does not recognise.

**An opened case derives a different key.** A ground-glass diffuser is epoxied into the optical chamber, and the laser and camera that watch blood clot read its speckle at every unlock. That reading is a term in the key that unwraps the seed, so a case that has been opened does not fail a check. It derives a different key, and the seed stays shut. Thermal drift is registered out against two reference patches and reported separately from tampering. Enrolment is optional. It costs one habit: because the laser is interlocked to the cartridge switch in hardware, an enrolled device needs the bay closed at every unlock, so leave a spent cartridge in the slot. `firmware/optical_puf.py`.

**Coercion needs a second PIN.** No measurement tells willing blood from coerced blood. Set a duress PIN and the device carries two wrapped seeds and two wallets; the duress PIN unlocks, signs and behaves identically, and opens the other one. Both seeds are written whether or not you configure one, so the card never says which kind of device this is. It protects what you sign, not what your device shows: the receive and identity screens are watch-only and still display the primary wallet. Fund the decoy plausibly. `firmware/duress.py`.

**A prepared laboratory attack is not in scope.** A well-made artificial finger containing a genuine haemoglobin-like absorber, driven by a pump replaying recorded variability, would pass the touch tier. So would a citrated sample recalcified immediately before loading, at the blood tier. Both need your blood, your device and your PIN together.

**Anyone taking anticoagulants cannot use the blood tier.** Their blood will not clot, and the gate will reject every sample.

## Repository layout

| Path | Contents |
|---|---|
| `BUILD.md` | Hardware specification: parts, wiring, optics, cartridge, firmware, calibration |
| `PRINTING.md` | Print runbook: order, checks, post-processing |
| `BOM.csv` | Bill of materials, by kit, with sourcing notes |
| `SAFETY.md` | Blood-contact handling. Read it first |
| `VALIDATION.md` | Verification status: what is tested, by what method |
| `CONTRIBUTING.md` | What this project actually needs |
| `firmware/blood_gate.py` | Blood tier, six gates |
| `firmware/touch_gate.py` | Touch tier, seven gates |
| `firmware/calibrate.py` | Spoof-panel harness for both tiers, and the synthetic self-test |
| `firmware/hardware.py` | Sensor drivers, and a bring-up checklist |
| `firmware/policy.py` | Tier selection and escalation rules |
| `firmware/signer.py` | The unlock chain: policy, confirm, PIN, gate, sign, attest |
| `firmware/attest.py` | Tier attestation and quorum verification |
| `firmware/ring.py` | The attestation with the device's name taken off it |
| `firmware/beacon.py` | Proof of life: the attestation with no transaction under it |
| `firmware/duress.py` | The second PIN |
| `firmware/optical_puf.py` | The chamber as a tamper boundary |
| `firmware/chamber_trng.py` | Seed entropy from the chamber, and its health tests |
| `firmware/se_atecc.py` | ATECC608B driver: CheckMac PIN, duress slots |
| `firmware/wallet.py` | Provisioning, and the two signing entry points |
| `firmware/app.py` | The loop, as a person uses it |
| `firmware/ur.py` | UR 2.0 framing, against the published vectors |
| `firmware/link.py` | The optional USB-C wire, and what choosing it costs |
| `firmware/names.py` | WNS, GNS and ENS names the owner registered, and what the screen may draw |
| `firmware/names.py` | WNS, GNS and ENS names the owner registered, and what the screen may draw |
| `firmware/run_tests.py` | Every self-test in one run. What CI runs |
| `tools/provision.py` | Choose a seed, wrap it, record the watch-only accounts |
| `tools/companion.py` | The host end of the USB-C variant's wire |
| `tools/ethnames.py` | Resolves WNS, GNS and ENS on the machine that has a network |
| `tools/ethnames.py` | Resolves WNS, GNS and ENS on the machine that has a network |
| `tools/gen_printables.py` | Generates every printable part, checks it, writes the manifest |
| `tools/gen_enclosure.py` | The inside of the two shells, and the fit checks |
| `tools/bench.py` | The checks only the built device can answer |
| `tools/regtest_e2e.py` | Sign with the firmware, make Bitcoin Core accept it |
| `tools/evm_e2e.py` | Deploy the contracts, make a node accept a beacon the firmware signed |
| `contracts/` | On-chain verification of the attestation record, and the registry |
| `models/print/` | The eleven printable STLs and their generated manifest |
| `viewer/` | Parametric three.js model of the enclosure |
| `diagrams/` | Explainer, build sheet, dimensioned drawings |

<img src="diagrams/build-sheet.svg" alt="Build sheet: parts, optical head, cartridge" width="100%">

## Licence

CC0 1.0. See `LICENSE`.
